import os
import re
import shutil
import tempfile
from html.parser import HTMLParser
from pathlib import Path

import pytest

TEST_ROOT = tempfile.mkdtemp(prefix="trustvault-tests-")
os.environ["TRUSTVAULT_DATA_DIR"] = str(Path(TEST_ROOT) / "data")
os.environ["TRUSTVAULT_DATABASE"] = str(Path(TEST_ROOT) / "test.sqlite3")
os.environ["TRUSTVAULT_STORAGE_DIR"] = str(Path(TEST_ROOT) / "private-files")
os.environ["TRUSTVAULT_AUDIT_KEY"] = "test-audit-signing-key-at-least-32-bytes-long"

from fastapi.testclient import TestClient

from trustvault.database import connect, initialize, seed_user, verify_audit
from trustvault.security import hash_password
from trustvault.web import app, create_demo_accounts, setup_demo_viewers


class CsrfParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.token = None

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == "input" and values.get("name") == "csrf_token":
            self.token = values.get("value")


def csrf_from(response):
    parser = CsrfParser()
    parser.feed(response.text)
    assert parser.token
    return parser.token


def login(client, email, password):
    response = client.get("/login")
    return client.post(
        "/login",
        data={"email": email, "password": password, "csrf_token": csrf_from(response)},
        follow_redirects=False,
    )


@pytest.fixture
def vault():
    db_path = Path(TEST_ROOT) / "test.sqlite3"
    if db_path.exists():
        db_path.unlink()
    storage = Path(TEST_ROOT) / "private-files"
    if storage.exists():
        shutil.rmtree(storage)
    initialize()
    password = "correct-horse-battery-staple"
    password_hash = hash_password(password)
    ids = {
        "owner": seed_user("owner@example.test", password_hash, "owner"),
        "viewer": seed_user("viewer@example.test", password_hash, "viewer"),
        "editor": seed_user("editor@example.test", password_hash, "viewer"),
        "admin": seed_user("admin@example.test", password_hash, "admin"),
    }
    db = connect()
    for name in ("HR", "Finance", "Contracts"):
        domain_id = name.lower()
        db.execute(
            "INSERT INTO domains (id, name, created_at) VALUES (?, ?, ?)",
            (domain_id, name, "2026-10-23T00:00:00+00:00"),
        )
        ids[f"domain_{name.lower()}"] = domain_id
    db.commit()
    db.close()
    with TestClient(app) as client:
        yield client, ids, password


def add_pdf(document_id, owner_id, name="Confidential salary letter"):
    storage_key = f"private-{document_id}"
    content = b"%PDF-1.7\nTrustVault test document\n"
    (Path(TEST_ROOT) / "private-files" / storage_key).write_bytes(content)
    db = connect()
    db.execute(
        """INSERT INTO documents
        (id, owner_id, name, category, domain_id, storage_key, media_type, size_bytes, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            document_id,
            owner_id,
            name,
            "HR",
            "hr",
            storage_key,
            "application/pdf",
            len(content),
            "2026-10-23T00:00:00+00:00",
            "2026-10-23T00:00:00+00:00",
        ),
    )
    db.commit()
    db.close()
    return content


def grant(client, document_id, email, permission):
    detail = client.get(f"/documents/{document_id}")
    return client.post(
        f"/documents/{document_id}/access",
        data={
            "csrf_token": csrf_from(detail),
            "email": email,
            "permission": permission,
        },
        follow_redirects=False,
    )


def test_ungranted_user_cannot_read_download_or_search_other_users_document(vault):
    client, ids, password = vault
    add_pdf("private-doc", ids["owner"])
    assert login(client, "viewer@example.test", password).status_code == 303

    assert client.get("/documents/private-doc").status_code == 404
    assert client.get("/documents/private-doc/download").status_code == 404
    search = client.get("/documents", params={"q": "Confidential"})
    assert "Confidential salary letter" not in search.text
    assert "0 documents" in search.text

    db = connect()
    denied = db.execute(
        """SELECT COUNT(*) FROM audit_events
        WHERE actor_id = ? AND outcome = 'denied' AND document_id = 'private-doc'""",
        (ids["viewer"],),
    ).fetchone()[0]
    assert denied == 2
    valid, broken = verify_audit(db)
    db.close()
    assert valid and broken is None


def test_dashboard_is_landing_page_and_scopes_documents(vault):
    client, ids, password = vault
    add_pdf("dashboard-private", ids["owner"])
    assert login(client, "owner@example.test", password).headers["location"] == "/dashboard"
    dashboard = client.get("/dashboard")
    assert dashboard.status_code == 200
    assert "Confidential salary letter" in dashboard.text
    assert "Dashboard" in dashboard.text
    assert client.get("/", follow_redirects=False).headers["location"] == "/dashboard"

    viewer = TestClient(app)
    assert login(viewer, "viewer@example.test", password).status_code == 303
    assert "Confidential salary letter" not in viewer.get("/dashboard").text
    viewer.close()

    admin = TestClient(app)
    assert login(admin, "admin@example.test", password).status_code == 303
    admin_dashboard = admin.get("/dashboard")
    assert admin_dashboard.status_code == 200
    assert "Recent activity" in admin_dashboard.text
    assert "Data lake" in admin_dashboard.text
    admin.close()


def test_admin_can_edit_document_metadata_owner_access_and_domains(vault):
    _, ids, password = vault
    add_pdf("admin-editable", ids["owner"], name="Original title")
    admin = TestClient(app)
    assert login(admin, "admin@example.test", password).status_code == 303
    detail = admin.get("/documents/admin-editable")
    updated = admin.post(
        "/documents/admin-editable/edit",
        data={
            "csrf_token": csrf_from(detail),
            "name": "Updated title",
            "category": "Policy",
            "domain_id": ids["domain_finance"],
            "owner_id": ids["owner"],
            "summary": "Reviewed administrator summary.",
        },
        follow_redirects=False,
    )
    assert updated.status_code == 303
    changed = admin.get("/documents/admin-editable")
    assert "Updated title" in changed.text
    assert "Reviewed administrator summary." in changed.text

    data_lake = admin.get("/admin/data-lake")
    new_domain = admin.post(
        "/admin/domains",
        data={
            "csrf_token": csrf_from(data_lake),
            "name": "Legal",
            "description": "Legal review materials",
        },
        follow_redirects=False,
    )
    assert new_domain.status_code == 303
    data_lake = admin.get("/admin/data-lake")
    domain_id = connect()
    legal_id = domain_id.execute(
        "SELECT id FROM domains WHERE name = 'Legal'"
    ).fetchone()["id"]
    domain_id.close()
    renamed = admin.post(
        f"/admin/domains/{legal_id}",
        data={
            "csrf_token": csrf_from(data_lake),
            "name": "Legal Affairs",
            "description": "Updated description",
        },
        follow_redirects=False,
    )
    assert renamed.status_code == 303
    data_lake = admin.get("/admin/data-lake")
    deleted = admin.post(
        f"/admin/domains/{legal_id}/delete",
        data={"csrf_token": csrf_from(data_lake)},
        follow_redirects=False,
    )
    assert deleted.status_code == 303

    db = connect()
    document = db.execute(
        """SELECT d.name, d.category, d.domain_id, d.summary, domains.name AS domain_name
        FROM documents d JOIN domains ON domains.id = d.domain_id
        WHERE d.id = 'admin-editable'"""
    ).fetchone()
    assert document["name"] == "Updated title"
    assert document["category"] == "Policy"
    assert document["domain_id"] == ids["domain_finance"]
    assert document["domain_name"] == "Finance"
    assert document["summary"] == "Reviewed administrator summary."
    assert db.execute("SELECT COUNT(*) FROM domains WHERE id = ?", (legal_id,)).fetchone()[0] == 0
    db.close()
    admin.close()


def test_admin_agent_chat_requires_confirmation_to_grant_and_revoke(vault):
    _, ids, password = vault
    add_pdf("agent-chat-doc", ids["owner"], name="Agent test document")
    admin = TestClient(app)
    assert login(admin, "admin@example.test", password).status_code == 303
    viewer = TestClient(app)
    assert login(viewer, "viewer@example.test", password).status_code == 303
    assert viewer.get("/admin/agent-chat").status_code == 403

    chat = admin.get("/admin/agent-chat")
    assert chat.status_code == 200
    pending_response = admin.post(
        "/admin/agent-chat",
        data={
            "csrf_token": csrf_from(chat),
            "message": "grant read access to viewer@example.test for document Agent test document",
        },
    )
    assert pending_response.status_code == 200
    assert "Confirm change" in pending_response.text
    assert viewer.get("/documents/agent-chat-doc").status_code == 404
    db = connect()
    assert db.execute("SELECT COUNT(*) FROM grants").fetchone()[0] == 0
    pending_token = db.execute(
        "SELECT token_hash FROM pending_agent_actions"
    ).fetchone()["token_hash"]
    db.close()

    cancel_chat = admin.get("/admin/agent-chat")
    cancelled_proposal = admin.post(
        "/admin/agent-chat",
        data={
            "csrf_token": csrf_from(cancel_chat),
            "message": "grant edit access to editor@example.test for document Agent test document",
        },
    )
    cancel_match = re.search(r"/admin/agent-chat/([^/]+)/cancel", cancelled_proposal.text)
    assert cancel_match
    cancelled = admin.post(
        f"/admin/agent-chat/{cancel_match.group(1)}/cancel",
        data={"csrf_token": csrf_from(cancelled_proposal)},
    )
    assert cancelled.status_code == 200
    db = connect()
    assert db.execute("SELECT COUNT(*) FROM grants").fetchone()[0] == 0
    db.close()

    token_match = re.search(r"/admin/agent-chat/([^/]+)/confirm", pending_response.text)
    assert token_match
    confirmed = admin.post(
        f"/admin/agent-chat/{token_match.group(1)}/confirm",
        data={"csrf_token": csrf_from(pending_response)},
        follow_redirects=False,
    )
    assert confirmed.status_code == 200
    assert "Grant operation completed" in confirmed.text
    assert viewer.get("/documents/agent-chat-doc").status_code == 200

    chat = admin.get("/admin/agent-chat")
    revoke_response = admin.post(
        "/admin/agent-chat",
        data={
            "csrf_token": csrf_from(chat),
            "message": "revoke access for viewer@example.test from document Agent test document",
        },
    )
    assert revoke_response.status_code == 200
    assert "Confirm change" in revoke_response.text
    assert viewer.get("/documents/agent-chat-doc").status_code == 200
    revoke_match = re.search(r"/admin/agent-chat/([^/]+)/confirm", revoke_response.text)
    assert revoke_match
    revoked = admin.post(
        f"/admin/agent-chat/{revoke_match.group(1)}/confirm",
        data={"csrf_token": csrf_from(revoke_response)},
    )
    assert revoked.status_code == 200
    assert "Revoke operation completed" in revoked.text
    assert viewer.get("/documents/agent-chat-doc").status_code == 404

    db = connect()
    grant = db.execute(
        "SELECT revoked_at FROM grants WHERE document_id = 'agent-chat-doc'"
    ).fetchone()
    actions = {
        row["action"]
        for row in db.execute(
            "SELECT action FROM audit_events WHERE document_id = 'agent-chat-doc'"
        )
    }
    assert grant["revoked_at"] is not None
    assert "permission_granted" in actions
    assert "permission_revoked" in actions
    assert db.execute(
        "SELECT COUNT(*) FROM pending_agent_actions WHERE token_hash = ?",
        (pending_token,),
    ).fetchone()[0] == 0
    db.close()
    viewer.close()
    admin.close()


def test_revocation_blocks_the_next_read_and_download(vault):
    client, ids, password = vault
    original = add_pdf("revocable-doc", ids["owner"])
    assert login(client, "owner@example.test", password).status_code == 303
    assert grant(client, "revocable-doc", "viewer@example.test", "read").status_code == 303

    viewer = TestClient(app)
    assert login(viewer, "viewer@example.test", password).status_code == 303
    assert viewer.get("/documents/revocable-doc").status_code == 200
    assert viewer.get("/documents/revocable-doc/download").content == original

    detail = client.get("/documents/revocable-doc")
    revoke = client.post(
        f"/documents/revocable-doc/access/{ids['viewer']}/revoke",
        data={"csrf_token": csrf_from(detail)},
        follow_redirects=False,
    )
    assert revoke.status_code == 303
    assert viewer.get("/documents/revocable-doc").status_code == 404
    assert viewer.get("/documents/revocable-doc/download").status_code == 404
    viewer.close()


def test_read_grant_cannot_edit_and_admin_can_manage_data_lake(vault):
    client, ids, password = vault
    add_pdf("read-only-doc", ids["owner"])
    assert login(client, "owner@example.test", password).status_code == 303
    assert grant(client, "read-only-doc", "viewer@example.test", "read").status_code == 303

    viewer = TestClient(app)
    assert login(viewer, "viewer@example.test", password).status_code == 303
    denied_edit = viewer.post(
        "/documents/read-only-doc/edit",
        data={"name": "Changed", "category": "Changed", "csrf_token": "not-needed-to-reach-policy"},
        follow_redirects=False,
    )
    assert denied_edit.status_code == 404
    viewer.close()

    admin = TestClient(app)
    assert login(admin, "admin@example.test", password).status_code == 303
    assert admin.get("/documents/read-only-doc").status_code == 200
    assert admin.get("/documents/read-only-doc/download").content.startswith(b"%PDF-")
    assert "read-only-doc" in admin.get("/documents").text
    admin.close()

    db = connect()
    name = db.execute("SELECT name FROM documents WHERE id = 'read-only-doc'").fetchone()["name"]
    db.close()
    assert name == "Confidential salary letter"


def test_edit_grant_allows_edit_but_not_permission_management_or_deletion(vault):
    client, ids, password = vault
    add_pdf("editable-doc", ids["owner"])
    assert login(client, "owner@example.test", password).status_code == 303
    assert grant(client, "editable-doc", "editor@example.test", "edit").status_code == 303

    editor = TestClient(app)
    assert login(editor, "editor@example.test", password).status_code == 303
    detail = editor.get("/documents/editable-doc")
    assert "Edit document details" in detail.text
    changed = editor.post(
        "/documents/editable-doc/edit",
        data={"name": "Updated agreement", "category": "Legal", "csrf_token": csrf_from(detail)},
        follow_redirects=False,
    )
    assert changed.status_code == 303
    replacement = b"%PDF-1.7\nreplacement version\n"
    replaced = editor.post(
        "/documents/editable-doc/content",
        data={"csrf_token": csrf_from(detail)},
        files={"file": ("agreement.pdf", replacement, "application/pdf")},
        follow_redirects=False,
    )
    assert replaced.status_code == 303
    assert editor.get("/documents/editable-doc/download").content == replacement
    assert editor.post(
        "/documents/editable-doc/access",
        data={
            "email": "admin@example.test",
            "permission": "read",
            "csrf_token": csrf_from(detail),
        },
        follow_redirects=False,
    ).status_code == 404
    assert editor.post(
        "/documents/editable-doc/delete",
        data={"csrf_token": csrf_from(detail)},
        follow_redirects=False,
    ).status_code == 404
    editor.close()


def test_disabled_account_loses_access_even_with_an_old_cookie(vault):
    client, ids, password = vault
    add_pdf("disabled-user-doc", ids["owner"])
    assert login(client, "owner@example.test", password).status_code == 303
    assert grant(client, "disabled-user-doc", "viewer@example.test", "read").status_code == 303

    viewer = TestClient(app)
    assert login(viewer, "viewer@example.test", password).status_code == 303

    admin = TestClient(app)
    assert login(admin, "admin@example.test", password).status_code == 303
    users_page = admin.get("/admin/users")
    disabled = admin.post(
        f"/admin/users/{ids['viewer']}/disable",
        data={"csrf_token": csrf_from(users_page)},
        follow_redirects=False,
    )
    assert disabled.status_code == 303
    assert viewer.get("/documents/disabled-user-doc").status_code == 401
    db = connect()
    revoked = db.execute(
        "SELECT revoked_at FROM grants WHERE document_id = 'disabled-user-doc' AND user_id = ?",
        (ids["viewer"],),
    ).fetchone()
    db.close()
    assert revoked["revoked_at"] is not None
    admin.close()
    viewer.close()


def test_local_access_assistant_only_grants_after_admin_approval(vault):
    _, ids, password = vault
    add_pdf("assistant-doc", ids["owner"], name="HR policy")
    db = connect()
    db.execute("UPDATE users SET department = 'HR' WHERE id = ?", (ids["viewer"],))
    db.commit()
    db.close()

    admin = TestClient(app)
    assert login(admin, "admin@example.test", password).status_code == 303
    page = admin.get("/admin/access-assistant", params={"selected_user": ids["viewer"]})
    assert page.status_code == 200
    db = connect()
    assert db.execute("SELECT COUNT(*) FROM access_suggestions").fetchone()[0] == 0
    db.close()

    suggested = admin.post(
        "/admin/access-assistant",
        data={"selected_user": ids["viewer"], "csrf_token": csrf_from(page)},
        follow_redirects=False,
    )
    assert suggested.status_code == 303
    db = connect()
    suggestion = db.execute(
        "SELECT * FROM access_suggestions WHERE recipient_id = ?",
        (ids["viewer"],),
    ).fetchone()
    assert suggestion["permission"] == "read"
    assert db.execute(
        "SELECT COUNT(*) FROM grants WHERE document_id = 'assistant-doc'"
    ).fetchone()[0] == 0
    db.close()

    detail = admin.get("/documents/assistant-doc")
    approval = admin.post(
        "/documents/assistant-doc/access",
        data={
            "email": "viewer@example.test",
            "permission": "read",
            "suggestion_id": suggestion["id"],
            "csrf_token": csrf_from(detail),
        },
        follow_redirects=False,
    )
    assert approval.status_code == 303
    db = connect()
    assert db.execute(
        "SELECT decision FROM access_suggestions WHERE id = ?", (suggestion["id"],)
    ).fetchone()["decision"] == "accepted"
    db.close()

    viewer = TestClient(app)
    assert login(viewer, "viewer@example.test", password).status_code == 303
    assert viewer.get("/documents/assistant-doc").status_code == 200
    viewer.close()
    admin.close()


def test_gemini_domain_mismatch_requires_confirmation_before_storage(
    vault, monkeypatch
):
    _, ids, password = vault
    monkeypatch.setenv("GEMINI_API_KEY", "test-only-key")
    monkeypatch.setattr(
        "trustvault.web.generate_gemini_metadata",
        lambda *_: {
            "summary": "A sample confidential HR document.",
            "suggested_domain": "HR",
            "suggested_category": "Policy",
        },
    )
    admin = TestClient(app)
    assert login(admin, "admin@example.test", password).status_code == 303
    form = admin.get("/documents/new")
    response = admin.post(
        "/documents",
        data={
            "csrf_token": csrf_from(form),
            "name": "Mismatch test",
            "domain_id": ids["domain_finance"],
            "use_gemini": "true",
        },
        files={"file": ("policy.pdf", b"%PDF-1.7\nexample", "application/pdf")},
        follow_redirects=False,
    )
    assert response.status_code == 200
    assert "Gemini suggested" in response.text
    token_match = re.search(r"/admin/pending-uploads/([^/]+)/confirm", response.text)
    assert token_match
    db = connect()
    assert db.execute("SELECT COUNT(*) FROM documents").fetchone()[0] == 0
    assert db.execute("SELECT COUNT(*) FROM pending_uploads").fetchone()[0] == 1
    assert db.execute("SELECT COUNT(*) FROM grants").fetchone()[0] == 0
    db.close()

    confirmed = admin.post(
        f"/admin/pending-uploads/{token_match.group(1)}/confirm",
        data={
            "csrf_token": csrf_from(response),
            "domain_id": ids["domain_hr"],
            "category": "Policy",
        },
        follow_redirects=False,
    )
    assert confirmed.status_code == 303
    document_id = confirmed.headers["location"].rsplit("/", 1)[-1]
    db = connect()
    document = db.execute(
        "SELECT domain_id, summary FROM documents WHERE id = ?", (document_id,)
    ).fetchone()
    assert document["domain_id"] == ids["domain_hr"]
    assert document["summary"] == "A sample confidential HR document."
    assert db.execute("SELECT COUNT(*) FROM pending_uploads").fetchone()[0] == 0
    db.close()
    admin.close()


def test_upload_validation_and_owner_only_access(vault):
    client, ids, password = vault
    assert login(client, "owner@example.test", password).status_code == 303
    form = client.get("/documents/new")
    token = csrf_from(form)
    uploaded = client.post(
        "/documents",
        data={"csrf_token": token, "name": "Quarterly report", "category": "Finance", "domain_id": ids["domain_finance"]},
        files={"file": ("report.pdf", b"%PDF-1.7\nsample", "application/pdf")},
        follow_redirects=False,
    )
    assert uploaded.status_code == 303
    document_id = uploaded.headers["location"].rsplit("/", 1)[-1]
    assert client.get(f"/documents/{document_id}/download").content == b"%PDF-1.7\nsample"

    form = client.get("/documents/new")
    rejected = client.post(
        "/documents",
        data={"csrf_token": csrf_from(form), "name": "Unsafe file", "category": "Finance", "domain_id": ids["domain_finance"]},
        files={"file": ("unsafe.html", b"<script>alert(1)</script>", "text/html")},
        follow_redirects=False,
    )
    assert rejected.status_code == 400
    assert "Allowed formats" in rejected.text

    viewer = TestClient(app)
    assert login(viewer, "viewer@example.test", password).status_code == 303
    assert viewer.get(f"/documents/{document_id}/download").status_code == 404
    viewer.close()


def test_named_editor_can_replace_content_and_every_change_is_audited(vault):
    client, ids, password = vault
    original = add_pdf("replaceable-doc", ids["owner"])
    assert login(client, "owner@example.test", password).status_code == 303
    assert grant(client, "replaceable-doc", "editor@example.test", "edit").status_code == 303

    editor = TestClient(app)
    assert login(editor, "editor@example.test", password).status_code == 303
    detail = editor.get("/documents/replaceable-doc")
    replacement = b"%PDF-1.7\nnew reviewed content\n"
    response = editor.post(
        "/documents/replaceable-doc/content",
        data={"csrf_token": csrf_from(detail)},
        files={"file": ("replacement.pdf", replacement, "application/pdf")},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert editor.get("/documents/replaceable-doc/download").content == replacement
    editor.close()

    db = connect()
    actions = {
        row["action"]
        for row in db.execute("SELECT action FROM audit_events WHERE document_id = 'replaceable-doc'")
    }
    assert "document_content_changed" in actions
    assert "permission_granted" in actions
    assert original != replacement
    db.close()


def test_csrf_is_required_for_grants_and_audit_modification_is_detected(vault):
    client, ids, password = vault
    add_pdf("audit-doc", ids["owner"])
    assert login(client, "owner@example.test", password).status_code == 303
    denied = client.post(
        "/documents/audit-doc/access",
        data={
            "email": "viewer@example.test",
            "permission": "read",
            "csrf_token": "invalid",
        },
        follow_redirects=False,
    )
    assert denied.status_code == 403

    db = connect()
    assert db.execute("SELECT COUNT(*) FROM grants").fetchone()[0] == 0
    valid, _ = verify_audit(db)
    assert valid
    db.execute("DROP TRIGGER audit_events_no_update")
    db.execute("UPDATE audit_events SET outcome = 'success' WHERE action = 'csrf_rejected'")
    db.commit()
    valid, broken_sequence = verify_audit(db)
    db.close()
    assert not valid
    assert broken_sequence is not None


def test_template_escapes_document_names(vault):
    client, ids, password = vault
    add_pdf("escaped-doc", ids["owner"], name="<script>alert(1)</script>.pdf")
    assert login(client, "owner@example.test", password).status_code == 303
    response = client.get("/documents/escaped-doc")
    assert response.status_code == 200
    assert "<script>alert(1)</script>" not in response.text
    assert "&lt;script&gt;" in response.text


def test_login_failures_are_generic_rate_limited_and_login_rotates_session(vault):
    client, _, password = vault
    login_page = client.get("/login")
    token = csrf_from(login_page)
    unknown = client.post(
        "/login",
        data={"email": "missing@example.test", "password": "incorrect-password", "csrf_token": token},
        follow_redirects=False,
    )
    known = client.post(
        "/login",
        data={"email": "viewer@example.test", "password": "incorrect-password", "csrf_token": token},
        follow_redirects=False,
    )
    assert unknown.status_code == known.status_code == 401
    assert "Sign-in failed." in unknown.text
    assert unknown.text == known.text
    for _ in range(7):
        response = client.post(
            "/login",
            data={"email": "viewer@example.test", "password": "incorrect-password", "csrf_token": token},
            follow_redirects=False,
        )
        assert response.status_code == 401
    limited = client.post(
        "/login",
        data={"email": "viewer@example.test", "password": password, "csrf_token": token},
        follow_redirects=False,
    )
    assert limited.status_code == 429

    fresh = TestClient(app)
    fresh.get("/login")
    before_login = fresh.cookies.get("trustvault_session")
    assert login(fresh, "owner@example.test", password).status_code == 303
    after_login = fresh.cookies.get("trustvault_session")
    assert before_login != after_login
    fresh.close()


def test_traversal_filename_never_becomes_a_storage_path(vault):
    client, ids, password = vault
    assert login(client, "owner@example.test", password).status_code == 303
    form = client.get("/documents/new")
    response = client.post(
        "/documents",
        data={
            "csrf_token": csrf_from(form),
            "name": "Safe display name",
            "category": "Contracts",
            "domain_id": ids["domain_contracts"],
        },
        files={"file": ("..\\..\\outside.pdf", b"%PDF-1.7\nsafe", "application/pdf")},
        follow_redirects=False,
    )
    assert response.status_code == 303
    document_id = response.headers["location"].rsplit("/", 1)[-1]
    db = connect()
    key = db.execute(
        "SELECT storage_key FROM documents WHERE id = ?", (document_id,)
    ).fetchone()["storage_key"]
    db.close()
    assert Path(key).name == key
    assert (Path(TEST_ROOT) / "private-files" / key).is_file()


def test_owner_deletion_blocks_future_access_and_keeps_an_audit_record(vault):
    client, ids, password = vault
    add_pdf("deleted-doc", ids["owner"])
    assert login(client, "owner@example.test", password).status_code == 303
    detail = client.get("/documents/deleted-doc")
    response = client.post(
        "/documents/deleted-doc/delete",
        data={"csrf_token": csrf_from(detail)},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert client.get("/documents/deleted-doc").status_code == 404
    assert client.get("/documents/deleted-doc/download").status_code == 404

    db = connect()
    deletion = db.execute(
        """SELECT outcome FROM audit_events
        WHERE actor_id = ? AND document_id = 'deleted-doc' AND action = 'document_delete'""",
        (ids["owner"],),
    ).fetchone()
    retained = db.execute(
        "SELECT deleted_at FROM documents WHERE id = 'deleted-doc'"
    ).fetchone()
    db.close()
    assert deletion["outcome"] == "success"
    assert retained["deleted_at"] is not None


def test_four_demo_viewers_have_independent_credentials_and_no_implicit_access(vault):
    _, ids, _ = vault
    add_pdf("viewers-private-doc", ids["owner"])
    credentials = setup_demo_viewers()
    assert set(credentials) == {"user1", "user2", "user3", "user4"}
    assert len({entry.split(" / ", 1)[1] for entry in credentials.values()}) == 4

    for number in range(1, 5):
        email, password = credentials[f"user{number}"].split(" / ", 1)
        db = connect()
        user = db.execute("SELECT id, role FROM users WHERE email = ?", (email,)).fetchone()
        db.close()
        assert user["role"] == "viewer"
        client = TestClient(app)
        assert login(client, email, password).status_code == 303
        assert client.get("/documents/viewers-private-doc").status_code == 404
        client.close()

    db = connect()
    assert db.execute(
        "SELECT email FROM users WHERE id = ?", (ids["viewer"],)
    ).fetchone()["email"] == "user1@example.test"
    db.close()


def test_demo_seed_creates_valid_roles_domain_and_sample_grant():
    db_path = Path(TEST_ROOT) / "test.sqlite3"
    if db_path.exists():
        db_path.unlink()
    storage = Path(TEST_ROOT) / "private-files"
    if storage.exists():
        shutil.rmtree(storage)

    credentials = create_demo_accounts()
    db = connect()
    users = db.execute("SELECT email, role FROM users").fetchall()
    assert len(users) == 6
    assert {row["role"] for row in users} == {"admin", "owner", "viewer"}
    sample = db.execute(
        """SELECT d.domain_id, domains.name AS domain_name, g.permission, u.email
        FROM documents d
        JOIN domains ON domains.id = d.domain_id
        JOIN grants g ON g.document_id = d.id AND g.revoked_at IS NULL
        JOIN users u ON u.id = g.user_id
        WHERE d.id = ?""",
        (credentials["sample_document"],),
    ).fetchone()
    assert sample["domain_name"] == "Contracts"
    assert sample["permission"] == "read"
    assert sample["email"] == "user1@example.test"
    db.close()
