import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, Request

from trustvault.config import SESSION_TTL_SECONDS
from trustvault.database import append_audit, utc_now


def hash_password(password: str) -> str:
    if len(password) < 12:
        raise ValueError("Passwords must be at least 12 characters long.")
    if len(password) > 1024:
        raise ValueError("Passwords must be 1024 characters or fewer.")
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1)
    return f"scrypt$16384$8$1${salt.hex()}${digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        scheme, n, r, p, salt_hex, digest_hex = encoded.split("$")
        if scheme != "scrypt":
            return False
        candidate = hashlib.scrypt(
            password.encode("utf-8"),
            salt=bytes.fromhex(salt_hex),
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=len(bytes.fromhex(digest_hex)),
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(candidate.hex(), digest_hex)


def hash_session(session_id: str) -> str:
    return hashlib.sha256(session_id.encode("utf-8")).hexdigest()


def create_session(db, user_id: str | None) -> tuple[str, str]:
    from datetime import timezone

    session_id = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    db.execute(
        "INSERT INTO sessions (session_hash, user_id, csrf_token, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
        (
            hash_session(session_id),
            user_id,
            csrf,
            now.isoformat(timespec="seconds"),
            (now + timedelta(seconds=SESSION_TTL_SECONDS)).isoformat(timespec="seconds"),
        ),
    )
    return session_id, csrf


def require_user(request: Request):
    user = getattr(request.state, "user", None)
    if user is None:
        append_audit(
            request.state.db,
            actor_id=None,
            action="authentication_required",
            outcome="denied",
            request_id=request.state.request_id,
            details={"path": request.url.path},
        )
        raise HTTPException(status_code=401, detail="Authentication required.")
    return user


def require_csrf(request: Request, submitted_token: str | None) -> None:
    session = getattr(request.state, "session", None)
    if session is None or not submitted_token or not hmac.compare_digest(
        session["csrf_token"], submitted_token
    ):
        append_audit(
            request.state.db,
            actor_id=getattr(getattr(request.state, "user", None), "id", None),
            action="csrf_rejected",
            outcome="denied",
            request_id=request.state.request_id,
            details={"path": request.url.path},
        )
        raise HTTPException(status_code=403, detail="Request verification failed.")


def require_admin(request: Request):
    user = require_user(request)
    if user["role"] != "admin":
        append_audit(
            request.state.db,
            actor_id=user["id"],
            action="admin_action",
            outcome="denied",
            request_id=request.state.request_id,
            details={"path": request.url.path},
        )
        raise HTTPException(status_code=403, detail="Administrator access required.")
    return user


def document_for(request: Request, document_id: str, action: str):
    user = require_user(request)
    db = request.state.db
    document = db.execute(
        """SELECT d.*, u.email AS owner_email, domains.name AS domain_name
        FROM documents d
        JOIN users u ON u.id = d.owner_id
        LEFT JOIN domains ON domains.id = d.domain_id
        WHERE d.id = ? AND d.deleted_at IS NULL""",
        (document_id,),
    ).fetchone()
    grant = None
    if document is not None and document["owner_id"] != user["id"]:
        grant = db.execute(
            """SELECT permission FROM grants
            WHERE document_id = ? AND user_id = ? AND revoked_at IS NULL""",
            (document_id, user["id"]),
        ).fetchone()

    is_owner = document is not None and document["owner_id"] == user["id"]
    is_admin = user["role"] == "admin"
    permission = (
        "admin"
        if is_admin
        else "owner"
        if is_owner
        else (grant["permission"] if grant else None)
    )
    allowed = document is not None and (
        action == "read" and permission in {"owner", "read", "edit"}
        or action == "edit" and permission in {"owner", "edit"}
        or action == "manage" and (is_owner or is_admin)
        or action == "delete" and (is_owner or is_admin)
        or is_admin and action in {"read", "edit"}
    )
    if not allowed:
        append_audit(
            db,
            actor_id=user["id"],
            action="document_access",
            outcome="denied",
            request_id=request.state.request_id,
            document_id=document_id,
            details={"operation": action},
        )
        raise HTTPException(status_code=404, detail="Document not found.")
    return document, permission


def record_access(request: Request, action: str, document_id: str, **details) -> None:
    append_audit(
        request.state.db,
        actor_id=request.state.user["id"],
        action=action,
        outcome="success",
        request_id=request.state.request_id,
        document_id=document_id,
        details=details,
    )


def utc_expiry_is_valid(expires_at: str) -> bool:
    try:
        expiry = datetime.fromisoformat(expires_at)
    except ValueError:
        return False
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    return expiry > datetime.now(timezone.utc)


def iso_now() -> str:
    return utc_now()
