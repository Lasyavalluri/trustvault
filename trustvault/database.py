import hashlib
import hmac
import json
import sqlite3
import uuid
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from trustvault.config import DATABASE_PATH, STORAGE_DIR, audit_key


SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin', 'owner', 'viewer')),
    department TEXT NOT NULL DEFAULT '',
    job_title TEXT NOT NULL DEFAULT '',
    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS domains (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE COLLATE NOCASE,
    description TEXT NOT NULL DEFAULT '',
    created_by TEXT REFERENCES users(id),
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS documents (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL REFERENCES users(id),
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    domain_id TEXT REFERENCES domains(id),
    summary TEXT NOT NULL DEFAULT '',
    storage_key TEXT NOT NULL UNIQUE,
    media_type TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    deleted_at TEXT
);
CREATE TABLE IF NOT EXISTS grants (
    id TEXT PRIMARY KEY,
    document_id TEXT NOT NULL REFERENCES documents(id),
    user_id TEXT NOT NULL REFERENCES users(id),
    permission TEXT NOT NULL CHECK (permission IN ('read', 'edit')),
    granted_by TEXT NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL,
    revoked_at TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS one_active_grant_per_user_document
ON grants(document_id, user_id) WHERE revoked_at IS NULL;
CREATE TABLE IF NOT EXISTS sessions (
    session_hash TEXT PRIMARY KEY,
    user_id TEXT REFERENCES users(id),
    csrf_token TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS login_attempts (
    bucket TEXT NOT NULL,
    attempted_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS login_attempts_by_bucket ON login_attempts(bucket, attempted_at);
CREATE TABLE IF NOT EXISTS audit_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    occurred_at TEXT NOT NULL,
    actor_id TEXT,
    action TEXT NOT NULL,
    document_id TEXT,
    subject_user_id TEXT,
    outcome TEXT NOT NULL,
    request_id TEXT NOT NULL,
    details_json TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS audit_events_no_update
BEFORE UPDATE ON audit_events BEGIN
    SELECT RAISE(ABORT, 'audit events are append-only');
END;
CREATE TRIGGER IF NOT EXISTS audit_events_no_delete
BEFORE DELETE ON audit_events BEGIN
    SELECT RAISE(ABORT, 'audit events are append-only');
END;
CREATE TABLE IF NOT EXISTS access_suggestions (
    id TEXT PRIMARY KEY,
    actor_id TEXT NOT NULL REFERENCES users(id),
    document_id TEXT NOT NULL REFERENCES documents(id),
    recipient_id TEXT NOT NULL REFERENCES users(id),
    permission TEXT NOT NULL CHECK (permission IN ('read', 'edit')),
    rationale TEXT NOT NULL,
    created_at TEXT NOT NULL,
    decision TEXT CHECK (decision IN ('accepted', 'rejected')),
    decided_by TEXT REFERENCES users(id),
    decided_at TEXT
);
CREATE TABLE IF NOT EXISTS pending_uploads (
    token_hash TEXT PRIMARY KEY,
    actor_id TEXT NOT NULL REFERENCES users(id),
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    domain_id TEXT NOT NULL REFERENCES domains(id),
    summary TEXT NOT NULL,
    suggested_domain TEXT NOT NULL,
    suggested_category TEXT NOT NULL,
    storage_key TEXT NOT NULL UNIQUE,
    media_type TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS pending_agent_actions (
    token_hash TEXT PRIMARY KEY,
    actor_id TEXT NOT NULL REFERENCES users(id),
    action TEXT NOT NULL CHECK (action IN ('grant', 'revoke')),
    document_id TEXT NOT NULL REFERENCES documents(id),
    user_id TEXT NOT NULL REFERENCES users(id),
    permission TEXT CHECK (permission IN ('read', 'edit')),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
"""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def connect() -> sqlite3.Connection:
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DATABASE_PATH, timeout=10, check_same_thread=False)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    db.execute("PRAGMA busy_timeout = 10000")
    return db


def initialize() -> None:
    STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    with closing(connect()) as db:
        db.executescript(SCHEMA)
        user_columns = {row["name"] for row in db.execute("PRAGMA table_info(users)")}
        if "department" not in user_columns:
            db.execute("ALTER TABLE users ADD COLUMN department TEXT NOT NULL DEFAULT ''")
        if "job_title" not in user_columns:
            db.execute("ALTER TABLE users ADD COLUMN job_title TEXT NOT NULL DEFAULT ''")
        document_columns = {row["name"] for row in db.execute("PRAGMA table_info(documents)")}
        if "domain_id" not in document_columns:
            db.execute("ALTER TABLE documents ADD COLUMN domain_id TEXT REFERENCES domains(id)")
        if "summary" not in document_columns:
            db.execute("ALTER TABLE documents ADD COLUMN summary TEXT NOT NULL DEFAULT ''")
        for row in db.execute(
            "SELECT DISTINCT category FROM documents WHERE category <> ''"
        ).fetchall():
            domain = db.execute(
                "SELECT id FROM domains WHERE name = ? COLLATE NOCASE", (row["category"],)
            ).fetchone()
            if domain is None:
                domain_id = uuid.uuid4().hex
                db.execute(
                    "INSERT INTO domains (id, name, created_at) VALUES (?, ?, ?)",
                    (domain_id, row["category"], utc_now()),
                )
            else:
                domain_id = domain["id"]
            db.execute(
                "UPDATE documents SET domain_id = ? WHERE category = ? AND domain_id IS NULL",
                (domain_id, row["category"]),
            )
        db.commit()


def append_audit(
    db: sqlite3.Connection,
    *,
    actor_id: str | None,
    action: str,
    outcome: str,
    request_id: str,
    document_id: str | None = None,
    subject_user_id: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    started_transaction = db.in_transaction
    if not started_transaction:
        db.execute("BEGIN IMMEDIATE")
    previous = db.execute(
        "SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1"
    ).fetchone()
    previous_hash = previous["event_hash"] if previous else "0" * 64
    occurred_at = utc_now()
    details_json = json.dumps(details or {}, sort_keys=True, separators=(",", ":"))
    event_id = uuid.uuid4().hex
    payload = json.dumps(
        {
            "action": action,
            "actor_id": actor_id,
            "details_json": details_json,
            "document_id": document_id,
            "event_id": event_id,
            "occurred_at": occurred_at,
            "outcome": outcome,
            "previous_hash": previous_hash,
            "request_id": request_id,
            "subject_user_id": subject_user_id,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    event_hash = hmac.new(audit_key(), previous_hash.encode() + b"\n" + payload, hashlib.sha256).hexdigest()
    db.execute(
        """INSERT INTO audit_events
        (event_id, occurred_at, actor_id, action, document_id, subject_user_id,
         outcome, request_id, details_json, previous_hash, event_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            event_id,
            occurred_at,
            actor_id,
            action,
            document_id,
            subject_user_id,
            outcome,
            request_id,
            details_json,
            previous_hash,
            event_hash,
        ),
    )
    if not started_transaction:
        db.commit()


def verify_audit(db: sqlite3.Connection) -> tuple[bool, int | None]:
    previous_hash = "0" * 64
    for row in db.execute("SELECT * FROM audit_events ORDER BY sequence"):
        if row["previous_hash"] != previous_hash:
            return False, row["sequence"]
        payload = json.dumps(
            {
                "action": row["action"],
                "actor_id": row["actor_id"],
                "details_json": row["details_json"],
                "document_id": row["document_id"],
                "event_id": row["event_id"],
                "occurred_at": row["occurred_at"],
                "outcome": row["outcome"],
                "previous_hash": row["previous_hash"],
                "request_id": row["request_id"],
                "subject_user_id": row["subject_user_id"],
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        expected = hmac.new(
            audit_key(), previous_hash.encode() + b"\n" + payload, hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(row["event_hash"], expected):
            return False, row["sequence"]
        previous_hash = row["event_hash"]
    return True, None


def seed_user(email: str, password_hash: str, role: str) -> str:
    user_id = uuid.uuid4().hex
    with closing(connect()) as db, db:
        db.execute(
            "INSERT INTO users (id, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)",
            (user_id, email.strip().lower(), password_hash, role, utc_now()),
        )
    return user_id


def database_path() -> Path:
    return DATABASE_PATH
