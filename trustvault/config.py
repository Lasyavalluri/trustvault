import os
import secrets
from pathlib import Path

from dotenv import load_dotenv


ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

DATA_DIR = Path(os.environ.get("TRUSTVAULT_DATA_DIR", ROOT / ".data")).resolve()
DATABASE_PATH = Path(os.environ.get("TRUSTVAULT_DATABASE", DATA_DIR / "trustvault.sqlite3"))
STORAGE_DIR = Path(os.environ.get("TRUSTVAULT_STORAGE_DIR", DATA_DIR / "documents")).resolve()
MAX_UPLOAD_BYTES = int(os.environ.get("TRUSTVAULT_MAX_UPLOAD_BYTES", 10 * 1024 * 1024))
SESSION_COOKIE = "trustvault_session"
SESSION_TTL_SECONDS = 8 * 60 * 60
PRODUCTION = os.environ.get("TRUSTVAULT_ENV", "development").lower() == "production"


def audit_key() -> bytes:
    configured = os.environ.get("TRUSTVAULT_AUDIT_KEY")
    if configured:
        key = configured.encode("utf-8")
        if len(key) < 32:
            raise RuntimeError("TRUSTVAULT_AUDIT_KEY must contain at least 32 bytes.")
        return key
    if PRODUCTION:
        raise RuntimeError("Set TRUSTVAULT_AUDIT_KEY to a protected, external secret in production.")

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    key_path = DATA_DIR / "audit.key"
    if not key_path.exists():
        try:
            with key_path.open("xb") as key_file:
                key_file.write(secrets.token_bytes(32))
        except FileExistsError:
            pass
    os.chmod(key_path, 0o600)
    return key_path.read_bytes()
