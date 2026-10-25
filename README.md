# TrustVault

TrustVault is a Python-only, server-rendered document-sharing demo. FastAPI serves Jinja2 HTML templates and plain CSS; there is no Node.js, React, Next.js, browser JavaScript, or separate frontend service.

> **Security status:** this is a local challenge/demo implementation, not a production-ready confidential-document service. It uses local SQLite and a local HMAC audit key. It has not been deployed, independently penetration-tested, malware-scanned, or anchored to an external WORM audit service. Do not upload real company documents or use real/reused passwords.

## Roles and permissions

- **Administrator:** onboards and disables accounts, maintains department/job-title profiles and domains, manages the document data lake and grants, and views activity. Admin document operations are intentionally broad and every operation is server-authorized and audited.
- **Owner:** uploads and manages documents they own; grants and revokes named users' `read` or `edit` permission; deletes their documents.
- **Viewers (`user1` to `user4`):** separate accounts with separate passwords. Each accesses only documents with an active, named grant. A `read` grant allows viewing and downloading.
- **Editor:** a viewer account with an `edit` grant can also edit that particular document's metadata. Editors cannot grant, revoke, or delete.

Every document page, download, search query, and mutation checks current account status and current per-document access on the server. Downloads are streamed from a private folder only after that check. Revocation is checked on the next request; it cannot recall bytes already downloaded or a transfer already in progress.

## Admin workflows and assistant boundaries

Administrators create named domains and upload/manage documents from the data-lake view. Departments and job titles are account metadata maintained by an administrator. The local access assistant recommends **read-only** document grants only when the selected account's department exactly matches a document domain. It explains the match and does not create a grant; an administrator must explicitly approve or reject each suggestion. Job title does not widen access.

The admin-only **Access agent chat** accepts explicit commands such as `grant read access to user1@example.test for document Sample supplier agreement` or `revoke access for user1@example.test from document Sample supplier agreement`. It resolves one exact account and document, displays a review/confirmation step, then applies and audits the permission change only after confirmation. Commands expire after five minutes. The chat is a deterministic local parser, not a generative AI; it cannot view or upload document contents, and Gemini is not involved in access decisions.

Gemini document summarization/classification is separate from access recommendations and is optional per upload. It is available only to administrators and requires `GEMINI_API_KEY`. The upload form warns that enabling it sends file contents to Google for processing; do not enable this for confidential files unless your organization has approved that transfer. Google's free tier may use submitted data to improve products; review current Google terms before sending sensitive material. Gemini output is validated against configured domains. A domain mismatch keeps the file in a short-lived pending area until an administrator confirms or cancels it. Gemini never grants access. The local rule assistant does not send employee or document data to Gemini.

## Requirements

- Python 3.10 or newer
- PowerShell on Windows

## Local setup

From this folder in PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt
```

If PowerShell blocks virtual-environment activation, run the interpreter and tools directly:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
```

The application creates `.data\trustvault.sqlite3`, a local audit signing key, and a private document directory under `.data\documents` on first run. `.data` is excluded from Git.

## Gemini API key (.env)

There is an ignored `.env.example` template in the project root. Copy it to `.env` (the same folder as `main.py`), then set your key:

```powershell
Copy-Item .env.example .env
notepad .env
```

Set `GEMINI_API_KEY=your_key_here` and save. The app loads that file at startup; restart Uvicorn after changing it. `.env` is ignored by Git and must never be committed or pasted into chat. Do not create/commit a real key in this repository. Alternatively, set `GEMINI_API_KEY` as a PowerShell environment variable before starting the server.

## Create demo accounts and run

For a **new, empty database**, seed one administrator, one owner, four individual viewers, and a sample agreement shared read-only with `user1`:

```powershell
python main.py seed-demo
```

The command generates random passwords and prints each account's one-time demo credentials. Save them locally; they are not written to the repository. Seed only an empty demo database. This is not a production account-provisioning process.

To add or reset the four viewer accounts in an **existing demo database**, use:

```powershell
python main.py setup-demo-viewers
```

This creates `user1@example.test` through `user4@example.test`, each with a newly generated unique password, and prints those passwords once. It reuses the old demo `viewer@example.test` account as `user1` when possible, preserving that account's existing document grants. Running it again intentionally resets all four demo passwords; secure and share the printed values privately.

Start FastAPI:

```powershell
uvicorn main:app --reload
```

Open <http://127.0.0.1:8000>. After sign-in, the dashboard is the landing page; the left navigation provides documents and the role-appropriate upload, data-lake, people, assistant, and audit views. The live health endpoint is <http://127.0.0.1:8000/health>. The interactive FastAPI docs are disabled so the documented, server-rendered routes are the interface.

Administrators can create, rename, describe, and remove unused domains. From a document's detail page, administrators can update its name, category, domain, assigned owner, summary, file contents, and access grants, or delete it. Domains referenced by retained or pending documents cannot be deleted; reassign or cancel those references first. Document and domain mutations are audited.

Run automated tests:

```powershell
python -m pytest -q
```

The tests use isolated temporary databases, private storage, and a test-only audit key.

## Authentication choice: OAuth 2.0 or OIDC?

OAuth 2.0 by itself is an **authorization** framework; it is not a sign-in protocol. For browser login, the usual choice is **OpenID Connect (OIDC)** on top of OAuth 2.0, using Authorization Code flow with PKCE. For a real company deployment, use the company's identity provider (for example Microsoft Entra ID or Google Workspace), require MFA there, restrict sign-in to the intended organization, validate issuer/audience/state/nonce, and map a verified stable `(issuer, subject)` identity to a TrustVault account. Keep the app's server-side session and document-grant checks: successful SSO must never imply access to every document.

For this local four-viewer demo, separate local passwords are simpler and testable without an identity-provider tenant, redirect URI, TLS domain, client registration, or client secret. **Do not** use the OAuth 2.0 Resource Owner Password Credentials grant (sometimes called the password grant) for a new integration. OIDC integration is not configured in this demo; provider secrets must be injected from a secrets manager/environment, never committed or shared in chat.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `TRUSTVAULT_DATA_DIR` | `.data` in the project root | Local app data and development audit key |
| `TRUSTVAULT_DATABASE` | `TRUSTVAULT_DATA_DIR\trustvault.sqlite3` | SQLite database path |
| `TRUSTVAULT_STORAGE_DIR` | `TRUSTVAULT_DATA_DIR\documents` | Private document storage |
| `TRUSTVAULT_MAX_UPLOAD_BYTES` | `10485760` | Maximum upload size (10 MiB) |
| `TRUSTVAULT_AUDIT_KEY` | Generated locally in `.data\audit.key` | HMAC signing key; supply an external secret of at least 32 bytes in production |
| `TRUSTVAULT_ENV` | `development` | Set to `production` to require an externally configured audit key and secure cookies |
| `GEMINI_API_KEY` | unset | Optional key for administrator-initiated Gemini summaries/classification |
| `TRUSTVAULT_GEMINI_MODEL` | `gemini-3.5-flash-lite` | Optional Gemini model identifier; this model was successfully tested with the current demo key |

When deploying behind HTTPS, set `TRUSTVAULT_ENV=production`, inject the audit key and optional Gemini key using the host's secret manager, use HTTPS, configure trusted proxy/host behavior at the edge, and persist the database and private files in protected storage. SQLite/local files are for a single-instance demo; production needs a supported shared database, backups, external audit anchoring, monitoring, malware scanning, and a tested restore/purge process. No live deployment or public demo credentials are provided by this repository.

## Upload and deletion behavior

Accepted formats are PDF, DOCX, XLSX, PNG, and JPEG. Extension, declared media type, file signatures, and Office ZIP contents are checked. Files are capped at 10 MiB by default and held outside the static web directory; this validation is **not** malware scanning. Files are always downloaded as attachments.

Deleting marks the document unavailable immediately and retains its private bytes and audit history. A scheduled purge/recovery policy has not been implemented; do not describe soft deletion as secure erasure.

## Documentation

- [API.md](./API.md): route-by-route callers and server-side checks.
- [THREATS.md](./THREATS.md): threat assumptions, mitigations, accepted gaps, and test mapping.
- [PROMPTS.md](./PROMPTS.md): dated AI-use record and corrections.
- [TRUSTVAULT_PLAN.md](./TRUSTVAULT_PLAN.md): original challenge design and build checklist.
