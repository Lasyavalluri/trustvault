# TrustVault: implementation guide

## Purpose and scope

This document began as the security-first implementation plan. The local demo now implements a subset of it; see [README.md](./README.md), [API.md](./API.md), and [THREATS.md](./THREATS.md) for verified behavior and explicit gaps. Items below remain design guidance unless the implementation and tests confirm them.

**Chosen stack:** Python with FastAPI; server-rendered HTML templates with Jinja2; plain CSS; no Next.js, React, or frontend JavaScript in the finished application. HTML forms submit to FastAPI routes, which validate the request and render the next page. Use Post/Redirect/Get after successful form submissions.

The Next.js scaffold has been removed. The current project is a local FastAPI/Jinja2 demo with server-side sessions, SQLite, private local document storage, named document grants, audit records, and route-level security tests. It is not a production deployment; consult the README and threat model for gaps.

## Product and permission decisions

### Roles and document access

Use a user's organization role for administrative capabilities and explicit, per-document grants for regular accounts. Administrators are a deliberate exception: their data-lake role permits broad document management, while owners are scoped to their own documents and viewers/editors require per-document grants.

| Actor | Allowed actions |
|---|---|
| Administrator | Manage accounts, profiles, domains, document data lake, grants, and audit views. Administrator document operations are broad by design and must always be authorized and audited. |
| Document owner | Read and download their document; edit its metadata or replace its content; grant and revoke named users' access; delete it. Ownership comes from the document record, not a client-supplied field. |
| Viewer | Read or download a document only while an active read or edit grant exists. Cannot edit, grant, revoke, or delete. |
| Named editor | A viewer or owner account with an `edit` grant can also read and download that specific document, and can edit its metadata or replace its content. Cannot grant access, revoke access, or delete the document. Those powers remain with the owner. |

Treat `edit` as including `read`. Do not support anonymous links, folder inheritance, group grants, public documents, or automatic access suggestions in the first version. An external partner must have an individual account and a document-specific grant.

An account that is disabled must lose access immediately, even if its browser still has a session cookie. Deleting a user should not erase audit history; deactivate the account and preserve its identifier in historical records.

### Access-control rule

For **every** document operation, the server must load the current account state and current document state, then check ownership or an active grant for that document before returning protected metadata or bytes or allowing a mutation. Centralize this in a reusable server-side authorization function and call it in each route. Never rely on a hidden button, an unguessable ID, a prior page check, or a grant stored in a session.

List and search queries must return only documents the current user may read; filtering unauthorized results after building a broad result set risks metadata leaks and pagination/count leaks. Use the same authorization policy for detail pages, downloads, edit and delete forms, replacement uploads, and grant management. Return a generic not-found response for inaccessible documents if distinguishing “exists but forbidden” would disclose information; record the actual denial in the audit trail.

## Data and storage design

Start with SQLite for local development and tests. Use migrations (for example, Alembic) and use PostgreSQL for deployment. Keep database credentials and cryptographic keys outside source control.

Suggested records:

- **User:** stable ID, normalized unique email, password hash, role, active/disabled status, creation time.
- **Document:** stable ID, owner ID, display name, category, description if needed, opaque storage key, detected media type, byte size, creation/update times, deletion time, and optional version number.
- **DocumentGrant:** document ID, grantee user ID, permission (`read` or `edit`), grantor ID, creation time, revocation time. Keep grant/revocation history in audit events; do not reuse a revoked grant row in a way that erases its history.
- **AuditEvent:** event ID, UTC timestamp, actor ID when known, action, document/user subject IDs, outcome, request/correlation ID, and a small, carefully chosen details object. Do not log passwords, session tokens, document contents, or unnecessary personal data.
- **Session:** opaque session ID or its hash, user ID, creation/expiry times, and revocation state. Store sessions server-side so logout, account disablement, and session revocation take effect without waiting for a self-contained token to expire.

Store uploaded bytes in a private directory outside the static web root, or in a private object-storage bucket. Generate storage keys on the server; never use a submitted filename as a path. Downloads must go through an authenticated application route that re-checks authorization at download time. Do not expose storage paths, mount the upload directory as static content, or issue long-lived signed URLs.

The original filename is display metadata only. Normalize it, escape it in templates, and return downloads as attachments with `X-Content-Type-Options: nosniff`. Do not render uploaded HTML or SVG inline.

Deletion should immediately mark a document deleted and make it unavailable to every reader and downloader. Keep a tombstone for audit and a clearly defined, short retention period for recovery, then purge the bytes and expired metadata through a scheduled job. Until that purge job is built and verified, describe retained bytes honestly; soft deletion is not physical erasure.

## Authentication and web protections

- Hash passwords with a suitable password-hashing algorithm such as Argon2id; never store plaintext or reversibly encrypted passwords.
- Use server-side sessions with high-entropy opaque identifiers. Set cookies `HttpOnly`, `SameSite=Lax`, and `Secure` in production; rotate the session after login; expire idle and absolute sessions; invalidate on logout and account disablement.
- Require CSRF tokens on every state-changing form, including upload, edit, grant, revoke, delete, login, and logout. SameSite cookies are an additional control, not a replacement for CSRF protection.
- Rate-limit login and other sensitive authentication actions. Use generic login failures and avoid exposing whether an email exists.
- Keep Jinja2 autoescaping enabled. Validate values on the server even when the HTML form uses input constraints.
- Use HTTPS in deployment. Configure trusted hosts, a restrictive Content Security Policy, security headers, secure secrets, and production error pages. Do not run the development server in production.
- Do not enable permissive cross-origin access: the planned product is a same-origin, server-rendered application, not a browser API consumed by a separate frontend.

## Upload validation

Choose a narrow initial allowlist of business formats (for example PDF, DOCX, XLSX, PNG, and JPEG) and document the exact list. Reject formats not explicitly supported, including HTML, SVG, executables, and archives unless there is a separately reviewed business need.

For each upload:

1. Require an authenticated owner or explicitly authorized editor, then check authorization before accepting or replacing content.
2. Enforce a configurable maximum byte size while streaming; do not trust the browser's declared size or `Content-Type`.
3. Check the extension, detected media type, and file signature for consistency. Treat these checks as validation, not proof that a file is safe.
4. Generate the storage key, store outside the public web root, and ensure a failed validation or write does not leave an accessible partial document.
5. Record successful uploads and rejected attempts without storing the file body in logs.
6. Before real organizational use, integrate malware scanning or a documented quarantine-and-review process. Do not claim that MIME checks replace malware scanning.

## Audit: evidence and its limits

Write audit events for successful and denied authentication where appropriate, uploads and validation rejections, downloads, metadata/content changes, deletion and purge, grants, revocations, account disablement, and denied document access. A denied request should leave a record even when the requester must receive a generic response. Record the actor, action, target, outcome, UTC time, and request ID; do not record secrets or document contents.

Make application audit operations append-only: normal application routes must not update or delete audit events. Add a verifiable integrity mechanism such as a hash/HMAC chain, with its signing key held separately from the database. Verify the chain in tests and provide an administrator audit view that makes suspicious gaps or verification failures visible.

**Do not call a database-only hash chain immutable.** A database administrator or attacker with both database-write access and the HMAC key could rewrite history. For stronger evidence in deployment, periodically anchor signed audit checkpoints in a separately controlled append-only/WORM service or independent security account, and alert on failed verification. Document the operational trust boundary, backup/retention policy, key rotation, and who can access the anchor. A local demo without an independent anchor provides tamper evidence, not absolute proof against a fully privileged host compromise.

## Search and administration

Support search by document name, owner, category, and a date range. Apply the authorization predicate before searching, counting, sorting, and paginating so unauthorized documents cannot be inferred from results or totals. Normalize and validate date inputs; define whether the date filters use UTC creation dates or another explicit timestamp.

The administrator view should show audit events and permission changes, with filters for time, actor, action, document ID, and outcome. Admin data-lake access includes authorized detail/download routes and is a high-impact privilege; log it and use strong identity controls in production. Escape search terms and event details in HTML.

## Route and permission map

Use ordinary HTML form routes. Every route except login and genuinely public health/status checks requires authentication; every document route performs its own current authorization check.

| Route | Caller and server-side check |
|---|---|
| `GET /login`, `POST /login` | Public form; validate credentials, rate-limit attempts, rotate session on success, and record relevant outcomes. Protect the POST with CSRF. |
| `POST /logout` | Authenticated; CSRF required; revoke the server-side session. |
| `GET /documents` | Any active account; return only documents readable by that account. Apply search filters inside that authorized query. |
| `GET /documents/new`, `POST /documents` | Active document owner; validate CSRF and the uploaded file; set owner from the authenticated identity, never from submitted form data. |
| `GET /documents/{id}` | Owner or user with an active read/edit grant; do not reveal inaccessible metadata. |
| `GET /documents/{id}/download` | Owner or user with an active read/edit grant, checked again immediately before streaming bytes. Never use a previously issued URL as authorization. |
| `POST /documents/{id}/edit` | Owner or active editor grant; CSRF required; allow only explicitly editable fields/content. |
| `POST /documents/{id}/delete` | Owner only; CSRF required; make the document inaccessible immediately and audit the deletion. |
| `GET /documents/{id}/access` | Owner only; show current named grants for that document. |
| `POST /documents/{id}/access` | Owner only; CSRF required; grant a selected permission to a named, active account and audit the decision. |
| `POST /documents/{id}/access/{user_id}/revoke` | Owner only; CSRF required; revoke only that document-specific grant and audit the change. |
| `GET /admin/audit` | Active administrator; audit records and HMAC-chain status. |
| `GET /admin/users`, `POST /admin/users/{id}/disable` | Active administrator; manage accounts and profiles. Disablement removes sessions and revokes all active grants. Require CSRF and audit account changes. |

FastAPI's automatically generated API schema is not a substitute for this route-level permission documentation. If JSON endpoints are added later, document and test them as separate access paths under the same server-side policy.

## Threat model and test plan

These are implementation requirements, not claims that the threats have already been eliminated. Tests should exercise the real routes and responses rather than test only the authorization helper.

| Threat or abuse case | Planned mitigation | Test that must fail if the route check is removed |
|---|---|---|
| User guesses or substitutes another document ID in a detail URL | Check owner/grant on every request; generic inaccessible response | A second user cannot retrieve the first user's detail page or metadata using a known ID |
| User calls the download URL directly or replays it | Check the current grant on every download; no public path or persistent signed URL | An ungranted user receives no bytes from a direct download request |
| Owner revokes access while a reader retains a session | Re-read active grants from the database per request; no grant cached in session | A user succeeds before revocation and is denied on the next request after revocation |
| User searches for or counts another user's documents | Scope search, counts, sorting, and pagination to authorized rows | Search by known name, owner, category, and date reveals neither the record nor a changed total |
| Read-only user posts edit, replacement, delete, grant, or revoke forms manually | Enforce the action-specific permission and CSRF on the server | Direct POST requests are denied and do not change content, grants, or deletion state |
| Administrator account is compromised or misused due to broad data-lake authority | Require an active admin session on every route and audit all document reads, downloads, edits, deletions, and grants; add MFA, alerting, and separation of duties for deployment | Admin authority is intentional in this iteration; compromise impact remains broad and is documented as an accepted operational risk |
| Disabled user reuses a still-valid cookie | Check account active status on each request and revoke sessions | Disable the account, then verify the old cookie cannot access a page or download |
| Submitted filename contains path traversal or collides with another upload | Server-generated opaque storage key; filename is never a path | Traversal names cannot read/overwrite outside storage; duplicate names do not overwrite bytes |
| Spoofed MIME type, oversized file, or unsupported extension is uploaded | Size limit plus extension/signature/type allowlist and consistent error handling | Invalid or oversized uploads are rejected, not listed as available, and leave no downloadable partial object |
| HTML/active content executes when opened from the service | Disallow active formats; attachment disposition; nosniff; template escaping | A crafted filename or document cannot inject HTML into the detail, search, or audit page |
| Cross-site request changes a grant or deletes a document | CSRF token validation on every state-changing form | A missing or invalid token cannot grant, revoke, edit, delete, upload, or log out |
| Attacker enumerates accounts or brute-forces passwords | Generic login failures and rate limiting | Wrong-password and unknown-user responses are indistinguishable; rate limit activates |
| Audit entry is silently edited or removed | Append-only application paths, integrity verification, separately protected key/anchor | Tests reject altered, reordered, or missing audit events; tampering is surfaced rather than reported as valid |
| Revocation and download race | Serialize/check authorization immediately before opening the object; define in-flight behavior | After revocation completes, a newly initiated download is denied. A transfer already in progress cannot have bytes recalled; document that limitation. |
| Stale backups or public storage restore old access | Private storage, protected backups, access re-check after restore, documented retention | Restored bytes are not publicly addressable and still require current authorization |
| Concurrent grant/revoke or duplicate form submission creates inconsistent access | Database transactions, uniqueness constraints, idempotent handling where appropriate | Concurrent operations leave one coherent current grant state and correctly ordered audit events |
| Error pages, logs, or browser cache disclose document contents | No sensitive response caching, generic errors, careful log redaction, HTTPS | Unauthorized responses contain no bytes; logs and rendered error pages contain no session secrets or file body |

Keep an authorization test for each route/action above. In particular, include the challenge's mutation check: the test suite must fail if a protected route's authorization enforcement is removed. Seed separate users and documents in tests, authenticate through the same session path the application uses, and exercise the real HTTP routes. Do not make all tests call the helper directly; helper-only tests will not detect a forgotten check in a route.

## Build order

1. **Repository and skeleton:** establish Git history, remove the Next.js app and Node manifests when replacing the frontend, retain Python, add FastAPI templates/static CSS, settings, and a health check.
2. **Persistence:** define database models and migrations; create development seed accounts and non-sensitive demo documents.
3. **Authentication:** add password hashing, login/logout, server-side sessions, CSRF protection, account status, and authentication tests.
4. **Authorization first:** implement the shared policy and route-level checks; write cross-user tests before adding broad document features.
5. **Private documents:** implement validated uploads, private storage, detail/search, protected downloads, edits, deletion, grants, and revocation; test direct requests and immediate revocation.
6. **Audit and administration:** audit success and denial outcomes, add integrity verification, permission/activity administration pages, and tampering tests.
7. **Hardening and operations:** add production configuration, TLS, backups, retention/purge, monitoring, deployment, and recovery checks; never seed real confidential documents.
8. **Submission evidence:** finish threat mapping, API docs, clean-clone setup, demo, and write-up; verify a fresh clone and deployed role-separated credentials.

## Submission checklist

- [ ] Public Git repository with meaningful history across the week, not just a final import.
- [ ] Live deployment with non-sensitive seed data and working sample credentials for admin, owner, and viewer in `README.md`. Use unique demo-only passwords; never publish real or reused credentials.
- [ ] `THREATS.md` mapping threats, controls, accepted risks, and corresponding automated tests.
- [ ] `PROMPTS.md` maintained as work happens, not reconstructed at the end.
- [ ] Automated authorization, upload validation, revocation, audit, and cross-user tests.
- [ ] Database schema/migrations, seed/setup instructions, and deployment instructions tested from a clean clone.
- [ ] Route-level API documentation with allowed callers and checks, including denial behavior.
- [ ] Five-minute demo video, with no real confidential documents or secrets visible.
- [ ] Short write-up covering the permission model, design choices, AI use and corrections, exclusions, and unfinished work.

### Keeping `PROMPTS.md` honest

Record each AI interaction while working. For each dated entry, capture the prompt or fair summary, what the tool produced, a specific defect or what you independently verified, what you changed, and the real commit link containing that correction. Include at least two entries about authorization or audit, and at least five entries overall as the challenge requires. Do **not** invent past dates, pretend a defect occurred, or make up commit links; if an answer was sound, describe the code and tests you used to verify it. Record reusable instructions/context in the same file. Start the public repository and commit early so those links and the week-long history can be genuine.

## Explicitly deferred and accepted limitations

- No anonymous/public links, group or folder inheritance, bulk sharing, or automatic AI permission grants. This keeps authorization document-scoped and human-approved.
- No in-browser document preview in the first version; downloading as an attachment reduces active-content risk.
- Malware scanning, independent WORM audit anchoring, external identity-provider integration, and production-grade backup/restore must be completed or clearly disclosed before claiming production readiness.
- A compromised application host or a fully privileged operator with access to both the audit database and signing key can defeat application-level audit protections unless an independent anchor exists.
- Revocation blocks subsequent authorized requests immediately; it cannot retract a file already downloaded or bytes already delivered in an in-progress transfer.
- Soft deletion is not erasure. Physical purge and backup-expiration behavior must be implemented, tested, and described before promising deletion.
