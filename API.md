# TrustVault route and permission reference

The product uses same-origin HTML forms and FastAPI routes, not a separate JSON API. All state-changing requests use POST and require a CSRF token. Session cookies are opaque, `HttpOnly`, `SameSite=Lax`, and `Secure` when `TRUSTVAULT_ENV=production`. Sessions and grants are looked up from the database on each request.

Inaccessible or deleted document IDs return the same not-found page whether or not the record exists. Denied document access is written to the audit trail.

| Method and path | Allowed caller | Server-side authorization |
|---|---|---|
| `GET /health` | Public | Returns application health only. |
| `GET /` | Any | Redirects an active signed-in user to `/dashboard`; otherwise to `/login`. |
| `GET /dashboard` | Signed-in active account | Shows administrator inventory/activity counts or only the current user's authorized document list. |
| `GET /login` | Public | Shows sign-in form and creates an anonymous CSRF session when needed; signed-in accounts are redirected to `/dashboard`. |
| `POST /login` | Public | CSRF validation, generic failure, rate limiting, password verification, active-account check, and session rotation; successful login redirects to `/dashboard`. |
| `POST /logout` | Signed-in active account | Requires active server-side session and CSRF; deletes the session. |
| `GET /documents` | Signed-in active account | SQL query scopes rows to owned documents or active named grants; administrators see the inventory. Name, owner, category, domain, and date filters run within that scope. |
| `GET /documents/new` | Owner or administrator | Requires an active account with one of these organization roles and lists configured domains. |
| `POST /documents` | Owner or administrator | Rechecks role and CSRF; caps bytes; validates filename, allowlisted extension, media type, signature, and Office archive contents; owner ID comes only from the session. Optional Gemini use is admin-only and auditable; mismatch uploads remain pending until confirmation. |
| `GET /documents/{id}` | Owner, administrator, or active `read`/`edit` grantee | Checks current authorization before returning metadata; records the successful view. Administrators can manage the data lake. |
| `GET /documents/{id}/download` | Owner, administrator, or active `read`/`edit` grantee | Rechecks current authorization immediately before streaming bytes; records the download; returns an attachment with `nosniff`. |
| `POST /documents/{id}/edit` | Owner, administrator, or active `edit` grantee | Rechecks current permission and CSRF before changing metadata. Domain, owner, and summary changes are administrator-only. |
| `POST /documents/{id}/content` | Owner, administrator, or active `edit` grantee | Rechecks permission and CSRF; validates a replacement file, stores it under a new opaque key, atomically updates the document record, audits the change, then removes the replaced private file after commit. |
| `POST /documents/{id}/delete` | Owner or administrator | Checks ownership/admin role and CSRF; marks document deleted and stops later access. |
| `POST /documents/{id}/access` | Owner or administrator | Checks ownership/admin role and CSRF; grants named active accounts `read` or `edit`. Assistant suggestions are accepted only through an explicit approval carrying a matching pending suggestion. |
| `POST /documents/{id}/access/{user_id}/revoke` | Owner or administrator | Checks ownership/admin role and CSRF; revokes the current grant; subsequent requests re-read the database and fail. |
| `GET /admin/users` | Active administrator | Lists account metadata. No document content or storage paths are returned. |
| `POST /admin/users` | Active administrator | Creates an account with validated email, role, password, department, and job title; requires CSRF. |
| `POST /admin/users/{user_id}/profile` | Active administrator | Changes a user's department/job-title metadata and records the update. |
| `POST /admin/users/{user_id}/disable` | Active administrator | Disables another account, removes sessions, revokes all active grants, and audits the revocations. Admin cannot disable itself through this route. |
| `GET /admin/data-lake` | Active administrator | Lists domains and document inventory. |
| `POST /admin/domains` | Active administrator | Creates a unique named domain; requires CSRF. |
| `POST /admin/domains/{domain_id}` | Active administrator | Updates the domain name/description; requires CSRF. |
| `POST /admin/domains/{domain_id}/delete` | Active administrator | Deletes a domain only if no retained document or pending upload references it. |
| `GET /admin/access-assistant?selected_user={id}` | Active administrator | Searches active accounts and displays pending recommendations; this GET has no grant-changing side effects. |
| `POST /admin/access-assistant` | Active administrator | Creates local, exact-department/domain read-only suggestions and audit events; does not grant access. |
| `POST /admin/access-suggestions/{id}/reject` | Active administrator | Records an explicit rejection of a pending suggestion. |
| `GET /admin/agent-chat` | Active administrator | Shows the local access command interface. |
| `POST /admin/agent-chat` | Active administrator | Accepts only exact supported grant/revoke command formats; resolves active users/documents and creates a five-minute, actor-bound pending action. No permission changes occur here. |
| `POST /admin/agent-chat/{token}/confirm` | Same active administrator who initiated the action | Checks CSRF, token hash, actor, expiry and current grant/account state, then applies and audits the grant/revocation. |
| `POST /admin/agent-chat/{token}/cancel` | Same active administrator who initiated the action | Cancels the pending action and audits the cancellation. |
| `POST /admin/pending-uploads/{token}/confirm` | Same active administrator who initiated pending upload | Checks CSRF, token hash, actor, expiration, chosen configured domain/category, then stores and audits the document. |
| `POST /admin/pending-uploads/{token}/cancel` | Same active administrator who initiated pending upload | Cancels the pending file, removes it after commit, and records the decision. |
| `GET /admin/audit` | Active administrator | Shows filtered audit records and HMAC-chain verification status. |

**Organization roles and document grants are distinct.** Administrators have explicit data-lake management privileges; owner access is limited to documents they own; viewer access requires a named active grant. A viewer with `edit` can edit only that document and cannot grant, revoke, or delete.

The application does not expose direct filesystem paths, static document URLs, anonymous share links, or generated API schema routes.
