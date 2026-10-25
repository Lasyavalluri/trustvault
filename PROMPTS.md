# AI prompt and correction log

This log records the actual project requests in this chat. Entries are dated on the day of the request, not backdated to imply a longer work history. The workspace is not a Git repository, so commit links do not exist yet; no commits or links are fabricated. Initialize a public repository and add real commit links when corrections are committed.

## 2026-10-21 - Initial environment request

- **Prompt (fair summary):** Set up HTML, CSS, Node.js, Next.js, and a Python backend for a project.
- **What the assistant produced:** A Next.js starter frontend, a minimal FastAPI health endpoint, dependency manifests, and an initial README; Node.js was installed for the frontend.
- **What was wrong:** The next project specification selected a Python-only frontend and explicitly excluded Next.js and JavaScript. The generated app was only a health-check starter, not an authorization-aware document system.
- **What changed instead:** This implementation removes the app's Next.js source and npm manifests and builds FastAPI/Jinja2 pages with CSS. Node.js remains installed on the machine, but is not used by this repository.
- **Verification / commit:** The finished build and tests are recorded in the final task report. Commit link unavailable; this workspace is not a Git repository.

## 2026-10-23 - TrustVault challenge requirements

- **Prompt (fair summary):** Build TrustVault with document-level permissions, auditability including denied attempts, immediate revocation, security tests, a threat model, and a dated AI prompt log.
- **What the assistant produced:** A written design plan specifying explicit grants, private storage, server-side checks, and threat-focused tests.
- **What was wrong or incomplete:** A plan is not an implementation. The plan discussed controls such as external audit anchoring, malware scanning, production deployment, migrations, and purge as design goals; none should be reported as existing unless implemented and verified.
- **What changed instead:** `README.md`, `API.md`, and `THREATS.md` distinguish implemented local demo controls from deferred production controls. The tests exercise route-level cross-user access and revocation.
- **Verification / commit:** The route tests and live run are listed in the final task report. Commit link unavailable; initialize Git before adding the real link.

## 2026-10-23 - Request for a guide before implementation

- **Prompt (fair summary):** First check the challenge requirements, explain what would go into a Markdown guide, ask any needed questions, and do not start implementation yet; require a Python backend and HTML/CSS-only frontend.
- **What the assistant produced:** A clarification form with framework, frontend, scaffold, and guide-file choices.
- **What was wrong or incomplete:** The guide alone would not satisfy the user once they later asked to implement it, and the existing scaffold needed to be handled explicitly rather than silently kept.
- **What changed instead:** The selected FastAPI + server-rendered HTML/CSS design was retained; the later implementation request authorized replacing the Next.js scaffold. The original guide remains as a design reference.
- **Verification / commit:** Current files and routes are described in `API.md`; no commit link exists yet.

## 2026-10-23 - Framework and scaffold choices

- **Prompt (fair summary):** Use FastAPI, HTML templates and CSS only, replace the Next.js scaffold later, and create `TRUSTVAULT_PLAN.md`.
- **What the assistant produced:** The plan and permission decisions, including no administrator content bypass and explicit named per-document grants.
- **What was wrong or incomplete:** The previous plan could be mistaken for shipped functionality if read without a status distinction; several security properties were still proposals.
- **What changed instead:** The implementation now supplies actual routes for authentication, documents, grants, search, admin views, and an audit chain, while the README/threat model call out limitations such as SQLite, no WORM anchor, no scanner, and retained deleted bytes.
- **Verification / commit:** The permissions and audit chain have targeted tests in `tests/test_security.py`. Commit link unavailable; no Git repository exists.

## 2026-10-23 - Implementation and cleanup request

- **Prompt (fair summary):** Implement the agreed TrustVault guide and delete unnecessary files.
- **What the assistant produced:** A FastAPI/Jinja2 application, CSS templates, route documentation, threat analysis, and security tests; the old frontend scaffold was removed.
- **What was wrong in the first implementation pass:** Review exposed that a CSRF token added to a template context after rendering would not appear in the HTML; a SQLite connection created in async middleware could be used by a worker thread; and write transactions needed committing after route execution. A visible remote-font import conflicted with the restrictive same-origin style policy. The first cross-user test run also caught that the generic HTTP error template rendered authorization failures with HTTP 200 instead of the intended 404/401/403 status.
- **What changed instead:** Tokens are now supplied before rendering, SQLite per-request connections permit FastAPI's worker-thread route execution, middleware commits successful/handled route changes and rolls back unhandled exceptions, CSS uses local system font fallbacks only, and the error handler preserves HTTP status codes. Tests specifically exercise login, CSRF, grants, revocation, direct downloads, cross-user search, content replacement, audit tampering, and HTML escaping.
- **Verification / commit:** These corrections are covered by the current targeted test suite and live HTTP checks. No commit link is available because the workspace is not initialized as Git.

## 2026-10-23 - Four viewers, authentication options, and access assistant

- **Prompt (fair summary):** Fix the flow to provide four independent viewer accounts, advise whether OAuth 2.0 is appropriate, add an agent to help owners decide who should receive access, and re-read the security requirements.
- **What the assistant produced:** The current demo only had one seeded viewer, local username/password sessions, and a manual owner-grant form. There was no permission-recommendation feature.
- **What needed care:** OAuth 2.0 alone is not a sign-in protocol, and sending confidential document text or employee data to an external AI model can itself disclose sensitive information. The recommendation must not create or broaden a grant without an owner's explicit confirmation; user purpose/department data is not currently modeled.
- **What changed instead:** Added setup/reset for four uniquely passworded viewer demo accounts, verified account isolation, and documented OIDC Authorization Code + PKCE as the appropriate later SSO option while retaining local login for this isolated demo. The user selected a local access recommender and Gemini summaries; they are separate features, and only the optional admin-initiated summary sends the explicitly selected file to Google.
- **Verification / commit:** `test_four_demo_viewers_have_independent_credentials_and_no_implicit_access` passes. Commit link unavailable; this workspace is not a Git repository.

## 2026-10-23 - Admin data lake, assistant approval, and Gemini metadata

- **Prompt (fair summary):** Extend TrustVault so administrators manage accounts, departments, domains, documents, and grants; provide local explainable access recommendations that never auto-grant; optionally use Google Gemini for summaries and domain/category suggestions, requiring a human decision on a domain mismatch.
- **What the assistant produced:** Preliminary database migration fields/tables, an admin authorization override, and a Gemini helper. The first integrated upload/query edits did not yet wire the full workflow.
- **What was wrong, specifically:** The upload INSERT still used the old column list after adding domain/summary values, domain IDs were not supplied by the upload UI, the demo seed tuple omitted the new domain reference, the existing test expected the now-obsolete policy that administrators could not manage documents, and the first assistant route performed writes on GET (so refreshing could mutate/audit state). The first test run exposed the policy expectation and missing upload domain; the next run exposed the optional Gemini SDK had not been installed.
- **What changed instead:** Wired admin domain/data-lake/user-profile routes, immediate grant revocation on account disable, exact department-to-domain read-only suggestions, and explicit approve/reject flow. Moved suggestion generation to CSRF-protected POST; GET only displays pending state. Added optional, disclosed Gemini upload metadata, strict output/domain validation, private 15-minute mismatch confirmation, and mocked tests that verify no document or grant exists before confirmation. Updated API, threat, and setup documentation to distinguish admin authority and external-provider risk.
- **Verification / commit:** The focused route suite passes 16 tests after installing the manifest-declared SDK; Pylance reports no diagnostics in the changed Python files, `pip check` is clean, and the running app returns HTTP 200 from `/health` and `/login`. Commit link unavailable; this workspace is not a Git repository.

## 2026-10-24 - Dashboard landing page and sidebar navigation

- **Prompt (fair summary):** Stop the running app, use a left-side navigation bar with easy access to main sections, make the dashboard the first page, and ensure administrators can edit domain/document data and the previously requested management features.
- **What the assistant produced:** Replaced top navigation with a responsive role-aware sidebar, routed successful sign-in and `/` to a dashboard, added role-scoped dashboard summaries, and expanded administrator editing for document owner/domain/category/name/summary/content/grants plus domain create/rename/delete.
- **What was wrong or incomplete:** The first dashboard test incorrectly expected an owner's own document not to appear; the route correctly included it. The first test also needed to check the actual security boundary (a different viewer must not see the document), rather than guessing from its ID.
- **What changed instead:** Corrected the test to assert the owner sees their own document and a viewer without a grant does not. Added route coverage for dashboard and administrator metadata/domain workflows, and kept the server stopped as requested.
- **Verification / commit:** All 18 route tests pass, Pylance reports no diagnostics in the changed Python files, dependencies and compilation check clean, and port 8000 is confirmed stopped. Commit link unavailable; this workspace is not a Git repository.

## 2026-10-24 - Admin access agent chat and Gemini key setup

- **Prompt (fair summary):** Add a chat interface where administrators can ask an agent to grant/revoke any document for a user, keep the system end-to-end, and explain where to put the Gemini API key.
- **What the assistant produced:** Added an admin-only local command chat, exact document/account resolution, and a separate confirm/cancel step before grant or revocation; confirmation is CSRF-protected, actor-bound, one-use, expires after five minutes, and audited. Added `.env` loading from the project root, a blank local `.env` placeholder, and `.env.example`; `.env` is Git-ignored.
- **What was wrong or incomplete:** Calling this a generative agent would overstate what is implemented. An unconstrained model deciding document permissions would add unnecessary risk; tests also need to prove the chat does not mutate grants before confirmation or when an action is cancelled.
- **What changed instead:** The access chat is deliberately a deterministic local parser with documented command forms; it does not call Gemini or inspect/send documents. Human confirmation is mandatory. Gemini remains optional for administrator-selected upload summaries only, with external processing disclosed. Tests verify admin-only access, cancellation, grant confirmation, revocation, and immediate loss of access.
- **Verification / commit:** All 19 route tests pass; Pylance reports no diagnostics in the changed Python files; `pip check` and Python compilation pass; port 8000 is stopped. `.env` is listed in `.gitignore`. Git is not installed/available in this workspace, so no commit link exists.

## 2026-10-24 - Select Gemini 2.5 Flash

- **Prompt (fair summary):** Use the Gemini 2.5 Flash model.
- **What the assistant produced:** The local `.env` already had `TRUSTVAULT_GEMINI_MODEL=gemini-2.5-flash`.
- **What was wrong or incomplete:** The code fallback and `.env.example` still selected the older `gemini-3.8-flash` identifier, and README documented the same stale default. A fresh setup or missing model setting could therefore ignore the user's requested model.
- **What changed instead:** Updated the code fallback, example environment file, and README default to `gemini-2.5-flash`. The private API key value was not read or printed.
- **Verification / commit:** Confirmed the local model setting without displaying other `.env` values; all 19 route tests pass and Pylance reports no diagnostics in `web.py`. The server was already listening on port 8000 when checked, so restart/reload it to ensure the process uses the new model setting. Commit link unavailable; this workspace is not a Git repository.

## 2026-10-24 - Test a free Gemini model

- **Prompt (fair summary):** Try any available free model after the selected Gemini 2.5 Flash model returned unavailable.
- **What the assistant produced:** Queried the model names available to the configured API key and tested `gemini-2.5-flash-lite` and `gemini-3.5-flash-lite` with harmless text-only prompts.
- **What was wrong or incomplete:** The key's model list included legacy model identifiers that still reject generation with HTTP 404; listing a model did not prove it was usable. Testing only `generateContent` would not verify the app's Interactions API call path.
- **What changed instead:** `gemini-2.5-flash-lite` was rejected as no longer available to new users. Both `generateContent` and the app-compatible Interactions API succeeded on `gemini-3.5-flash-lite`. Set this model in `.env`, the example, code fallback, and README; documented the free-tier data-use caution.
- **Verification / commit:** Two harmless text-only requests succeeded, including the app-compatible Interactions API; all 19 route tests pass and Pylance reports no diagnostics in `web.py`. No document/user data or API key value was disclosed. The model is set in `.env`; restart the already-running server to load it. Commit link unavailable; this workspace is not a Git repository.

## Reusable context used

- The user's TrustVault challenge description and its non-negotiable authorization, audit, and revocation criteria.
- `TRUSTVAULT_PLAN.md`, created from the user's requested design choices.
- The project instructions to prefer a small, server-enforced permission model, verify changes, and state security limitations honestly.

## Continue the log

Add entries when AI materially influences the next implementation or review step. Record what was actually wrong and the checks that caught it. After each correction is committed, replace the “commit link unavailable” note for that entry with the real commit URL; do not invent dates, findings, tests, or commit history.
