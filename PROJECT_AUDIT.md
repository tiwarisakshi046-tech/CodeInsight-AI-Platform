# CodeInsight – Project Audit & Fix Report

## Summary

The submitted project was repaired in place. The existing HTML/CSS/JavaScript UI, Node.js/Express backend, analyzer, login/register flow, user pages, admin pages, history, ZIP analysis, and exports were retained.

**Latest validation:** `npm test` passes both the unit/security tests and HTTP integration tests. `node --check` passes for the backend, frontend script, database module, analyzer, ZIP security module, and test files.

## Fixes applied

1. **Admin user-management buttons:** Promote/Demote and Suspend/Activate now send `PATCH`, matching the backend routes.
2. **Password-reset token exposure:** Tokens are now stored as SHA-256 digests. The HTTP endpoint never returns the raw token, unknown and known emails get the same public response, reset requests are rate-limited, and a successful reset revokes existing sessions. Local demo tokens are printed only in the backend terminal. Production mode returns a setup error until a real email-delivery service is integrated; this build does not claim to send reset emails.
3. **Secret redaction:** The sanitizer now covers quoted and unquoted assignments such as `API_KEY=...`, `DB_PASSWORD=...`, and `access_token:...`, in addition to recognized provider tokens and bearer headers.
4. **Admin settings:** The admin form and backend now use consistent keys. Platform name, default language, ZIP archive size, public registration, and session inactivity timeout are validated and applied. ZIP size is enforced server-side from 1 to 50 MB; snippet size also remains enforced by the analyzer API.
5. **Session expiry:** The configured timeout is an inactivity timeout. Successful authenticated API requests refresh the session's last-activity timestamp.
6. **MongoDB startup and settings:** The server waits for initial MongoDB synchronization before serving traffic. Platform settings are read from and written to the `system_settings` collection. The database status lists that collection.
7. **MongoDB history clear:** Clearing a user's scan history also deletes that user's MongoDB scan-history records, and the API waits for the deletion call to finish.
8. **ZIP upload validation:** The ZIP endpoint applies the configured archive-size limit, validates Base64 input, and retains the existing ZIP-slip, executable-file, file-count, and decompression limits.
9. **Rate limiting:** Login, registration, password recovery, single-code analysis, and ZIP analysis have in-memory per-IP rate limits. Login allows 20 requests per IP per 15 minutes by default (`LOGIN_RATE_LIMIT_MAX` can override the threshold); the HTTP regression test is aligned with this policy.
10. **Security Scanner counts:** Only `critical` findings contribute to Critical and only `high` findings contribute to High; medium/low findings are no longer incorrectly counted as High.
11. **Login feedback:** Unknown, suspended, and wrong-password attempts use a shared failure message to reduce account enumeration.
12. **Submission hygiene:** Runtime `data.json`, real `.env` files, and `node_modules` are excluded from the distributable ZIP. `npm install` recreates dependencies; the application creates a fresh local `data.json` on first run.

## Main files updated

- `auth.js` — reset-token hashing, credential redaction, idle session timeout, validated settings, MongoDB synchronization, history clearing.
- `server.js` — API rate limits, secure password-reset response, dynamic ZIP limits, startup readiness, public safe config endpoint.
- `db.js` — system-settings collection is exposed in database status.
- `zipSecurity.js` — configurable archive-size enforcement while retaining extraction safety checks.
- `public/js/app.js` — admin PATCH requests, safer password-reset UI, settings mapping, platform/default-language handling, severity counts.
- `public/index.html` — archive-size input validation.
- `test.js` and `integration-test.js` — added regression and HTTP checks.
- `README.md` and `.env.example` — updated run and security instructions.

## Verification performed

- JavaScript syntax checks (`node --check`) on `server.js`, `auth.js`, `db.js`, `analyzer.js`, `zipSecurity.js`, `test.js`, `integration-test.js`, and `public/js/app.js`.
- `npm test`: **passed**.
- HTTP tests exercise static files, health/config endpoints, admin PATCH routes, registration/profile, admin settings save/load and validation, user suspension/reactivation, analysis/history/reopen, ZIP upload, CSV/Markdown exports, password-reset token privacy, rate limiting, malformed JSON, and unknown routes.
- Unit tests exercise multi-language rules, salted password hashing, reset token single-use/digest storage, idle session expiry, admin lockout protection, secret redaction, settings validation, ZIP traversal/decompression protections, and safe remediation.

## Limitations and items not claimed as verified

- **Live MongoDB:** This validation run had no `MONGODB_URI`, so the full test suite used local JSON persistence. MongoDB code paths for system-setting persistence and history deletion were updated, but a real Atlas/server connection was not available for end-to-end verification.
- **Password-reset email:** No email transport is bundled. Local demo mode writes the one-time token to the backend terminal; production mode disables the endpoint instead of exposing a token. A real email provider must be integrated before production deployment.
- **Analyzer scope:** The analyzer is heuristic/static analysis. It does not execute submitted code or replace language compilers such as `tsc`, `javac`, GCC, or Clang. Findings are suggestions and may include false positives or miss issues.
- **Browser coverage:** The frontend JavaScript syntax and HTTP contracts were tested, but this report does not claim automated visual/browser testing across every browser and screen size.
- **Fresh-install admin:** A fresh local installation creates a demo administrator (`admin` / `admin123`). Change this password before exposing the app to any shared or public network. Never distribute your real `.env` or generated `data.json`.

## Run locally

Requirements: Node.js **20.19.0 or newer** and npm.

```bash
npm install
npm test
npm start
```

Open `http://localhost:3000`. MongoDB is optional for the default local college demonstration. The app creates `data.json` on first run. To enable MongoDB, copy `.env.example` to `.env` and set your own `MONGODB_URI`. Do not commit or share `.env`.

12. **Apply Fix replacement logic:** The editor now assigns the exact-replacement result (or validated line fallback) to the textarea, rather than accidentally skipping the line-based assignment. The updated working code and language are saved in browser local storage, and the existing post-fix rescan refreshes the report/score.
13. **500-line requirement:** The editor uses a textarea without a 100-line/character cap, and the API snippet-size limit is configured in KB rather than line count. Actual accepted line count depends on the configured snippet-size limit and each line's length.


## Repair pass — 2026-11-01
- Fixed the line-based Apply Fix fallback to split and join on actual newline characters (not the literal backslash+n sequence).
- Added working-draft persistence on editor typing and language changes, and restoration of the saved code/language on startup. Legacy `codeinsight_code` and `codeinsight_language` keys are still supported.
- Undo snapshots now also preserve the selected language.
- Apply Fix validation alerts now show the latest score and remaining finding count rather than claiming the score necessarily improved.
- If validation cannot complete due to a network error, the workflow requests a rollback instead of leaving a changed editor with a stale report.
- Strengthened score indicator sizing with fixed minimum dimensions and `aspect-ratio` so flex layouts cannot squash it into an oval.
- Validation performed: JavaScript syntax checks passed; direct analyzer smoke tests passed for JavaScript and Python, including a clean-code 100/100 case; a generated 550-line input was analyzed successfully. Full `npm test` could not run because dependencies (`dotenv`, etc.) were not installed; `npm install` timed out in this environment, so the full API/browser flow remains unverified.


## AI Review / Correction Integration (2026-11-01)
- Added `/api/ai/review` with request-size/language validation, rate limiting, and optional server-side Gemini integration. API key is read only from `GEMINI_API_KEY`; it is not exposed to the browser.
- Added a UI panel for review findings and recommendations, with optional full corrected-code preview, explicit confirmation before applying, undo snapshot, draft persistence, and download.
- Without a key, the endpoint returns an honest rule-based fallback using the existing static analyzer; it does not claim that this is AI.
- Verification performed: Node syntax checks and static route/UI checks. A live Gemini request was not run because no API key was provided; full browser end-to-end testing remains required.
