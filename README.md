# CodeInsight — Multi-Language Static Code Analysis & Diagnostic Platform

A high-performance, web-based static code analysis platform providing real-time syntax checking, security auditing, beginner-friendly diagnostic explanations, reviewable automated code remediation, and role-based access governance.

---

## 1. Product Overview

**CodeInsight** is an enterprise-grade static code analysis platform engineered to help software engineers, educators, and developers inspect, debug, and improve source code across multiple programming languages. Writing robust software requires identifying syntax errors, dangerous idioms, security vulnerabilities, and code quality pitfalls early.

CodeInsight provides an intuitive, responsive interface powered by an in-memory lexical parsing engine. Source code is analyzed in milliseconds without executing untrusted code or transmitting files to external networks. For each identified issue, CodeInsight provides:
- Exact file location and line numbers with synchronized visual highlighting.
- Clear, plain-English explanations answering *what happened*, *why it matters*, and the *underlying concept*.
- Actionable proposed fixes with side-by-side before/after diff verification, confirmation dialogs, post-remediation validation rescans, and an instant reversible undo stack.
- Dedicated security scanning for OWASP/CWE patterns (e.g. `eval()` injection, `innerHTML` XSS, SQL injection, memory safety flaws).
- Role-based administration and telemetry for user management and compliance reporting.

---

## 2. Platform Architecture & Pages

The application is structured into three distinct operational domains with role-appropriate navigation:

### A. Common Pages
1. **Login Page (`#login`):** Backend authentication, session token issuance, and automatic role-based routing (Admin to Admin Dashboard, Standard User to User Dashboard).
2. **Registration Page (`#register`):** Full name, email, and password registration with salted `scrypt` hashing and duplicate email protection.
3. **Password Recovery (`#forgot-password`):** Single-use reset tokens expire after 15 minutes and are stored as SHA-256 digests. The browser never receives the token. In local demo mode, the backend prints the token in its terminal so it can be copied into the reset form. Production mode disables password recovery until a real email-delivery service is integrated.

### B. User Panel
4. **User Dashboard (`#user-dashboard`):** Code health metrics overview, total analyses run, average score, error/warning/security counters, and recent analysis history table.
5. **Code Analyzer (`#analyzer`):** Core diagnostic workbench featuring:
   - 7 supported languages with auto-detection.
   - Curated presets (clean code, beginner traps, syntax errors, security risks).
   - Synchronized line numbers gutter, real-time character/LOC counts.
   - Secure single file and ZIP archive upload options.
   - Clear, Copy, and Analyze Code actions.
6. **Analysis Results (`#results`):** Grouped findings workbench with severity filtering (All, Errors, Warnings, Quality, Security), detailed diagnostic inspection, and synchronized code viewer with line-level highlight markers.
7. **Security Scanner (`#security-scanner`):** High-level vulnerability overview highlighting critical and high-severity security vectors with attack explanations and remediation advice.
8. **Code Suggestions (`#suggestions`):** Interactive quality remediation workbench with side-by-side diff preview, confirmation safeguards, automated post-apply validation rescans, and an undo stack for instant rollback.
9. **Language Support Matrix (`#languages`):** Live catalog of supported languages, engine implementations (lexical parser vs syntax tokenizer), rule counts, and explicit static limitations.
10. **Analysis History (`#history`):** User-isolated historical records with timestamp, language, score, findings breakdown, and 1-click **Reopen Analysis** to restore past buffers.
11. **User Profile (`#user-profile`):** Account avatar, name, email, role badge, total scans metric, and profile updater form.
12. **User Settings (`#user-settings`):** Dark/Light theme toggles, default analysis language preferences, auto-detect toggles, and secure password change form.
13. **About / Help (`#about`):** Platform architecture documentation, usage guide, keyboard shortcuts, and static analysis boundaries.

### C. Admin Panel (Role-Based Access Control)
14. **Admin Dashboard (`#admin-dashboard`):** Global platform telemetry from live database queries (total users, platform scans, security findings, average health score) and real-time audit log stream.
15. **Admin Profile (`#admin-profile`):** Administrator credentials, privilege badge, and profile manager.
16. **User Management (`#admin-users`):** User directory with role promotion/demotion, account activation/suspension, and deletion. Protected by **Root Admin and Last Active Administrator Lockout Prevention**.
17. **Analysis Logs (`#admin-logs`):** System-wide analysis inspection with language filtering and automated secret/password redaction.
18. **Reports & Analytics (`#admin-reports`):** Vulnerability distribution analytics, language usage breakdowns, and sanitized CSV telemetry export.
19. **System Settings (`#admin-settings`):** Platform-level configurations (public registration toggle, max upload size, default language, session inactivity timeouts).

---

## 3. Supported Languages & Engine Capabilities

| Language | Support Level | Engine Type | Key Capabilities | Boundaries & Limitations |
| :--- | :---: | :--- | :--- | :--- |
| **JavaScript** | **Full** | Lexical Parser + Pattern Engine | Bracket/delimiter balancing, strict equality (`===`), `eval()` code injection, `innerHTML` XSS, `var` hoisting, `NaN` comparison bugs, DOM loops | Pure static text parsing; does not execute in V8 or evaluate dynamic `Function()` strings |
| **Python** | **Full** | Lexical Scanner + Indentation Rules | Bracket symmetry, mutable default arguments, bare `except:` clauses, unquoted strings, comment-safe colon checks | Does not execute in Python runtime; dynamic imports are unverified |
| **TypeScript** | **Partial** | Syntax Tokenizer + Type Linting | Loose `any` type usage, non-null assertions (`!`), strict type idioms | Does not execute `tsc` compiler; external type definition files (`.d.ts`) not loaded |
| **HTML5** | **Full** | Structural Regex + a11y Scanner | Document structure, unclosed tags, image `alt` accessibility, inline `javascript:` URI vectors | Does not validate external CSS styles or runtime DOM mutations |
| **CSS3** | **Full** | Selector & Rule Scanner | Bracket balancing, `!important` overuse, universal selector performance, empty rulesets | Does not compute cascaded CSS specificity graphs |
| **Java** | **Partial** | Lexical Pattern Scanner | Bracket balancing, dynamic SQL query concatenation, insecure pseudo-random generators (`java.util.Random`) | Does not build JVM bytecode or resolve Maven/Gradle classpaths |
| **C / C++** | **Partial** | Lexical Pattern Scanner | Delimiter balancing, unsafe functions (`gets()`, `strcpy()`, `sprintf()`), memory safety patterns | Does not invoke GCC/Clang or run Valgrind dynamic memory tracing |

---

## 4. Security & Hardening Architecture

CodeInsight incorporates defensive programming and security engineering:

1. **Authentication & Password Hashing:**
   - Passwords hashed using Node.js crypto's salted `scrypt` key derivation function with random 16-byte salts.
   - Backward compatibility for legacy SHA-256 hashes with automatic migration on subsequent authentications.
2. **Password Recovery Workflow:**
   - Cryptographically random single-use reset tokens are stored as SHA-256 digests and expire after 15 minutes.
   - The reset token is never returned by the HTTP API. In local development (`NODE_ENV` not set to `production`), the token is printed only in the backend terminal for demo/testing. Production mode fails closed until a real email transport is configured.
3. **Administrator Lockout Prevention:**
   - System prevents deletion, suspension, or demotion of root administrator accounts (`admin` / `usr-admin-01`).
   - Platform verifies active administrator count (`countActiveAdmins() <= 1`) before permitting demotion or suspension of any administrator.
4. **ZIP Archive Extraction Security (`zipSecurity.js`):**
   - **Zip Slip Prevention:** Rejects entries attempting path traversal (`../` or `..\`) or absolute paths (`/etc/`, `C:\`).
   - **Decompression Bomb Defense:** Enforces strict limits: max 100 entries, max 1.5MB per decompressed file, max 10MB total uncompressed archive size.
   - **Executable Blocking:** Immediately rejects archives containing executable extensions (`.exe`, `.bat`, `.cmd`, `.sh`, `.vbs`, `.ps1`).
5. **Secret Redaction:**
   - Analysis logs and audit tables automatically redact detected API keys (`AKIA...`, `sk_live_...`, `AIza...`), bearer tokens, and password strings.
6. **CSV Injection & HTTP Response Splitting:**
   - CSV export sanitizes formulas starting with `=`, `+`, `-`, or `@` to prevent spreadsheet command execution.
   - Report export enforces a strict whitelist for requested languages and replaces newline delimiters (`\r`, `\n`) to prevent HTTP response splitting.
7. **Remediation Safety Workflow:**
   - Source line content is verified prior to replacement.
   - Automated post-apply validation rescan checks that the code remains syntactically intact.
   - Changes are reversible via the client-side snapshot undo stack.

---

Additional hardening includes in-memory per-IP rate limits on login (20 requests per 15 minutes by default; configurable with `LOGIN_RATE_LIMIT_MAX`), registration, password recovery, and analysis endpoints; unquoted secret redaction; dynamic idle-session expiry; configurable ZIP limits (1–50 MB); persisted MongoDB system settings; and MongoDB scan-history deletion when a user clears history.

## 5. Getting Started & Running the Platform

### Prerequisites
- **Node.js**: v20.19.0 or higher (required by the installed Mongoose version)
- **npm**: v9.0.0 or higher

### Installation & Launch

1. **Clone or Navigate to the Workspace:**
   ```bash
   cd code_insight_updated
   ```

2. **Install Dependencies:**
   ```bash
   npm install
   ```
   The app uses local JSON persistence by default. MongoDB is optional; configure `MONGODB_URI` in `.env` only if you have a MongoDB server running.

3. **Run the Automated Unit + HTTP Integration Tests:**
   ```bash
   npm test
   ```
   *Verifies multi-language static analysis, security rules, authentication/RBAC, history persistence, ZIP project scans, exports, API response contracts, and error handling.*

4. **Start the CodeInsight Server:**
   ```bash
   npm start
   ```
   *The server initializes on port `3000` (or `process.env.PORT`).*

5. **Access the Web Platform:**
   Open your browser and navigate to:
   ```
   http://localhost:3000
   ```

### Default Credentials
- **Administrator (fresh local installation only):**
  - Username: `admin`
  - Password: `admin123`
  - Capabilities: User directory management, audit logs, system reports, and system settings.
- **Standard user:** Create an account from the Register page. New accounts do not receive administrator privileges.

**Security note:** The administrator credentials above are for a local college demonstration only. Change the password before exposing the application to a network. The `data.json` file is generated on first launch and stores local development data; do not share it because it can contain user profile and analysis-history information.

## Local demo login accounts

On a fresh local installation, the application ensures these demo accounts exist:

- Administrator: `admin` / `admin123`
- Developer: `developer` / `dev123`

The login form starts empty. Use the **Use Admin** or **Use Developer** button to fill the corresponding fields; this does not submit the form automatically. Existing accounts and changed passwords are not overwritten. These demo credentials are for local college demonstration only; change/remove them before any public deployment.

## Authentication troubleshooting

Run `npm install`, then `npm test`, then `npm start`. Open `http://localhost:3000`. If you use MongoDB, set `MONGODB_URI` in a local `.env` file. Never share `.env` or your database connection string. The app uses local `data.json` persistence when MongoDB is not configured.


## AI-Powered Review & Correction Assistant

The Code Analyzer includes an optional AI review panel. It always runs the built-in static analyzer first. Without an API key, the panel clearly identifies itself as **rule-based fallback** and shows local findings/recommendations. To enable actual AI-generated review summaries, findings, and proposed full-code corrections, create a private `.env` file from `.env.example`, set `GEMINI_API_KEY` to your own Google Gemini API key, optionally set `GEMINI_MODEL`, and restart the server. Never commit `.env` or expose the key in browser code. AI-proposed code is never applied automatically: the user must review it, confirm replacement, then CodeInsight re-runs static analysis. AI output can be wrong; inspect the corrected code and test it before using it in real projects.
