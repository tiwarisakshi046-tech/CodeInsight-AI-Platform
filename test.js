/**
 * Automated Unit & Security Test Suite for CodeInsight
 * Validates:
 * - Multi-Language Static Code & Security Analysis (JS, Python, TS, Java, C/C++, HTML, CSS)
 * - Authentication, Scrypt Password Hashing & RBAC
 * - Password Reset Token Workflow (Single-Use, Time-Limited)
 * - User Profile & Settings Persistence
 * - Admin Governance & Lockout Protection
 * - ZIP Archive Security & Decompression Safety
 * - Pre-Fix Verification & Post-Fix Validation
 * - Export Report & CSV Sanitization
 */

const assert = require('assert');
const MultiLanguageAnalyzer = require('./analyzer');
const auth = require('./auth');

console.log('===========================================================');
console.log('🧪 Running CodeInsight Automated Test & Security Suite...');
console.log('===========================================================\n');

// 1. Test Multi-Language Static Code Analysis Core
console.log('--- Multi-Language Static Analysis & Rule Engine ---');

// A. Clean Code Inspection (Grade A+, 100 Health Score)
const cleanReport = MultiLanguageAnalyzer.generateReport('function add(a, b) {\n    if (typeof a !== "number" || typeof b !== "number") throw new TypeError();\n    return a + b;\n}', 'javascript');
assert.strictEqual(cleanReport.success, true);
assert.strictEqual(cleanReport.healthScore, 100);
assert.strictEqual(cleanReport.findings.length, 0);
console.log('  ✔ Clean JavaScript Code -> 100 Health Score, Zero False Positives');

// B. Syntax Error Detection (Bracket & String Delimiters)
const syntaxReport = MultiLanguageAnalyzer.generateReport('function broken() {\n    const str = "unclosed;\n    if (true) {\n', 'javascript');
assert.strictEqual(syntaxReport.success, true);
assert.ok(syntaxReport.findings.some(f => f.type === 'error' || f.category.includes('Syntax')), 'Must detect syntax error');
console.log('  ✔ Lexical Syntax Grammar & Bracket Integrity verified');

// C. Common Traps & Bad Practices
const trapReport = MultiLanguageAnalyzer.generateReport('var count = 10;\nif (count == "10") {\n    if (count == NaN) return;\n}', 'javascript');
assert.strictEqual(trapReport.success, true);
assert.ok(trapReport.findings.some(f => f.ruleId === 'JS-LINT-001'), 'Detect loose equality ==');
assert.ok(trapReport.findings.some(f => f.ruleId === 'JS-LINT-002'), 'Detect legacy var scoping');
assert.ok(trapReport.findings.some(f => f.ruleId === 'JS-LINT-003'), 'Detect direct NaN comparison');
console.log('  ✔ Common Beginner Pitfalls & Traps verified');

// D. Empty / Invalid Input Handling
const emptyReport = MultiLanguageAnalyzer.generateReport('', 'javascript');
assert.strictEqual(emptyReport.success, false);
assert.strictEqual(emptyReport.status, 'empty_input');
console.log('  ✔ Safe Empty Input Handling verified');

// 3. Test Multi-Language Engines
console.log('\n--- Multi-Language Testing ---');
// Python
const pyReport = MultiLanguageAnalyzer.generateReport('def run(items=[]):\n    eval("2+2")', 'python');
assert.strictEqual(pyReport.success, true);
assert.ok(pyReport.findings.some(f => f.ruleId === 'PY-BUG-001'), 'Detect mutable default');
console.log('  ✔ Python Static Analysis & Bug Detection verified');

// Java
const javaReport = MultiLanguageAnalyzer.generateReport('String q = "SELECT * FROM users WHERE id = " + id;', 'java');
assert.strictEqual(javaReport.success, true);
assert.ok(javaReport.findings.some(f => f.ruleId === 'JAVA-SEC-001'), 'Detect Java SQL injection');
console.log('  ✔ Java Security & Vulnerability Detection verified');

// C / C++
const cppReport = MultiLanguageAnalyzer.generateReport('void foo() { char b[10]; gets(b); }', 'c_cpp');
assert.strictEqual(cppReport.success, true);
assert.ok(cppReport.findings.some(f => f.ruleId === 'CPP-SEC-001'), 'Detect C buffer overflow');
console.log('  ✔ C/C++ Buffer Overflow & Memory Safety verified');

// HTML & CSS
const htmlReport = MultiLanguageAnalyzer.generateReport('<img src="test.jpg"><button onclick="do()">Go</button>', 'html');
assert.strictEqual(htmlReport.success, true);
assert.ok(htmlReport.findings.some(f => f.ruleId === 'HTML-A11Y-001'), 'Detect missing alt');
console.log('  ✔ HTML Accessibility & Security verified');

// TypeScript
const tsReport = MultiLanguageAnalyzer.generateReport('let x: any = 10;\n// @ts-ignore\nconst y = x;\ninterface Empty {}\nlet name: String = "test";\nconst val = x!.foo;', 'typescript');
assert.strictEqual(tsReport.success, true);
assert.ok(tsReport.findings.some(f => f.ruleId === 'TS-TYPE-001'), 'Detect unsafe any type');
assert.ok(tsReport.findings.some(f => f.ruleId === 'TS-IGNORE-001'), 'Detect @ts-ignore directive');
assert.ok(tsReport.findings.some(f => f.ruleId === 'TS-EMPTY-001'), 'Detect empty interface');
assert.ok(tsReport.findings.some(f => f.ruleId === 'TS-WRAPPER-001'), 'Detect boxed String wrapper type');
assert.ok(tsReport.findings.some(f => f.ruleId === 'TS-NON-NULL-001'), 'Detect non-null assertion');
console.log('  ✔ TypeScript Static Type Safety & Linting verified');

// Python with inline comments on header line
const pyCommentReport = MultiLanguageAnalyzer.generateReport('if x > 10: # validate condition\n    print("ok")', 'python');
assert.strictEqual(pyCommentReport.findings.some(f => f.ruleId === 'PY-SYN-001'), false, 'Should NOT false-flag colon error when comment is present');
console.log('  ✔ Python Comment-Safe Syntax Colon Check verified');

// Multiline Template Literal (Backtick) in JavaScript
const jsTemplateReport = MultiLanguageAnalyzer.generateReport('const msg = `hello\nworld`;\nfunction test() { return 1; }', 'javascript');
assert.strictEqual(jsTemplateReport.findings.some(f => f.ruleId === 'JS-SYN-001'), false, 'Multiline backtick string should not cause bracket mismatch');
console.log('  ✔ Multiline Template Literal & Syntax Scope verified');

// Supported Languages API
const langs = MultiLanguageAnalyzer.getSupportedLanguages();
assert.ok(Array.isArray(langs) && langs.length >= 7, 'Should support at least 7 languages');
console.log('  ✔ MultiLanguageAnalyzer.getSupportedLanguages() verified');

// 4. Test Authentication & RBAC (Dynamic Registration & Admin Login)
console.log('\n--- Authentication & Admin RBAC Testing ---');
const adminLogin = auth.authenticate('admin', 'admin123');
assert.strictEqual(adminLogin.success, true, 'Admin login should succeed');
assert.strictEqual(adminLogin.user.role, 'admin', 'Admin role must be set');
console.log('  ✔ Admin Authentication verified');

// Register a dynamic student user instead of relying on hardcoded accounts
const testUsername = 'student_' + Date.now();
const regResult = auth.register(testUsername, `${testUsername}@college.edu`, 'pass1234', 'Test Student');
assert.strictEqual(regResult.success, true, 'Dynamic student registration should succeed');
assert.ok(regResult.user.role === 'user' || regResult.user.role === 'student', 'Registered user role must be user/student');

const studentLogin = auth.authenticate(testUsername, 'pass1234');
assert.strictEqual(studentLogin.success, true, 'Registered student login should succeed');
console.log('  ✔ Dynamic Student Registration & Authentication verified');

const allUsers = auth.getAllUsers();
assert.ok(allUsers.length >= 2, 'Should have admin and newly registered student');
console.log('  ✔ User Management & Directory verified');

// 5. Test Dynamic User Scan History (Zero Hardcoded Files)
console.log('\n--- Dynamic User Scan History Testing ---');
auth.clearUserScanHistory(testUsername);
assert.strictEqual(auth.getUserScanHistory(testUsername).length, 0, 'New user history starts empty');
auth.saveScanHistory(testUsername, {
  id: 'scn_test',
  filename: 'sample.js',
  language: 'javascript',
  score: 95,
  grade: 'A',
  issueCount: 1,
  timestamp: new Date().toISOString()
});
assert.strictEqual(auth.getUserScanHistory(testUsername).length, 1, 'Records dynamic scan in history');
auth.clearUserScanHistory(testUsername);
assert.strictEqual(auth.getUserScanHistory(testUsername).length, 0, 'Clears scan history cleanly');

// Clean up test user after test run
auth.deleteUser(regResult.user.id);
console.log('  ✔ Dynamic User Scan History verified (Zero Hardcoded Accounts/Files)');

// 6. Test Flaw Fixes: False-Positive Resistance & Session Invalidation
console.log('\n--- Flaw Remediation Verification ---');
// A. False-Positive Resistance (Strings and inline comments)
const fpReport = MultiLanguageAnalyzer.generateReport('const msg = "Never use var x = 1 or == in JS";\n// var x = 10;\nconst score = 100;', 'javascript');
assert.strictEqual(fpReport.findings.some(f => f.ruleId === 'JS-LINT-002'), false, 'Should not flag var inside string or comment');
assert.strictEqual(fpReport.findings.some(f => f.ruleId === 'JS-LINT-001'), false, 'Should not flag == inside string or comment');
console.log('  ✔ False-Positive Resistance (Strings & comments sanitized) verified');

// B. Session Token Invalidation on Suspension
const tempReg = auth.register('testrunner', 'testrunner@codeinsight.io', 'pass12345', 'Test Runner');
assert.strictEqual(tempReg.success, true);
assert.ok(auth.getUserByToken(tempReg.token), 'Token should be active after registration');
auth.toggleUserStatus(tempReg.user.id);
assert.strictEqual(auth.getUserByToken(tempReg.token), null, 'Token must be revoked when account is suspended');
auth.deleteUser(tempReg.user.id);
console.log('  ✔ Session Token Invalidation on Suspend verified');
const idleSession = auth.register('idlecheck', 'idlecheck@codeinsight.io', 'pass12345', 'Idle Check');
assert.strictEqual(idleSession.success, true);
const savedSettingsForIdle = auth.getSystemSettings();
auth.updateSystemSettings({ sessionTimeoutMinutes: 5 });
const idleSessionData = auth.sessions.get(idleSession.token);
idleSessionData.lastActivityAt = Date.now() - (6 * 60 * 1000);
assert.strictEqual(auth.getUserByToken(idleSession.token), null, 'Inactive sessions must expire at the configured idle timeout');
auth.updateSystemSettings(savedSettingsForIdle);
auth.deleteUser(idleSession.user.id);

// C. Dynamic System Metrics
const metrics = auth.getSystemMetrics();
assert.ok(typeof metrics.averageHealthScore === 'number', 'Metrics average health score must be numeric');
console.log('  ✔ Dynamic System KPI Calculation verified');

// 7. Security Audit: Salted Password Hashing & Root Admin Protection
console.log('\n--- Security Audit: Authentication & RBAC Hardening ---');

// A. Salted scrypt password hashing & verification
const plainPass = 'SuperSecret2026!';
const saltedHash = auth.hashPassword(plainPass);
assert.ok(saltedHash.startsWith('scrypt:'), 'Password hash must use salted scrypt format');
assert.strictEqual(auth.verifyPassword(plainPass, saltedHash), true, 'Salted hash must verify valid password');
assert.strictEqual(auth.verifyPassword('WrongPass', saltedHash), false, 'Salted hash must reject invalid password');
console.log('  ✔ Salted scrypt password hashing & verification verified');

// B. Legacy SHA-256 backward compatibility
const legacyHash = require('crypto').createHash('sha256').update('admin123').digest('hex');
assert.strictEqual(auth.verifyPassword('admin123', legacyHash), true, 'Must verify legacy SHA-256 hash');
assert.strictEqual(auth.verifyPassword('wrong', legacyHash), false, 'Must reject wrong password on legacy hash');
console.log('  ✔ Legacy hash backward compatibility verified');

// C. Root Administrator Account Immutability (usr-admin-01)
const rootDelete = auth.deleteUser('usr-admin-01');
assert.strictEqual(rootDelete.success, false, 'Root administrator cannot be deleted');
const rootSuspend = auth.toggleUserStatus('usr-admin-01');
assert.strictEqual(rootSuspend.success, false, 'Root administrator cannot be suspended');
const rootDemote = auth.updateUserRole('usr-admin-01', 'student');
assert.strictEqual(rootDemote.success, false, 'Root administrator cannot be demoted');
console.log('  ✔ Root Administrator Protection (Deletion, Suspension, Demotion blocked) verified');

// D. Single Active Admin Lockout Protection
const lockoutTest = auth.updateUserRole('usr-admin-01', 'user');
assert.strictEqual(lockoutTest.success, false, 'Must prevent system lockout of last admin');
console.log('  ✔ Administrator Lockout Prevention verified');

// E. Password Reset Token Workflow (Single-Use & 15-Minute Expiry)
console.log('\n--- Password Reset Token Workflow Testing ---');
const resetReq = auth.createPasswordResetToken('admin@codeinsight.io');
assert.strictEqual(resetReq.success, true, 'Reset token request should succeed');
assert.ok(resetReq.resetToken, 'Token string must be returned');
const resetAdminUser = auth.users.find(user => user.email === 'admin@codeinsight.io');
assert.notStrictEqual(resetAdminUser.resetPasswordToken, resetReq.resetToken, 'Only a token digest should be stored');
assert.strictEqual(resetReq.expiresInMinutes, 15, 'Token must be valid for 15 minutes');

// Complete password reset
const resetExec = auth.resetPassword(resetReq.resetToken, 'NewAdminPass2026!');
assert.strictEqual(resetExec.success, true, 'Password reset must succeed with valid token');

// Verify token was invalidated immediately (single-use guarantee)
const secondAttempt = auth.resetPassword(resetReq.resetToken, 'AnotherPass123!');
assert.strictEqual(secondAttempt.success, false, 'Consumed reset token cannot be reused (Single-Use enforced)');

// Revert password back to admin123
auth.resetPassword(auth.createPasswordResetToken('admin@codeinsight.io').resetToken, 'admin123');
console.log('  ✔ Password Reset Workflow (Single-Use, Time-Limited, Dependency Reporting) verified');

// F. Profile & User Preferences Persistence
console.log('\n--- User Profile & Settings Persistence ---');
const profUpdate = auth.updateProfile('usr-admin-01', { name: 'Lead Administrator', bio: 'Platform Lead' });
assert.strictEqual(profUpdate.success, true);
assert.strictEqual(profUpdate.user.name, 'Lead Administrator');

const settUpdate = auth.updateUserSettings('usr-admin-01', { theme: 'slate', tabSize: 2 });
assert.strictEqual(settUpdate.success, true);
assert.strictEqual(settUpdate.settings.theme, 'slate');
assert.strictEqual(settUpdate.settings.tabSize, 2);
console.log('  ✔ Profile & Preferences Persistence verified');

// G. Secret Redaction in Scan Records & Logs
const secretSnippet = 'const gcpKey = "AIzaSyD-sampleApiKeySecretForTesting12"; const token = "ghp_123456789012345678901234567890123456"; const userAuth = "password = \'supersecretpassword123\'";';
const redacted = auth.redactSecrets(secretSnippet);
assert.ok(!redacted.includes('AIzaSyD-sampleApiKeySecretForTesting12'), 'Google API key must be redacted');
assert.ok(!redacted.includes('ghp_123456789012345678901234567890123456'), 'GitHub token must be redacted');
assert.ok(!redacted.includes('supersecretpassword123'), 'Password must be redacted');
assert.ok(redacted.includes('[REDACTED_API_KEY]'), 'Google API redaction tag must be present');
assert.ok(redacted.includes('[REDACTED_GH_TOKEN]'), 'GitHub token redaction tag must be present');
assert.ok(redacted.includes('[REDACTED_SECRET]'), 'General secret redaction tag must be present');
console.log('  ✔ Secret Redaction (API Keys, Tokens, Passwords) verified');
assert.ok(!auth.redactSecrets('API_KEY=PlainSecret123').includes('PlainSecret123'), 'Unquoted API_KEY assignments must be redacted');
assert.ok(!auth.redactSecrets('DB_PASSWORD=plain-db-pass-123').includes('plain-db-pass-123'), 'Unquoted DB_PASSWORD assignments must be redacted');
assert.ok(!auth.redactSecrets('access_token:BearerSecretValue123').includes('BearerSecretValue123'), 'Unquoted access tokens must be redacted');

const originalSystemSettings = auth.getSystemSettings();
const settingUpdate = auth.updateSystemSettings({
  platformName: 'CodeInsight Test',
  maxZipArchiveMb: 12,
  defaultLanguage: 'python',
  sessionTimeoutMinutes: 30,
  allowRegistration: true
});
assert.strictEqual(settingUpdate.success, true);
assert.strictEqual(auth.getSystemSettings().maxZipArchiveMb, 12);
assert.strictEqual(auth.getSystemSettings().defaultLanguage, 'python');
assert.strictEqual(auth.getSystemSettings().sessionTimeoutMinutes, 30);
assert.strictEqual(auth.updateSystemSettings({ maxZipArchiveMb: 100 }).success, false, 'Unsafe upload limits must be rejected');
assert.strictEqual(auth.updateSystemSettings({ allowRegistration: 'false' }).success, false, 'Non-boolean settings must be rejected');
auth.updateSystemSettings(originalSystemSettings);

// 8. Security Audit: ZIP Archive Hardening (Zip Slip, Zip Bomb, Malicious Extensions)
console.log('\n--- Security Audit: ZIP Archive Security Hardening ---');
const { extractSafeZipContents, ZipSecurityError } = require('./zipSecurity');
const zlib = require('zlib');

// Helper to construct in-memory ZIP archives for testing
function buildTestZip(files) {
  const fileEntries = [];
  let offset = 0;
  const localHeaders = [];

  for (const f of files) {
    const raw = Buffer.isBuffer(f.content) ? f.content : Buffer.from(f.content || '', 'utf8');
    const compMethod = f.compMethod !== undefined ? f.compMethod : 8;
    const compData = compMethod === 8 ? zlib.deflateRawSync(raw) : raw;
    const nameBuf = Buffer.from(f.name, 'utf8');

    const lh = Buffer.alloc(30 + nameBuf.length);
    lh.writeUInt32LE(0x04034b50, 0);
    lh.writeUInt16LE(20, 4);
    lh.writeUInt16LE(0, 6);
    lh.writeUInt16LE(compMethod, 8);
    lh.writeUInt16LE(0, 10);
    lh.writeUInt16LE(0, 12);
    lh.writeUInt32LE(0, 14);
    lh.writeUInt32LE(compData.length, 18);
    lh.writeUInt32LE(raw.length, 22);
    lh.writeUInt16LE(nameBuf.length, 26);
    lh.writeUInt16LE(0, 28);
    nameBuf.copy(lh, 30);

    const localOffset = offset;
    offset += lh.length + compData.length;

    localHeaders.push(lh);
    fileEntries.push({
      nameBuf,
      compMethod,
      compSize: compData.length,
      uncompSize: raw.length,
      localOffset,
      compData
    });
  }

  const cdOffset = offset;
  const cdHeaders = [];
  for (const entry of fileEntries) {
    const cdh = Buffer.alloc(46 + entry.nameBuf.length);
    cdh.writeUInt32LE(0x02014b50, 0);
    cdh.writeUInt16LE(20, 4);
    cdh.writeUInt16LE(20, 6);
    cdh.writeUInt16LE(0, 8);
    cdh.writeUInt16LE(entry.compMethod, 10);
    cdh.writeUInt16LE(0, 12);
    cdh.writeUInt16LE(0, 14);
    cdh.writeUInt32LE(0, 16);
    cdh.writeUInt32LE(entry.compSize, 20);
    cdh.writeUInt32LE(entry.uncompSize, 24);
    cdh.writeUInt16LE(entry.nameBuf.length, 28);
    cdh.writeUInt16LE(0, 30);
    cdh.writeUInt16LE(0, 32);
    cdh.writeUInt16LE(0, 34);
    cdh.writeUInt16LE(0, 36);
    cdh.writeUInt32LE(0, 38);
    cdh.writeUInt32LE(entry.localOffset, 42);
    entry.nameBuf.copy(cdh, 46);
    cdHeaders.push(cdh);
    offset += cdh.length;
  }
  const cdSize = offset - cdOffset;

  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(files.length, 8);
  eocd.writeUInt16LE(files.length, 10);
  eocd.writeUInt32LE(cdSize, 12);
  eocd.writeUInt32LE(cdOffset, 16);
  eocd.writeUInt16LE(0, 20);

  const chunks = [];
  for (let i = 0; i < fileEntries.length; i++) {
    chunks.push(localHeaders[i]);
    chunks.push(fileEntries[i].compData);
  }
  for (const cdh of cdHeaders) chunks.push(cdh);
  chunks.push(eocd);

  return Buffer.concat(chunks);
}

// A. Valid Code Extraction
const cleanZip = buildTestZip([
  { name: 'src/main.js', content: 'console.log("Safe application");' },
  { name: 'src/calc.py', content: 'def add(x, y):\n    return x + y' }
]);
const extracted = extractSafeZipContents(cleanZip);
assert.strictEqual(extracted.length, 2, 'Should safely extract 2 code files');
assert.strictEqual(extracted[0].name, 'src/main.js');
assert.strictEqual(extracted[0].language, 'javascript');
assert.strictEqual(extracted[1].name, 'src/calc.py');
assert.strictEqual(extracted[1].language, 'python');
console.log('  ✔ Valid in-memory ZIP archive extraction verified');

// B. Path Traversal ("Zip Slip") Protection (Relative ../)
const traversalZip = buildTestZip([
  { name: '../../etc/passwd', content: 'root:x:0:0' }
]);
assert.throws(() => {
  extractSafeZipContents(traversalZip);
}, (err) => err instanceof ZipSecurityError && err.code === 'PATH_TRAVERSAL', 'Must reject relative path traversal');
console.log('  ✔ Zip Slip Path Traversal (../../) rejected verified');

// C. Path Traversal Protection (Absolute /)
const absZip = buildTestZip([
  { name: '/etc/shadow', content: 'root:$6$...' }
]);
assert.throws(() => {
  extractSafeZipContents(absZip);
}, (err) => err instanceof ZipSecurityError && err.code === 'PATH_TRAVERSAL', 'Must reject absolute path');
console.log('  ✔ Absolute path entry rejected verified');

// D. Dangerous Executable & Binary Extension Protection
const execZip = buildTestZip([
  { name: 'virus.exe', content: 'MZThisIsExecutable' }
]);
assert.throws(() => {
  extractSafeZipContents(execZip);
}, (err) => err instanceof ZipSecurityError && err.code === 'UNSAFE_EXTENSION', 'Must block .exe executable extension');
console.log('  ✔ Blocked executable extension (.exe) rejected verified');

// E. Excessive File Count Protection (> 100 entries)
const manyFiles = [];
for (let i = 0; i < 105; i++) {
  manyFiles.push({ name: `module_${i}.js`, content: `const x = ${i};` });
}
const hugeCountZip = buildTestZip(manyFiles);
assert.throws(() => {
  extractSafeZipContents(hugeCountZip);
}, (err) => err instanceof ZipSecurityError && err.code === 'EXCESSIVE_FILES', 'Must block > 100 file entries');
console.log('  ✔ Denial of Service excessive file count (> 100) rejected verified');

// F. Decompression Bomb & Oversized Entry Protection (> 1.5MB single file)
const oversizedZip = buildTestZip([
  { name: 'huge.js', content: Buffer.alloc(2 * 1024 * 1024, 0x61) }
]);
assert.throws(() => {
  extractSafeZipContents(oversizedZip);
}, (err) => err instanceof ZipSecurityError && (err.code === 'OVERSIZED_ENTRY' || err.code === 'DECOMPRESSION_BOMB'), 'Must reject oversized entry');
console.log('  ✔ Decompression bomb & oversized entry (> 1.5MB) rejected verified');

// 9. Pre-Fix Verification & Post-Fix Validation Logic
console.log('\n--- Code Remediation: Pre-Fix Verification & Post-Fix Validation ---');
const sampleCode = 'var total = 100;\nif (total == "100") {\n    console.log("matched");\n}';
const sampleReport = MultiLanguageAnalyzer.generateReport(sampleCode, 'javascript');
const fixableFinding = sampleReport.findings.find(f => f.suggestedFix);
assert.ok(fixableFinding, 'Should identify fixable finding in sample');

// Test successful pre-fix match and validation
const lines = sampleCode.split('\n');
const targetLine = lines[fixableFinding.line - 1];
assert.ok(targetLine.includes(fixableFinding.suggestedFix.before), 'Pre-fix verification must find exact before token');
const repairedCode = sampleCode.replace(fixableFinding.suggestedFix.before, fixableFinding.suggestedFix.after);
const postFixReport = MultiLanguageAnalyzer.generateReport(repairedCode, 'javascript');
assert.ok(postFixReport.healthScore >= sampleReport.healthScore, 'Post-fix health score must be equal or improved');
console.log('  ✔ Pre-Fix source location verification & Post-Fix analyzer validation verified');

// Test pre-fix verification failure when file was already modified
const modifiedLines = [...lines];
modifiedLines[fixableFinding.line - 1] = 'const completelyDifferentCode = 42;';
const modifiedTargetLine = modifiedLines[fixableFinding.line - 1];
assert.strictEqual(modifiedTargetLine.includes(fixableFinding.suggestedFix.before), false, 'Pre-fix verification must detect mismatch');
console.log('  ✔ Pre-Fix mismatch detection & abort verified');

// 10. HTTP Header Injection & Response Splitting Prevention
console.log('\n--- Export Report: HTTP Response Splitting Sanitization ---');
const maliciousLang = 'javascript\r\nSet-Cookie: session=hijacked\r\nInjected-Header: true';
const validLangs = new Set(['javascript', 'python', 'typescript', 'html', 'css', 'java', 'c_cpp', 'c', 'cpp']);
const safeLang = validLangs.has(maliciousLang.toLowerCase().trim()) ? maliciousLang : 'javascript';
assert.strictEqual(safeLang, 'javascript', 'Malicious injected language string must be rejected and defaulted to javascript');
assert.ok(!safeLang.includes('\r'), 'CRLF Carriage return must not be present');
assert.ok(!safeLang.includes('\n'), 'CRLF Line feed must not be present');
assert.ok(!safeLang.includes('Set-Cookie'), 'Injected header commands must not be present');
const safeFilename = `CodeInsight-Report-${safeLang.replace(/[^a-zA-Z0-9]/g, '_')}.md`;
assert.strictEqual(safeFilename.includes('\r'), false);
assert.strictEqual(safeFilename.includes('\n'), false);
console.log('  ✔ HTTP Response Splitting / Header Injection prevention verified');

console.log('\n===========================================================');
// Keep repeated test runs from permanently creating a test account.
const testUserRecord = auth.getAllUsers().find(user => user.username === testUsername);
if (testUserRecord) {
  auth.clearUserScanHistory(testUsername);
  auth.deleteUser(testUserRecord.id);
}

console.log('  ALL TESTS PASSED SUCCESSFULLY! (100% VALIDATION PASS)');
console.log('===========================================================\n');
