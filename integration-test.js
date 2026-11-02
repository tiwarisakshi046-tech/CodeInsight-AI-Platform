/**
 * HTTP integration tests for frontend/backend response contracts.
 * Uses Node's built-in fetch; no extra test dependency is required.
 */
const assert = require('node:assert/strict');
const zlib = require('node:zlib');
const app = require('./server');

const server = app.listen(0, '127.0.0.1');
let baseUrl = '';
let adminToken = '';
let testUserToken = '';
let testUserId = '';
let testUsername = '';

async function request(route, options = {}) {
  return fetch(`${baseUrl}${route}`, options);
}

async function jsonRequest(route, body, token, method = 'POST') {
  return request(route, {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {})
    },
    body: JSON.stringify(body)
  });
}

function buildTestZip(files) {
  const localHeaders = [];
  const entries = [];
  let offset = 0;
  for (const file of files) {
    const raw = Buffer.from(file.content, 'utf8');
    const compressed = zlib.deflateRawSync(raw);
    const name = Buffer.from(file.name, 'utf8');
    const local = Buffer.alloc(30 + name.length);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(8, 8);
    local.writeUInt32LE(compressed.length, 18);
    local.writeUInt32LE(raw.length, 22);
    local.writeUInt16LE(name.length, 26);
    name.copy(local, 30);
    localHeaders.push(local, compressed);
    entries.push({ name, compressedSize: compressed.length, rawSize: raw.length, offset });
    offset += local.length + compressed.length;
  }
  const centralOffset = offset;
  const centralHeaders = [];
  for (const entry of entries) {
    const central = Buffer.alloc(46 + entry.name.length);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(8, 10);
    central.writeUInt32LE(entry.compressedSize, 20);
    central.writeUInt32LE(entry.rawSize, 24);
    central.writeUInt16LE(entry.name.length, 28);
    central.writeUInt32LE(entry.offset, 42);
    entry.name.copy(central, 46);
    centralHeaders.push(central);
    offset += central.length;
  }
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(offset - centralOffset, 12);
  end.writeUInt32LE(centralOffset, 16);
  return Buffer.concat([...localHeaders, ...centralHeaders, end]);
}

async function main() {
  await new Promise((resolve, reject) => {
    server.once('listening', resolve);
    server.once('error', reject);
  });
  baseUrl = `http://127.0.0.1:${server.address().port}`;

  try {
    const home = await request('/');
    assert.equal(home.status, 200, 'Frontend home page should load');
    assert.match(await home.text(), /CodeInsight/i);

    const staticAsset = await request('/js/app.js');
    assert.equal(staticAsset.status, 200, 'Frontend JavaScript asset should load');
    assert.match(staticAsset.headers.get('content-type') || '', /javascript/i);

    const health = await (await request('/api/health')).json();
    assert.equal(health.status, 'online');
    assert.equal(health.database.uri, undefined, 'Health response must not expose a database connection URI');

    const languagesResponse = await request('/api/languages');
    const languages = await languagesResponse.json();
    assert.equal(languagesResponse.status, 200);
    assert.equal(languages.success, true);
    assert.ok(Array.isArray(languages.languages) && languages.languages.length >= 7);
    const publicConfig = await (await request('/api/config')).json();
    assert.equal(publicConfig.success, true);
    assert.equal(publicConfig.defaultLanguage, 'javascript');
    assert.equal(typeof publicConfig.platformName, 'string');

    const unsupportedLanguage = await jsonRequest('/api/analyze', {
      code: 'console.log(1);', language: '<img src=x onerror=alert(1)>'
    });
    assert.equal(unsupportedLanguage.status, 400, 'Untrusted language identifiers must be rejected');
    await unsupportedLanguage.text();

    const unauthenticatedHistory = await request('/api/user/history');
    assert.equal(unauthenticatedHistory.status, 401,
      'Personal history must require authentication');
    await unauthenticatedHistory.text();

    const adminLoginResponse = await jsonRequest('/api/auth/login', {
      identifier: 'admin', password: 'admin123'
    });
    const adminLogin = await adminLoginResponse.json();
    assert.equal(adminLoginResponse.status, 200, 'Fresh-install administrator credentials should work');
    assert.equal(adminLogin.success, true);
    assert.equal(adminLogin.user.role, 'admin');
    adminToken = adminLogin.token;

    const me = await (await request('/api/auth/me', {
      headers: { Authorization: `Bearer ${adminToken}` }
    })).json();
    assert.equal(me.success, true, 'Session validation should match the frontend contract');
    assert.equal(me.authenticated, true);

    for (const [route, key] of [
      ['/api/admin/metrics', 'metrics'],
      ['/api/admin/users', 'users'],
      ['/api/admin/audit-logs', 'logs'],
      ['/api/admin/logs', 'logs'],
      ['/api/admin/reports', 'report'],
      ['/api/admin/settings', 'settings']
    ]) {
      const response = await request(route, { headers: { Authorization: `Bearer ${adminToken}` } });
      const payload = await response.json();
      assert.equal(response.status, 200, `${route} should be accessible to an administrator`);
      assert.equal(payload.success, true, `${route} should return success:true`);
      assert.ok(payload[key] !== undefined, `${route} should return ${key}`);
    }

    const originalSettingsResponse = await request('/api/admin/settings', { headers: { Authorization: `Bearer ${adminToken}` } });
    const originalSettings = (await originalSettingsResponse.json()).settings;
    const updatedSettingsResponse = await jsonRequest('/api/admin/settings', {
      platformName: 'CodeInsight Integration',
      allowRegistration: true,
      maxZipArchiveMb: 12,
      defaultLanguage: 'python',
      sessionTimeoutMinutes: 45
    }, adminToken, 'PUT');
    assert.equal(updatedSettingsResponse.status, 200);
    assert.equal((await updatedSettingsResponse.json()).success, true);
    const updatedPublicConfig = await (await request('/api/config')).json();
    assert.equal(updatedPublicConfig.platformName, 'CodeInsight Integration');
    assert.equal(updatedPublicConfig.defaultLanguage, 'python');
    const invalidSettingsResponse = await jsonRequest('/api/admin/settings', { maxZipArchiveMb: 100 }, adminToken, 'PUT');
    assert.equal((await invalidSettingsResponse.json()).success, false, 'Invalid archive limits must be rejected');
    await jsonRequest('/api/admin/settings', originalSettings, adminToken, 'PUT');

    testUsername = `http_test_${Date.now()}`;
    const registrationResponse = await jsonRequest('/api/auth/register', {
      username: testUsername,
      email: `${testUsername}@example.test`,
      password: 'testpass123',
      name: 'HTTP Integration Test'
    });
    const registration = await registrationResponse.json();
    assert.equal(registrationResponse.status, 201);
    assert.equal(registration.success, true);
    testUserToken = registration.token;
    testUserId = registration.user.id;

    const promoteResponse = await jsonRequest(`/api/admin/users/${testUserId}/role`, { role: 'admin' }, adminToken, 'PATCH');
    assert.equal(promoteResponse.status, 200, 'Admin Promote button must use the backend PATCH route');
    assert.equal((await promoteResponse.json()).success, true);
    const demoteResponse = await jsonRequest(`/api/admin/users/${testUserId}/role`, { role: 'user' }, adminToken, 'PATCH');
    assert.equal(demoteResponse.status, 200, 'Admin Demote button must use the backend PATCH route');
    assert.equal((await demoteResponse.json()).success, true);

    const suspendResponse = await jsonRequest(`/api/admin/users/${testUserId}/status`, { status: 'suspended' }, adminToken, 'PATCH');
    assert.equal(suspendResponse.status, 200, 'Admin Suspend button must use the backend PATCH route');
    assert.equal((await suspendResponse.json()).user.status, 'suspended');
    const suspendedProfile = await request('/api/user/profile', { headers: { Authorization: `Bearer ${testUserToken}` } });
    assert.equal(suspendedProfile.status, 401, 'Suspension must revoke the user session');
    const activateResponse = await jsonRequest(`/api/admin/users/${testUserId}/status`, { status: 'active' }, adminToken, 'PATCH');
    assert.equal(activateResponse.status, 200);
    assert.equal((await activateResponse.json()).user.status, 'active');
    const reloginResponse = await jsonRequest('/api/auth/login', { identifier: testUsername, password: 'testpass123' });
    const relogin = await reloginResponse.json();
    assert.equal(reloginResponse.status, 200);
    testUserToken = relogin.token;

    const forbiddenResponse = await request('/api/admin/users', {
      headers: { Authorization: `Bearer ${testUserToken}` }
    });
    assert.equal(forbiddenResponse.status, 403, 'A standard user must not access admin APIs');
    await forbiddenResponse.text();

    const profileResponse = await request('/api/user/profile', {
      headers: { Authorization: `Bearer ${testUserToken}` }
    });
    assert.equal(profileResponse.status, 200);
    assert.equal((await profileResponse.json()).success, true);

    const sampleCode = 'const total = 5;\nconsole.log(total);';
    const analysisResponse = await jsonRequest('/api/analyze', {
      code: sampleCode, language: 'javascript', filename: 'integration-test.js'
    }, testUserToken);
    const analysis = await analysisResponse.json();
    assert.equal(analysisResponse.status, 200);
    assert.equal(analysis.success, true);
    assert.ok(typeof analysis.score === 'number');
    assert.ok(analysis.scanRecord && analysis.scanRecord.id);

    const historyResponse = await request('/api/user/history', {
      headers: { Authorization: `Bearer ${testUserToken}` }
    });
    const history = await historyResponse.json();
    assert.equal(historyResponse.status, 200);
    assert.equal(history.success, true);
    assert.ok(Array.isArray(history.history) && history.history.length > 0);
    const scan = history.history.find(record => record.id === analysis.scanRecord.id);
    assert.ok(scan, 'Analysis result should be persisted to history');
    assert.equal(scan.healthScore, analysis.score);
    assert.equal(scan.scanId, analysis.scanRecord.id);

    const detailResponse = await request(`/api/user/history/${encodeURIComponent(scan.id)}`, {
      headers: { Authorization: `Bearer ${testUserToken}` }
    });
    const detail = await detailResponse.json();
    assert.equal(detailResponse.status, 200);
    assert.equal(detail.success, true);
    assert.equal(detail.scan.id, scan.id);
    assert.equal(detail.scan.codeSnippet, sampleCode);

    const zip = buildTestZip([
      { name: 'src/main.c', content: '#include <string.h>\nvoid run(char *input) { char buffer[8]; strcpy(buffer, input); }' },
      { name: 'src/app.js', content: 'function run(input) { return eval(input); }' }
    ]);
    const zipResponse = await jsonRequest('/api/analyze/zip', {
      zipBase64: zip.toString('base64'), filename: 'sample-project.zip'
    }, testUserToken);
    const projectReport = await zipResponse.json();
    assert.equal(zipResponse.status, 200, 'ZIP endpoint should accept the JSON base64 contract');
    assert.equal(projectReport.success, true);
    assert.equal(projectReport.kind, 'project');
    assert.equal(projectReport.fileCount, 2);
    assert.ok(typeof projectReport.score === 'number');
    assert.ok(projectReport.findings.some(finding => finding.fileName === 'src/main.c'));
    assert.ok(projectReport.findings.some(finding => finding.fileName === 'src/app.js'));

    const csvResponse = await request('/api/export/csv', {
      headers: { Authorization: `Bearer ${testUserToken}` }
    });
    assert.equal(csvResponse.status, 200);
    assert.match(csvResponse.headers.get('content-type') || '', /text\/csv/i);
    assert.match(await csvResponse.text(), /integration-test\.js/);

    const markdownResponse = await jsonRequest('/api/export/report', {
      code: 'const total = 5;', language: 'javascript', report: analysis
    }, testUserToken);
    assert.equal(markdownResponse.status, 200);
    assert.match(markdownResponse.headers.get('content-type') || '', /text\/markdown/i);
    assert.match(await markdownResponse.text(), /CodeInsight Analysis/);

    const adminLogs = await (await request('/api/admin/logs', {
      headers: { Authorization: `Bearer ${adminToken}` }
    })).json();
    assert.ok(adminLogs.logs.some(log => log.id === scan.id && log.username === testUsername),
      'Admin logs should include owner, scan ID, and scan fields');

    const forgotResponse = await jsonRequest('/api/auth/forgot-password', { email: 'admin@codeinsight.io' });
    const forgotPayload = await forgotResponse.json();
    assert.equal(forgotResponse.status, 200);
    assert.equal(forgotPayload.success, true);
    assert.equal(Object.prototype.hasOwnProperty.call(forgotPayload, 'resetToken'), false,
      'Forgot-password API must never expose the reset token to the browser');

    // Two successful logins have already occurred in this test. Add 18 failed
    // attempts to reach the configured 20-request per-IP threshold; the next
    // request must be throttled. Keep this test aligned with server.js.
    for (let i = 0; i < 18; i++) {
      const failedLogin = await jsonRequest('/api/auth/login', { identifier: 'no-such-user', password: 'bad-password' });
      assert.equal(failedLogin.status, 401);
    }
    const throttledLogin = await jsonRequest('/api/auth/login', { identifier: 'no-such-user', password: 'bad-password' });
    assert.equal(throttledLogin.status, 429, 'Login endpoint must enforce rate limits');

    const malformed = await request('/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{broken json'
    });
    assert.equal(malformed.status, 400);
    assert.equal((await malformed.json()).success, false);

    const missingApi = await request('/api/does-not-exist');
    assert.equal(missingApi.status, 404);
    assert.equal((await missingApi.json()).success, false);

    const missingAsset = await request('/css/missing-file.css');
    assert.equal(missingAsset.status, 404, 'Missing assets must not return the SPA HTML shell');
    await missingAsset.text();

    console.log('  ✔ Frontend static assets and health endpoint verified');
    console.log('  ✔ Language, authentication, profile, and admin API contracts verified');
    console.log('  ✔ Role-based access control verified over HTTP');
    console.log('  ✔ Analysis → history → reopen/detail flow verified');
    console.log('  ✔ ZIP upload → multi-file analysis → aggregate report verified');
    console.log('  ✔ Authenticated CSV and Markdown exports verified');
    console.log('  ✔ Malformed JSON and unknown route handling verified');
    console.log('\nALL HTTP INTEGRATION TESTS PASSED.\n');
  } finally {
    // Remove only the temporary account created by this test suite.
    if (adminToken && testUserId) {
      try {
        await request(`/api/admin/users/${encodeURIComponent(testUserId)}`, {
          method: 'DELETE',
          headers: { Authorization: `Bearer ${adminToken}` }
        });
      } catch (_) {}
    }
    const closePromise = new Promise(resolve => server.close(resolve));
    if (typeof server.closeAllConnections === 'function') server.closeAllConnections();
    await closePromise;
  }
}

main().catch(error => {
  console.error('\nHTTP INTEGRATION TEST FAILED:', error.stack || error.message);
  process.exitCode = 1;
  server.close();
  if (typeof server.closeAllConnections === 'function') server.closeAllConnections();
});
