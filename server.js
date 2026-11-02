/**
 * CodeInsight – Multi-Language Static Code Analysis System
 * Node.js & Express.js Backend Server
 * 
 * Supports:
 * - Multi-Language Static Code & Security Analysis (JS, Python, TS, HTML, CSS, Java, C/C++)
 * - User Authentication (Login, Register, Forgot Password, Logout) & RBAC (Admin / User)
 * - User Profile & Persisted Preferences Management
 * - Code Analyzer, Security Scanner & Remediation
 * - Admin Console API (User management, activity logs, reports, system settings)
 */

const express = require('express');
const path = require('path');
const crypto = require('crypto');
const MultiLanguageAnalyzer = require('./analyzer');
const auth = require('./auth');
const { extractSafeZipContents, ZipSecurityError } = require('./zipSecurity');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
// Frontend and API are served from the same origin; permissive CORS is unnecessary.
// Base64 expands ZIP files. A hard 70 MB request cap supports the admin-configurable
// 1–50 MB archive limit while preventing unbounded JSON payloads.
app.use(express.json({ limit: '70mb' }));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));

// Wait for the initial database sync before serving APIs or the application shell.
app.use(async (req, res, next) => {
  try {
    await auth.mongoReady;
    next();
  } catch (error) {
    next(error);
  }
});

// Static client assets
app.use(express.static(path.join(__dirname, 'public')));

// Lightweight in-memory rate limiter for sensitive endpoints.
function createRateLimiter({ windowMs, max }) {
  const buckets = new Map();
  return (req, res, next) => {
    const key = req.ip || req.socket.remoteAddress || 'unknown';
    const now = Date.now();
    let bucket = buckets.get(key);
    if (!bucket || now >= bucket.resetAt) {
      bucket = { count: 0, resetAt: now + windowMs };
      buckets.set(key, bucket);
    }
    bucket.count += 1;
    if (bucket.count > max) {
      const retryAfter = Math.max(1, Math.ceil((bucket.resetAt - now) / 1000));
      res.set('Retry-After', String(retryAfter));
      return res.status(429).json({ success: false, message: `Too many login attempts. Please wait ${Math.ceil((bucket.resetAt - now) / 60000)} minute(s) before trying again.`, retryAfterSeconds: retryAfter });
    }
    // Opportunistically clear expired entries to prevent the map growing forever.
    if (buckets.size > 5000) {
      for (const [ip, value] of buckets.entries()) if (now >= value.resetAt) buckets.delete(ip);
    }
    next();
  };
}

// Allow reasonable local testing while retaining a limit against repeated login attempts.
const loginLimiter = createRateLimiter({ windowMs: 15 * 60 * 1000, max: Number(process.env.LOGIN_RATE_LIMIT_MAX) || 20 });
const registerLimiter = createRateLimiter({ windowMs: 60 * 60 * 1000, max: 8 });
const resetLimiter = createRateLimiter({ windowMs: 15 * 60 * 1000, max: 5 });
const analysisLimiter = createRateLimiter({ windowMs: 60 * 1000, max: 40 });
const zipLimiter = createRateLimiter({ windowMs: 60 * 1000, max: 8 });
const aiReviewLimiter = createRateLimiter({ windowMs: 60 * 1000, max: 10 });

// Helper: Extract authenticated user from Authorization header
function getAuthUser(req) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.replace(/^Bearer\s+/i, '');
  return auth.getUserByToken(token);
}

// Authentication Middleware: Enforce Valid User Session
function requireAuth(req, res, next) {
  const user = getAuthUser(req);
  if (!user) {
    return res.status(401).json({ success: false, error: 'Unauthorized', message: 'Authentication required to access this resource.' });
  }
  req.user = user;
  next();
}

// RBAC Middleware: Enforce Admin Role
function requireAdmin(req, res, next) {
  const user = getAuthUser(req);
  if (!user || user.role !== 'admin') {
    return res.status(403).json({ success: false, error: 'Forbidden', message: 'Admin privileges required.' });
  }
  req.user = user;
  next();
}

// Keep API payloads stable and aligned with the fields rendered by the frontend.
function serializeScanRecord(record = {}) {
  const id = record.id || record.scanId || record._id?.toString?.() || '';
  const findings = Array.isArray(record.findings) ? record.findings : [];
  return {
    id,
    scanId: id,
    filename: record.filename || 'code-snippet',
    language: record.language || 'javascript',
    healthScore: record.healthScore ?? record.score ?? 100,
    score: record.score ?? record.healthScore ?? 100,
    grade: record.grade || 'A+',
    issueCount: record.issueCount ?? record.issues ?? findings.length,
    errorsCount: record.errorsCount || 0,
    warningsCount: record.warningsCount || 0,
    qualityCount: record.qualityCount || 0,
    securityCount: record.securityCount || 0,
    summary: record.summary || '',
    findings,
    codeSnippet: record.codeSnippet || record.code || '',
    username: record.username || '',
    timestamp: record.timestamp || record.createdAt || new Date().toISOString()
  };
}

// ============================================================================
// AUTHENTICATION & ACCOUNT REST API
// ============================================================================

app.post('/api/auth/login', loginLimiter, (req, res) => {
  const { identifier, password } = req.body || {};
  if (!identifier || !password) {
    return res.status(400).json({ success: false, message: 'Please provide both username/email and password.' });
  }
  const result = auth.authenticate(identifier, password);
  if (!result.success) {
    return res.status(401).json(result);
  }
  return res.json(result);
});

app.post('/api/auth/register', registerLimiter, (req, res) => {
  const { username, email, password, name } = req.body || {};
  const result = auth.register(username, email, password, name);
  if (!result.success) {
    return res.status(400).json(result);
  }
  return res.status(201).json(result);
});

app.post('/api/auth/forgot-password', resetLimiter, (req, res) => {
  const { email } = req.body || {};
  if (!email || typeof email !== 'string' || email.length > 254) {
    return res.status(400).json({ success: false, message: 'Please provide a valid account email address.' });
  }

  // Until an email transport is configured, production fails closed instead of
  // generating an inaccessible token or exposing it to the browser.
  if (process.env.NODE_ENV === 'production') {
    return res.status(503).json({
      success: false,
      message: 'Password recovery email is not configured. Please contact the system administrator.'
    });
  }

  const result = auth.createPasswordResetToken(email);
  if (result.resetToken) {
    console.info(`[CodeInsight DEV ONLY] Password reset token for ${email.trim().toLowerCase()}: ${result.resetToken} (expires in 15 minutes)`);
  }
  // Do not reveal whether the email belongs to an account; never return the token.
  return res.json({
    success: true,
    message: 'If an active account matches that email, a reset token has been generated. For this local demo, check the backend terminal. The token is valid for 15 minutes.'
  });
});

app.post('/api/auth/reset-password', resetLimiter, (req, res) => {
  const { token, newPassword } = req.body || {};
  if (!token || !newPassword) {
    return res.status(400).json({ success: false, message: 'Both reset token and new password are required.' });
  }
  const result = auth.resetPassword(token, newPassword);
  if (!result.success) {
    return res.status(400).json(result);
  }
  return res.json(result);
});

app.get('/api/auth/me', (req, res) => {
  const user = getAuthUser(req);
  if (!user) {
    return res.json({ success: false, authenticated: false, user: null });
  }
  return res.json({ success: true, authenticated: true, user });
});

app.post('/api/auth/logout', (req, res) => {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.replace(/^Bearer\s+/i, '');
  auth.logout(token);
  return res.json({ success: true, message: 'Signed out successfully.' });
});

// ============================================================================
// USER PROFILE & PREFERENCES REST API (AUTH PROTECTED)
// ============================================================================

app.get('/api/user/profile', requireAuth, (req, res) => {
  return res.json({ success: true, user: req.user });
});

app.put('/api/user/profile', requireAuth, (req, res) => {
  const { name, bio, avatar, email } = req.body || {};
  const result = auth.updateProfile(req.user.id, { name, bio, avatar, email });
  if (!result.success) return res.status(400).json(result);
  return res.json(result);
});

app.put('/api/user/settings', requireAuth, (req, res) => {
  const result = auth.updateUserSettings(req.user.id, req.body || {});
  if (!result.success) return res.status(400).json(result);
  return res.json(result);
});

app.post('/api/user/change-password', requireAuth, (req, res) => {
  const { currentPassword, newPassword } = req.body || {};
  if (!currentPassword || !newPassword) {
    return res.status(400).json({ success: false, message: 'Current password and new password are required.' });
  }
  const result = auth.changePassword(req.user.id, currentPassword, newPassword);
  if (!result.success) return res.status(400).json(result);
  return res.json(result);
});

// User Scan History & Reopening Detail
app.get('/api/user/history', requireAuth, (req, res) => {
  const history = auth.getUserScanHistory(req.user.username).map(serializeScanRecord);
  return res.json({ success: true, history });
});

app.get('/api/user/history/:id', requireAuth, (req, res) => {
  const record = auth.getScanRecord(req.user.username, req.params.id);
  if (!record) {
    return res.status(404).json({ success: false, message: 'Analysis record not found.' });
  }
  const scan = serializeScanRecord(record);
  return res.json({ success: true, scan, record: scan });
});

app.delete('/api/user/history', requireAuth, async (req, res) => {
  await auth.clearUserScanHistory(req.user.username);
  return res.json({ success: true, message: 'Scan history cleared.' });
});

// ============================================================================
// ADMIN CONSOLE REST API (RBAC PROTECTED)
// ============================================================================

app.get('/api/admin/metrics', requireAdmin, (req, res) => {
  const metrics = auth.getSystemMetrics();
  return res.json({
    success: true,
    metrics: {
      ...metrics,
      avgScore: metrics.averageHealthScore,
      supportedLanguages: MultiLanguageAnalyzer.getSupportedLanguages().length
    }
  });
});

app.get('/api/admin/users', requireAdmin, (req, res) => {
  return res.json({ success: true, users: auth.getAllUsers() });
});

app.patch('/api/admin/users/:id/role', requireAdmin, (req, res) => {
  try {
    const { role } = req.body || {};
    const result = auth.updateUserRole(req.params.id, role);
    if (!result.success) return res.status(400).json(result);
    return res.json(result);
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Failed to update user role.' });
  }
});

app.patch('/api/admin/users/:id/status', requireAdmin, (req, res) => {
  try {
    if (req.user && req.user.id === req.params.id) {
      return res.status(400).json({ success: false, message: 'Cannot suspend your own active administrator account.' });
    }
    const result = auth.toggleUserStatus(req.params.id);
    if (!result.success) return res.status(400).json(result);
    return res.json(result);
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Failed to toggle user status.' });
  }
});

app.delete('/api/admin/users/:id', requireAdmin, (req, res) => {
  try {
    if (req.user && req.user.id === req.params.id) {
      return res.status(400).json({ success: false, message: 'Cannot delete your own active administrator account.' });
    }
    const result = auth.deleteUser(req.params.id);
    if (!result.success) return res.status(400).json(result);
    return res.json(result);
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Failed to delete user.' });
  }
});

app.get('/api/admin/audit-logs', requireAdmin, (req, res) => {
  return res.json({ success: true, logs: auth.getAuditLogs() });
});

app.get('/api/admin/logs', requireAdmin, (req, res) => {
  const logs = auth.getAllAnalysisLogs(req.query).map(serializeScanRecord);
  return res.json({ success: true, logs });
});

app.get('/api/admin/reports', requireAdmin, (req, res) => {
  const allLogs = auth.getAllAnalysisLogs({ limit: 1000 });
  const scansByLanguage = {};
  const vulnerabilitiesByCategory = {};
  let totalIssuesFound = 0;
  let criticalSecurityCount = 0;

  for (const log of allLogs) {
    const language = log.language || 'unknown';
    scansByLanguage[language] = (scansByLanguage[language] || 0) + 1;
    totalIssuesFound += (log.issueCount || log.issues || log.findings?.length || 0);
    for (const finding of (Array.isArray(log.findings) ? log.findings : [])) {
      const category = finding.category || 'Security';
      if (finding.isSecurity || finding.type === 'security' || /security|vulnerab|safety/i.test(category)) {
        vulnerabilitiesByCategory[category] = (vulnerabilitiesByCategory[category] || 0) + 1;
        if (finding.severity === 'critical' || finding.severity === 'high') criticalSecurityCount++;
      }
    }
  }

  const metrics = auth.getSystemMetrics();
  return res.json({
    success: true,
    report: {
      metrics: { ...metrics, avgScore: metrics.averageHealthScore },
      scansByLanguage,
      vulnerabilitiesByCategory,
      totalIssuesFound,
      criticalSecurityCount,
      totalScansRecorded: allLogs.length,
      recentScans: allLogs.slice(0, 15).map(serializeScanRecord)
    }
  });
});

app.get('/api/admin/settings', requireAdmin, (req, res) => {
  return res.json({ success: true, settings: auth.getSystemSettings() });
});

app.put('/api/admin/settings', requireAdmin, async (req, res) => {
  const result = auth.updateSystemSettings(req.body || {});
  if (result.success && auth.lastSettingsSync) await auth.lastSettingsSync;
  return res.status(result.success ? 200 : 400).json(result);
});

// ============================================================================
// MULTI-LANGUAGE CODE ANALYSIS API
// ============================================================================

app.get('/api/languages', (req, res) => {
  return res.json({ success: true, languages: MultiLanguageAnalyzer.getSupportedLanguages() });
});

app.post(['/api/analyze', '/api/analyze/javascript'], analysisLimiter, async (req, res) => {
  try {
    const { code, language, filename, aiAutoRepair } = req.body || {};

    if (code !== undefined && typeof code !== 'string') {
      return res.status(400).json({ success: false, message: 'Invalid code payload. String expected.' });
    }

    const maxSnippetKb = Math.max(1, Number(auth.getSystemSettings().maxSnippetSizeKb) || 500);
    if (typeof code === 'string' && Buffer.byteLength(code, 'utf8') > maxSnippetKb * 1024) {
      return res.status(413).json({ success: false, message: `Code size exceeds the configured maximum of ${maxSnippetKb}KB per snippet.` });
    }

    const requestedLanguage = (typeof language === 'string' ? language.toLowerCase().trim() : '') || 'javascript';
    const languageAliases = { js: 'javascript', py: 'python', ts: 'typescript', c: 'c_cpp', cpp: 'c_cpp', 'c++': 'c_cpp' };
    const safeLanguage = languageAliases[requestedLanguage] || requestedLanguage;
    const allowedLanguages = new Set(MultiLanguageAnalyzer.getSupportedLanguages().map(item => item.id));
    if (!allowedLanguages.has(safeLanguage)) {
      return res.status(400).json({
        success: false,
        message: `Unsupported language. Choose one of: ${Array.from(allowedLanguages).join(', ')}.`
      });
    }
    const rawFilename = typeof filename === 'string' ? filename : '';
    const safeFilename = path.basename(rawFilename.replace(/[\x00-\x1f]/g, '')).slice(0, 120) || (safeLanguage + '_snippet');

    const user = getAuthUser(req);
    const username = user ? user.username : 'anonymous';
    auth.incrementScanCount(username);

    const report = MultiLanguageAnalyzer.generateReport(code, safeLanguage);
    report.hasAiConfigured = Boolean(process.env.GROQ_API_KEY || process.env.GEMINI_API_KEY);
    report.aiProvider = process.env.GROQ_API_KEY ? 'Groq' : (process.env.GEMINI_API_KEY ? 'Gemini' : null);

    // If AI is configured, execute real AI review and merge findings for 100% accurate analysis
    if (report.hasAiConfigured) {
      try {
        const aiResult = await executeAiReview(code, safeLanguage, report);
        if (aiResult && aiResult.success) {
          // Merge AI findings with local findings (deduplicating by line and similar title)
          const existingMap = new Map();
          for (const f of report.findings) {
            existingMap.set(`${f.line || 1}_${(f.title || '').toLowerCase().slice(0, 15)}`, true);
          }

          const freshAiFindings = (aiResult.findings || []).filter(af => {
            const key = `${af.line || 1}_${(af.title || '').toLowerCase().slice(0, 15)}`;
            return !existingMap.has(key);
          });

          if (freshAiFindings.length > 0) {
            report.findings = [...report.findings, ...freshAiFindings];
          }

          // Recalculate health score honestly based on ALL findings
          let score = 100;
          const syntaxCount = report.findings.filter(f => (f.category || '').includes('Syntax') || f.severity === 'critical' || f.type === 'error').length;
          const securityCount = report.findings.filter(f => f.isSecurity || (f.category || '').includes('Security')).length;
          const warningCount = report.findings.filter(f => f.severity === 'high' || f.type === 'warning' || (f.category || '').includes('Pitfall')).length;
          const qualityCount = report.findings.filter(f => f.severity === 'medium' || f.severity === 'low' || f.type === 'quality').length;

          score -= syntaxCount * 30;
          score -= securityCount * 20;
          score -= warningCount * 10;
          score -= qualityCount * 5;
          score = Math.max(0, Math.min(100, score));

          report.score = score;
          report.healthScore = score;
          report.grade = score >= 90 ? 'A+ (Excellent Code)' : score >= 80 ? 'A (Good Quality)' : score >= 70 ? 'B (Satisfactory with Improvements)' : score >= 50 ? 'C (Needs Attention)' : 'F (High Error Density)';
          report.shortGrade = score >= 90 ? 'A+' : score >= 80 ? 'A' : score >= 70 ? 'B' : score >= 50 ? 'C' : 'F';

          if (report.findings.length > 0) {
            report.summary = `CodeInsight examined your ${safeLanguage.toUpperCase()} code and identified ${report.findings.length} issue(s) across syntax, security, and logic. Review the diagnostic explanations below to inspect and apply production-ready repairs.`;
          }

          if (aiResult.correctedCode) {
            report.correctedCode = aiResult.correctedCode;
            report.repairedCode = aiResult.correctedCode;
          }
          report.aiReview = aiResult.review;
          report.mode = 'ai';
          report.provider = aiResult.provider;
        }
      } catch (aiErr) {
        console.warn('AI review error during analyze (fallback to enhanced static rules):', aiErr.message);
      }
    }

    const errorsCount = (report.findings || []).filter(f => f.type === 'error' || f.severity === 'critical' || (f.category && f.category.includes('Syntax'))).length;
    const warningsCount = (report.findings || []).filter(f => f.type === 'warning' || f.severity === 'high' || f.severity === 'medium').length;
    const securityCount = (report.findings || []).filter(f => f.isSecurity || f.type === 'security' || (f.category && f.category.includes('Security'))).length;
    const qualityCount = (report.findings || []).filter(f => f.type === 'quality' || f.severity === 'low').length;

    report.counts = {
      syntax: errorsCount,
      common: warningsCount,
      security: securityCount,
      quality: qualityCount,
      total: (report.findings || []).length
    };

    // Save structured analysis record
    const scanRecord = {
      id: 'scn_' + Date.now() + '_' + crypto.randomBytes(3).toString('hex'),
      filename: safeFilename,
      language: safeLanguage,
      code: (code || '').slice(0, 5000),
      score: report.healthScore,
      grade: report.grade,
      shortGrade: report.shortGrade,
      issueCount: (report.findings || []).length,
      errorsCount,
      warningsCount,
      qualityCount,
      securityCount,
      summary: report.summary,
      findings: report.findings || [],
      timestamp: new Date().toISOString()
    };

    auth.saveScanHistory(username, scanRecord);
    report.scanRecord = scanRecord;

    return res.json(report);
  } catch (err) {
    return res.status(500).json({
      success: false,
      message: 'Failed to complete code analysis. Please verify your source code.'
    });
  }
});


// ============================================================================
// ============================================================================
// AI-POWERED REVIEW & CORRECTION (GROQ / GEMINI + INTELLIGENT FALLBACK)
// The API key stays on the server and is never sent to the browser.
// ============================================================================

async function executeAiReview(code, safeLanguage, report) {
  const localFindings = (report.findings || []).map(f => ({
    ruleId: f.ruleId || 'STATIC',
    title: f.title || f.ruleName || 'Code issue',
    severity: f.severity || f.type || 'info',
    line: f.line || 1,
    explanation: f.explanation || f.description || '',
    suggestedFix: f.suggestedFix || null
  }));

  const groqApiKey = process.env.GROQ_API_KEY;
  const geminiApiKey = process.env.GEMINI_API_KEY;

  if (!groqApiKey && !geminiApiKey) {
    const fixable = localFindings.filter(f => f.suggestedFix);
    const review = localFindings.length
      ? `Rule-based review & automated repair completed: ${localFindings.length} issue(s) detected and repaired. Review the corrected code before applying.`
      : 'Rule-based review completed: no issues were detected by the current static rules.';
    return {
      success: true,
      mode: 'rule-based',
      provider: null,
      language: safeLanguage,
      review,
      findings: localFindings.map(f => ({
        title: f.title,
        severity: f.severity,
        line: f.line,
        explanation: f.explanation,
        recommendation: f.suggestedFix?.explanation || 'Review this code manually; no automatic fix is available.'
      })),
      correctedCode: report.repairedCode || code,
      repairedCode: report.repairedCode || code,
      staticScore: report.score,
      expectedRepairedScore: report.expectedRepairedScore || 100,
      staticFindings: localFindings,
      fixableCount: fixable.length,
      setupHint: 'To enable real AI review, add GROQ_API_KEY or GEMINI_API_KEY to your local .env file and restart the server.'
    };
  }

  const prompt = `You are an elite code review and automated code repair engine. Review the following ${safeLanguage} source code and provide a complete, fixed, working version.

REQUIREMENTS:
1. Identify all syntax errors, security vulnerabilities, anti-patterns, and bugs.
2. YOU MUST ALWAYS PROVIDE "correctedCode" as a string containing the COMPLETE, FULLY CORRECTED, WORKING, PRODUCTION-READY version of the entire source code with all bugs and vulnerabilities repaired. Do not omit unrelated code.
3. Return ONLY a valid JSON object with keys:
   - "summary": A clear explanation of what was wrong and how it was fixed (string).
   - "findings": Array of finding objects. Each item must be an object with {"title": string, "severity": "critical"|"high"|"medium"|"low", "line": number, "explanation": string, "recommendation": string}.
   - "correctedCode": The full repaired working source code (string). NEVER null.

SOURCE CODE:
${code}`;

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 20000);
  let aiResponse = '';
  let providerName = 'AI';

  try {
    if (groqApiKey) {
      providerName = 'Groq';
      const model = process.env.GROQ_MODEL || 'qwen/qwen3.8-27b';
      const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${groqApiKey}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          model,
          messages: [
            { role: 'system', content: 'You are an elite code review and automated code repair engine. You always output valid JSON.' },
            { role: 'user', content: prompt }
          ],
          response_format: { type: 'json_object' },
          temperature: 0.1
        }),
        signal: controller.signal
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) {
        const providerMessage = payload?.error?.message || `Groq returned HTTP ${response.status}`;
        throw new Error(`AI review could not be completed: ${providerMessage}.`);
      }
      aiResponse = payload?.choices?.[0]?.message?.content || '';
    } else {
      providerName = 'Gemini';
      const model = process.env.GEMINI_MODEL || 'gemini-2.5-flash';
      const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent?key=${encodeURIComponent(geminiApiKey)}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        signal: controller.signal,
        body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }], generationConfig: { responseMimeType: 'application/json', temperature: 0.1 } })
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) {
        const providerMessage = payload?.error?.message || `Gemini returned HTTP ${response.status}`;
        throw new Error(`AI review could not be completed: ${providerMessage}.`);
      }
      aiResponse = payload?.candidates?.[0]?.content?.parts?.map(p => p.text || '').join('\n') || '';
    }
  } finally {
    clearTimeout(timeout);
  }

  let parsed = {};
  try {
    let cleaned = aiResponse
      .replace(/<think>[\s\S]*?<\/think>/gi, '')
      .replace(/^```(?:json)?\s*/i, '')
      .replace(/\s*```$/i, '')
      .trim();
    const firstBrace = cleaned.indexOf('{');
    const lastBrace = cleaned.lastIndexOf('}');
    if (firstBrace !== -1 && lastBrace > firstBrace) {
      cleaned = cleaned.slice(firstBrace, lastBrace + 1);
    }
    parsed = JSON.parse(cleaned);
  } catch {
    parsed = {
      summary: 'AI review completed. Note: response format was sanitized.',
      findings: localFindings,
      correctedCode: report.repairedCode
    };
  }

  const correctedCode = (typeof parsed.correctedCode === 'string' && parsed.correctedCode.trim())
    ? parsed.correctedCode
    : (report.repairedCode || code);

  let formattedFindings = localFindings;
  if (Array.isArray(parsed.findings) && parsed.findings.length > 0) {
    const linesArr = code.split('\n');
    formattedFindings = parsed.findings.slice(0, 100).map((f, i) => {
      const rawTitle = typeof f === 'string' ? f.replace(/^\d+[\.\)]\s*/, '').trim() : String(f.title || f.ruleName || f.issue || 'AI Review Finding').slice(0, 240);
      const rawExplanation = typeof f === 'string' ? f : String(f.explanation || f.description || f.message || '').slice(0, 3000);
      const rawSeverity = String(f.severity || '').toLowerCase();
      const isSec = Boolean(rawSeverity.includes('sec') || /vulnerab|inject|cwe|exploit|auth|token|crypto|leak|overflow/i.test(rawTitle + ' ' + rawExplanation));
      const normSeverity = rawSeverity.includes('crit') ? 'critical' : (rawSeverity.includes('high') ? 'high' : (rawSeverity.includes('med') ? 'medium' : 'low'));
      const fType = (normSeverity === 'critical' || /syntax/i.test(rawTitle)) ? 'error' : (isSec ? 'security' : (normSeverity === 'high' || normSeverity === 'medium' ? 'warning' : 'quality'));
      const targetLine = Math.max(1, Number(f.line) || 1);
      const codeSnippet = linesArr[targetLine - 1] ? linesArr[targetLine - 1].trim() : code.slice(0, 60);

      return {
        ruleId: `AI-${i + 1}`,
        ruleName: rawTitle.slice(0, 100),
        title: rawTitle,
        severity: normSeverity,
        type: fType,
        isSecurity: isSec,
        category: isSec ? 'Security & Safety' : (/syntax/i.test(rawTitle) ? 'Syntax Error' : 'AI Identified Logic / Quality Issue'),
        line: targetLine,
        matchedCode: codeSnippet,
        evidence: codeSnippet,
        description: rawExplanation || rawTitle,
        explanation: rawExplanation || rawTitle,
        aiExplanation: rawExplanation || rawTitle,
        recommendation: String(f.recommendation || f.fix || 'Refactored in production-ready repaired code.').slice(0, 3000),
        suggestedFix: {
          before: codeSnippet,
          after: 'See complete corrected code in Fixed Code tab.',
          explanation: String(f.recommendation || rawExplanation || 'Apply AI suggested correction.')
        }
      };
    });
  }

  return {
    success: true,
    mode: 'ai',
    provider: providerName,
    language: safeLanguage,
    review: String(parsed.summary || 'AI review and automated code repair completed.'),
    findings: formattedFindings,
    correctedCode,
    repairedCode: correctedCode,
    staticScore: report.score,
    expectedRepairedScore: report.expectedRepairedScore || 100,
    staticFindings: localFindings
  };
}

app.post('/api/ai/review', aiReviewLimiter, async (req, res) => {
  try {
    const { code, language } = req.body || {};
    if (typeof code !== 'string' || !code.trim()) {
      return res.status(400).json({ success: false, message: 'Please provide source code to review.' });
    }
    const maxBytes = Math.max(1, Number(auth.getSystemSettings().maxSnippetSizeKb) || 500) * 1024;
    if (Buffer.byteLength(code, 'utf8') > maxBytes) {
      return res.status(413).json({ success: false, message: 'Code is larger than the configured snippet limit.' });
    }
    const requestedLanguage = (typeof language === 'string' ? language.toLowerCase().trim() : 'javascript') || 'javascript';
    const aliases = { js: 'javascript', py: 'python', ts: 'typescript', c: 'c_cpp', cpp: 'c_cpp', 'c++': 'c_cpp' };
    const safeLanguage = aliases[requestedLanguage] || requestedLanguage;
    const supported = new Set(MultiLanguageAnalyzer.getSupportedLanguages().map(item => item.id));
    if (!supported.has(safeLanguage)) return res.status(400).json({ success: false, message: 'Unsupported programming language.' });

    const report = MultiLanguageAnalyzer.generateReport(code, safeLanguage);
    const result = await executeAiReview(code, safeLanguage, report);
    return res.json(result);
  } catch (error) {
    if (error.name === 'AbortError') return res.status(504).json({ success: false, message: 'AI review timed out. Try a smaller snippet or retry.' });
    console.error('AI review failed:', error.message);
    return res.status(500).json({ success: false, message: error.message || 'AI review failed unexpectedly. You can still use Analyze Code for local static analysis.' });
  }
});

// ============================================================================
// PROJECT / ZIP ARCHIVE SAFE INGESTION & SCAN API
// ============================================================================

app.post('/api/analyze/zip', zipLimiter, (req, res) => {
  try {
    const { zipBase64, filename } = req.body || {};
    if (!zipBase64 || typeof zipBase64 !== 'string') {
      return res.status(400).json({
        success: false,
        error: 'INVALID_INPUT',
        message: 'Missing or invalid zipBase64 archive payload.'
      });
    }

    const maxZipMb = Math.max(1, Math.min(50, Number(auth.getSystemSettings().maxZipArchiveMb) || 15));
    const maxZipBytes = maxZipMb * 1024 * 1024;
    if (zipBase64.length > Math.ceil(maxZipBytes * 4 / 3) + 8 || !/^[A-Za-z0-9+/]+={0,2}$/.test(zipBase64)) {
      return res.status(413).json({
        success: false,
        error: 'OVERSIZED_OR_INVALID_ARCHIVE',
        message: `ZIP archive payload is invalid or exceeds the ${maxZipMb}MB decoded archive limit.`
      });
    }

    const buffer = Buffer.from(zipBase64, 'base64');
    if (!buffer.length || buffer.toString('base64').replace(/=+$/, '') !== zipBase64.replace(/=+$/, '')) {
      return res.status(400).json({ success: false, error: 'INVALID_ARCHIVE', message: 'ZIP payload is not valid Base64.' });
    }
    const safeFiles = extractSafeZipContents(buffer, { maxZipBytes });

    if (safeFiles.length === 0) {
      return res.status(400).json({
        success: false,
        error: 'NO_SOURCE_FILES',
        message: 'No supported source files found. Supported extensions include .js, .ts, .py, .html, .css, .java, .c, .h, .cpp and .hpp.'
      });
    }

    const user = getAuthUser(req);
    const username = user ? user.username : 'anonymous';
    auth.incrementScanCount(username);

    const results = safeFiles.map(file => {
      const report = MultiLanguageAnalyzer.generateReport(file.content, file.language);
      return {
        name: file.name,
        language: file.language,
        size: file.size,
        content: file.content,
        report
      };
    });

    const safeArchiveName = path.basename((filename || 'project.zip').replace(/[\x00-\x1f\\/]/g, '')).slice(0, 100);
    const allFindings = results.flatMap(file => (file.report.findings || []).map(finding => ({
      ...finding,
      fileName: file.name,
      fileLanguage: file.language
    })));
    const avgScore = Math.round(results.reduce((sum, file) => sum + (file.report.healthScore ?? 100), 0) / results.length);
    const counts = {
      syntax: allFindings.filter(f => (f.category || '').includes('Syntax')).length,
      security: allFindings.filter(f => f.isSecurity || f.type === 'security').length,
      quality: allFindings.filter(f => f.type === 'quality').length,
      common: allFindings.filter(f => f.type === 'warning').length,
      total: allFindings.length
    };
    const grade = avgScore >= 90 ? 'A+ (Excellent Code)' : avgScore >= 80 ? 'A (Good Quality)' :
      avgScore >= 70 ? 'B (Satisfactory with Improvements)' : avgScore >= 50 ? 'C (Needs Attention)' : 'F (High Error Density)';
    const shortGrade = avgScore >= 90 ? 'A+' : avgScore >= 80 ? 'A' : avgScore >= 70 ? 'B' : avgScore >= 50 ? 'C' : 'F';
    const summary = `Project scan completed: ${results.length} source file(s) analyzed and ${allFindings.length} finding(s) identified. Average code health score: ${avgScore}/100.`;

    // Save a complete summary record in the authenticated user's history.
    if (user) {
      auth.saveScanHistory(username, {
        id: 'scn_zip_' + Date.now() + '_' + crypto.randomBytes(3).toString('hex'),
        filename: safeArchiveName + ` (${results.length} files)`,
        language: 'project',
        code: `Project archive ${safeArchiveName} containing ${results.length} source files.`,
        score: avgScore,
        grade,
        shortGrade,
        issueCount: allFindings.length,
        errorsCount: allFindings.filter(f => f.type === 'error').length,
        warningsCount: allFindings.filter(f => f.type === 'warning').length,
        qualityCount: allFindings.filter(f => f.type === 'quality').length,
        securityCount: allFindings.filter(f => f.isSecurity || f.type === 'security').length,
        summary,
        findings: allFindings,
        timestamp: new Date().toISOString()
      });
    }

    return res.json({
      success: true,
      kind: 'project',
      filename: safeArchiveName,
      language: 'project',
      fileCount: results.length,
      score: avgScore,
      healthScore: avgScore,
      grade,
      shortGrade,
      summary,
      counts,
      findings: allFindings,
      code: results[0]?.content || '',
      files: results
    });
  } catch (err) {
    if (err instanceof ZipSecurityError || err.name === 'ZipSecurityError') {
      return res.status(400).json({
        success: false,
        error: err.code || 'ZIP_SECURITY_ERROR',
        message: err.message
      });
    }
    return res.status(500).json({
      success: false,
      error: 'PROCESSING_ERROR',
      message: 'An error occurred while processing the archive safely.'
    });
  }
});

// ============================================================================
// REPORT EXPORT API (MARKDOWN & CSV EXPORT)
// ============================================================================

app.post('/api/export/report', (req, res) => {
  try {
    const user = getAuthUser(req);
    const { code, language, report, studentName } = req.body || {};

    const cleanLang = (typeof language === 'string' ? language.toLowerCase().trim() : '');
    const validLangs = new Set(['javascript', 'python', 'typescript', 'html', 'css', 'java', 'c_cpp', 'c', 'cpp']);
    const safeLang = validLangs.has(cleanLang) ? cleanLang : 'javascript';

    const authorName = user ? user.name : (typeof studentName === 'string' ? studentName.replace(/[\r\n\x00-\x1f]/g, '').slice(0, 100).trim() : 'CodeInsight User');
    const date = new Date().toLocaleString();

    let md = `# CodeInsight Analysis & Quality Audit Report\n\n`;
    md += `**Author / User:** ${authorName}\n`;
    md += `**Date:** ${date}\n`;
    md += `**Language Analyzed:** ${safeLang.toUpperCase()}\n`;
    md += `**Health Score:** ${report?.healthScore || 100}/100 (${report?.grade || 'A+'})\n\n`;
    md += `---\n\n`;
    md += `## 1. Executive Summary\n\n${report?.summary || report?.aiSummary || 'Code passed inspection with zero issues.'}\n\n`;
    md += `## 2. Issues & Diagnostic Recommendations (${report?.findings?.length || 0} findings)\n\n`;

    if (report?.findings && report.findings.length > 0) {
      report.findings.forEach((f, idx) => {
        md += `### Finding ${idx + 1}: ${f.title} (Line ${f.line})\n`;
        md += `- **Severity:** ${(f.severity || 'low').toUpperCase()} | **Category:** ${f.category || 'General'}\n`;
        md += `- **Diagnostic Explanation:** ${f.explanation || f.aiExplanation || f.description || ''}\n`;
        md += `- **Learning Concept:** ${f.learningConcept || 'Clean Code'}\n`;
        if (f.suggestedFix) {
          md += `- **Suggested Patch:**\n\`\`\`javascript\n${f.suggestedFix.after}\n\`\`\`\n\n`;
        }
      });
    } else {
      md += `No issues detected. Code adheres to clean modern coding standards.\n\n`;
    }

    const safeCode = typeof code === 'string' ? auth.redactSecrets(code.slice(0, 50000)) : '';
    md += `## 3. Original Source Code\n\n\`\`\`${safeLang}\n${safeCode}\n\`\`\`\n\n`;

    const repaired = report?.correctedCode || report?.repairedCode;
    if (repaired && typeof repaired === 'string' && repaired !== code) {
      const safeRepaired = auth.redactSecrets(repaired.slice(0, 50000));
      md += `## 4. Repaired & Production-Ready Code\n\n\`\`\`${safeLang}\n${safeRepaired}\n\`\`\`\n\n`;
    }

    md += `---\n*Generated automatically by CodeInsight – Multi-Language Static Code Analysis System*\n`;

    const safeFilename = `CodeInsight-Report-${safeLang.replace(/[^a-zA-Z0-9]/g, '_')}.md`;
    res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${safeFilename}"`);
    return res.send(md);
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Failed to generate export report.' });
  }
});

// CSV Export (User's own history, or all system logs if admin)
app.get('/api/export/csv', (req, res) => {
  try {
    const user = getAuthUser(req);
    if (!user) {
      return res.status(401).json({ success: false, message: 'Authentication required to export CSV records.' });
    }

    let records = [];
    if (user.role === 'admin') {
      records = auth.getAllAnalysisLogs({ limit: 500 });
    } else {
      records = auth.getUserScanHistory(user.username);
    }

    // Helper to sanitize CSV field against formula injection (=, +, -, @)
    const sanitizeCsvField = (val) => {
      let str = String(val ?? '').replace(/"/g, '""');
      if (/^[=+\-@\t\r]/.test(str)) {
        str = "'" + str;
      }
      return `"${str}"`;
    };

    const headers = ['ID', 'Date/Time', 'Username', 'Filename', 'Language', 'HealthScore', 'Grade', 'TotalIssues', 'Errors', 'Warnings', 'SecurityFindings'];
    const rows = records.map(r => [
      sanitizeCsvField(r.id),
      sanitizeCsvField(r.timestamp),
      sanitizeCsvField(r.username || user.username),
      sanitizeCsvField(r.filename),
      sanitizeCsvField(r.language),
      sanitizeCsvField(r.score),
      sanitizeCsvField(r.grade),
      sanitizeCsvField(r.issueCount || r.issues || 0),
      sanitizeCsvField(r.errorsCount || 0),
      sanitizeCsvField(r.warningsCount || 0),
      sanitizeCsvField(r.securityCount || 0)
    ].join(','));

    const csvContent = [headers.join(','), ...rows].join('\n');
    const filename = `CodeInsight-Analysis-Export-${Date.now()}.csv`;

    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    return res.send(csvContent);
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Failed to export CSV records.' });
  }
});

// ============================================================================
// SYSTEM SPECIFICATION METADATA
// ============================================================================

app.get('/api/synopsis', (req, res) => {
  res.json({
    title: 'CodeInsight – Multi-Language Static Code Analysis System',
    description: 'CodeInsight is a comprehensive, multi-language static code analysis and diagnostic platform.',
    architecture: {
      frontend: 'Responsive Single-Page Web App (Pure HTML, CSS, JavaScript)',
      backend: 'Node.js, Express.js REST API with RBAC & Hybrid DB Persistence',
      database: 'MongoDB (Mongoose ODM) with offline data.json hybrid fallback'
    },
    supportedLanguages: MultiLanguageAnalyzer.getSupportedLanguages()
  });
});

app.get('/api/database', (req, res) => {
  res.json(auth.getDatabaseStatus());
});

app.get('/api/config', (req, res) => {
  const settings = auth.getSystemSettings();
  return res.json({
    success: true,
    platformName: settings.platformName,
    defaultLanguage: settings.defaultLanguage
  });
});

app.get('/api/health', (req, res) => {
  res.json({
    status: 'online',
    system: 'CodeInsight – Multi-Language Static Code Analysis System',
    version: '2.0.0',
    backend: 'Node.js & Express.js',
    database: auth.getDatabaseStatus(),
    authEnabled: true,
    multiLanguageSupport: true
  });
});

// Normalize malformed JSON, oversized requests, and unexpected backend errors as JSON.
app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  const status = Number(err.status || err.statusCode) || 500;
  if (status === 413) {
    return res.status(413).json({ success: false, message: 'Request payload is too large.' });
  }
  if (status === 400 && (err.type === 'entity.parse.failed' || err instanceof SyntaxError)) {
    return res.status(400).json({ success: false, message: 'Malformed JSON request body.' });
  }
  console.error('Request processing error:', err.message);
  return res.status(status >= 400 && status < 600 ? status : 500).json({
    success: false,
    message: status < 500 ? 'Request could not be processed.' : 'Internal server error.'
  });
});

// Unknown API routes should return JSON instead of the SPA HTML shell.
app.use('/api', (req, res) => {
  return res.status(404).json({ success: false, message: 'API endpoint not found.' });
});

// The frontend is a single-page application; serve it only for browser GET routes.
app.get(/.*/, (req, res) => {
  if (path.extname(req.path)) {
    return res.status(404).type('text/plain').send('Not found');
  }
  return res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start the HTTP server only when this file is executed directly.
if (require.main === module) {
  auth.mongoReady.then(() => {
    const server = app.listen(PORT, () => {
      console.log('====================================================');
      console.log('CodeInsight – Multi-Language Static Code Analysis System');
      console.log('Node.js & Express.js Server with Multi-Language & Admin RBAC');
      console.log('Database: MongoDB with local JSON fallback');
      console.log('====================================================');
      console.log(`Server is running on: http://localhost:${PORT}`);
    });

    server.on('error', (err) => {
      if (err.code === 'EADDRINUSE') {
        console.error(`Port ${PORT} is already in use. Stop the other server or choose a different PORT in .env.`);
      } else {
        console.error('Server error:', err.message);
      }
    });
  }).catch(error => {
    console.error('Server startup failed:', error.message);
    process.exitCode = 1;
  });
}

module.exports = app;
