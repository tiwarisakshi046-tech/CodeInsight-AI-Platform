/**
 * CodeInsight - User Authentication & Role-Based Access Control (RBAC)
 * Supports Admin & Student accounts, MongoDB Database via Mongoose ODM,
 * audit trails, scan histories, and persistent hybrid storage fallback.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const db = require('./db');

const DATA_FILE = path.join(__dirname, 'data.json');

class AuthService {
  constructor() {
    this.sessions = new Map(); // token -> user
    this.loadState();
    this.ensureDefaultAccounts();
    // Server/API requests wait for initial MongoDB sync to finish.
    this.mongoReady = this.initMongo().catch(error => {
      console.warn('MongoDB initialization notice:', error.message);
      return false;
    });
  }

  async initMongo() {
    const connected = await db.connectDB();
    if (!connected) return;

    try {
      // 1. Sync Users from MongoDB or Seed MongoDB
      const mongoUsers = await db.User.find({}).lean();
      if (mongoUsers && mongoUsers.length > 0) {
        this.users = mongoUsers.map(u => ({
          id: u.id,
          username: u.username,
          name: u.name || u.username,
          email: u.email,
          passwordHash: u.passwordHash,
          resetPasswordToken: u.resetPasswordToken || null,
          resetPasswordExpires: u.resetPasswordExpires || null,
          role: u.role || 'user',
          status: u.status || 'active',
          avatar: u.avatar || '',
          bio: u.bio || 'Developer & CodeInsight user',
          settings: u.settings || {
            theme: 'dark',
            defaultLanguage: 'javascript',
            autoDetect: true,
            tabSize: 4,
            showLineNumbers: true
          },
          createdAt: u.createdAt,
          scanCount: u.scanCount || 0
        }));
        this.ensureDefaultAccounts();
        // Persist any missing demo accounts to MongoDB without resetting existing passwords.
        for (const u of this.users) {
          await db.User.updateOne({ id: u.id }, { $set: u }, { upsert: true });
        }
        this.saveState();
      } else {
        // Seed MongoDB from local data
        for (const u of this.users) {
          await db.User.updateOne({ id: u.id }, { $set: u }, { upsert: true });
        }
      }

      // 2. Sync Audit Logs
      const mongoLogs = await db.AuditLog.find({}).sort({ createdAt: -1 }).limit(100).lean();
      if (mongoLogs && mongoLogs.length > 0) {
        this.auditLogs = mongoLogs;
        this.saveState();
      } else {
        for (const l of this.auditLogs) {
          await db.AuditLog.updateOne({ id: l.id }, { $set: l }, { upsert: true });
        }
      }

      // 3. Sync platform settings (or seed them from the local JSON store).
      const mongoSettings = await db.SystemSetting.findOne({ key: 'platform' }).lean();
      if (mongoSettings && mongoSettings.value) {
        this.systemSettings = { ...this.getSystemSettings(), ...mongoSettings.value };
        this.saveState();
      } else {
        await db.SystemSetting.findOneAndUpdate(
          { key: 'platform' },
          { $set: { key: 'platform', value: this.getSystemSettings(), updatedAt: new Date().toISOString() } },
          { upsert: true, new: true }
        );
      }

      // 4. Sync Scan Histories
      const mongoScans = await db.ScanHistory.find({}).sort({ createdAt: -1 }).limit(100).lean();
      if (mongoScans && mongoScans.length > 0) {
        for (const s of mongoScans) {
          const userKey = String(s.username || '').toLowerCase();
          if (!userKey) continue;
          if (!this.userScanHistories.has(userKey)) this.userScanHistories.set(userKey, []);
          const history = this.userScanHistories.get(userKey);
          const record = {
            id: s.id,
            filename: s.filename || 'code-snippet',
            language: s.language || 'javascript',
            code: s.codeSnippet || '',
            score: s.score ?? 100,
            grade: s.grade || 'A+',
            issueCount: s.issues ?? (Array.isArray(s.findings) ? s.findings.length : 0),
            errorsCount: s.errorsCount || 0,
            warningsCount: s.warningsCount || 0,
            qualityCount: s.qualityCount || 0,
            securityCount: s.securityCount || 0,
            summary: s.summary || '',
            findings: Array.isArray(s.findings) ? s.findings : [],
            timestamp: s.timestamp || s.createdAt || new Date().toISOString()
          };
          const existingIndex = history.findIndex(item => item.id && item.id === record.id);
          if (existingIndex >= 0) history[existingIndex] = record;
          else history.push(record);
        }
        for (const history of this.userScanHistories.values()) {
          history.sort((a, b) => new Date(b.timestamp || 0) - new Date(a.timestamp || 0));
        }
        this.saveState();
      }
    } catch (e) {
      console.warn('MongoDB initial sync notice:', e.message);
    }
  }

  async syncToMongo(type, data) {
    if (!db.isMongoConnected()) return;
    try {
      if (type === 'USER_UPSERT') {
        await db.User.updateOne({ id: data.id }, { $set: data }, { upsert: true });
      } else if (type === 'USER_DELETE') {
        await db.User.deleteOne({ id: data.id });
        await db.ScanHistory.deleteMany({ username: data.username });
      } else if (type === 'AUDIT_LOG') {
        await db.AuditLog.create(data);
      } else if (type === 'SCAN_HISTORY') {
        await db.ScanHistory.create(data);
      } else if (type === 'SCAN_HISTORY_CLEAR') {
        await db.ScanHistory.deleteMany({ username: data.username });
      } else if (type === 'SYSTEM_SETTINGS') {
        await db.SystemSetting.findOneAndUpdate(
          { key: 'platform' },
          { $set: { key: 'platform', value: data, updatedAt: new Date().toISOString() } },
          { upsert: true, new: true }
        );
      }
    } catch (e) {
      console.warn(`MongoDB ${type} sync notice:`, e.message);
      return false;
    }
    return true;
  }

  loadState() {
    try {
      if (fs.existsSync(DATA_FILE)) {
        const raw = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
        this.users = raw.users || [];
        this.auditLogs = raw.auditLogs || [];
        this.userScanHistories = new Map(Object.entries(raw.userScanHistories || {}));
        this.systemSettings = {
          platformName: 'CodeInsight',
          maxSnippetSizeKb: 500,
          maxZipArchiveMb: 15,
          defaultLanguage: 'javascript',
          sessionTimeoutMinutes: 60,
          defaultHealthThreshold: 80,
          maintenanceMode: false,
          allowRegistration: true,
          ...(raw.systemSettings || {})
        };
        return;
      }
    } catch (e) {
      console.warn('Initializing fresh data store:', e.message);
    }

    // Default state: Only 1 Master Admin account (No dummy student/guest accounts)
    this.users = [
      {
        id: 'usr-admin-01',
        username: 'admin',
        name: 'System Administrator',
        email: 'admin@codeinsight.io',
        passwordHash: this.hashPassword('admin123'),
        role: 'admin',
        status: 'active',
        avatar: '',
        bio: 'Lead Security Auditor & Platform Administrator',
        settings: {
          theme: 'dark',
          defaultLanguage: 'javascript',
          autoDetect: true,
          tabSize: 4,
          showLineNumbers: true
        },
        createdAt: new Date().toISOString(),
        scanCount: 0
      }
    ];
    this.auditLogs = [];
    this.userScanHistories = new Map();
    this.systemSettings = {
      platformName: 'CodeInsight',
      maxSnippetSizeKb: 500,
      maxZipArchiveMb: 15,
      defaultLanguage: 'javascript',
      sessionTimeoutMinutes: 60,
      defaultHealthThreshold: 80,
      maintenanceMode: false,
      allowRegistration: true
    };
    this.saveState();
  }

  ensureDefaultAccounts() {
    // Keep the demo credentials shown on the Sign In page in sync with real accounts.
    // Never overwrite an existing account or reset a password that an admin changed.
    if (!Array.isArray(this.users)) this.users = [];
    let changed = false;
    const defaults = [
      {
        id: 'usr-admin-01', username: 'admin', name: 'System Administrator',
        email: 'admin@codeinsight.io', password: 'admin123', role: 'admin',
        bio: 'Lead Security Auditor & Platform Administrator'
      },
      {
        id: 'usr-developer-01', username: 'developer', name: 'Demo Developer',
        email: 'developer@codeinsight.io', password: 'dev123', role: 'user',
        bio: 'Demo developer account'
      }
    ];
    for (const account of defaults) {
      const exists = this.users.some(u =>
        String(u.username || '').toLowerCase() === account.username ||
        String(u.email || '').toLowerCase() === account.email
      );
      if (exists) continue;
      this.users.push({
        id: account.id,
        username: account.username,
        name: account.name,
        email: account.email,
        passwordHash: this.hashPassword(account.password),
        role: account.role,
        status: 'active',
        avatar: '',
        bio: account.bio,
        settings: {
          theme: 'dark', defaultLanguage: 'javascript', autoDetect: true,
          tabSize: 4, showLineNumbers: true
        },
        createdAt: new Date().toISOString(),
        scanCount: 0
      });
      changed = true;
    }
    if (changed) this.saveState();
  }

  saveState() {
    try {
      const historyObj = Object.fromEntries(this.userScanHistories);
      fs.writeFileSync(
        DATA_FILE,
        JSON.stringify({
          users: this.users,
          auditLogs: this.auditLogs,
          userScanHistories: historyObj,
          systemSettings: this.systemSettings
        }, null, 2),
        'utf8'
      );
    } catch (e) {
      console.error('Failed to save state:', e.message);
    }
  }

  hashPassword(password, salt = null) {
    const s = salt || crypto.randomBytes(16).toString('hex');
    const hash = crypto.scryptSync(password, s, 32).toString('hex');
    return `scrypt:${s}:${hash}`;
  }

  verifyPassword(password, storedHash) {
    if (!storedHash || typeof storedHash !== 'string') return false;

    // Check if new salted scrypt format (scrypt:salt:hash)
    if (storedHash.startsWith('scrypt:')) {
      const parts = storedHash.split(':');
      if (parts.length === 3) {
        const [, salt, hash] = parts;
        try {
          const testHash = crypto.scryptSync(password, salt, 32).toString('hex');
          const hashBuf = Buffer.from(hash, 'hex');
          const testBuf = Buffer.from(testHash, 'hex');
          if (hashBuf.length !== testBuf.length) return false;
          return crypto.timingSafeEqual(hashBuf, testBuf);
        } catch (e) {
          return false;
        }
      }
    }

    // Fallback: Check if simple salt:hash format
    if (storedHash.includes(':') && !storedHash.startsWith('scrypt:')) {
      const [salt, hash] = storedHash.split(':');
      try {
        const testHash = crypto.scryptSync(password, salt, 32).toString('hex');
        const hashBuf = Buffer.from(hash, 'hex');
        const testBuf = Buffer.from(testHash, 'hex');
        if (hashBuf.length !== testBuf.length) return false;
        return crypto.timingSafeEqual(hashBuf, testBuf);
      } catch (e) {
        return false;
      }
    }

    // Backward compatibility with legacy SHA-256
    try {
      const legacyHash = crypto.createHash('sha256').update(password).digest('hex');
      const legBuf = Buffer.from(legacyHash, 'hex');
      const storeBuf = Buffer.from(storedHash, 'hex');
      if (legBuf.length !== storeBuf.length) return false;
      return crypto.timingSafeEqual(legBuf, storeBuf);
    } catch (e) {
      return false;
    }
  }

  redactSecrets(str) {
    if (!str || typeof str !== 'string') return '';
    return str
      .replace(/AIza[-A-Za-z0-9_]{20,45}/g, '[REDACTED_API_KEY]')
      .replace(/gh[pousr]_[a-zA-Z0-9]{20,}/g, '[REDACTED_GH_TOKEN]')
      .replace(/\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/g, '[REDACTED_OPENAI_KEY]')
      .replace(/\bgsk_[a-zA-Z0-9_-]{20,}\b/g, '[REDACTED_GROQ_KEY]')
      .replace(/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, '[REDACTED_AWS_KEY]')
      .replace(/(authorization\s*:\s*bearer\s+)[^\s'"]+/gi, '$1[REDACTED_TOKEN]')
      .replace(/((?:api[_-]?key|client[_-]?secret|secret(?:[_-]?key)?|password|passwd|pwd|auth[_-]?token|access[_-]?token|refresh[_-]?token|bearer)\s*[:=]\s*)(?:"[^"]*"|'[^']*'|`[^`]*`|[^\s,;]+)/gi, '$1"[REDACTED_SECRET]"');
  }

  redactSensitiveData(value) {
    if (typeof value === 'string') return this.redactSecrets(value);
    if (Array.isArray(value)) return value.map(item => this.redactSensitiveData(item));
    if (value && typeof value === 'object') {
      return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, this.redactSensitiveData(child)]));
    }
    return value;
  }

  authenticate(identifier, password) {
    const cleanId = (identifier || '').trim().toLowerCase();
    const user = this.users.find(
      u => String(u.username || '').toLowerCase() === cleanId || String(u.email || '').toLowerCase() === cleanId
    );

    // Use one response for unknown users, suspended users, and wrong passwords
    // so the login API does not disclose account existence or status.
    if (!user || user.status !== 'active' || !this.verifyPassword(password, user.passwordHash)) {
      return { success: false, message: 'Invalid username/email or password.' };
    }

    // Auto-upgrade legacy hash to salted scrypt
    if (!user.passwordHash.startsWith('scrypt:')) {
      user.passwordHash = this.hashPassword(password);
      this.saveState();
      this.syncToMongo('USER_UPSERT', user);
    }

    const token = 'ci_sess_' + crypto.randomBytes(24).toString('hex');
    const safeUser = this.sanitizeUser(user);
    this.sessions.set(token, { user: safeUser, createdAt: Date.now(), lastActivityAt: Date.now() });

    this.logAction(user.username, 'USER_LOGIN', `Logged in via web client (${user.role.toUpperCase()})`);
    return { success: true, token, user: safeUser };
  }

  register(username, email, password, name = '') {
    if (this.getSystemSettings().allowRegistration === false) {
      return { success: false, message: 'New account registration is currently disabled by the administrator.' };
    }
    const cleanUser = (username || '').trim().toLowerCase();
    const cleanEmail = (email || '').trim().toLowerCase();

    // Username validation: alphanumeric + underscores/hyphens, 3-30 chars
    if (!cleanUser || !/^[a-zA-Z0-9_-]{3,30}$/.test(cleanUser)) {
      return { success: false, message: 'Username must be between 3 and 30 alphanumeric characters (letters, numbers, _, -).' };
    }

    // Email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!cleanEmail || !emailRegex.test(cleanEmail) || cleanEmail.length > 100) {
      return { success: false, message: 'Please provide a valid email address.' };
    }

    // Password length validation
    if (!password || typeof password !== 'string' || password.length < 6 || password.length > 128) {
      return { success: false, message: 'Password must be between 6 and 128 characters long.' };
    }

    const cleanName = (name || '').replace(/[\x00-\x1f]/g, '').trim().slice(0, 60);

    const exists = this.users.some(u => u.username === cleanUser || u.email === cleanEmail);
    if (exists) {
      return { success: false, message: 'A user with that username or email already exists.' };
    }

    const newUser = {
      id: 'usr-' + crypto.randomBytes(6).toString('hex'),
      username: cleanUser,
      name: cleanName || cleanUser,
      email: cleanEmail,
      passwordHash: this.hashPassword(password),
      role: 'user',
      status: 'active',
      avatar: '',
      bio: 'Developer & CodeInsight user',
      settings: {
        theme: 'dark',
        defaultLanguage: 'javascript',
        autoDetect: true,
        tabSize: 4,
        showLineNumbers: true
      },
      createdAt: new Date().toISOString(),
      scanCount: 0
    };

    this.users.push(newUser);
    const token = 'ci_sess_' + crypto.randomBytes(24).toString('hex');
    const safeUser = this.sanitizeUser(newUser);
    this.sessions.set(token, { user: safeUser, createdAt: Date.now(), lastActivityAt: Date.now() });

    this.logAction(cleanUser, 'USER_REGISTER', 'Created new account');
    this.saveState();
    this.syncToMongo('USER_UPSERT', newUser);
    return { success: true, token, user: safeUser };
  }

  // ==========================================================================
  // PASSWORD RESET WORKFLOW (Single-Use, 15-Min TTL)
  // ==========================================================================

  createPasswordResetToken(email) {
    const cleanEmail = String(email || '').trim().toLowerCase();
    const user = this.users.find(u => String(u.email || '').toLowerCase() === cleanEmail);

    // Keep a generic response for unknown/suspended users at the HTTP layer.
    if (!user || user.status !== 'active') {
      return { success: false, message: 'If an active account matches that email, reset instructions will be available.' };
    }

    const token = crypto.randomBytes(32).toString('hex');
    // Store only a SHA-256 digest; the raw token is never sent back through the API.
    user.resetPasswordToken = crypto.createHash('sha256').update(token).digest('hex');
    user.resetPasswordExpires = Date.now() + 15 * 60 * 1000;

    this.saveState();
    this.syncToMongo('USER_UPSERT', user);
    this.logAction(user.username, 'PASSWORD_RESET_REQUEST', 'Requested password reset token');

    return {
      success: true,
      resetToken: token, // Internal return for local development logging and unit tests only.
      expiresInMinutes: 15,
      message: 'If an active account matches that email, reset instructions will be available.'
    };
  }

  resetPassword(token, newPassword) {
    if (!token || typeof token !== 'string') {
      return { success: false, message: 'A valid password reset token is required.' };
    }
    if (!newPassword || newPassword.length < 6) {
      return { success: false, message: 'New password must be at least 6 characters long.' };
    }

    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const user = this.users.find(u => {
      if (!u.resetPasswordToken) return false;
      // Support previously-issued legacy raw tokens during migration.
      if (u.resetPasswordToken === token) return true;
      return u.resetPasswordToken === tokenHash;
    });
    if (!user) {
      return { success: false, message: 'Invalid or already consumed password reset token.' };
    }

    if (!user.resetPasswordExpires || user.resetPasswordExpires < Date.now()) {
      user.resetPasswordToken = null;
      user.resetPasswordExpires = null;
      this.saveState();
      this.syncToMongo('USER_UPSERT', user);
      return { success: false, message: 'Password reset token has expired (15-minute validity). Please request a new token.' };
    }

    // Invalidate token immediately (single-use guarantee) & update password
    user.passwordHash = this.hashPassword(newPassword);
    user.resetPasswordToken = null;
    user.resetPasswordExpires = null;
    for (const [sessionToken, session] of this.sessions.entries()) {
      const sessionUser = session.user || session;
      if (sessionUser.id === user.id) this.sessions.delete(sessionToken);
    }

    this.saveState();
    this.syncToMongo('USER_UPSERT', user);
    this.logAction(user.username, 'PASSWORD_RESET_SUCCESS', 'Password updated successfully via reset token');
    return { success: true, message: 'Password has been reset successfully. You may now log in.' };
  }

  // ==========================================================================
  // PROFILE & SETTINGS MANAGEMENT
  // ==========================================================================

  updateProfile(userId, { name, bio, avatar, email }) {
    const user = this.users.find(u => u.id === userId);
    if (!user) return { success: false, message: 'User not found.' };

    if (email) {
      const cleanEmail = email.trim().toLowerCase();
      if (!cleanEmail.includes('@')) {
        return { success: false, message: 'Please provide a valid email address.' };
      }
      const duplicate = this.users.find(u => u.email.toLowerCase() === cleanEmail && u.id !== userId);
      if (duplicate) {
        return { success: false, message: 'Email is already in use by another account.' };
      }
      user.email = cleanEmail;
    }

    if (name !== undefined) user.name = (name || '').trim().slice(0, 80);
    if (bio !== undefined) user.bio = (bio || '').trim().slice(0, 250);
    if (avatar !== undefined) user.avatar = (avatar || '').trim().slice(0, 2000);

    const safeUser = this.sanitizeUser(user);
    for (const [, sess] of this.sessions.entries()) {
      if (sess.user && sess.user.id === userId) {
        sess.user = safeUser;
      }
    }

    this.logAction(user.username, 'PROFILE_UPDATE', 'Updated user profile information');
    this.saveState();
    this.syncToMongo('USER_UPSERT', user);
    return { success: true, user: safeUser, message: 'Profile updated successfully.' };
  }

  updateUserSettings(userId, newSettings) {
    const user = this.users.find(u => u.id === userId);
    if (!user) return { success: false, message: 'User not found.' };

    user.settings = {
      ...(user.settings || {}),
      ...newSettings
    };

    const safeUser = this.sanitizeUser(user);
    for (const [, sess] of this.sessions.entries()) {
      if (sess.user && sess.user.id === userId) {
        sess.user = safeUser;
      }
    }

    this.logAction(user.username, 'SETTINGS_UPDATE', 'Updated user preferences');
    this.saveState();
    this.syncToMongo('USER_UPSERT', user);
    return { success: true, settings: user.settings, user: safeUser, message: 'Settings saved successfully.' };
  }

  changePassword(userId, currentPassword, newPassword) {
    const user = this.users.find(u => u.id === userId);
    if (!user) return { success: false, message: 'User not found.' };

    if (!this.verifyPassword(currentPassword, user.passwordHash)) {
      return { success: false, message: 'Current password does not match.' };
    }
    if (!newPassword || newPassword.length < 6) {
      return { success: false, message: 'New password must be at least 6 characters long.' };
    }

    user.passwordHash = this.hashPassword(newPassword);
    this.logAction(user.username, 'PASSWORD_CHANGE', 'User changed their password');
    this.saveState();
    this.syncToMongo('USER_UPSERT', user);
    return { success: true, message: 'Password updated successfully.' };
  }

  // ==========================================================================
  // SYSTEM SETTINGS (ADMIN MANAGED)
  // ==========================================================================

  getSystemSettings() {
    return {
      platformName: 'CodeInsight',
      maxSnippetSizeKb: 500,
      maxZipArchiveMb: 15,
      defaultLanguage: 'javascript',
      sessionTimeoutMinutes: 60,
      defaultHealthThreshold: 80,
      maintenanceMode: false,
      allowRegistration: true,
      ...(this.systemSettings || {})
    };
  }

  updateSystemSettings(newSettings = {}) {
    const current = this.getSystemSettings();
    const allowedLanguages = new Set(['javascript', 'python', 'typescript', 'html', 'css', 'java', 'c_cpp']);
    const next = { ...current };

    if (typeof newSettings.platformName === 'string') {
      const value = newSettings.platformName.trim().slice(0, 60);
      if (value) next.platformName = value;
    }
    if (newSettings.allowRegistration !== undefined) {
      if (typeof newSettings.allowRegistration !== 'boolean') {
        return { success: false, message: 'Allow Registration must be true or false.' };
      }
      next.allowRegistration = newSettings.allowRegistration;
    }
    if (newSettings.maintenanceMode !== undefined) {
      if (typeof newSettings.maintenanceMode !== 'boolean') {
        return { success: false, message: 'Maintenance Mode must be true or false.' };
      }
      next.maintenanceMode = newSettings.maintenanceMode;
    }
    if (newSettings.maxZipArchiveMb !== undefined) {
      const value = Number(newSettings.maxZipArchiveMb);
      if (!Number.isFinite(value) || value < 1 || value > 50) {
        return { success: false, message: 'Maximum ZIP size must be between 1 and 50 MB.' };
      }
      next.maxZipArchiveMb = Math.round(value);
    }
    if (newSettings.maxSnippetSizeKb !== undefined) {
      const value = Number(newSettings.maxSnippetSizeKb);
      if (!Number.isFinite(value) || value < 1 || value > 5000) {
        return { success: false, message: 'Maximum snippet size must be between 1 and 5000 KB.' };
      }
      next.maxSnippetSizeKb = Math.round(value);
    }
    if (newSettings.defaultLanguage !== undefined) {
      if (!allowedLanguages.has(newSettings.defaultLanguage)) {
        return { success: false, message: 'Unsupported default language.' };
      }
      next.defaultLanguage = newSettings.defaultLanguage;
    }
    if (newSettings.sessionTimeoutMinutes !== undefined) {
      const value = Number(newSettings.sessionTimeoutMinutes);
      if (!Number.isFinite(value) || value < 5 || value > 1440) {
        return { success: false, message: 'Session timeout must be between 5 and 1440 minutes.' };
      }
      next.sessionTimeoutMinutes = Math.round(value);
    }

    this.systemSettings = next;
    this.saveState();
    // Expose the pending write so the HTTP route can wait for MongoDB persistence.
    this.lastSettingsSync = this.syncToMongo('SYSTEM_SETTINGS', next);
    this.logAction('admin', 'SYSTEM_SETTINGS_UPDATE', 'Updated system-wide platform settings');
    return { success: true, settings: this.getSystemSettings(), message: 'System settings updated successfully.' };
  }

  getUserByToken(token) {
    if (!token) return null;
    const sess = this.sessions.get(token);
    if (!sess) return null;

    // Session lifetime is controlled by the admin-configured platform setting.
    const timeoutMinutes = Number(this.getSystemSettings().sessionTimeoutMinutes) || 60;
    const SESSION_TTL_MS = Math.max(5, Math.min(1440, timeoutMinutes)) * 60 * 1000;
    const now = Date.now();
    const lastActivityAt = sess.lastActivityAt || sess.createdAt || now;
    if (now - lastActivityAt > SESSION_TTL_MS) {
      this.sessions.delete(token);
      return null;
    }
    // Refresh activity only after the token passes its expiry check.
    sess.lastActivityAt = now;

    const sessUser = sess.user || sess;
    const dbUser = this.users.find(u => u.id === sessUser.id);
    if (!dbUser || dbUser.status !== 'active') {
      this.sessions.delete(token);
      return null;
    }
    return this.sanitizeUser(dbUser);
  }

  logout(token) {
    if (token) {
      const sess = this.sessions.get(token);
      const user = sess ? (sess.user || sess) : null;
      if (user) {
        this.logAction(user.username, 'USER_LOGOUT', 'User signed out');
      }
      this.sessions.delete(token);
    }
    return { success: true };
  }

  getAllUsers() {
    return this.users.map(u => this.sanitizeUser(u));
  }

  countActiveAdmins() {
    return this.users.filter(u => u.role === 'admin' && u.status === 'active').length;
  }

  updateUserRole(userId, newRole) {
    const user = this.users.find(u => u.id === userId);
    if (!user) return { success: false, message: 'User not found' };

    const validRoles = ['admin', 'user', 'student'];
    if (!validRoles.includes(newRole)) {
      return { success: false, message: 'Invalid role specified. Must be "admin" or "user".' };
    }

    // Lockout protection: prevent demoting root admin or the last active admin
    if (user.role === 'admin' && newRole !== 'admin') {
      if (user.id === 'usr-admin-01' || user.username === 'admin') {
        return { success: false, message: 'Cannot demote the root administrator account.' };
      }
      if (this.countActiveAdmins() <= 1 && user.status === 'active') {
        return { success: false, message: 'Lockout Protection: Cannot demote the last remaining active administrator.' };
      }
    }

    user.role = newRole;
    for (const [, sess] of this.sessions.entries()) {
      const su = sess.user || sess;
      if (su.id === userId) su.role = newRole;
    }
    this.logAction('admin', 'ROLE_UPDATE', `Changed role of ${user.username} to ${newRole}`);
    this.saveState();
    this.syncToMongo('USER_UPSERT', user);
    return { success: true, user: this.sanitizeUser(user) };
  }

  toggleUserStatus(userId) {
    const user = this.users.find(u => u.id === userId);
    if (!user) return { success: false, message: 'User not found' };

    // Lockout protection: prevent suspending root admin or the last active admin
    if (user.status === 'active' && user.role === 'admin') {
      if (user.id === 'usr-admin-01' || user.username === 'admin') {
        return { success: false, message: 'Cannot suspend the root administrator account.' };
      }
      if (this.countActiveAdmins() <= 1) {
        return { success: false, message: 'Lockout Protection: Cannot suspend the last remaining active administrator.' };
      }
    }

    user.status = user.status === 'active' ? 'suspended' : 'active';
    if (user.status === 'suspended') {
      for (const [token, sess] of this.sessions.entries()) {
        const su = sess.user || sess;
        if (su.id === userId) this.sessions.delete(token);
      }
    }
    this.logAction('admin', 'STATUS_TOGGLE', `Updated status of ${user.username} to ${user.status}`);
    this.saveState();
    this.syncToMongo('USER_UPSERT', user);
    return { success: true, user: this.sanitizeUser(user) };
  }

  deleteUser(userId) {
    const index = this.users.findIndex(u => u.id === userId);
    if (index === -1) return { success: false, message: 'User not found' };
    const user = this.users[index];

    // Lockout protection: prevent deleting root admin or the last active admin
    if (user.role === 'admin') {
      if (user.id === 'usr-admin-01' || user.username === 'admin') {
        return { success: false, message: 'Cannot delete the root administrator account.' };
      }
      if (this.countActiveAdmins() <= 1 && user.status === 'active') {
        return { success: false, message: 'Lockout Protection: Cannot delete the last remaining active administrator.' };
      }
    }

    const deleted = this.users.splice(index, 1)[0];
    for (const [token, sess] of this.sessions.entries()) {
      const su = sess.user || sess;
      if (su.id === userId) this.sessions.delete(token);
    }
    if (deleted && deleted.username) {
      this.userScanHistories.delete(deleted.username.toLowerCase());
    }
    this.logAction('admin', 'USER_DELETE', `Deleted account ${deleted.username}`);
    this.saveState();
    this.syncToMongo('USER_DELETE', { id: userId, username: deleted.username });
    return { success: true };
  }

  incrementScanCount(username) {
    const user = this.users.find(u => u.username === username);
    if (user) {
      user.scanCount = (user.scanCount || 0) + 1;
      this.saveState();
      this.syncToMongo('USER_UPSERT', user);
    }
  }

  logAction(username, action, details) {
    const logEntry = {
      id: 'log-' + crypto.randomBytes(4).toString('hex'),
      timestamp: new Date().toISOString(),
      username,
      action,
      details
    };
    this.auditLogs.unshift(logEntry);
    if (this.auditLogs.length > 200) this.auditLogs.pop();
    this.saveState();
    this.syncToMongo('AUDIT_LOG', logEntry);
  }

  getAuditLogs() {
    return this.auditLogs;
  }

  saveScanHistory(username, scanRecord) {
    const userKey = (username || 'anonymous').toLowerCase();
    if (!this.userScanHistories.has(userKey)) {
      this.userScanHistories.set(userKey, []);
    }
    const safeRecord = {
      ...scanRecord,
      code: this.redactSecrets((scanRecord.code || scanRecord.codeSnippet || '').slice(0, 5000)),
      findings: this.redactSensitiveData(Array.isArray(scanRecord.findings) ? scanRecord.findings : [])
    };
    const history = this.userScanHistories.get(userKey);
    history.unshift(safeRecord);
    if (history.length > 100) history.pop();
    this.saveState();

    this.syncToMongo('SCAN_HISTORY', {
      id: safeRecord.id || ('scan-' + crypto.randomBytes(6).toString('hex')),
      username: userKey,
      filename: safeRecord.filename || 'code-snippet',
      language: safeRecord.language || 'javascript',
      score: safeRecord.score ?? 100,
      grade: safeRecord.grade || 'A+',
      issues: safeRecord.issueCount || safeRecord.issues || 0,
      errorsCount: safeRecord.errorsCount || 0,
      warningsCount: safeRecord.warningsCount || 0,
      qualityCount: safeRecord.qualityCount || 0,
      securityCount: safeRecord.securityCount || 0,
      summary: safeRecord.summary || '',
      findings: safeRecord.findings || [],
      codeSnippet: safeRecord.code || '',
      timestamp: safeRecord.timestamp || new Date().toISOString()
    });

    return history;
  }

  getUserScanHistory(username) {
    const userKey = (username || 'anonymous').toLowerCase();
    return this.userScanHistories.get(userKey) || [];
  }

  getScanRecord(username, scanId) {
    const history = this.getUserScanHistory(username);
    return history.find(s => s.id === scanId) || null;
  }

  async clearUserScanHistory(username) {
    const userKey = (username || 'anonymous').toLowerCase();
    this.userScanHistories.set(userKey, []);
    this.saveState();
    await this.syncToMongo('SCAN_HISTORY_CLEAR', { username: userKey });
    return { success: true };
  }

  getAllAnalysisLogs({ username, language, startDate, endDate, limit = 100 } = {}) {
    let allRecords = [];
    for (const [userKey, scans] of this.userScanHistories.entries()) {
      if (username && !userKey.includes(username.toLowerCase())) continue;
      for (const s of scans) {
        if (language && s.language !== language.toLowerCase()) continue;
        if (startDate && new Date(s.timestamp) < new Date(startDate)) continue;
        if (endDate && new Date(s.timestamp) > new Date(endDate)) continue;
        allRecords.push({
          ...s,
          username: userKey
        });
      }
    }
    // Sort latest first
    allRecords.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    return allRecords.slice(0, Number(limit) || 100);
  }

  getSystemMetrics() {
    const totalUsers = this.users.length;
    const totalScans = this.users.reduce((sum, u) => sum + (u.scanCount || 0), 0);

    let allScans = [];
    let totalSecurityIssues = 0;
    for (const scans of this.userScanHistories.values()) {
      allScans = allScans.concat(scans);
      for (const s of scans) {
        totalSecurityIssues += (s.securityCount || 0);
      }
    }
    const avgScore = allScans.length > 0
      ? Math.round(allScans.reduce((s, r) => s + (r.score ?? 100), 0) / allScans.length)
      : 100;

    return {
      totalUsers,
      totalScans,
      totalSecurityFindings: totalSecurityIssues,
      supportedLanguages: 7,
      systemUptime: process.uptime(),
      averageHealthScore: avgScore,
      activeSessions: this.sessions.size,
      database: db.getStatus(),
      systemSettings: this.getSystemSettings()
    };
  }

  getDatabaseStatus() {
    return db.getStatus();
  }

  sanitizeUser(user) {
    return {
      id: user.id,
      username: user.username,
      name: user.name || user.username,
      email: user.email,
      role: user.role || 'user',
      status: user.status || 'active',
      avatar: user.avatar || '',
      bio: user.bio || 'CodeInsight developer',
      settings: user.settings || {
        theme: 'dark',
        defaultLanguage: 'javascript',
        autoDetect: true,
        tabSize: 4,
        showLineNumbers: true
      },
      createdAt: user.createdAt,
      scanCount: user.scanCount || 0
    };
  }
}

module.exports = new AuthService();