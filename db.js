/**
 * CodeInsight – MongoDB Database Connector & Mongoose Schemas
 * Implements Mongoose ODM Models for Users, Audit Logs, and Scan History.
 */

require('dotenv').config();
const mongoose = require('mongoose');

const MONGODB_URI = process.env.MONGODB_URI || null;

// 1. User Schema & Model (users collection)
const userSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  username: { type: String, required: true, unique: true, index: true },
  name: { type: String, default: '' },
  email: { type: String, required: true, unique: true, index: true },
  passwordHash: { type: String, required: true },
  role: { type: String, enum: ['student', 'user', 'admin'], default: 'user' },
  status: { type: String, enum: ['active', 'suspended'], default: 'active' },
  avatar: { type: String, default: '' },
  bio: { type: String, default: 'Developer & CodeInsight user' },
  settings: {
    theme: { type: String, default: 'dark' },
    defaultLanguage: { type: String, default: 'javascript' },
    autoDetect: { type: Boolean, default: true },
    tabSize: { type: Number, default: 4 },
    showLineNumbers: { type: Boolean, default: true }
  },
  resetPasswordToken: { type: String, default: null },
  resetPasswordExpires: { type: Date, default: null },
  scanCount: { type: Number, default: 0 },
  createdAt: { type: String, default: () => new Date().toISOString() }
}, { timestamps: true });

// 2. Audit Log Schema & Model (audit_logs collection)
const auditLogSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  timestamp: { type: String, default: () => new Date().toISOString() },
  username: { type: String, required: true, index: true },
  action: { type: String, required: true },
  details: { type: String, default: '' }
}, { timestamps: true });

// 3. Scan History Schema & Model (scan_histories collection)
const scanHistorySchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  username: { type: String, required: true, index: true },
  filename: { type: String, default: 'code-snippet' },
  language: { type: String, required: true },
  score: { type: Number, default: 100 },
  grade: { type: String, default: 'A+' },
  issues: { type: Number, default: 0 },
  errorsCount: { type: Number, default: 0 },
  warningsCount: { type: Number, default: 0 },
  qualityCount: { type: Number, default: 0 },
  securityCount: { type: Number, default: 0 },
  summary: { type: String, default: '' },
  findings: { type: Array, default: [] },
  codeSnippet: { type: String, default: '' },
  timestamp: { type: String, default: () => new Date().toISOString() }
}, { timestamps: true });

// 4. System Settings Schema & Model (system_settings collection)
const systemSettingSchema = new mongoose.Schema({
  key: { type: String, required: true, unique: true },
  value: { type: mongoose.Schema.Types.Mixed, required: true },
  updatedAt: { type: String, default: () => new Date().toISOString() }
});

const User = mongoose.model('User', userSchema);
const AuditLog = mongoose.model('AuditLog', auditLogSchema);
const ScanHistory = mongoose.model('ScanHistory', scanHistorySchema);
const SystemSetting = mongoose.model('SystemSetting', systemSettingSchema);

let isConnected = false;

async function connectDB() {
  if (!MONGODB_URI) {
    isConnected = false;
    console.log('🍃 [MongoDB] MONGODB_URI is not configured. Using local JSON persistence.');
    return false;
  }

  try {
    await mongoose.connect(MONGODB_URI, {
      serverSelectionTimeoutMS: 2500, // Timeout smoothly without freezing server
    });
    isConnected = true;
    console.log(`🍃 [MongoDB] Connected to database: ${mongoose.connection.name || 'configured database'}`);
    return true;
  } catch (err) {
    isConnected = false;
    console.log(`🍃 [MongoDB] Standby Mode: ${err.message}`);
    console.log(`💡 [MongoDB] Hybrid Persistence Active (Auto-syncs with data.json when MongoDB is offline).`);
    return false;
  }
}

function getStatus() {
  return {
    engine: 'MongoDB',
    odm: 'Mongoose',
    connected: isConnected,
    databaseName: 'codeinsight',
    uriConfigured: Boolean(process.env.MONGODB_URI),
    collections: [
      { name: 'users', model: 'User', description: 'User accounts, hashed passwords, roles & scan counters' },
      { name: 'audit_logs', model: 'AuditLog', description: 'System security audit trail & administrative events' },
      { name: 'scan_histories', model: 'ScanHistory', description: 'User code scan logs, languages & quality health scores' },
      { name: 'system_settings', model: 'SystemSetting', description: 'Persisted platform settings and admin configuration' }
    ]
  };
}

module.exports = {
  connectDB,
  getStatus,
  isMongoConnected: () => isConnected,
  User,
  AuditLog,
  ScanHistory,
  SystemSetting
};
