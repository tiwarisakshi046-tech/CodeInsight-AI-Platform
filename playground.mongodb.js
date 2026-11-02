/* global use, db */
// =============================================================================
// CodeInsight – MongoDB Interactive Playground
// You can run this directly in Antigravity using the MongoDB Extension!
// =============================================================================

// Select the database
use('codeinsight');

// 1. Query all users (Admin & Students)
console.log('--- 1. Registered Users ---');
db.getCollection('users').find({}, { passwordHash: 0 });

// 2. Query recent System Audit Logs
// console.log('--- 2. Security Audit Logs ---');
// db.getCollection('audit_logs').find({}).sort({ timestamp: -1 }).limit(10);

// 3. Query Code Scan History
// console.log('--- 3. Code Scan History ---');
// db.getCollection('scan_histories').find({}).sort({ timestamp: -1 });
