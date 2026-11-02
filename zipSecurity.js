/**
 * CodeInsight – ZIP Archive Security & Validation Engine
 * 
 * Enforces strict security boundaries against:
 * 1. Path Traversal ("Zip Slip" vulnerability: ../ or absolute paths)
 * 2. Decompression Bombs (Zip bombs: cumulative uncompressed size limit & ratio checks)
 * 3. Oversized Files (Limits archive and individual file sizes)
 * 4. Excessive File Counts (Denial of Service prevention: limits total entries)
 * 5. Unsafe Filenames & Dangerous Executable Extensions
 */

const zlib = require('zlib');
const path = require('path');

const LIMITS = {
  MAX_ZIP_BYTES: 15 * 1024 * 1024,          // 15 MB archive limit
  MAX_TOTAL_UNCOMPRESSED: 10 * 1024 * 1024,  // 10 MB total uncompressed content
  MAX_FILE_UNCOMPRESSED: 1.5 * 1024 * 1024,  // 1.5 MB max per single file
  MAX_FILE_COUNT: 100,                       // 100 code files max
  MAX_PATH_LENGTH: 200,                      // 200 chars max file path
  ALLOWED_EXTENSIONS: new Set([
    'js', 'mjs', 'cjs',
    'ts', 'tsx',
    'py', 'pyw',
    'html', 'htm',
    'css',
    'java',
    'c', 'cpp', 'cc', 'cxx', 'h', 'hpp'
  ]),
  BLOCKED_EXTENSIONS: new Set([
    'exe', 'dll', 'so', 'dylib', 'bin', 'com', 'bat', 'cmd', 'ps1', 'sh', 'bash',
    'vbs', 'vbe', 'js.bak', 'scr', 'pif', 'msi', 'jar', 'apk', 'app'
  ])
};

class ZipSecurityError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'ZipSecurityError';
    this.code = code;
  }
}

/**
 * Validates a relative file path for Zip Slip (path traversal) and unsafe characters.
 */
function sanitizeZipEntryPath(rawPath) {
  if (!rawPath || typeof rawPath !== 'string') {
    throw new ZipSecurityError('UNSAFE_ENTRY', 'Invalid or empty entry path in ZIP archive.');
  }

  // Check for null bytes or control characters
  if (/[\x00-\x1f\x7f]/.test(rawPath)) {
    throw new ZipSecurityError('UNSAFE_FILENAME', 'File path contains illegal control characters or null bytes.');
  }

  // Normalize path separators to forward slash
  const normalized = rawPath.replace(/\\/g, '/');

  // Check for absolute paths
  if (normalized.startsWith('/') || /^[a-zA-Z]:/.test(normalized)) {
    throw new ZipSecurityError('PATH_TRAVERSAL', `Absolute path detected in ZIP entry: "${rawPath}". Access denied.`);
  }

  // Check for path traversal components (..)
  const parts = normalized.split('/');
  for (const part of parts) {
    if (part === '..' || part.trim() === '..') {
      throw new ZipSecurityError('PATH_TRAVERSAL', `Directory traversal sequence ("..") detected in entry: "${rawPath}".`);
    }
  }

  // Path length check
  if (normalized.length > LIMITS.MAX_PATH_LENGTH) {
    throw new ZipSecurityError('OVERSIZED_PATH', `File path exceeds maximum permitted length of ${LIMITS.MAX_PATH_LENGTH} characters.`);
  }

  return parts.filter(p => p && p !== '.').join('/');
}

/**
 * Safely parses and extracts supported source files from a ZIP buffer in memory.
 * Does not write any files to the filesystem.
 * 
 * @param {Buffer} buffer - Raw ZIP file buffer
 * @returns {Array<{ name: string, content: string, language: string, size: number }>}
 */
function extractSafeZipContents(buffer, options = {}) {
  if (!Buffer.isBuffer(buffer)) {
    throw new ZipSecurityError('INVALID_INPUT', 'Expected a valid Buffer for ZIP processing.');
  }

  const configuredMax = Number(options.maxZipBytes);
  const maxZipBytes = Number.isFinite(configuredMax)
    ? Math.max(1, Math.min(50, configuredMax / (1024 * 1024))) * 1024 * 1024
    : LIMITS.MAX_ZIP_BYTES;
  if (buffer.length > maxZipBytes) {
    const maxMb = Math.round(maxZipBytes / (1024 * 1024));
    throw new ZipSecurityError('OVERSIZED_ARCHIVE', `ZIP archive size (${(buffer.length / (1024 * 1024)).toFixed(1)}MB) exceeds maximum limit of ${maxMb}MB.`);
  }

  if (buffer.length < 22) {
    throw new ZipSecurityError('CORRUPT_ZIP', 'File is too small to be a valid ZIP archive.');
  }

  let totalUncompressed = 0;
  let fileCount = 0;
  const extractedFiles = [];

  // Parse End of Central Directory Record to locate central directory
  // Search backward from end of buffer for signature 0x06054b50
  let eocdOffset = -1;
  const maxSearch = Math.min(buffer.length, 65557);
  for (let i = buffer.length - 22; i >= buffer.length - maxSearch; i--) {
    if (buffer.readUInt32LE(i) === 0x06054b50) {
      eocdOffset = i;
      break;
    }
  }

  if (eocdOffset !== -1) {
    // Standard Central Directory parsing
    const totalEntries = buffer.readUInt16LE(eocdOffset + 10);
    const cdOffset = buffer.readUInt32LE(eocdOffset + 16);
    let curOffset = cdOffset;

    for (let idx = 0; idx < totalEntries; idx++) {
      if (curOffset + 46 > buffer.length) break;
      if (buffer.readUInt32LE(curOffset) !== 0x02014b50) break; // Central Directory header

      const compMethod = buffer.readUInt16LE(curOffset + 10);
      const compSize = buffer.readUInt32LE(curOffset + 20);
      const uncompSize = buffer.readUInt32LE(curOffset + 24);
      const nameLen = buffer.readUInt16LE(curOffset + 28);
      const extraLen = buffer.readUInt16LE(curOffset + 30);
      const commentLen = buffer.readUInt16LE(curOffset + 32);
      const localHeaderOffset = buffer.readUInt32LE(curOffset + 42);

      const rawName = buffer.toString('utf8', curOffset + 46, curOffset + 46 + nameLen);
      curOffset += 46 + nameLen + extraLen + commentLen;

      // Skip directory entries
      if (rawName.endsWith('/') || rawName.endsWith('\\')) continue;
      // Skip Mac metadata directory
      if (rawName.startsWith('__MACOSX/')) continue;

      // 1. Path Traversal & Unsafe Filename Check (Enforced on ALL entries)
      const safePath = sanitizeZipEntryPath(rawName);

      // Skip hidden files (e.g. .DS_Store, .gitignore)
      if (safePath.split('/').some(p => p.startsWith('.') && p !== '..' && p !== '.')) continue;

      const ext = (safePath.includes('.') ? safePath.split('.').pop() : '').toLowerCase();

      // 2. Block dangerous executable extensions
      if (LIMITS.BLOCKED_EXTENSIONS.has(ext)) {
        throw new ZipSecurityError('UNSAFE_EXTENSION', `Blocked executable/binary extension ".${ext}" detected in ZIP: "${safePath}".`);
      }

      // Check if allowed source extension
      if (!LIMITS.ALLOWED_EXTENSIONS.has(ext)) continue;

      fileCount++;
      if (fileCount > LIMITS.MAX_FILE_COUNT) {
        throw new ZipSecurityError('EXCESSIVE_FILES', `ZIP archive exceeds limit of ${LIMITS.MAX_FILE_COUNT} code files (Denial of Service protection).`);
      }

      // 3. Decompression Bomb Check (Header check before decompressing)
      if (uncompSize > LIMITS.MAX_FILE_UNCOMPRESSED) {
        throw new ZipSecurityError('OVERSIZED_ENTRY', `File "${safePath}" uncompressed size (${(uncompSize / 1024).toFixed(0)}KB) exceeds 1.5MB single file limit.`);
      }

      totalUncompressed += uncompSize;
      if (totalUncompressed > LIMITS.MAX_TOTAL_UNCOMPRESSED) {
        throw new ZipSecurityError('DECOMPRESSION_BOMB', `Cumulative uncompressed size exceeds security threshold of 10MB (potential zip bomb).`);
      }

      // Read from Local Header
      if (localHeaderOffset + 30 > buffer.length) continue;
      if (buffer.readUInt32LE(localHeaderOffset) !== 0x04034b50) continue;

      const localNameLen = buffer.readUInt16LE(localHeaderOffset + 26);
      const localExtraLen = buffer.readUInt16LE(localHeaderOffset + 28);
      const dataStart = localHeaderOffset + 30 + localNameLen + localExtraLen;
      const dataEnd = dataStart + compSize;

      if (dataEnd > buffer.length) continue;

      const compData = buffer.slice(dataStart, dataEnd);
      let uncompressedBuffer;

      if (compMethod === 0) {
        // Stored (uncompressed)
        uncompressedBuffer = compData;
      } else if (compMethod === 8) {
        // Deflated
        try {
          uncompressedBuffer = zlib.inflateRawSync(compData, {
            maxOutputLength: LIMITS.MAX_FILE_UNCOMPRESSED
          });
        } catch (zErr) {
          throw new ZipSecurityError('DECOMPRESSION_FAILED', `Failed to decompress "${safePath}": ${zErr.message}`);
        }
      } else {
        // Unsupported compression method
        continue;
      }

      // Validate actual decompressed bytes
      if (uncompressedBuffer.length > LIMITS.MAX_FILE_UNCOMPRESSED) {
        throw new ZipSecurityError('OVERSIZED_ENTRY', `Decompressed size of "${safePath}" exceeded safety limit.`);
      }

      const content = uncompressedBuffer.toString('utf8');

      // Map extension to language
      const langMap = {
        js: 'javascript', mjs: 'javascript', cjs: 'javascript',
        ts: 'typescript', tsx: 'typescript',
        py: 'python', pyw: 'python',
        html: 'html', htm: 'html',
        css: 'css',
        java: 'java',
        cpp: 'c_cpp', c: 'c_cpp', cc: 'c_cpp', cxx: 'c_cpp', h: 'c_cpp', hpp: 'c_cpp'
      };

      extractedFiles.push({
        name: safePath,
        content,
        language: langMap[ext] || 'javascript',
        size: content.length
      });
    }
  } else {
    // Fallback: Local file headers sequential scan
    let offset = 0;
    while (offset + 30 <= buffer.length) {
      if (buffer.readUInt32LE(offset) !== 0x04034b50) {
        offset++;
        continue;
      }

      const compMethod = buffer.readUInt16LE(offset + 8);
      const compSize = buffer.readUInt32LE(offset + 18);
      const uncompSize = buffer.readUInt32LE(offset + 22);
      const nameLen = buffer.readUInt16LE(offset + 26);
      const extraLen = buffer.readUInt16LE(offset + 28);

      const rawName = buffer.toString('utf8', offset + 30, offset + 30 + nameLen);
      const dataStart = offset + 30 + nameLen + extraLen;
      const dataEnd = dataStart + compSize;

      offset = dataEnd;

      if (rawName.endsWith('/') || rawName.endsWith('\\') || rawName.startsWith('__MACOSX/')) continue;

      const safePath = sanitizeZipEntryPath(rawName);
      const ext = (safePath.includes('.') ? safePath.split('.').pop() : '').toLowerCase();

      if (LIMITS.BLOCKED_EXTENSIONS.has(ext)) {
        throw new ZipSecurityError('UNSAFE_EXTENSION', `Blocked executable/binary extension ".${ext}" in ZIP entry: "${safePath}".`);
      }

      if (!LIMITS.ALLOWED_EXTENSIONS.has(ext)) continue;

      fileCount++;
      if (fileCount > LIMITS.MAX_FILE_COUNT) {
        throw new ZipSecurityError('EXCESSIVE_FILES', `ZIP archive exceeds limit of ${LIMITS.MAX_FILE_COUNT} files.`);
      }

      totalUncompressed += uncompSize;
      if (totalUncompressed > LIMITS.MAX_TOTAL_UNCOMPRESSED) {
        throw new ZipSecurityError('DECOMPRESSION_BOMB', `Cumulative uncompressed size exceeds limit of 10MB.`);
      }

      if (dataEnd > buffer.length) break;

      const compData = buffer.slice(dataStart, dataEnd);
      let uncompressedBuffer;

      if (compMethod === 0) {
        uncompressedBuffer = compData;
      } else if (compMethod === 8) {
        try {
          uncompressedBuffer = zlib.inflateRawSync(compData, {
            maxOutputLength: LIMITS.MAX_FILE_UNCOMPRESSED
          });
        } catch (zErr) {
          continue;
        }
      } else {
        continue;
      }

      const content = uncompressedBuffer.toString('utf8');
      const langMap = {
        js: 'javascript', mjs: 'javascript', cjs: 'javascript',
        ts: 'typescript', tsx: 'typescript',
        py: 'python', pyw: 'python',
        html: 'html', htm: 'html',
        css: 'css',
        java: 'java',
        cpp: 'c_cpp', c: 'c_cpp', cc: 'c_cpp', cxx: 'c_cpp', h: 'c_cpp', hpp: 'c_cpp'
      };

      extractedFiles.push({
        name: safePath,
        content,
        language: langMap[ext] || 'javascript',
        size: content.length
      });
    }
  }

  return extractedFiles;
}

module.exports = {
  LIMITS,
  ZipSecurityError,
  sanitizeZipEntryPath,
  extractSafeZipContents
};
