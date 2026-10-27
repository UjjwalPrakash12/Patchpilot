const fs = require('fs');
const path = require('path');

const IGNORED_DIRS = new Set([
  'node_modules',
  '.git',
  '.svn',
  '.hg',
  'dist',
  'build',
  'out',
  '.next',
  '.nuxt',
  'coverage',
  '__MACOSX',
  '.cache',
  'vendor',
  '.idea',
  '.vscode',
]);

const BINARY_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.webp', '.bmp',
  '.woff', '.woff2', '.eot', '.ttf', '.otf',
  '.zip', '.tar', '.gz', '.bz2', '.7z', '.rar',
  '.mp4', '.mp3', '.mov', '.avi', '.wav', '.ogg',
  '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
  '.exe', '.dll', '.so', '.dylib', '.bin', '.obj', '.class',
]);

const MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024; // 2MB

/**
 * Recursively scans a directory for files, ignoring standard vendor/build/binary directories and files
 * @param {string} rootDir - Root directory to scan
 * @param {Object} options - Options { extensions, includeEnvFiles }
 * @returns {Array<{ absolutePath: string, relativePath: string }>}
 */
function getProjectFiles(rootDir, options = {}) {
  const { extensions = null, includeEnvFiles = true } = options;
  const results = [];

  function traverse(currentDir) {
    let entries;
    try {
      entries = fs.readdirSync(currentDir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      const fullPath = path.join(currentDir, entry.name);
      const relPath = path.relative(rootDir, fullPath).replace(/\\/g, '/');

      if (entry.isDirectory()) {
        if (!IGNORED_DIRS.has(entry.name)) {
          traverse(fullPath);
        }
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        if (BINARY_EXTENSIONS.has(ext)) {
          continue;
        }

        try {
          const stats = fs.statSync(fullPath);
          if (stats.size > MAX_FILE_SIZE_BYTES) {
            continue;
          }
        } catch {
          continue;
        }

        const isEnvFile = entry.name.startsWith('.env');
        if (isEnvFile && !includeEnvFiles) {
          continue;
        }

        if (extensions && extensions.length > 0) {
          if (!extensions.includes(ext) && !isEnvFile) {
            continue;
          }
        }

        results.push({
          absolutePath: fullPath,
          relativePath: relPath,
        });
      }
    }
  }

  traverse(rootDir);
  return results;
}

/**
 * Safely read a file's content as UTF-8 string
 * @param {string} filePath
 * @returns {string|null}
 */
function readFileSafe(filePath) {
  try {
    return fs.readFileSync(filePath, 'utf8');
  } catch {
    return null;
  }
}

/**
 * Redact sensitive values showing first 4 chars + '****'
 * @param {string} val
 * @returns {string}
 */
function redactSecret(val) {
  if (!val || typeof val !== 'string') return '****';
  const trimmed = val.trim();
  if (trimmed.length <= 4) return '****';
  return `${trimmed.slice(0, 4)}****`;
}

/**
 * Check if a value or line looks like a mock/sample/test placeholder
 * @param {string} str
 * @returns {boolean}
 */
function isLikelyTestOrPlaceholder(str) {
  if (!str) return false;
  const lower = str.toLowerCase();
  const testPatterns = [
    'test',
    'example',
    'placeholder',
    'your-',
    'xxx',
    'changeme',
    'dummy',
    'sample',
    '<insert',
    '<your',
    'todo',
    'replace_me',
    '12345678',
    'fake',
    'mock',
    'localhost',
  ];
  return testPatterns.some((p) => lower.includes(p));
}

/**
 * Get line number and 1-3 line context snippet for a match index
 * @param {string} content
 * @param {number} matchIndex
 * @param {number} matchLength
 * @returns {{ startLine: number, endLine: number, codeSnippet: string }}
 */
function getLineAndSnippet(content, matchIndex, matchLength = 0) {
  const beforeMatch = content.slice(0, matchIndex);
  const startLine = beforeMatch.split('\n').length;

  const matchedPart = content.slice(matchIndex, matchIndex + matchLength);
  const matchLinesCount = matchedPart.split('\n').length;
  const endLine = startLine + matchLinesCount - 1;

  const allLines = content.split('\n');
  const snippetStart = Math.max(0, startLine - 2);
  const snippetEnd = Math.min(allLines.length, endLine + 1);

  const snippet = allLines.slice(snippetStart, snippetEnd).join('\n').trim();

  return {
    startLine,
    endLine,
    codeSnippet: snippet || allLines[startLine - 1] || '',
  };
}

module.exports = {
  getProjectFiles,
  readFileSafe,
  redactSecret,
  isLikelyTestOrPlaceholder,
  getLineAndSnippet,
  IGNORED_DIRS,
};
