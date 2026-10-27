const fs = require('fs');
const path = require('path');
const AdmZip = require('adm-zip');
const config = require('../config');

const SKIPPED_ARCHIVE_DIRS = [
  'node_modules/',
  '.git/',
  'dist/',
  'build/',
  '__MACOSX/',
  '.next/',
  '.cache/',
];

/**
 * Safely extracts a ZIP archive to a destination directory with zip-slip and bomb protection
 * @param {string} filePath - Absolute path to zip file
 * @param {string} destPath - Destination directory
 * @returns {Promise<string[]>} - List of extracted relative file paths
 */
async function extractZip(filePath, destPath) {
  if (!fs.existsSync(filePath)) {
    throw new Error(`Archive file not found: ${filePath}`);
  }

  // Ensure destination directory exists
  if (!fs.existsSync(destPath)) {
    fs.mkdirSync(destPath, { recursive: true });
  }

  const resolvedDest = path.resolve(destPath);
  const zip = new AdmZip(filePath);
  const zipEntries = zip.getEntries();
  const MAX_SINGLE_FILE_SIZE = 25 * 1024 * 1024; // 25 MB max per file

  // 1. Guard against excessive entry count (Zip Bomb protection)
  if (zipEntries.length > config.MAX_FILES_IN_ARCHIVE) {
    throw new Error(
      `Archive contains too many files (${zipEntries.length} > maximum allowed ${config.MAX_FILES_IN_ARCHIVE})`
    );
  }

  // 2. Guard against excessive header-declared decompressed size
  let totalHeaderSize = 0;
  for (const entry of zipEntries) {
    totalHeaderSize += entry.header.size;
    if (totalHeaderSize > config.MAX_DECOMPRESSED_SIZE) {
      throw new Error(
        `Decompressed archive size exceeds maximum limit of ${(config.MAX_DECOMPRESSED_SIZE / (1024 * 1024)).toFixed(0)}MB`
      );
    }
  }

  const extractedFiles = [];
  let actualDecompressedSize = 0;

  try {
    for (const entry of zipEntries) {
      const rawName = entry.entryName.replace(/\\/g, '/');

      // Reject symlinks to prevent symlink-based path traversal attacks
      if (entry.attr && ((entry.attr >>> 16) & 0o170000) === 0o120000) {
        throw new Error(`Security Violation: Symbolic links are forbidden in archives: ${rawName}`);
      }

      // Check directory nesting depth (max 15 levels)
      const pathSegments = rawName.split('/').filter(Boolean);
      if (pathSegments.length > 15) {
        throw new Error(`Security Violation: Path depth exceeds safe limit of 15 levels: ${rawName}`);
      }

      // Skip ignored directories
      const isSkipped = SKIPPED_ARCHIVE_DIRS.some(
        (dir) => rawName.includes(dir) || rawName.startsWith(dir)
      );
      if (isSkipped) {
        continue;
      }

      // Zip Slip path traversal security check
      const targetPath = path.resolve(resolvedDest, rawName);
      if (!targetPath.startsWith(resolvedDest + path.sep) && targetPath !== resolvedDest) {
        throw new Error(`Security Violation: Zip Slip path traversal detected in entry: ${rawName}`);
      }

      if (entry.isDirectory) {
        if (!fs.existsSync(targetPath)) {
          fs.mkdirSync(targetPath, { recursive: true });
        }
      } else {
        const parentDir = path.dirname(targetPath);
        if (!fs.existsSync(parentDir)) {
          fs.mkdirSync(parentDir, { recursive: true });
        }

        const fileData = entry.getData();
        if (fileData.length > MAX_SINGLE_FILE_SIZE) {
          throw new Error(
            `Archive entry exceeds maximum single-file size of ${(MAX_SINGLE_FILE_SIZE / (1024 * 1024)).toFixed(0)}MB: ${rawName}`
          );
        }

        actualDecompressedSize += fileData.length;
        if (actualDecompressedSize > config.MAX_DECOMPRESSED_SIZE) {
          throw new Error(
            `Decompressed archive size exceeds maximum limit of ${(config.MAX_DECOMPRESSED_SIZE / (1024 * 1024)).toFixed(0)}MB`
          );
        }

        fs.writeFileSync(targetPath, fileData);
        extractedFiles.push(path.relative(resolvedDest, targetPath).replace(/\\/g, '/'));
      }
    }

    return extractedFiles;
  } catch (err) {
    // Purge any partially extracted files to avoid leaving artifacts on disk
    try {
      if (fs.existsSync(resolvedDest)) {
        fs.rmSync(resolvedDest, { recursive: true, force: true });
      }
    } catch {}
    throw err;
  }
}

module.exports = {
  extractZip,
};
