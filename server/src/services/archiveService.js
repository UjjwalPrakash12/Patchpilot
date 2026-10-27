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

  // 1. Guard against excessive entry count (Zip Bomb protection)
  if (zipEntries.length > config.MAX_FILES_IN_ARCHIVE) {
    throw new Error(
      `Archive contains too many files (${zipEntries.length} > maximum allowed ${config.MAX_FILES_IN_ARCHIVE})`
    );
  }

  // 2. Guard against excessive decompressed size
  let totalDecompressedSize = 0;
  for (const entry of zipEntries) {
    totalDecompressedSize += entry.header.size;
    if (totalDecompressedSize > config.MAX_DECOMPRESSED_SIZE) {
      throw new Error(
        `Decompressed archive size exceeds maximum limit of ${(config.MAX_DECOMPRESSED_SIZE / (1024 * 1024)).toFixed(0)}MB`
      );
    }
  }

  const extractedFiles = [];

  for (const entry of zipEntries) {
    const rawName = entry.entryName.replace(/\\/g, '/');

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

      fs.writeFileSync(targetPath, entry.getData());
      extractedFiles.push(path.relative(resolvedDest, targetPath).replace(/\\/g, '/'));
    }
  }

  return extractedFiles;
}

module.exports = {
  extractZip,
};
