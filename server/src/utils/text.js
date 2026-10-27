'use strict';

const crypto = require('crypto');

/**
 * Split a string into lines, preserving empty lines
 * @param {string} text
 * @returns {string[]}
 */
function splitLines(text) {
  if (!text) return [];
  return text.split(/\r?\n/);
}

/**
 * Truncate a string with an ellipsis if it exceeds maxLength
 * @param {string} str
 * @param {number} maxLength
 * @returns {string}
 */
function truncate(str, maxLength = 80) {
  if (!str) return '';
  const s = String(str);
  if (s.length <= maxLength) return s;
  return s.slice(0, maxLength - 1) + '…';
}

/**
 * Calculate Shannon Entropy of a string (useful for secret detection)
 * Higher entropy means more randomness (e.g., API keys, secrets)
 * @param {string} str
 * @returns {number}
 */
function shannonEntropy(str) {
  if (!str) return 0;
  const len = str.length;
  const frequencies = {};
  for (let i = 0; i < len; i++) {
    const char = str[i];
    frequencies[char] = (frequencies[char] || 0) + 1;
  }
  let entropy = 0;
  for (const char in frequencies) {
    const p = frequencies[char] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * Hash a string with SHA-256
 * @param {string} val
 * @returns {string}
 */
function sha256(val) {
  return crypto.createHash('sha256').update(val).digest('hex');
}

/**
 * Mask secret showing only the first few characters
 * @param {string} secret
 * @returns {string}
 */
function maskSecret(secret) {
  if (!secret) return '****';
  const str = String(secret).trim();
  if (str.length <= 4) return '****';
  return `${str.slice(0, 4)}****`;
}

module.exports = {
  splitLines,
  truncate,
  shannonEntropy,
  sha256,
  maskSecret,
};
