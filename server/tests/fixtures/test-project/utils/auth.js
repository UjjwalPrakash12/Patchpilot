const crypto = require('crypto');

/**
 * Insecure MD5 hashing for passwords
 */
function hashPassword(password) {
  return crypto.createHash('md5').update(password).digest('hex');
}

/**
 * Cryptographically weak token generator using Math.random()
 */
function generateResetToken() {
  const token = Math.random().toString(36).substring(2) + Math.random().toString(36).substring(2);
  return token;
}

// TODO: fix security review issues in authentication flow

module.exports = {
  hashPassword,
  generateResetToken,
};
