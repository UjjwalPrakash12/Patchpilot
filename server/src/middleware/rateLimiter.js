const rateLimit = require('express-rate-limit');

/**
 * Rate limiter for project scanning endpoints (max 10 scans per IP per 15 minutes)
 */
const scanRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // Limit each IP to 10 scan creation requests per window
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error: {
      message: 'Too many scans initiated from this IP address. Please wait 15 minutes before submitting again.',
      code: 'SCAN_RATE_LIMIT_EXCEEDED',
    },
  },
});

/**
 * General API rate limiter for standard read queries
 */
const apiRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error: {
      message: 'Too many requests. Please slow down.',
      code: 'API_RATE_LIMIT_EXCEEDED',
    },
  },
});

module.exports = {
  scanRateLimiter,
  apiRateLimiter,
};
