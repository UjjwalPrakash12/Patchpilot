const config = require('../config');

/**
 * Custom ApiError for operational errors
 */
class ApiError extends Error {
  constructor(statusCode, message, code = 'INTERNAL_ERROR', details = null) {
    super(message);
    this.statusCode = statusCode;
    this.code = code;
    this.details = details;
    Error.captureStackTrace(this, this.constructor);
  }
}

/**
 * Centralized Express error-handling middleware
 */
function errorHandler(err, req, res, next) {
  let statusCode = err.statusCode || 500;
  let message = err.message || 'An unexpected server error occurred';
  let code = err.code || 'INTERNAL_SERVER_ERROR';
  let details = err.details || null;

  // Handle Multer file upload errors
  if (err.name === 'MulterError') {
    statusCode = 400;
    code = 'UPLOAD_ERROR';
    if (err.code === 'LIMIT_FILE_SIZE') {
      message = `Uploaded file exceeds size limit of ${(config.UPLOAD_MAX_SIZE / (1024 * 1024)).toFixed(0)}MB`;
    } else if (err.code === 'LIMIT_UNEXPECTED_FILE') {
      message = `Unexpected upload field: ${err.field}`;
    }
  }

  // Handle Mongoose Validation Errors
  if (err.name === 'ValidationError') {
    statusCode = 400;
    code = 'VALIDATION_ERROR';
    const errors = Object.values(err.errors).map((e) => e.message);
    message = errors.join(', ');
  }

  // Handle Mongoose CastError (e.g. invalid ObjectId or UUID format)
  if (err.name === 'CastError') {
    statusCode = 400;
    code = 'INVALID_IDENTIFIER';
    message = `Invalid format for field: ${err.path}`;
  }

  // Log error in non-test environments
  if (config.NODE_ENV !== 'test') {
    console.error(`[ERROR] ${req.method} ${req.originalUrl}:`, err);
  }

  const response = {
    success: false,
    error: {
      message,
      code,
      ...(details ? { details } : {}),
      ...(config.NODE_ENV === 'development' && err.stack ? { stack: err.stack } : {}),
    },
  };

  res.status(statusCode).json(response);
}

module.exports = {
  errorHandler,
  ApiError,
};
