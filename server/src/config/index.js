const path = require('path');
const os = require('os');
const dotenv = require('dotenv');

// Load environment variables from .env
dotenv.config({ path: path.resolve(__dirname, '../../.env') });

const parseNumber = (val, defaultVal) => {
  const parsed = parseInt(val, 10);
  return Number.isNaN(parsed) ? defaultVal : parsed;
};

const config = {
  PORT: parseNumber(process.env.PORT, 5001),
  NODE_ENV: process.env.NODE_ENV || 'development',
  MONGODB_URI: process.env.MONGODB_URI || 'mongodb://localhost:27017/patchpilot',
  CORS_ORIGIN: process.env.CORS_ORIGIN || 'http://localhost:5173',
  UPLOAD_MAX_SIZE: parseNumber(process.env.UPLOAD_MAX_SIZE, 50 * 1024 * 1024), // 50MB
  MAX_FILES_IN_ARCHIVE: parseNumber(process.env.MAX_FILES_IN_ARCHIVE, 5000),
  MAX_DECOMPRESSED_SIZE: parseNumber(process.env.MAX_DECOMPRESSED_SIZE, 200 * 1024 * 1024), // 200MB
  OPENAI_API_KEY: process.env.OPENAI_API_KEY || null,
  TEMP_DIR: process.env.TEMP_DIR || path.join(os.tmpdir(), 'patchpilot-scans'),
};

module.exports = config;
