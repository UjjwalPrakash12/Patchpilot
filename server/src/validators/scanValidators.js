const path = require('path');
const config = require('../config');

/**
 * Validates a GitHub repository URL for correctness and security
 * @param {string} url
 * @returns {{ isValid: boolean, error: string|null, owner?: string, repo?: string }}
 */
function validateGitHubUrl(url) {
  if (!url || typeof url !== 'string') {
    return { isValid: false, error: 'Repository URL is required and must be a string' };
  }

  const trimmed = url.trim();

  // Disallow query parameters, URL fragments, and authentication credentials
  if (trimmed.includes('?')) {
    return { isValid: false, error: 'Query parameters are not allowed in the repository URL' };
  }
  if (trimmed.includes('#')) {
    return { isValid: false, error: 'URL fragments are not allowed in the repository URL' };
  }
  if (trimmed.includes('@')) {
    return { isValid: false, error: 'Authentication tokens or credentials in URL are strictly forbidden' };
  }

  // Enforce strict HTTPS github.com pattern
  const githubUrlRegex = /^https:\/\/github\.com\/([a-zA-Z0-9_.-]+)\/([a-zA-Z0-9_.-]+?)(?:\.git|\/)?$/;
  const match = trimmed.match(githubUrlRegex);

  if (!match) {
    return {
      isValid: false,
      error: 'Invalid GitHub URL. Must be in the format: https://github.com/owner/repository',
    };
  }

  const owner = match[1];
  let repo = match[2];
  if (repo.endsWith('.git')) {
    repo = repo.slice(0, -4);
  }

  return {
    isValid: true,
    error: null,
    owner,
    repo,
  };
}

/**
 * Validates an uploaded archive file object (from multer)
 * @param {Object} file
 * @returns {{ isValid: boolean, error: string|null }}
 */
function validateUpload(file) {
  if (!file) {
    return { isValid: false, error: 'ZIP file upload is required' };
  }

  const ext = path.extname(file.originalname).toLowerCase();
  if (ext !== '.zip') {
    return {
      isValid: false,
      error: `Invalid file extension '${ext}'. Only .zip archives are supported`,
    };
  }

  const allowedMimeTypes = [
    'application/zip',
    'application/x-zip-compressed',
    'multipart/x-zip',
    'application/octet-stream',
    'application/x-compressed',
  ];

  if (file.mimetype && !allowedMimeTypes.includes(file.mimetype)) {
    return {
      isValid: false,
      error: `Invalid MIME type '${file.mimetype}'. Expected application/zip`,
    };
  }

  if (file.size > config.UPLOAD_MAX_SIZE) {
    return {
      isValid: false,
      error: `File size exceeds the ${(config.UPLOAD_MAX_SIZE / (1024 * 1024)).toFixed(0)}MB limit`,
    };
  }

  if (file.size === 0) {
    return {
      isValid: false,
      error: 'Uploaded archive file is empty',
    };
  }

  return { isValid: true, error: null };
}

/**
 * Express middleware for validating GitHub scan request body
 */
function validateGitHubScanRequest(req, res, next) {
  const { repositoryUrl } = req.body || {};
  const validation = validateGitHubUrl(repositoryUrl);

  if (!validation.isValid) {
    return res.status(400).json({
      success: false,
      error: {
        message: validation.error,
        code: 'INVALID_GITHUB_URL',
      },
    });
  }

  req.validatedGitHub = validation;
  next();
}

/**
 * Express middleware for validating file upload request
 */
function validateUploadScanRequest(req, res, next) {
  const validation = validateUpload(req.file);

  if (!validation.isValid) {
    return res.status(400).json({
      success: false,
      error: {
        message: validation.error,
        code: 'INVALID_UPLOAD_FILE',
      },
    });
  }

  next();
}

module.exports = {
  validateGitHubUrl,
  validateUpload,
  validateGitHubScanRequest,
  validateUploadScanRequest,
};
