const { validateGitHubScanRequest, validateUploadScanRequest } = require('../src/validators/scanValidators');
const { errorHandler, ApiError } = require('../src/middleware/errorHandler');

describe('PatchPilot Middleware and Controllers Unit Tests', () => {
  describe('GitHub Scan Request Validator Middleware', () => {
    it('should reject invalid or non-GitHub URLs with 400', () => {
      const req = { body: { repositoryUrl: 'https://evil.com/repo' } };
      let statusCode;
      let jsonBody;
      const res = {
        status: (code) => {
          statusCode = code;
          return {
            json: (data) => {
              jsonBody = data;
            },
          };
        },
      };
      const next = jest.fn();

      validateGitHubScanRequest(req, res, next);
      expect(statusCode).toBe(400);
      expect(jsonBody.success).toBe(false);
      expect(jsonBody.error.code).toBe('INVALID_GITHUB_URL');
      expect(next).not.toHaveBeenCalled();
    });

    it('should accept valid GitHub repository URL and call next()', () => {
      const req = { body: { repositoryUrl: 'https://github.com/expressjs/express' } };
      const res = {};
      const next = jest.fn();

      validateGitHubScanRequest(req, res, next);
      expect(next).toHaveBeenCalled();
      expect(req.validatedGitHub.owner).toBe('expressjs');
      expect(req.validatedGitHub.repo).toBe('express');
    });
  });

  describe('Upload Scan Request Validator Middleware', () => {
    it('should reject missing upload file with 400', () => {
      const req = { file: null };
      let statusCode;
      let jsonBody;
      const res = {
        status: (code) => {
          statusCode = code;
          return {
            json: (data) => {
              jsonBody = data;
            },
          };
        },
      };
      const next = jest.fn();

      validateUploadScanRequest(req, res, next);
      expect(statusCode).toBe(400);
      expect(jsonBody.success).toBe(false);
      expect(jsonBody.error.code).toBe('INVALID_UPLOAD_FILE');
    });

    it('should accept valid zip file upload', () => {
      const req = {
        file: {
          originalname: 'my-project.zip',
          size: 1024 * 50,
          mimetype: 'application/zip',
        },
      };
      const res = {};
      const next = jest.fn();

      validateUploadScanRequest(req, res, next);
      expect(next).toHaveBeenCalled();
    });
  });

  describe('Centralized Error Handler Middleware', () => {
    it('should format errors consistently without leaking stack trace in production', () => {
      const error = new ApiError(403, 'Permission denied', 'ACCESS_DENIED');
      const req = { method: 'POST', originalUrl: '/api/scans' };
      let statusCode;
      let jsonBody;
      const res = {
        status: (code) => {
          statusCode = code;
          return {
            json: (data) => {
              jsonBody = data;
            },
          };
        },
      };

      errorHandler(error, req, res, jest.fn());

      expect(statusCode).toBe(403);
      expect(jsonBody).toEqual({
        success: false,
        error: {
          message: 'Permission denied',
          code: 'ACCESS_DENIED',
        },
      });
    });
  });
});
