const path = require('path');
const fs = require('fs');
const os = require('os');
const AdmZip = require('adm-zip');
const { extractZip } = require('../src/services/archiveService');
const { redactSecret, isLikelyTestOrPlaceholder, getLineAndSnippet } = require('../src/scanners/scannerUtils');
const { proposeFix } = require('../src/services/findingService');

describe('Security Controls & Hardening Unit Tests', () => {
  describe('Secret Redaction', () => {
    it('should mask sensitive credential strings leaving only preview characters', () => {
      expect(redactSecret('super-secret-production-token')).toBe('supe****');
      expect(redactSecret('AKIA1234567890EXAMPLE')).toBe('AKIA****');
      expect(redactSecret('abc')).toBe('****');
      expect(redactSecret('')).toBe('****');
      expect(redactSecret(null)).toBe('****');
    });

    it('should identify obvious test/mock placeholders', () => {
      expect(isLikelyTestOrPlaceholder('sk-test-fake-key')).toBe(true);
      expect(isLikelyTestOrPlaceholder('your-api-key-here')).toBe(true);
      expect(isLikelyTestOrPlaceholder('example12345678')).toBe(true);
      expect(isLikelyTestOrPlaceholder('prod_live_9a8b7c6d5e4f3a2b')).toBe(false);
    });
  });

  describe('Zip-Slip & Path Traversal Archive Protection', () => {
    let tempDir;
    let maliciousZipPath;

    beforeEach(() => {
      tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'patchpilot-security-test-'));
      maliciousZipPath = path.join(tempDir, 'malicious.zip');
    });

    afterEach(() => {
      try {
        fs.rmSync(tempDir, { recursive: true, force: true });
      } catch {
        // ignore cleanup errors in tests
      }
    });

    it('should detect and reject zip-slip path traversal attack archives', async () => {
      const zip = new AdmZip();
      zip.addFile('evil.txt', Buffer.from('malicious payload'));
      zip.getEntries()[0].entryName = '../../evil.txt';
      zip.writeZip(maliciousZipPath);

      const targetExtract = path.join(tempDir, 'extracted');
      await expect(extractZip(maliciousZipPath, targetExtract)).rejects.toThrow(
        /Zip Slip path traversal detected/i
      );
    });

    it('should safely extract legitimate nested archives', async () => {
      const zip = new AdmZip();
      zip.addFile('src/index.js', Buffer.from('console.log("hello");'));
      zip.addFile('package.json', Buffer.from('{"name":"test-app"}'));
      zip.writeZip(maliciousZipPath);

      const targetExtract = path.join(tempDir, 'extracted');
      const files = await extractZip(maliciousZipPath, targetExtract);
      expect(files).toContain('src/index.js');
      expect(files).toContain('package.json');
      expect(fs.existsSync(path.join(targetExtract, 'src/index.js'))).toBe(true);
    });
  });

  describe('Deterministic Remediation Proposals (proposeFix)', () => {
    it('should propose safe helmet and rate-limiting fixes for Express config', async () => {
      const mockFinding = {
        findingId: 'f-1',
        category: 'configuration',
        ruleId: 'CONF-MISSING-HELMET',
        filePath: 'server.js',
        startLine: 10,
        codeSnippet: 'const app = express();',
      };

      const fix = await proposeFix(mockFinding);
      expect(fix).toHaveProperty('fixedCode');
      expect(fix.fixedCode).toContain('helmet');
      expect(fix.explanation).toContain('Helmet');
    });

    it('should propose safe replacements for dangerous eval() calls', async () => {
      const mockFinding = {
        findingId: 'f-2',
        category: 'source-code',
        ruleId: 'SA-EVAL-USAGE',
        filePath: 'calculator.js',
        startLine: 5,
        codeSnippet: 'const res = eval(expression);',
      };

      const fix = await proposeFix(mockFinding);
      expect(fix).toHaveProperty('fixedCode');
      expect(fix.fixedCode).not.toContain('eval(');
      expect(fix.risks).toBeDefined();
    });

    it('should propose secure parameterized alternatives for SQL injection', async () => {
      const mockFinding = {
        findingId: 'f-3',
        category: 'source-code',
        ruleId: 'SA-SQL-INJECTION-CONCAT',
        filePath: 'db.js',
        startLine: 20,
        codeSnippet: 'db.query("SELECT * FROM users WHERE id = " + userId);',
      };

      const fix = await proposeFix(mockFinding);
      expect(fix.fixedCode).toContain('?');
      expect(fix.explanation).toMatch(/parameterized/i);
    });
  });

  describe('Multi-Tenant Access Control & Token Isolation', () => {
    const { Scan, Finding } = require('../src/models');
    const { getScans } = require('../src/controllers/scanController');
    const { verifyFindingOwnership } = require('../src/middleware/ownershipMiddleware');

    it('should strip ownerToken when serializing Scan to JSON', () => {
      const scan = new Scan({
        scanId: 'scan-sec-test',
        projectName: 'private-repo',
        submissionType: 'zip',
        status: 'completed',
        ownerToken: 'secret-owner-token-12345',
      });

      const serialized = scan.toJSON();
      expect(serialized.ownerToken).toBeUndefined();
      expect(serialized.scanId).toBe('scan-sec-test');
      expect(serialized.projectName).toBe('private-repo');
    });

    it('should return empty list when getScans is called without an x-owner-token', async () => {
      let responseData;
      const req = { headers: {}, query: {} };
      const res = {
        json: (data) => {
          responseData = data;
        },
      };
      const next = jest.fn();

      await getScans(req, res, next);
      expect(responseData.success).toBe(true);
      expect(responseData.data).toEqual([]);
      expect(responseData.pagination.total).toBe(0);
      expect(next).not.toHaveBeenCalled();
    });

    it('should block finding access when x-owner-token does not match scan owner', async () => {
      jest.spyOn(Finding, 'findOne').mockResolvedValue({
        findingId: 'finding-101',
        scanId: 'scan-202',
      });
      jest.spyOn(Scan, 'findOne').mockResolvedValue({
        scanId: 'scan-202',
        ownerToken: 'expected-owner-token-abc',
      });

      let statusCode;
      let errorBody;
      const req = {
        params: { findingId: 'finding-101' },
        headers: { 'x-owner-token': 'wrong-attacker-token' },
      };
      const res = {
        status: (code) => {
          statusCode = code;
          return {
            json: (body) => {
              errorBody = body;
            },
          };
        },
      };
      const next = jest.fn();

      await verifyFindingOwnership(req, res, next);

      expect(statusCode).toBe(403);
      expect(errorBody.success).toBe(false);
      expect(errorBody.error.code).toBe('FORBIDDEN_FINDING_ACCESS');
      expect(next).not.toHaveBeenCalled();

      Finding.findOne.mockRestore();
      Scan.findOne.mockRestore();
    });

    it('should permit finding access when x-owner-token matches scan owner', async () => {
      const mockFinding = { findingId: 'finding-101', scanId: 'scan-202' };
      const mockScan = { scanId: 'scan-202', ownerToken: 'matching-token-xyz' };

      jest.spyOn(Finding, 'findOne').mockResolvedValue(mockFinding);
      jest.spyOn(Scan, 'findOne').mockResolvedValue(mockScan);

      const req = {
        params: { findingId: 'finding-101' },
        headers: { 'x-owner-token': 'matching-token-xyz' },
      };
      const res = {};
      const next = jest.fn();

      await verifyFindingOwnership(req, res, next);

      expect(next).toHaveBeenCalled();
      expect(req.finding).toBe(mockFinding);
      expect(req.scan).toBe(mockScan);

      Finding.findOne.mockRestore();
      Scan.findOne.mockRestore();
    });
  });

  describe('Archive Extraction Hardening (Symlinks & Nesting Depth)', () => {
    let tempDir;
    let testZipPath;

    beforeEach(() => {
      tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'patchpilot-arch-test-'));
      testZipPath = path.join(tempDir, 'depth-test.zip');
    });

    afterEach(() => {
      try {
        fs.rmSync(tempDir, { recursive: true, force: true });
      } catch {}
    });

    it('should reject archives containing directory paths deeper than 15 levels', async () => {
      const zip = new AdmZip();
      const deepPath = '1/2/3/4/5/6/7/8/9/10/11/12/13/14/15/16/payload.txt';
      zip.addFile(deepPath, Buffer.from('deep file'));
      zip.writeZip(testZipPath);

      const targetExtract = path.join(tempDir, 'extracted');
      await expect(extractZip(testZipPath, targetExtract)).rejects.toThrow(
        /Path depth exceeds safe limit/i
      );
    });

    it('should clean up partially extracted files on extraction failure', async () => {
      const zip = new AdmZip();
      zip.addFile('safe.txt', Buffer.from('ok file'));
      const evilEntry = '1/2/3/4/5/6/7/8/9/10/11/12/13/14/15/16/evil.txt';
      zip.addFile(evilEntry, Buffer.from('too deep'));
      zip.writeZip(testZipPath);

      const targetExtract = path.join(tempDir, 'extracted');
      await expect(extractZip(testZipPath, targetExtract)).rejects.toThrow();
      expect(fs.existsSync(path.join(targetExtract, 'safe.txt'))).toBe(false);
    });
  });

  describe('Query Sanitization against NoSQL Injection and ReDoS', () => {
    const { getFindingsByScan } = require('../src/services/findingService');
    const { Finding } = require('../src/models');

    it('should safely escape regex special characters in finding search query without error', async () => {
      let capturedQuery;
      jest.spyOn(Finding, 'find').mockReturnValue({
        sort: () => ({
          skip: () => ({
            limit: jest.fn().mockImplementation(() => {
              return Promise.resolve([]);
            }),
          }),
        }),
      });
      jest.spyOn(Finding, 'countDocuments').mockImplementation((q) => {
        capturedQuery = q;
        return Promise.resolve(0);
      });

      // Pass characters that normally crash unescaped regex or trigger ReDoS: unbalanced [ ( + * ?
      const result = await getFindingsByScan('scan-safe-test', {
        search: '([a-z]+)*?+^${}|',
      });

      expect(result.total).toBe(0);
      expect(capturedQuery.$or).toBeDefined();
      expect(capturedQuery.$or[0].title).toBeInstanceOf(RegExp);

      Finding.find.mockRestore();
      Finding.countDocuments.mockRestore();
    });

    it('should ignore and sanitize NoSQL operator injection payloads in filters', async () => {
      let capturedQuery;
      jest.spyOn(Finding, 'find').mockReturnValue({
        sort: () => ({
          skip: () => ({
            limit: jest.fn().mockImplementation(() => {
              return Promise.resolve([]);
            }),
          }),
        }),
      });
      jest.spyOn(Finding, 'countDocuments').mockImplementation((q) => {
        capturedQuery = q;
        return Promise.resolve(0);
      });

      // Pass NoSQL query operator objects instead of valid scalar strings
      await getFindingsByScan('scan-safe-test', {
        severity: { $ne: 'low' },
        category: { $gt: '' },
        status: { $where: '1 == 1' },
      });

      // Operators must not be passed into the MongoDB query object
      expect(capturedQuery.severity).toBeUndefined();
      expect(capturedQuery.category).toBeUndefined();
      expect(capturedQuery.status).toBeUndefined();
      expect(capturedQuery.scanId).toBe('scan-safe-test');

      Finding.find.mockRestore();
      Finding.countDocuments.mockRestore();
    });
  });
});

