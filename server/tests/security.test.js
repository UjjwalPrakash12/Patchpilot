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
});
