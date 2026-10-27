const path = require('path');
const {
  runAllScanners,
  scanForSecrets,
  scanDependencies,
  scanStaticAnalysis,
  scanConfiguration,
  scanProjectSpecific,
} = require('../src/scanners');
const { proposeFix } = require('../src/services/findingService');
const { validateGitHubUrl, validateUpload } = require('../src/validators/scanValidators');

const TEST_PROJECT_PATH = path.resolve(__dirname, 'fixtures/test-project');

describe('PatchPilot Security Scanners Suite', () => {
  describe('Secret Scanner', () => {
    it('should detect hardcoded secrets and committed .env files', async () => {
      const findings = await scanForSecrets(TEST_PROJECT_PATH);
      expect(Array.isArray(findings)).toBe(true);
      expect(findings.length).toBeGreaterThan(0);

      const rules = findings.map((f) => f.ruleId);
      expect(rules).toContain('SEC-ENV-FILE-VALUES');
      expect(rules).toContain('SEC-DATABASE-URI-CREDS');
    });
  });

  describe('Dependency Scanner', () => {
    it('should detect vulnerable packages and wide ranges', async () => {
      const findings = await scanDependencies(TEST_PROJECT_PATH);
      expect(Array.isArray(findings)).toBe(true);
      expect(findings.length).toBeGreaterThan(0);

      const rules = findings.map((f) => f.ruleId);
      expect(rules).toContain('DEP-VULNERABLE-LODASH');
      expect(rules).toContain('DEP-VULNERABLE-EXPRESS');
      expect(rules).toContain('DEP-WIDE-VERSION-RANGE');
    });
  });

  describe('Static Analysis Scanner', () => {
    it('should detect dangerous JS/TS code patterns', async () => {
      const findings = await scanStaticAnalysis(TEST_PROJECT_PATH);
      expect(Array.isArray(findings)).toBe(true);
      expect(findings.length).toBeGreaterThan(0);

      const rules = findings.map((f) => f.ruleId);
      expect(rules).toContain('SA-EVAL-USAGE');
      expect(rules).toContain('SA-INNERHTML-ASSIGNMENT');
      expect(rules).toContain('SA-WEAK-HASH-ALGO');
      expect(rules).toContain('SA-INSECURE-RANDOM');
    });
  });

  describe('Configuration Scanner', () => {
    it('should detect misconfigurations like wildcard CORS and missing headers', async () => {
      const findings = await scanConfiguration(TEST_PROJECT_PATH);
      expect(Array.isArray(findings)).toBe(true);
      expect(findings.length).toBeGreaterThan(0);

      const rules = findings.map((f) => f.ruleId);
      expect(rules).toContain('CONF-CORS-WILDCARD');
      expect(rules).toContain('CONF-MISSING-HELMET');
      expect(rules).toContain('CONF-MISSING-RATE-LIMIT');
    });
  });

  describe('Project-Specific Scanner', () => {
    it('should detect web storage tokens, logging credentials, and TODO comments', async () => {
      const findings = await scanProjectSpecific(TEST_PROJECT_PATH);
      expect(Array.isArray(findings)).toBe(true);
      expect(findings.length).toBeGreaterThan(0);

      const rules = findings.map((f) => f.ruleId);
      expect(rules).toContain('FRAMEWORK-REACT-LOCALSTORAGE-TOKEN');
      expect(rules).toContain('FRAMEWORK-LOG-SENSITIVE-DATA');
      expect(rules).toContain('FRAMEWORK-SECURITY-TODO');
    });
  });

  describe('Scanner Orchestrator (runAllScanners)', () => {
    it('should execute all scanners and aggregate deduplicated findings', async () => {
      const result = await runAllScanners(TEST_PROJECT_PATH);
      expect(result).toHaveProperty('scannerResults');
      expect(result).toHaveProperty('findings');
      expect(result.findings.length).toBeGreaterThan(15);

      expect(result.scannerResults.secrets.status).toBe('completed');
      expect(result.scannerResults.dependencies.status).toBe('completed');
      expect(result.scannerResults.staticAnalysis.status).toBe('completed');
      expect(result.scannerResults.configuration.status).toBe('completed');
      expect(result.scannerResults.projectSpecific.status).toBe('completed');

      // Check finding structure
      const sample = result.findings[0];
      expect(sample).toHaveProperty('findingId');
      expect(sample).toHaveProperty('title');
      expect(sample).toHaveProperty('category');
      expect(sample).toHaveProperty('severity');
      expect(sample).toHaveProperty('filePath');
      expect(sample).toHaveProperty('startLine');
    });
  });

  describe('Validators', () => {
    it('should validate legitimate GitHub URLs', () => {
      const valid = validateGitHubUrl('https://github.com/expressjs/express');
      expect(valid.isValid).toBe(true);
      expect(valid.owner).toBe('expressjs');
      expect(valid.repo).toBe('express');
    });

    it('should reject invalid, SSRF, or credentialed GitHub URLs', () => {
      expect(validateGitHubUrl('http://github.com/owner/repo').isValid).toBe(false);
      expect(validateGitHubUrl('https://evil.com/owner/repo').isValid).toBe(false);
      expect(validateGitHubUrl('https://github.com/owner/repo?token=secret').isValid).toBe(false);
      expect(validateGitHubUrl('https://user:pass@github.com/owner/repo').isValid).toBe(false);
    });

    it('should validate upload archives by extension and size', () => {
      expect(validateUpload(null).isValid).toBe(false);
      expect(validateUpload({ originalname: 'code.tar.gz', size: 1000 }).isValid).toBe(false);
      expect(validateUpload({ originalname: 'code.zip', size: 1024, mimetype: 'application/zip' }).isValid).toBe(true);
    });
  });
});
