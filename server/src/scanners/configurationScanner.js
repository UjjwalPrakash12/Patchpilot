const fs = require('fs');
const path = require('path');
const {
  getProjectFiles,
  readFileSafe,
  getLineAndSnippet,
  isInsideComment,
} = require('./scannerUtils');

/**
 * Scans project for security configuration oversights
 * @param {string} projectPath
 * @returns {Promise<Array<Object>>}
 */
async function scanConfiguration(projectPath) {
  const findings = [];
  const files = getProjectFiles(projectPath, { includeEnvFiles: true });

  let isExpressProject = false;
  let hasHelmet = false;
  let hasRateLimiting = false;
  let hasHttpsRedirect = false;
  let primaryEntryFile = null;

  // Check package.json for Express
  const pkgPath = path.join(projectPath, 'package.json');
  if (fs.existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(readFileSafe(pkgPath));
      const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
      if (deps.express) {
        isExpressProject = true;
      }
      if (deps.helmet) {
        hasHelmet = true;
      }
      if (deps['express-rate-limit'] || deps['rate-limiter-flexible']) {
        hasRateLimiting = true;
      }
    } catch {
      // Ignore JSON parse error here
    }
  }

  // Identify entry candidates
  const entryCandidates = ['server.js', 'app.js', 'index.js', 'src/server.js', 'src/app.js', 'src/index.js'];
  for (const candidate of entryCandidates) {
    if (fs.existsSync(path.join(projectPath, candidate))) {
      primaryEntryFile = candidate;
      break;
    }
  }

  for (const file of files) {
    const { absolutePath, relativePath } = file;
    const baseName = path.basename(relativePath).toLowerCase();

    // 1. Committed .env files (not examples)
    if (
      baseName.startsWith('.env') &&
      !baseName.includes('example') &&
      !baseName.includes('sample') &&
      !baseName.includes('template')
    ) {
      findings.push({
        category: 'configuration',
        title: `Committed Environment File: ${relativePath}`,
        severity: 'high',
        confidence: 'high',
        scanner: 'configurationScanner',
        ruleId: 'CONF-ENV-COMMITTED',
        filePath: relativePath,
        startLine: 1,
        endLine: 1,
        evidence: `File exists: ${relativePath}`,
        description: `The file '${relativePath}' is committed to the repository. Environment files often store production credentials and configuration secrets.`,
        impact: 'Exposure of configuration parameters, API keys, database credentials, and service tokens in version control.',
        remediation: `Add '${baseName}' and other .env variants to .gitignore. Use a sanitized .env.example for repository commits.`,
        codeSnippet: `Committed file: ${relativePath}`,
        references: [
          'https://cheatsheetseries.owasp.org/cheatsheets/DotNet_Security_Cheat_Sheet.html',
          'https://12factor.net/config',
        ],
      });
    }

    const content = readFileSafe(absolutePath);
    if (!content) continue;

    // Detect express usage in code if not found in package.json
    if (/require\(['"]express['"]\)|from\s+['"]express['"]/i.test(content)) {
      isExpressProject = true;
    }

    if (/helmet\(\)/.test(content)) {
      hasHelmet = true;
    }

    if (/rateLimit|express-rate-limit/.test(content)) {
      hasRateLimiting = true;
    }

    if (/httpsRedirect|express-sslify|x-forwarded-proto/i.test(content)) {
      hasHttpsRedirect = true;
    }

    // 2. CORS Wildcard check
    const corsWildcardRegex = /cors\(\s*\{\s*origin\s*:\s*['"`]\*['"`]|cors\(\s*\)|res\.header\s*\(\s*['"`]Access-Control-Allow-Origin['"`]\s*,\s*['"`]\*['"`]\)|res\.setHeader\s*\(\s*['"`]Access-Control-Allow-Origin['"`]\s*,\s*['"`]\*['"`]\)/g;
    let match;
    while ((match = corsWildcardRegex.exec(content)) !== null) {
      if (isInsideComment(content, match.index)) continue;
      const { startLine, endLine, codeSnippet } = getLineAndSnippet(content, match.index, match[0].length);
      const lineEvidence = (content.split('\n')[startLine - 1] || match[0]).trim();
      findings.push({
        category: 'configuration',
        title: 'Permissive CORS Configuration (Wildcard Origin "*")',
        severity: 'high',
        confidence: 'high',
        scanner: 'configurationScanner',
        ruleId: 'CONF-CORS-WILDCARD',
        filePath: relativePath,
        startLine,
        endLine,
        evidence: lineEvidence,
        description: 'CORS is configured to accept requests from any origin ("*") or default open configuration.',
        impact: 'Allows any malicious third-party site to make authenticated cross-origin requests, potentially stealing private user data.',
        remediation: 'Specify explicit, trusted origins in the CORS configuration (e.g., origin: ["https://app.example.com"]).',
        codeSnippet,
        references: [
          'https://portswigger.net/web-security/cors',
          'https://cheatsheetseries.owasp.org/cheatsheets/Cross-Origin_Resource_Sharing_Cheat_Sheet.html',
        ],
      });
    }

    // 3. Cookies without Secure / HttpOnly flags
    const cookieRegex = /res\.cookie\s*\(\s*['"`][^'"`]+['"`]\s*,\s*[^,)]+(?:,\s*(\{[^}]*\}))?\)/g;
    while ((match = cookieRegex.exec(content)) !== null) {
      if (isInsideComment(content, match.index)) continue;
      const options = match[1] || '';
      const hasHttpOnly = /httpOnly\s*:\s*true/i.test(options);
      const hasSecure = /secure\s*:\s*true|secure\s*:\s*process\.env/i.test(options);

      if (!hasHttpOnly || !hasSecure) {
        const { startLine, endLine, codeSnippet } = getLineAndSnippet(content, match.index, match[0].length);
        const lineEvidence = (content.split('\n')[startLine - 1] || match[0]).trim();
        findings.push({
          category: 'configuration',
          title: 'Cookie Set Without Recommended Security Flags (HttpOnly / Secure)',
          severity: 'medium',
          confidence: 'high',
          scanner: 'configurationScanner',
          ruleId: 'CONF-INSECURE-COOKIE',
          filePath: relativePath,
          startLine,
          endLine,
          evidence: lineEvidence,
          description: `Cookie options are missing ${!hasHttpOnly ? 'httpOnly' : ''} ${!hasSecure ? 'secure' : ''} flags.`,
          impact: 'Without HttpOnly, cookies are accessible to client-side scripts (vulnerable to XSS theft). Without Secure, cookies can be transmitted over plain HTTP.',
          remediation: 'Configure cookie options with: { httpOnly: true, secure: process.env.NODE_ENV === "production", sameSite: "lax" }',
          codeSnippet,
          references: [
            'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#cookies-attributes',
          ],
        });
      }
    }

    // 4. Session secrets hardcoded
    const sessionSecretRegex = /session\s*\(\s*\{[^}]*secret\s*:\s*['"`]([^'"`\r\n]{4,})['"`]/gi;
    while ((match = sessionSecretRegex.exec(content)) !== null) {
      if (isInsideComment(content, match.index)) continue;
      const secret = match[1];
      const { startLine, endLine, codeSnippet } = getLineAndSnippet(content, match.index, match[0].length);
      const lineEvidence = (content.split('\n')[startLine - 1] || `secret: '${secret.slice(0, 3)}****'`).trim();
      findings.push({
        category: 'configuration',
        title: 'Hardcoded Express Session Secret',
        severity: 'high',
        confidence: 'high',
        scanner: 'configurationScanner',
        ruleId: 'CONF-HARDCODED-SESSION-SECRET',
        filePath: relativePath,
        startLine,
        endLine,
        evidence: lineEvidence.replace(secret, `${secret.slice(0, 3)}****`),
        description: 'Express session middleware is configured with a hardcoded secret string.',
        impact: 'Attackers can forge or tamper with session cookies to hijack active user accounts.',
        remediation: 'Store session secret in an environment variable (e.g. process.env.SESSION_SECRET).',
        codeSnippet,
        references: [
          'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html',
        ],
      });
    }

    // 5. Debug mode enabled in production configs
    const debugModeRegex = /(?:debug\s*:\s*true|DEBUG\s*=\s*['"]?true['"]?)/gi;
    while ((match = debugModeRegex.exec(content)) !== null) {
      if (isInsideComment(content, match.index)) continue;
      const isConfigFile = /(?:config|setting|env|default)/i.test(relativePath);
      if (isConfigFile) {
        const { startLine, endLine, codeSnippet } = getLineAndSnippet(content, match.index, match[0].length);
        const lineEvidence = (content.split('\n')[startLine - 1] || match[0]).trim();
        findings.push({
          category: 'configuration',
          title: 'Debug Mode Enabled in Application Configuration',
          severity: 'medium',
          confidence: 'medium',
          scanner: 'configurationScanner',
          ruleId: 'CONF-DEBUG-ENABLED-PROD',
          filePath: relativePath,
          startLine,
          endLine,
          evidence: lineEvidence,
          description: 'Debug flag is statically enabled in configuration file.',
          impact: 'Debug mode can expose internal system state, memory dumps, query execution details, and verbose stack traces to attackers.',
          remediation: 'Ensure debug flags are strictly disabled in production or conditionally toggled via environment variables.',
          codeSnippet,
          references: ['https://cwe.mitre.org/data/definitions/215.html'],
        });
      }
    }

    // 6. Exposed stack traces in error handler
    const stackTraceRegex = /res\.(?:status\(500\)|json|send)\s*\(\s*\{[^}]*stack\s*:\s*err(?:or)?\.stack/gi;
    while ((match = stackTraceRegex.exec(content)) !== null) {
      if (isInsideComment(content, match.index)) continue;
      const { startLine, endLine, codeSnippet } = getLineAndSnippet(content, match.index, match[0].length);
      const lineEvidence = (content.split('\n')[startLine - 1] || match[0]).trim();
      findings.push({
        category: 'configuration',
        title: 'Unconditional Error Stack Trace Leak',
        severity: 'medium',
        confidence: 'high',
        scanner: 'configurationScanner',
        ruleId: 'CONF-STACK-TRACE-LEAK',
        filePath: relativePath,
        startLine,
        endLine,
        evidence: lineEvidence,
        description: 'Error handler exposes raw stack traces in HTTP responses without checking environment.',
        impact: 'Internal file paths, database schemas, and stack traces reveal implementation details that facilitate targeted exploits.',
        remediation: 'Only return stack traces when process.env.NODE_ENV !== "production".',
        codeSnippet,
        references: ['https://cwe.mitre.org/data/definitions/209.html'],
      });
    }

    // 7. Unauthenticated MongoDB connection string in production config
    const mongoNoAuthRegex = /mongodb:\/\/(?:localhost|127\.0\.0\.1|0\.0\.0\.0)(?::\d+)?\/[a-zA-Z0-9_\-]+/gi;
    while ((match = mongoNoAuthRegex.exec(content)) !== null) {
      if (isInsideComment(content, match.index)) continue;
      const { startLine, endLine, codeSnippet } = getLineAndSnippet(content, match.index, match[0].length);
      const lineEvidence = (content.split('\n')[startLine - 1] || match[0]).trim();
      findings.push({
        category: 'configuration',
        title: 'Unauthenticated Local MongoDB Connection String',
        severity: 'medium',
        confidence: 'medium',
        scanner: 'configurationScanner',
        ruleId: 'CONF-MONGODB-NO-AUTH',
        filePath: relativePath,
        startLine,
        endLine,
        evidence: lineEvidence,
        description: 'MongoDB connection string lacks authentication credentials or TLS settings.',
        impact: 'If deployed without network isolation, unauthenticated databases are susceptible to ransomware and unauthorized data dumps.',
        remediation: 'Configure authentication and TLS/SSL in MongoDB connection strings via environment variables.',
        codeSnippet,
        references: ['https://cwe.mitre.org/data/definitions/306.html'],
      });
    }

    // 8. Permissive file upload configuration (multer without limits)
    const multerNoLimitsRegex = /multer\s*\(\s*(?:\{\s*\}|\(\s*\))?\s*\)/g;
    while ((match = multerNoLimitsRegex.exec(content)) !== null) {
      if (isInsideComment(content, match.index)) continue;
      const { startLine, endLine, codeSnippet } = getLineAndSnippet(content, match.index, match[0].length);
      const lineEvidence = (content.split('\n')[startLine - 1] || match[0]).trim();
      findings.push({
        category: 'configuration',
        title: 'Permissive File Upload Configuration (Missing Limits / Filter)',
        severity: 'medium',
        confidence: 'high',
        scanner: 'configurationScanner',
        ruleId: 'CONF-PERMISSIVE-FILE-UPLOAD',
        filePath: relativePath,
        startLine,
        endLine,
        evidence: lineEvidence,
        description: 'Multer middleware initialized without specifying fileSize limits or fileFilter.',
        impact: 'Allows Denial of Service (DoS) through disk exhaustion or upload of malicious executable files.',
        remediation: 'Set limits: { fileSize: 5 * 1024 * 1024 } and validate file types using a fileFilter callback.',
        codeSnippet,
        references: [
          'https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html',
        ],
      });
    }
  }

  // Check Express app-level missing protections
  const targetReportFile = primaryEntryFile || 'package.json';

  if (isExpressProject && !hasHelmet) {
    findings.push({
      category: 'configuration',
      title: 'Missing Security Headers Middleware (Helmet)',
      severity: 'medium',
      confidence: 'high',
      scanner: 'configurationScanner',
      ruleId: 'CONF-MISSING-HELMET',
      filePath: targetReportFile,
      startLine: 1,
      endLine: 1,
      evidence: 'No helmet middleware found in Express application',
      description: 'The Express application does not utilize helmet() to configure essential security HTTP headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options).',
      impact: 'Leaves the application exposed to clickjacking, MIME-type sniffing, cross-site scripting (XSS), and missing SSL enforcement.',
      remediation: 'Install helmet (`npm install helmet`) and use it in your express app: app.use(helmet());',
      codeSnippet: 'app.use(helmet());',
      references: [
        'https://helmetjs.github.io/',
        'https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html',
      ],
    });
  }

  if (isExpressProject && !hasRateLimiting) {
    findings.push({
      category: 'configuration',
      title: 'Missing Rate Limiting Middleware',
      severity: 'medium',
      confidence: 'high',
      scanner: 'configurationScanner',
      ruleId: 'CONF-MISSING-RATE-LIMIT',
      filePath: targetReportFile,
      startLine: 1,
      endLine: 1,
      evidence: 'No rate limiting middleware detected in Express application',
      description: 'The application does not apply rate limiting on endpoints or sensitive routes.',
      impact: 'Enables brute-force attacks against authentication endpoints, resource exhaustion, and Denial of Service (DoS).',
      remediation: 'Install express-rate-limit (`npm install express-rate-limit`) and apply rate limiters to routes.',
      codeSnippet: 'const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }); app.use(limiter);',
      references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html',
      ],
    });
  }

  return findings;
}

module.exports = {
  scanConfiguration,
};
