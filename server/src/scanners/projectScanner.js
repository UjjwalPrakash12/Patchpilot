const fs = require('fs');
const path = require('path');
const {
  getProjectFiles,
  readFileSafe,
  getLineAndSnippet,
  isInsideComment,
} = require('./scannerUtils');

const CODE_EXTENSIONS = ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'];

/**
 * Framework-specific and general code hygiene security scanner
 * @param {string} projectPath
 * @returns {Promise<Array<Object>>}
 */
async function scanProjectSpecific(projectPath) {
  const findings = [];
  const files = getProjectFiles(projectPath, { extensions: CODE_EXTENSIONS });

  let hasNextApiRoutes = false;
  let hasNextMiddleware = false;
  let isNextProject = false;

  const pkgPath = path.join(projectPath, 'package.json');
  if (fs.existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(readFileSafe(pkgPath));
      const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
      if (deps.next) {
        isNextProject = true;
      }
    } catch {
      // Ignore parse error
    }
  }

  // Check for Next.js middleware file
  const middlewarePaths = [
    'middleware.js',
    'middleware.ts',
    'src/middleware.js',
    'src/middleware.ts',
  ];
  for (const mp of middlewarePaths) {
    if (fs.existsSync(path.join(projectPath, mp))) {
      hasNextMiddleware = true;
      break;
    }
  }

  for (const file of files) {
    const { absolutePath, relativePath } = file;
    const content = readFileSafe(absolutePath);
    if (!content) continue;

    // Track Next.js API routes
    if (relativePath.includes('pages/api/') || relativePath.includes('app/api/')) {
      hasNextApiRoutes = true;
    }

    // 1. Express: body-parser without size limit
    const bodyLimitRegex = /(?:express\.json|bodyParser\.json|express\.urlencoded|bodyParser\.urlencoded)\s*\(\s*(?:\{\s*\}|\(\s*\))?\s*\)/g;
    let match;
    while ((match = bodyLimitRegex.exec(content)) !== null) {
      if (isInsideComment(content, match.index)) continue;
      // If it doesn't specify limit
      if (!match[0].includes('limit')) {
        const { startLine, endLine, codeSnippet } = getLineAndSnippet(content, match.index, match[0].length);
        const lineEvidence = (content.split('\n')[startLine - 1] || match[0]).trim();
        findings.push({
          category: 'configuration',
          title: 'Express Body Parser Without Explicit Payload Limit',
          severity: 'medium',
          confidence: 'high',
          scanner: 'projectScanner',
          ruleId: 'FRAMEWORK-EXPRESS-BODY-LIMIT',
          filePath: relativePath,
          startLine,
          endLine,
          evidence: lineEvidence,
          description: 'express.json() or bodyParser is registered without explicit request size limits.',
          impact: 'Attackers can send massive JSON payloads, consuming server RAM and causing Denial of Service (DoS) crashes.',
          remediation: 'Specify a strict limit option, e.g.: app.use(express.json({ limit: "1mb" }))',
          codeSnippet,
          references: [
            'https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html',
          ],
        });
      }
    }

    // 2. React / Frontend: Storing tokens in localStorage or sessionStorage
    const tokenStorageRegex = /(?:localStorage|sessionStorage)\.setItem\s*\(\s*['"`](?:token|jwt|accessToken|refreshToken|authToken|idToken|auth)['"`]\s*,\s*([^)]+)\)/gi;
    while ((match = tokenStorageRegex.exec(content)) !== null) {
      if (isInsideComment(content, match.index)) continue;
      const { startLine, endLine, codeSnippet } = getLineAndSnippet(content, match.index, match[0].length);
      const lineEvidence = (content.split('\n')[startLine - 1] || match[0]).trim();
      findings.push({
        category: 'source-code',
        title: 'Sensitive Authentication Token Stored in Browser Web Storage',
        severity: 'high',
        confidence: 'high',
        scanner: 'projectScanner',
        ruleId: 'FRAMEWORK-REACT-LOCALSTORAGE-TOKEN',
        filePath: relativePath,
        startLine,
        endLine,
        evidence: lineEvidence,
        description: 'Sensitive session tokens or JWTs are stored in localStorage or sessionStorage.',
        impact: 'Web Storage is globally readable by any script running on the page. Any XSS flaw allows instant token theft and account takeover.',
        remediation: 'Store tokens in HttpOnly, Secure, SameSite cookies rather than localStorage.',
        codeSnippet,
        references: [
          'https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#local-storage',
        ],
      });
    }

    // 3. General: console.log with sensitive variables
    const sensitiveLogRegex = /console\.(?:log|info|debug|warn|error)\s*\([^)]*(?:password|passwd|secret|token|apiKey|req\.body|authorization)[^)]*\)/gi;
    while ((match = sensitiveLogRegex.exec(content)) !== null) {
      if (isInsideComment(content, match.index)) continue;
      const { startLine, endLine, codeSnippet } = getLineAndSnippet(content, match.index, match[0].length);
      const lineEvidence = (content.split('\n')[startLine - 1] || match[0]).trim();
      findings.push({
        category: 'source-code',
        title: 'Potential Sensitive Data Logged to Console',
        severity: 'medium',
        confidence: 'medium',
        scanner: 'projectScanner',
        ruleId: 'FRAMEWORK-LOG-SENSITIVE-DATA',
        filePath: relativePath,
        startLine,
        endLine,
        evidence: lineEvidence,
        description: 'Console logging statement includes variable names associated with passwords, tokens, or raw request payloads.',
        impact: 'Exposes sensitive user credentials or tokens in log aggregation tools, server stdout, or client-side developer consoles.',
        remediation: 'Sanitize or mask sensitive fields prior to logging, and use a structured logger with redaction filters.',
        codeSnippet,
        references: [
          'https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html',
          'https://cwe.mitre.org/data/definitions/532.html',
        ],
      });
    }

    // 4. General: TODO / FIXME security comments
    const todoSecurityRegex = /\/\/(?:[^\n]*)(?:TODO|FIXME|HACK|XXX)\b[^\n]*(?:security|vulnerab|auth|sanitize|escape|bypass|fixme|exploit)[^\n]*/gi;
    while ((match = todoSecurityRegex.exec(content)) !== null) {
      const { startLine, endLine, codeSnippet } = getLineAndSnippet(content, match.index, match[0].length);
      findings.push({
        category: 'source-code',
        title: 'Unresolved Security-Related Code Comment (TODO / FIXME)',
        severity: 'low',
        confidence: 'high',
        scanner: 'projectScanner',
        ruleId: 'FRAMEWORK-SECURITY-TODO',
        filePath: relativePath,
        startLine,
        endLine,
        evidence: match[0].trim(),
        description: 'Code contains an unaddressed comment regarding security, authentication, or input sanitization.',
        impact: 'May indicate unfinished security logic, known bugs, or temporary bypasses left in production code.',
        remediation: 'Review and resolve the highlighted security issue before deploying to production.',
        codeSnippet,
        references: ['https://cwe.mitre.org/data/definitions/546.html'],
      });
    }

    // 5. General: Hardcoded localhost URL in configuration or code
    const localhostRegex = /['"]http:\/\/(?:localhost|127\.0\.0\.1)(?::\d+)?(?:\/[^'"]*)?['"]/gi;
    const isConfigOrProd = /(?:config|prod|service|api|client)/i.test(relativePath) && !relativePath.includes('test');
    if (isConfigOrProd) {
      while ((match = localhostRegex.exec(content)) !== null) {
        if (isInsideComment(content, match.index)) continue;
        const { startLine, endLine, codeSnippet } = getLineAndSnippet(content, match.index, match[0].length);
        const lineEvidence = (content.split('\n')[startLine - 1] || match[0]).trim();
        findings.push({
          category: 'configuration',
          title: 'Hardcoded Localhost URL in Application Code',
          severity: 'low',
          confidence: 'low',
          scanner: 'projectScanner',
          ruleId: 'FRAMEWORK-HARDCODED-LOCALHOST',
          filePath: relativePath,
          startLine,
          endLine,
          evidence: lineEvidence,
          description: `Hardcoded reference to local host endpoint '${match[0]}' found in '${relativePath}'.`,
          impact: 'Hardcoded URLs fail in deployed environments or can trigger SSRF/CORS routing misconfigurations.',
          remediation: 'Reference base API URLs via environment variables (e.g., process.env.API_BASE_URL).',
          codeSnippet,
          references: ['https://12factor.net/config'],
        });
      }
    }
  }

  // Next.js specific check: API routes present but no root middleware
  if (isNextProject && hasNextApiRoutes && !hasNextMiddleware) {
    findings.push({
      category: 'configuration',
      title: 'Next.js API Routes Present Without Centralized Middleware',
      severity: 'low',
      confidence: 'medium',
      scanner: 'projectScanner',
      ruleId: 'FRAMEWORK-NEXTJS-MISSING-MIDDLEWARE',
      filePath: 'package.json',
      startLine: 1,
      endLine: 1,
      evidence: 'Next.js project contains API routes but lacks middleware.js/ts',
      description: 'The Next.js application exposes API routes without a centralized middleware to enforce global authentication or security headers.',
      impact: 'Individual routes may inadvertently omit authentication checks.',
      remediation: 'Implement a root middleware.js to enforce authentication policies and security headers uniformly across routes.',
      codeSnippet: '// Add middleware.js in project root',
      references: ['https://nextjs.org/docs/app/building-your-application/routing/middleware'],
    });
  }

  return findings;
}

module.exports = {
  scanProjectSpecific,
};
