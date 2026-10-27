const {
  getProjectFiles,
  readFileSafe,
  getLineAndSnippet,
} = require('./scannerUtils');

const JS_TS_EXTENSIONS = ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'];

/**
 * Custom static analysis rules for JavaScript / TypeScript source code
 * @param {string} projectPath
 * @returns {Promise<Array<Object>>}
 */
async function scanStaticAnalysis(projectPath) {
  const findings = [];
  const files = getProjectFiles(projectPath, { extensions: JS_TS_EXTENSIONS });

  for (const file of files) {
    const { absolutePath, relativePath } = file;
    const content = readFileSafe(absolutePath);
    if (!content) continue;

    // 1. eval() and Function constructor usage
    const evalRegex = /\b(?:eval|new\s+Function)\s*\(/g;
    let match;
    while ((match = evalRegex.exec(content)) !== null) {
      const { startLine, endLine, codeSnippet } = getLineAndSnippet(content, match.index, match[0].length);
      findings.push({
        category: 'source-code',
        title: 'Dangerous Code Execution via eval() or Function()',
        severity: 'critical',
        confidence: 'high',
        scanner: 'staticAnalysisScanner',
        ruleId: 'SA-EVAL-USAGE',
        filePath: relativePath,
        startLine,
        endLine,
        evidence: match[0],
        description: 'Direct invocation of eval() or new Function() allows arbitrary string execution in the current JS scope.',
        impact: 'If user input reaches dynamic evaluation, it leads directly to Remote Code Execution (RCE) on servers or Universal XSS in browsers.',
        remediation: 'Avoid eval(). Use JSON.parse() for structured data, or refactor to explicit functions and object lookups.',
        codeSnippet,
        references: [
          'https://owasp.org/www-community/attacks/Code_Injection',
          'https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval#never_use_eval!',
        ],
      });
    }

    // 2. innerHTML and outerHTML assignments
    const innerHtmlRegex = /\.(?:innerHTML|outerHTML)\s*=/g;
    while ((match = innerHtmlRegex.exec(content)) !== null) {
      const { startLine, endLine, codeSnippet } = getLineAndSnippet(content, match.index, match[0].length);
      findings.push({
        category: 'source-code',
        title: 'Dangerous innerHTML/outerHTML Assignment (DOM XSS)',
        severity: 'high',
        confidence: 'high',
        scanner: 'staticAnalysisScanner',
        ruleId: 'SA-INNERHTML-ASSIGNMENT',
        filePath: relativePath,
        startLine,
        endLine,
        evidence: match[0],
        description: 'Assigning raw string markup to innerHTML or outerHTML bypasses browser HTML escaping.',
        impact: 'Enables DOM-based Cross-Site Scripting (DOM XSS), allowing attackers to execute arbitrary scripts in victims\' browsers.',
        remediation: 'Use textContent / innerText for plain text, or sanitize HTML using DOMPurify before setting innerHTML.',
        codeSnippet,
        references: [
          'https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html',
        ],
      });
    }

    // 3. React dangerouslySetInnerHTML
    const reactDangerRegex = /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:/g;
    while ((match = reactDangerRegex.exec(content)) !== null) {
      const { startLine, endLine, codeSnippet } = getLineAndSnippet(content, match.index, match[0].length);
      findings.push({
        category: 'source-code',
        title: 'Dangerous React HTML Injection (dangerouslySetInnerHTML)',
        severity: 'high',
        confidence: 'high',
        scanner: 'staticAnalysisScanner',
        ruleId: 'SA-DANGEROUSLY-SET-INNERHTML',
        filePath: relativePath,
        startLine,
        endLine,
        evidence: match[0],
        description: 'dangerouslySetInnerHTML in React renders raw HTML without standard framework JSX escaping.',
        impact: 'Leaves the component vulnerable to Stored or Reflected Cross-Site Scripting (XSS).',
        remediation: 'Sanitize HTML input with DOMPurify.sanitize() before assigning to __html, or use standard JSX elements.',
        codeSnippet,
        references: [
          'https://react.dev/reference/react-dom/components/common#dangerously-setting-the-inner-html',
        ],
      });
    }

    // 4. document.write / document.writeln
    const docWriteRegex = /\bdocument\.write(?:ln)?\s*\(/g;
    while ((match = docWriteRegex.exec(content)) !== null) {
      const { startLine, endLine, codeSnippet } = getLineAndSnippet(content, match.index, match[0].length);
      findings.push({
        category: 'source-code',
        title: 'Use of Insecure document.write()',
        severity: 'medium',
        confidence: 'high',
        scanner: 'staticAnalysisScanner',
        ruleId: 'SA-DOCUMENT-WRITE',
        filePath: relativePath,
        startLine,
        endLine,
        evidence: match[0],
        description: 'document.write() writes directly into the document stream and can lead to DOM XSS and UI race conditions.',
        impact: 'Exposes users to XSS attacks and degrades rendering performance.',
        remediation: 'Replace document.write() with modern DOM manipulation methods like document.createElement() or textContent.',
        codeSnippet,
        references: [
          'https://developer.mozilla.org/en-US/docs/Web/API/Document/write',
        ],
      });
    }

    // 5. child_process command injection
    const cmdInjectRegex = /(?:child_process|cp|\b)\.(?:exec|execSync)\s*\(\s*(?:`[^`]*\${|['"][^'"]*['"]\s*\+|\w+\s*\+)/g;
    while ((match = cmdInjectRegex.exec(content)) !== null) {
      const { startLine, endLine, codeSnippet } = getLineAndSnippet(content, match.index, match[0].length);
      findings.push({
        category: 'source-code',
        title: 'Command Injection via child_process.exec()',
        severity: 'critical',
        confidence: 'high',
        scanner: 'staticAnalysisScanner',
        ruleId: 'SA-COMMAND-INJECTION',
        filePath: relativePath,
        startLine,
        endLine,
        evidence: match[0],
        description: 'Executing system shell commands with concatenated or template string variables can lead to Command Injection.',
        impact: 'Allows attackers to inject shell metacharacters (; & | `) to execute arbitrary commands with process privileges.',
        remediation: 'Use child_process.execFile or child_process.spawn with an array of arguments, avoiding shell interpolation.',
        codeSnippet,
        references: [
          'https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html#avoid-command-injection',
          'https://cwe.mitre.org/data/definitions/78.html',
        ],
      });
    }

    // 6. SQL Injection patterns (string concatenation in queries)
    const sqlInjectRegex = /(?:db|pool|client|sequelize|knex|connection|mongoose)?\.(?:query|raw|execute)\s*\(\s*(?:`[^`]*(?:SELECT|INSERT|UPDATE|DELETE|DROP|FROM|WHERE)[^`]*\${|['"][^'"]*(?:SELECT|INSERT|UPDATE|DELETE|DROP|FROM|WHERE)[^'"]*['"]\s*\+)/gi;
    while ((match = sqlInjectRegex.exec(content)) !== null) {
      const { startLine, endLine, codeSnippet } = getLineAndSnippet(content, match.index, match[0].length);
      findings.push({
        category: 'source-code',
        title: 'SQL Injection via Query Concatenation',
        severity: 'critical',
        confidence: 'high',
        scanner: 'staticAnalysisScanner',
        ruleId: 'SA-SQL-INJECTION',
        filePath: relativePath,
        startLine,
        endLine,
        evidence: match[0],
        description: 'Database query constructed using string concatenation or unescaped template literals.',
        impact: 'Enables attackers to bypass authentication, read or destroy sensitive database tables, and execute arbitrary SQL commands.',
        remediation: 'Use parameterized queries or prepared statements with placeholder variables ($1, ?, :param).',
        codeSnippet,
        references: [
          'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html',
          'https://cwe.mitre.org/data/definitions/89.html',
        ],
      });
    }

    // 7. Prototype pollution patterns
    const protoPollutionRegex = /(?:Object\.assign\s*\([^,\n]+,\s*(?:req\.body|req\.query|req\.params|input|payload)\b|(?:\b__proto__\b|prototype\[|constructor\[))/gi;
    while ((match = protoPollutionRegex.exec(content)) !== null) {
      const { startLine, endLine, codeSnippet } = getLineAndSnippet(content, match.index, match[0].length);
      findings.push({
        category: 'source-code',
        title: 'Potential Prototype Pollution Vulnerability',
        severity: 'high',
        confidence: 'medium',
        scanner: 'staticAnalysisScanner',
        ruleId: 'SA-PROTOTYPE-POLLUTION',
        filePath: relativePath,
        startLine,
        endLine,
        evidence: match[0],
        description: 'Merging untrusted user-supplied objects into target objects or directly referencing prototype properties.',
        impact: 'Can lead to prototype pollution, causing denial of service, privilege escalation, or remote code execution.',
        remediation: 'Validate input against an explicit schema (e.g., Zod/Joi), use Object.create(null), or freeze object prototypes.',
        codeSnippet,
        references: [
          'https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html#prototype-pollution',
          'https://cwe.mitre.org/data/definitions/1321.html',
        ],
      });
    }

    // 8. Unvalidated redirects
    const openRedirectRegex = /res\.redirect\s*\(\s*(?:req\.query|req\.body|req\.params|url|target|redirectUrl|returnTo)\b/gi;
    while ((match = openRedirectRegex.exec(content)) !== null) {
      const { startLine, endLine, codeSnippet } = getLineAndSnippet(content, match.index, match[0].length);
      findings.push({
        category: 'source-code',
        title: 'Open / Unvalidated Redirect Vulnerability',
        severity: 'medium',
        confidence: 'high',
        scanner: 'staticAnalysisScanner',
        ruleId: 'SA-OPEN-REDIRECT',
        filePath: relativePath,
        startLine,
        endLine,
        evidence: match[0],
        description: 'Passing user-controlled URL input directly to res.redirect() allows attackers to redirect users to malicious websites.',
        impact: 'Attackers craft trusted domain links that silently redirect users to phishing pages or malware download sites.',
        remediation: 'Validate target URLs against an explicit whitelist of allowed domains or relative paths starting with /.',
        codeSnippet,
        references: [
          'https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html',
          'https://cwe.mitre.org/data/definitions/601.html',
        ],
      });
    }

    // 9. Reflected XSS in template literals sent in HTTP response
    const xssTemplateRegex = /res\.(?:send|write)\s*\(\s*`[^`]*<[^>]+>[^`]*\${(?:req\.query|req\.body|req\.params|[a-zA-Z0-9_]+)}[^`]*`/gi;
    while ((match = xssTemplateRegex.exec(content)) !== null) {
      const { startLine, endLine, codeSnippet } = getLineAndSnippet(content, match.index, match[0].length);
      findings.push({
        category: 'source-code',
        title: 'Reflected XSS via Template Literals in HTML Response',
        severity: 'high',
        confidence: 'high',
        scanner: 'staticAnalysisScanner',
        ruleId: 'SA-XSS-TEMPLATE-LITERAL',
        filePath: relativePath,
        startLine,
        endLine,
        evidence: match[0],
        description: 'Dynamically interpolating variables into an HTML string sent in an HTTP response without HTML encoding.',
        impact: 'Enables Cross-Site Scripting (XSS), session hijacking, and theft of user credentials.',
        remediation: 'Use a template engine with automatic HTML entity encoding, or sanitize content with DOMPurify / escape-html.',
        codeSnippet,
        references: [
          'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html',
          'https://cwe.mitre.org/data/definitions/79.html',
        ],
      });
    }

    // 10. Weak cryptographic hash algorithms (MD5 / SHA1)
    const weakHashRegex = /crypto\.createHash\s*\(\s*['"`](?:md5|sha1)['"`]\s*\)/gi;
    while ((match = weakHashRegex.exec(content)) !== null) {
      const { startLine, endLine, codeSnippet } = getLineAndSnippet(content, match.index, match[0].length);
      findings.push({
        category: 'source-code',
        title: 'Weak Cryptographic Hash Algorithm (MD5 / SHA-1)',
        severity: 'high',
        confidence: 'high',
        scanner: 'staticAnalysisScanner',
        ruleId: 'SA-WEAK-HASH-ALGO',
        filePath: relativePath,
        startLine,
        endLine,
        evidence: match[0],
        description: 'MD5 and SHA-1 algorithms are cryptographically broken and vulnerable to practical collision attacks.',
        impact: 'Facilitates hash cracking, signature forgery, and authentication bypass if used for passwords or integrity verification.',
        remediation: 'Use SHA-256 / SHA-512 for general integrity hashing, and argon2 or bcrypt for password hashing.',
        codeSnippet,
        references: [
          'https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html',
          'https://cwe.mitre.org/data/definitions/327.html',
        ],
      });
    }

    // 11. Insecure random number generator for security tokens
    const insecureRandomRegex = /(?:token|secret|password|passwd|key|auth|session|salt|nonce|pin|code)\s*[:=][^;\n]*Math\.random\s*\(\s*\)/gi;
    while ((match = insecureRandomRegex.exec(content)) !== null) {
      const { startLine, endLine, codeSnippet } = getLineAndSnippet(content, match.index, match[0].length);
      findings.push({
        category: 'source-code',
        title: 'Cryptographically Weak PRNG Used for Security Token',
        severity: 'high',
        confidence: 'high',
        scanner: 'staticAnalysisScanner',
        ruleId: 'SA-INSECURE-RANDOM',
        filePath: relativePath,
        startLine,
        endLine,
        evidence: match[0],
        description: 'Math.random() is predictable and unsuitable for generating cryptographic keys, session IDs, or security tokens.',
        impact: 'Attackers can predict generated tokens to hijack sessions, reset accounts, or forge authorization credentials.',
        remediation: 'Use crypto.randomBytes() or crypto.randomUUID() for cryptographically secure random values.',
        codeSnippet,
        references: [
          'https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html#rule---use-cryptographically-secure-pseudo-random-number-generators',
          'https://cwe.mitre.org/data/definitions/338.html',
        ],
      });
    }

    // 12. Suppressed ESLint security rules
    const eslintDisableRegex = /\/\*+\s*eslint-disable(?:-next-line)?\s+([^*]+)\*+\/|\/\/\s*eslint-disable(?:-next-line)?\s+(.+)$/gm;
    while ((match = eslintDisableRegex.exec(content)) !== null) {
      const disabledRules = (match[1] || match[2] || '').trim();
      const isSecurityRule =
        disabledRules.includes('security') ||
        disabledRules.includes('no-eval') ||
        disabledRules.includes('no-danger') ||
        disabledRules.length === 0; // blanket disable

      if (isSecurityRule) {
        const { startLine, endLine, codeSnippet } = getLineAndSnippet(content, match.index, match[0].length);
        findings.push({
          category: 'source-code',
          title: 'ESLint Security Rule Suppressed',
          severity: 'low',
          confidence: 'high',
          scanner: 'staticAnalysisScanner',
          ruleId: 'SA-ESLINT-DISABLED-SECURITY',
          filePath: relativePath,
          startLine,
          endLine,
          evidence: match[0],
          description: `Security linter check disabled via comment: "${disabledRules || 'all rules'}".`,
          impact: 'Disabling lint rules can mask underlying security vulnerabilities and prevent automated quality checks.',
          remediation: 'Resolve the root security issue rather than suppressing the linter warning.',
          codeSnippet,
          references: ['https://eslint.org/docs/latest/use/configure/rules#disabling-rules'],
        });
      }
    }
  }

  return findings;
}

module.exports = {
  scanStaticAnalysis,
};
