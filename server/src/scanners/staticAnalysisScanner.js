const {
  getProjectFiles,
  readFileSafe,
  isInsideComment,
  getLineAndSnippet,
} = require('./scannerUtils');

const JS_TS_EXTENSIONS = ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'];

/**
 * Extracts the single line of code at line number from content
 * @param {string} content
 * @param {number} lineNumber
 * @returns {string}
 */
function getLineEvidence(content, lineNumber) {
  if (!content || lineNumber < 1) return '';
  const lines = content.split('\n');
  return (lines[lineNumber - 1] || '').trim();
}

/**
 * Custom static analysis rules for JavaScript / TypeScript source code
 * Uses comment-aware semantic inspection and AST-level pattern matching
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
    // Matches eval(...) or new Function(...) when NOT inside comments
    const evalRegex = /\b(?:eval|new\s+Function)\s*\(/g;
    let match;
    while ((match = evalRegex.exec(content)) !== null) {
      if (isInsideComment(content, match.index)) continue;

      const { startLine, endLine, codeSnippet } = getLineAndSnippet(content, match.index, match[0].length);
      const evidence = getLineEvidence(content, startLine);

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
        evidence: evidence || match[0],
        description: 'Direct invocation of eval() or new Function() allows arbitrary JavaScript execution in the current application context. If dynamic input reaches this execution point, an attacker can execute arbitrary server or client code.',
        impact: 'If user-controllable input reaches dynamic evaluation, it leads directly to Remote Code Execution (RCE) on servers or Universal Cross-Site Scripting (XSS) in browsers.',
        remediation: 'Eliminate eval(). Use JSON.parse() for structured data, or refactor to explicit functions, object lookups, or mathematical parser libraries.',
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
      if (isInsideComment(content, match.index)) continue;

      const { startLine, endLine, codeSnippet } = getLineAndSnippet(content, match.index, match[0].length);
      const evidence = getLineEvidence(content, startLine);

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
        evidence: evidence || match[0],
        description: 'Assigning raw string markup directly to innerHTML or outerHTML bypasses standard browser escaping. Any untrusted data embedded in the string will be parsed as active HTML and script.',
        impact: 'Enables DOM-based Cross-Site Scripting (DOM XSS), allowing attackers to steal session tokens, manipulate page contents, or perform unauthorized actions as the victim.',
        remediation: 'Use textContent or innerText for plain text. If HTML rendering is required, sanitize markup with DOMPurify.sanitize() before assignment.',
        codeSnippet,
        references: [
          'https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html',
          'https://cwe.mitre.org/data/definitions/79.html',
        ],
      });
    }

    // 3. React dangerouslySetInnerHTML
    const reactDangerRegex = /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:/g;
    while ((match = reactDangerRegex.exec(content)) !== null) {
      if (isInsideComment(content, match.index)) continue;

      const { startLine, endLine, codeSnippet } = getLineAndSnippet(content, match.index, match[0].length);
      const evidence = getLineEvidence(content, startLine);

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
        evidence: evidence || match[0],
        description: 'React normally escapes values rendered in JSX to prevent XSS. Using dangerouslySetInnerHTML disables this native protection and injects raw unescaped HTML into the DOM.',
        impact: 'If user-supplied data reaches this property without strict server/client sanitization, attackers can inject malicious scripts into other users\' sessions.',
        remediation: 'Sanitize HTML input with DOMPurify.sanitize() before assigning to __html, or refactor to standard React JSX elements.',
        codeSnippet,
        references: [
          'https://react.dev/reference/react-dom/components/common#dangerously-setting-the-inner-html',
          'https://cwe.mitre.org/data/definitions/79.html',
        ],
      });
    }

    // 4. document.write / document.writeln
    const docWriteRegex = /document\.(?:write|writeln)\s*\(/g;
    while ((match = docWriteRegex.exec(content)) !== null) {
      if (isInsideComment(content, match.index)) continue;

      const { startLine, endLine, codeSnippet } = getLineAndSnippet(content, match.index, match[0].length);
      const evidence = getLineEvidence(content, startLine);

      findings.push({
        category: 'source-code',
        title: 'Unsafe document.write() Execution',
        severity: 'high',
        confidence: 'high',
        scanner: 'staticAnalysisScanner',
        ruleId: 'SA-DOCUMENT-WRITE',
        filePath: relativePath,
        startLine,
        endLine,
        evidence: evidence || match[0],
        description: 'document.write() writes directly to the open document stream and is a leading vector for DOM-based XSS when used with dynamic inputs.',
        impact: 'Facilitates client-side injection attacks and interferes with modern browser rendering and security policies.',
        remediation: 'Use modern DOM manipulation APIs such as document.createElement(), appendChild(), or framework state rendering.',
        codeSnippet,
        references: ['https://cwe.mitre.org/data/definitions/79.html'],
      });
    }

    // 5. Command Injection via child_process.exec with string concatenation
    const commandExecRegex = /(?:child_process|cp)\.exec\s*\(\s*(?:['"`][^'"`\r\n]*['"`]\s*\+|[a-zA-Z0-9_]+\s*\+|`[^`]*\${)/g;
    while ((match = commandExecRegex.exec(content)) !== null) {
      if (isInsideComment(content, match.index)) continue;

      const { startLine, endLine, codeSnippet } = getLineAndSnippet(content, match.index, match[0].length);
      const evidence = getLineEvidence(content, startLine);

      findings.push({
        category: 'source-code',
        title: 'Command Injection Risk in child_process.exec()',
        severity: 'critical',
        confidence: 'high',
        scanner: 'staticAnalysisScanner',
        ruleId: 'SA-COMMAND-INJECTION',
        filePath: relativePath,
        startLine,
        endLine,
        evidence: evidence || match[0],
        description: 'Dynamic string concatenation or template literal interpolation passed to child_process.exec() passes input directly to the operating system shell.',
        impact: 'Attackers can append shell metacharacters (;, |, &, `) to execute arbitrary commands with the privileges of the Node.js server process.',
        remediation: 'Use child_process.execFile() or spawn() with arguments passed as a separate array of strings rather than a concatenated command string.',
        codeSnippet,
        references: [
          'https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html',
          'https://cwe.mitre.org/data/definitions/78.html',
        ],
      });
    }

    // 6. SQL Injection via string concatenation
    const sqlConcatRegex = /(?:db|connection|pool|client)\.(?:query|execute|raw)\s*\(\s*(?:['"`](?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)[^'"`\r\n]*['"`]\s*\+|`[^`]*(?:SELECT|INSERT|UPDATE|DELETE)[^`]*\${)/gi;
    while ((match = sqlConcatRegex.exec(content)) !== null) {
      if (isInsideComment(content, match.index)) continue;

      const { startLine, endLine, codeSnippet } = getLineAndSnippet(content, match.index, match[0].length);
      const evidence = getLineEvidence(content, startLine);

      findings.push({
        category: 'source-code',
        title: 'SQL Injection Vulnerability via Query Concatenation',
        severity: 'critical',
        confidence: 'high',
        scanner: 'staticAnalysisScanner',
        ruleId: 'SA-SQL-INJECTION-CONCAT',
        filePath: relativePath,
        startLine,
        endLine,
        evidence: evidence || match[0],
        description: 'SQL query construction uses string concatenation (+) or template literals (${}) to merge dynamic variables directly into the query string.',
        impact: 'Attackers can break out of data context to execute arbitrary SQL commands, bypass authentication, exfiltrate the full database, or modify records.',
        remediation: 'Use parameterized queries with placeholders ($1, ?, :param) or an established ORM (Prisma, Mongoose, TypeORM) with parameterized bindings.',
        codeSnippet,
        references: [
          'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html',
          'https://cwe.mitre.org/data/definitions/89.html',
        ],
      });
    }

    // 7. Prototype Pollution patterns
    const prototypePollutionRegex = /(?:Object\.assign|lodash\.merge|_\.merge|\.extend)\s*\(\s*(?:\{\s*\}|[a-zA-Z0-9_]+)\s*,\s*(?:req\.body|req\.query|parsedBody|payload|input)\b/gi;
    while ((match = prototypePollutionRegex.exec(content)) !== null) {
      if (isInsideComment(content, match.index)) continue;

      const { startLine, endLine, codeSnippet } = getLineAndSnippet(content, match.index, match[0].length);
      const evidence = getLineEvidence(content, startLine);

      findings.push({
        category: 'source-code',
        title: 'Prototype Pollution via Unfiltered Deep Object Merge',
        severity: 'high',
        confidence: 'high',
        scanner: 'staticAnalysisScanner',
        ruleId: 'SA-PROTOTYPE-POLLUTION',
        filePath: relativePath,
        startLine,
        endLine,
        evidence: evidence || match[0],
        description: 'Merging untrusted user-controlled objects directly into target objects without validating special keys (__proto__, constructor, prototype).',
        impact: 'Attackers can inject properties into Object.prototype, leading to property injection, logic bypasses, Denial of Service, or remote code execution.',
        remediation: 'Validate input against an explicit schema (e.g. Zod, Joi), freeze prototypes with Object.freeze(), or use Object.create(null) for dictionary objects.',
        codeSnippet,
        references: [
          'https://portswigger.net/web-security/prototype-pollution',
          'https://cwe.mitre.org/data/definitions/1321.html',
        ],
      });
    }

    // 8. Unvalidated redirects
    const openRedirectRegex = /res\.redirect\s*\(\s*(?:req\.query|req\.body|req\.params|url|target|redirectUrl|returnTo)\b/gi;
    while ((match = openRedirectRegex.exec(content)) !== null) {
      if (isInsideComment(content, match.index)) continue;

      const { startLine, endLine, codeSnippet } = getLineAndSnippet(content, match.index, match[0].length);
      const evidence = getLineEvidence(content, startLine);

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
        evidence: evidence || match[0],
        description: 'Passing user-controlled URL input directly to res.redirect() allows attackers to redirect users to malicious external websites.',
        impact: 'Attackers craft trusted domain links that silently redirect users to phishing pages or malware download sites.',
        remediation: 'Validate target URLs against an explicit whitelist of allowed domains or relative paths starting with a single forward slash (/).',
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
      if (isInsideComment(content, match.index)) continue;

      const { startLine, endLine, codeSnippet } = getLineAndSnippet(content, match.index, match[0].length);
      const evidence = getLineEvidence(content, startLine);

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
        evidence: evidence || match[0],
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
      if (isInsideComment(content, match.index)) continue;

      const { startLine, endLine, codeSnippet } = getLineAndSnippet(content, match.index, match[0].length);
      const evidence = getLineEvidence(content, startLine);

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
        evidence: evidence || match[0],
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
      if (isInsideComment(content, match.index)) continue;

      const { startLine, endLine, codeSnippet } = getLineAndSnippet(content, match.index, match[0].length);
      const evidence = getLineEvidence(content, startLine);

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
        evidence: evidence || match[0],
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
        const evidence = getLineEvidence(content, startLine);

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
          evidence: evidence || match[0],
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
