const path = require('path');
const {
  getProjectFiles,
  readFileSafe,
  redactSecret,
  isLikelyTestOrPlaceholder,
  isInsideComment,
  getLineAndSnippet,
} = require('./scannerUtils');
const { shannonEntropy } = require('../utils/text');

/**
 * Scans project files for hardcoded secrets, API keys, credentials, and committed .env values.
 * @param {string} projectPath
 * @returns {Promise<Array<Object>>}
 */
async function scanForSecrets(projectPath) {
  const findings = [];
  const files = getProjectFiles(projectPath, { includeEnvFiles: true });

  for (const file of files) {
    const { absolutePath, relativePath } = file;
    const baseName = path.basename(relativePath).toLowerCase();

    // Check for committed .env files (not examples/samples)
    const isEnvSample =
      baseName.includes('example') ||
      baseName.includes('sample') ||
      baseName.includes('template');

    if (baseName.startsWith('.env') && !isEnvSample) {
      const envContent = readFileSafe(absolutePath);
      if (envContent) {
        const lines = envContent.split('\n');
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i].trim();
          if (!line || line.startsWith('#')) continue;

          const eqIndex = line.indexOf('=');
          if (eqIndex > 0) {
            const key = line.slice(0, eqIndex).trim();
            const value = line.slice(eqIndex + 1).trim().replace(/^['"]|['"]$/g, '');

            if (value && value.length >= 3) {
              const looksSensitive =
                /(key|secret|password|pass|token|auth|cred|db|uri|dsn)/i.test(key) ||
                value.length >= 16;

              if (looksSensitive && !isLikelyTestOrPlaceholder(value)) {
                findings.push({
                  category: 'secrets',
                  title: `Hardcoded secret in committed environment file: ${key}`,
                  severity: 'high',
                  confidence: 'high',
                  scanner: 'secretScanner',
                  ruleId: 'SEC-ENV-FILE-VALUES',
                  filePath: relativePath,
                  startLine: i + 1,
                  endLine: i + 1,
                  evidence: `${key}=${redactSecret(value)}`,
                  description: `Found sensitive environment key '${key}' committed with a non-placeholder value in '${relativePath}'.`,
                  impact: 'Secrets committed in repository files may be leaked to unauthorized collaborators or through version control history.',
                  remediation: `Remove '${key}' from '${relativePath}', add '${baseName}' to .gitignore, and provide dummy values in .env.example.`,
                  codeSnippet: `${key}=${redactSecret(value)}`,
                  references: [
                    'https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password',
                    'https://cwe.mitre.org/data/definitions/798.html',
                  ],
                });
              }
            }
          }
        }
      }
      // Continue to check other patterns or next file
    }

    // Skip scanning .env files again with regex if already parsed
    const content = readFileSafe(absolutePath);
    if (!content) continue;

    // Is this a test file? If so, lower confidence or skip obvious placeholders
    const isTestFile =
      relativePath.toLowerCase().includes('test') ||
      relativePath.toLowerCase().includes('spec') ||
      relativePath.toLowerCase().includes('mock');

    // 1. AWS Access Key Pattern
    const awsRegex = /(?:^|[^A-Z0-9])(AKIA[0-9A-Z]{16})(?:[^A-Z0-9]|$)/g;
    let match;
    while ((match = awsRegex.exec(content)) !== null) {
      if (isInsideComment(content, match.index)) continue;
      const fullMatch = match[1];
      if (isLikelyTestOrPlaceholder(fullMatch)) continue;

      const { startLine, endLine, codeSnippet } = getLineAndSnippet(content, match.index, fullMatch.length);
      findings.push({
        category: 'secrets',
        title: 'Hardcoded AWS Access Key ID Detected',
        severity: 'critical',
        confidence: isTestFile ? 'medium' : 'high',
        scanner: 'secretScanner',
        ruleId: 'SEC-AWS-ACCESS-KEY',
        filePath: relativePath,
        startLine,
        endLine,
        evidence: `AWS Access Key: ${redactSecret(fullMatch)}`,
        description: 'An AWS Access Key ID was found embedded in the source code.',
        impact: 'Attackers can use exposed AWS credentials to gain unauthorized access to cloud resources, escalate privileges, and exfiltrate data.',
        remediation: 'Immediately revoke the exposed key in the AWS IAM Console, rotate credentials, and use AWS IAM roles or environment variables.',
        codeSnippet,
        references: [
          'https://docs.aws.amazon.com/general/latest/gr/aws-access-keys-best-practices.html',
          'https://cwe.mitre.org/data/definitions/798.html',
        ],
      });
    }

    // 2. Private Key Pattern (RSA, DSA, EC, OPENSSH)
    const privateKeyRegex = /-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PGP)?\s*PRIVATE\s+KEY-----/g;
    while ((match = privateKeyRegex.exec(content)) !== null) {
      if (isInsideComment(content, match.index)) continue;
      const { startLine, endLine, codeSnippet } = getLineAndSnippet(content, match.index, match[0].length);
      findings.push({
        category: 'secrets',
        title: 'Private Encryption / SSH Key Embedded in Code',
        severity: 'critical',
        confidence: 'high',
        scanner: 'secretScanner',
        ruleId: 'SEC-PRIVATE-KEY',
        filePath: relativePath,
        startLine,
        endLine,
        evidence: match[0],
        description: 'An unencrypted private key header was identified in the codebase.',
        impact: 'Exposure of private keys can lead to complete compromise of TLS certificates, SSH servers, code signing identities, or encrypted data.',
        remediation: 'Remove private keys from git history, revoke and reissue corresponding certificates/keypairs, and use secret management vaults.',
        codeSnippet,
        references: [
          'https://cwe.mitre.org/data/definitions/312.html',
          'https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html',
        ],
      });
    }

    // 3. Database URI with credentials
    const dbUriRegex = /(mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|mariadb):\/\/([^:\s'"/]+):([^@\s'"/]+)@([^\s/'"]+)/gi;
    while ((match = dbUriRegex.exec(content)) !== null) {
      if (isInsideComment(content, match.index)) continue;
      const scheme = match[1];
      const username = match[2];
      const password = match[3];
      const host = match[4];

      if (isLikelyTestOrPlaceholder(password) && isLikelyTestOrPlaceholder(username)) {
        continue;
      }

      const { startLine, endLine, codeSnippet } = getLineAndSnippet(content, match.index, match[0].length);
      findings.push({
        category: 'secrets',
        title: `Database Connection String with Credentials (${scheme})`,
        severity: 'critical',
        confidence: isTestFile ? 'medium' : 'high',
        scanner: 'secretScanner',
        ruleId: 'SEC-DATABASE-URI-CREDS',
        filePath: relativePath,
        startLine,
        endLine,
        evidence: `${scheme}://${username}:${redactSecret(password)}@${host}`,
        description: `Hardcoded database URI with credentials found for protocol '${scheme}'.`,
        impact: 'Exposed database connection strings allow direct unauthorized access to production databases, risking data breach and loss.',
        remediation: 'Supply database connection strings via environment variables (e.g. MONGODB_URI, DATABASE_URL) instead of committing them in code.',
        codeSnippet,
        references: [
          'https://cwe.mitre.org/data/definitions/798.html',
          'https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure',
        ],
      });
    }

    // 4. JWT Secret assignment or inline usage
    const jwtSecretRegex = /(?:jwt_secret|jwtSecret|JWT_SECRET)\s*[:=]\s*['"`]([^'"`\r\n]{4,})['"`]/gi;
    while ((match = jwtSecretRegex.exec(content)) !== null) {
      if (isInsideComment(content, match.index)) continue;
      const secret = match[1];
      if (isLikelyTestOrPlaceholder(secret)) continue;

      const { startLine, endLine, codeSnippet } = getLineAndSnippet(content, match.index, match[0].length);
      findings.push({
        category: 'secrets',
        title: 'Hardcoded JWT Secret',
        severity: 'high',
        confidence: 'high',
        scanner: 'secretScanner',
        ruleId: 'SEC-JWT-SECRET',
        filePath: relativePath,
        startLine,
        endLine,
        evidence: `JWT secret: ${redactSecret(secret)}`,
        description: 'A JSON Web Token (JWT) signing secret appears hardcoded in the application.',
        impact: 'Attackers can forge valid JWT tokens for any user or role, completely bypassing authentication and authorization controls.',
        remediation: 'Store JWT signing keys in environment variables (e.g., process.env.JWT_SECRET) with sufficient entropy (at least 256 bits).',
        codeSnippet,
        references: [
          'https://auth0.com/blog/brute-forcing-hs256-is-possible-heres-how-to-prevent-it/',
          'https://cwe.mitre.org/data/definitions/798.html',
        ],
      });
    }

    // 5. Provider-Specific API Keys (GitHub, Stripe, Slack, OpenAI)
    const providerPatterns = [
      {
        regex: /(?:^|[^a-zA-Z0-9])(gh[pousr]_[A-Za-z0-9_]{36,255})(?:[^a-zA-Z0-9]|$)/g,
        ruleId: 'SEC-GITHUB-TOKEN',
        title: 'Hardcoded GitHub Personal Access / OAuth Token',
        name: 'GitHub Token',
      },
      {
        regex: /(?:^|[^a-zA-Z0-9])(sk_live_[0-9a-zA-Z]{24,})(?:[^a-zA-Z0-9]|$)/g,
        ruleId: 'SEC-STRIPE-LIVE-KEY',
        title: 'Hardcoded Stripe Live Secret Key',
        name: 'Stripe Live Secret Key',
      },
      {
        regex: /(?:^|[^a-zA-Z0-9])(xox[baprs]-[0-9a-zA-Z]{10,48})(?:[^a-zA-Z0-9]|$)/g,
        ruleId: 'SEC-SLACK-TOKEN',
        title: 'Hardcoded Slack Bot / API Token',
        name: 'Slack Token',
      },
      {
        regex: /(?:^|[^a-zA-Z0-9])(sk-[a-zA-Z0-9]{32,})(?:[^a-zA-Z0-9]|$)/g,
        ruleId: 'SEC-OPENAI-KEY',
        title: 'Hardcoded OpenAI API Secret Key',
        name: 'OpenAI API Key',
      },
    ];

    for (const prov of providerPatterns) {
      prov.regex.lastIndex = 0;
      while ((match = prov.regex.exec(content)) !== null) {
        if (isInsideComment(content, match.index)) continue;
        const secretVal = match[1];
        if (isLikelyTestOrPlaceholder(secretVal)) continue;

        const { startLine, endLine, codeSnippet } = getLineAndSnippet(content, match.index, secretVal.length);
        findings.push({
          category: 'secrets',
          title: prov.title,
          severity: 'critical',
          confidence: 'high',
          scanner: 'secretScanner',
          ruleId: prov.ruleId,
          filePath: relativePath,
          startLine,
          endLine,
          evidence: `${prov.name}: ${redactSecret(secretVal)}`,
          description: `An active ${prov.name} was discovered embedded in the source code.`,
          impact: 'Enables unauthorized access to third-party provider accounts, data exfiltration, and fraudulent API consumption.',
          remediation: `Immediately revoke this key in the provider console, rotate credentials, and load keys from environment variables.`,
          codeSnippet,
          references: ['https://cwe.mitre.org/data/definitions/798.html'],
        });
      }
    }

    // 6. Generic API Keys & Tokens with Shannon Entropy Filter
    const apiKeyRegex = /(?:api_key|apiKey|api-key|secret_key|secretKey|access_token|auth_token)\s*[:=]\s*['"`]([A-Za-z0-9_\-]{8,})['"`]/gi;
    while ((match = apiKeyRegex.exec(content)) !== null) {
      if (isInsideComment(content, match.index)) continue;
      const token = match[1];
      if (isLikelyTestOrPlaceholder(token)) continue;

      // Entropy check: true secrets have high information entropy (> 2.8)
      if (token.length > 8 && shannonEntropy(token) < 2.5) continue;

      const { startLine, endLine, codeSnippet } = getLineAndSnippet(content, match.index, match[0].length);
      findings.push({
        category: 'secrets',
        title: 'Hardcoded API Key or Access Token',
        severity: 'high',
        confidence: 'medium',
        scanner: 'secretScanner',
        ruleId: 'SEC-GENERIC-API-KEY',
        filePath: relativePath,
        startLine,
        endLine,
        evidence: `API Key / Token: ${redactSecret(token)}`,
        description: 'Hardcoded API key or authorization token detected in source code.',
        impact: 'Exposed API tokens can lead to unauthorized access to third-party APIs, data theft, and unexpected billing charges.',
        remediation: 'Move all API credentials to environment variables or an enterprise secret store.',
        codeSnippet,
        references: ['https://cwe.mitre.org/data/definitions/798.html'],
      });
    }

    // 6. Hardcoded password assignment
    const passwordRegex = /(?:password|passwd|db_pass|db_password|dbPassword)\s*[:=]\s*['"`]([^'"`\r\n]{4,})['"`]/gi;
    while ((match = passwordRegex.exec(content)) !== null) {
      if (isInsideComment(content, match.index)) continue;
      const pass = match[1];
      if (isLikelyTestOrPlaceholder(pass)) continue;
      // Skip common schema definitions or CSS/HTML attributes
      if (pass === 'string' || pass === 'password' || pass === 'text') continue;

      const { startLine, endLine, codeSnippet } = getLineAndSnippet(content, match.index, match[0].length);
      findings.push({
        category: 'secrets',
        title: 'Hardcoded Password in Code',
        severity: 'high',
        confidence: isTestFile ? 'low' : 'medium',
        scanner: 'secretScanner',
        ruleId: 'SEC-PASSWORD-HARDCODED',
        filePath: relativePath,
        startLine,
        endLine,
        evidence: `Password: ${redactSecret(pass)}`,
        description: 'A hardcoded password was found assigned to a variable in code.',
        impact: 'Hardcoded credentials can easily be harvested by attackers with repository access or decompilation tools.',
        remediation: 'Load passwords securely from environment variables, system keyrings, or secrets managers.',
        codeSnippet,
        references: ['https://cwe.mitre.org/data/definitions/259.html'],
      });
    }
  }

  return findings;
}

module.exports = {
  scanForSecrets,
};
