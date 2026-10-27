const { Finding } = require('../models');

/**
 * Retrieves findings for a scan with filtering, search, and pagination
 * @param {string} scanId
 * @param {Object} filters - { severity, category, status, search, page, limit }
 * @returns {Promise<{ findings: Array<Object>, total: number, page: number, totalPages: number }>}
 */
async function getFindingsByScan(scanId, filters = {}) {
  const query = { scanId };

  if (filters.severity) {
    if (Array.isArray(filters.severity)) {
      query.severity = { $in: filters.severity };
    } else {
      query.severity = filters.severity;
    }
  }

  if (filters.category) {
    if (Array.isArray(filters.category)) {
      query.category = { $in: filters.category };
    } else {
      query.category = filters.category;
    }
  }

  if (filters.status) {
    query.status = filters.status;
  }

  if (filters.ruleId) {
    query.ruleId = filters.ruleId;
  }

  if (filters.search) {
    const searchRegex = new RegExp(filters.search, 'i');
    query.$or = [
      { title: searchRegex },
      { description: searchRegex },
      { filePath: searchRegex },
      { evidence: searchRegex },
    ];
  }

  const page = Math.max(1, parseInt(filters.page, 10) || 1);
  const limit = Math.min(200, Math.max(1, parseInt(filters.limit, 10) || 50));
  const skip = (page - 1) * limit;

  const [findings, total] = await Promise.all([
    Finding.find(query).sort({ severity: 1, createdAt: -1 }).skip(skip).limit(limit),
    Finding.countDocuments(query),
  ]);

  return {
    findings,
    total,
    page,
    totalPages: Math.ceil(total / limit) || 1,
  };
}

/**
 * Retrieves a single finding by its unique findingId
 * @param {string} findingId
 * @returns {Promise<Object>}
 */
async function getFindingById(findingId) {
  const finding = await Finding.findOne({ findingId });
  if (!finding) {
    throw new Error(`Finding not found with ID: ${findingId}`);
  }
  return finding;
}

/**
 * Updates the triage status of a finding
 * @param {string} findingId
 * @param {string} status - One of ['open', 'fix-proposed', 'fixed-verified', 'accepted-risk', 'false-positive']
 * @returns {Promise<Object>}
 */
async function updateFindingStatus(findingId, status) {
  const allowedStatuses = ['open', 'fix-proposed', 'fixed-verified', 'accepted-risk', 'false-positive'];
  if (!allowedStatuses.includes(status)) {
    throw new Error(
      `Invalid status '${status}'. Must be one of: ${allowedStatuses.join(', ')}`
    );
  }

  const finding = await Finding.findOne({ findingId });
  if (!finding) {
    throw new Error(`Finding not found with ID: ${findingId}`);
  }

  finding.status = status;
  await finding.save();
  return finding;
}

/**
 * Generates an automated remediation code proposal and explanation for a finding
 * @param {string} findingId
 * @returns {Promise<{ originalCode: string, fixedCode: string, explanation: string, risks: string }>}
 */
async function proposeFix(findingIdOrFinding) {
  let finding;
  if (findingIdOrFinding && typeof findingIdOrFinding === 'object') {
    finding = findingIdOrFinding;
  } else {
    finding = await Finding.findOne({ findingId: findingIdOrFinding });
  }

  if (!finding) {
    throw new Error(`Finding not found with ID: ${findingIdOrFinding}`);
  }

  const originalCode = finding.codeSnippet || finding.evidence || '';
  let fixedCode = '';
  let explanation = '';
  let risks = '';

  const ruleId = finding.ruleId || '';

  // Rule-specific remediation logic
  if (ruleId.startsWith('SEC-') || finding.category === 'secrets') {
    if (ruleId === 'SEC-JWT-SECRET') {
      fixedCode = `// In server configuration:
const jwtSecret = process.env.JWT_SECRET;
if (!jwtSecret) {
  throw new Error('FATAL: JWT_SECRET environment variable is missing.');
}

// In signing logic:
const token = jwt.sign(payload, jwtSecret, { expiresIn: '1h' });`;
      explanation = 'Load the JWT secret key from an environment variable (JWT_SECRET) with sufficient entropy (256-bit or greater).';
      risks = 'Existing tokens issued with the old hardcoded key will be invalidated once the secret is rotated.';
    } else if (ruleId === 'SEC-DATABASE-URI-CREDS') {
      fixedCode = `// Load database connection string from environment:
const dbUri = process.env.MONGODB_URI || process.env.DATABASE_URL;
if (!dbUri) {
  throw new Error('FATAL: Database connection URI is not set in environment.');
}

await mongoose.connect(dbUri);`;
      explanation = 'Move credentials out of source code. Define the connection URI in server environment variables or a secret vault.';
      risks = 'Ensure environment variables are configured in all host and CI/CD environments before deployment.';
    } else {
      fixedCode = `// Store secret in .env and access via process.env:
const secretValue = process.env.SERVICE_API_KEY;
if (!secretValue) {
  throw new Error('Required API secret is not set in environment variables.');
}`;
      explanation = 'Avoid hardcoding secrets or credentials. Store them in environment variables or external secrets vaults (AWS Secrets Manager, HashiCorp Vault).';
      risks = 'Revoke the previously committed key immediately, as git commit history may have exposed it.';
    }
  } else if (ruleId === 'SA-EVAL-USAGE' || ruleId === 'PP-SAST-EVAL') {
    fixedCode = `// Safe structured parsing instead of dynamic evaluation:
// If parsing data, use JSON.parse:
const parsedData = JSON.parse(userString);

// If executing dynamic operations, use a safe dispatch map:
const operations = {
  add: (a, b) => a + b,
  multiply: (a, b) => a * b,
};
const result = operations[operationName]?.(arg1, arg2);`;
    explanation = 'Replace eval() with standard JSON.parse() or a dictionary of approved callable functions.';
    risks = 'JSON.parse() requires valid JSON format (quoted keys). Check input format compatibility.';
  } else if (ruleId === 'SA-INNERHTML-ASSIGNMENT' || ruleId === 'PP-SAST-XSS-DOM') {
    fixedCode = `// Option A: If content is plain text, use textContent (safest):
element.textContent = userMessage;

// Option B: If rendering HTML markup is strictly necessary, sanitize using DOMPurify:
import DOMPurify from 'dompurify';
element.innerHTML = DOMPurify.sanitize(userMarkup);`;
    explanation = 'Use textContent for text. If HTML is required, sanitize using DOMPurify to strip malicious scripts and event handlers.';
    risks = 'DOMPurify removes active script tags and dangerous attributes. Verify required style/layout tags are preserved.';
  } else if (ruleId === 'SA-DANGEROUSLY-SET-INNERHTML' || ruleId === 'PP-SAST-XSS-REACT') {
    fixedCode = `import DOMPurify from 'dompurify';

function SafeHtmlViewer({ htmlContent }) {
  const cleanHtml = DOMPurify.sanitize(htmlContent);
  return <div dangerouslySetInnerHTML={{ __html: cleanHtml }} />;
}`;
    explanation = 'Sanitize raw HTML using DOMPurify before passing to React dangerouslySetInnerHTML.';
    risks = 'Requires installing dompurify (or isomorphic-dompurify for SSR).';
  } else if (ruleId === 'SA-COMMAND-INJECTION' || ruleId === 'PP-SAST-CMD-INJECTION') {
    fixedCode = `const { execFile } = require('child_process');

// Pass arguments as a distinct array - NEVER concatenate user input into shell command strings:
execFile('/usr/bin/git', ['log', '-n', '5'], (err, stdout, stderr) => {
  if (err) {
    console.error('Command failed:', err);
    return;
  }
  console.log(stdout);
});`;
    explanation = 'Use child_process.execFile or spawn with argument arrays rather than exec(). This prevents shell metacharacter expansion.';
    risks = 'Shell built-in commands or pipes cannot be invoked directly without explicit stream chaining.';
  } else if (ruleId === 'SA-SQL-INJECTION' || ruleId === 'SA-SQL-INJECTION-CONCAT' || ruleId === 'PP-SAST-SQLI') {
    fixedCode = `// Use parameterized queries with bind placeholders:
const query = 'SELECT id, username, email FROM users WHERE id = ? AND status = ?';
const result = await db.query(query, [userId, 'active']);`;
    explanation = 'Use parameterized queries or prepared statements. Query parameters are treated strictly as data, never executable SQL.';
    risks = 'None. Parameterization also improves query execution caching.';
  } else if (ruleId === 'SA-NOSQL-INJECTION' || ruleId === 'PP-SAST-NOSQLI') {
    fixedCode = `// Force input to primitive string to prevent operator injection ($ne, $gt):
const sanitizedInput = String(req.body.username || '');
const user = await User.findOne({ username: sanitizedInput });`;
    explanation = 'Sanitize or type-cast user inputs to string/number before passing into NoSQL query filters.';
    risks = 'Ensures MongoDB query filters only accept literal values and rejects injected query operator objects.';
  } else if (ruleId === 'SA-PATH-TRAVERSAL' || ruleId === 'PP-SAST-PATH-TRAVERSAL') {
    fixedCode = `const path = require('path');
const baseDir = path.resolve('/safe/base/directory');
const targetFile = path.basename(req.params.fileName);
const resolvedPath = path.resolve(baseDir, targetFile);

if (!resolvedPath.startsWith(baseDir + path.sep)) {
  return res.status(400).send('Invalid file path');
}
res.sendFile(resolvedPath);`;
    explanation = 'Use path.basename to isolate the file name and verify resolved path starts with the intended base directory.';
    risks = 'Subdirectories inside the base path will be disallowed unless specifically mapped.';
  } else if (ruleId === 'SA-SSRF' || ruleId === 'PP-SAST-SSRF') {
    fixedCode = `// Whitelist allowed target hosts:
const ALLOWED_HOSTS = new Set(['api.example.com', 'storage.googleapis.com']);
const parsedUrl = new URL(req.query.targetUrl);

if (parsedUrl.protocol !== 'https:' || !ALLOWED_HOSTS.has(parsedUrl.hostname)) {
  return res.status(400).send('Disallowed destination host');
}
const response = await fetch(parsedUrl.toString());`;
    explanation = 'Validate protocol and restrict outbound requests to a strict whitelist of approved domain names.';
    risks = 'Destinations not explicitly listed in the whitelist will be blocked.';
  } else if (ruleId === 'PP-SAST-OPEN-REDIRECT') {
    fixedCode = `// Restrict redirect to relative application routes:
const destination = String(req.query.returnUrl || '/');
const safeUrl = (destination.startsWith('/') && !destination.startsWith('//')) ? destination : '/';
res.redirect(safeUrl);`;
    explanation = 'Ensure redirect URLs start with a single "/" and not "//" or external protocol schemes.';
    risks = 'External redirects must be explicitly permitted through an allowlist.';
  } else if (ruleId === 'CONF-CORS-WILDCARD') {
    fixedCode = `const cors = require('cors');

const allowedOrigins = (process.env.CORS_ORIGIN || 'http://localhost:5173')
  .split(',')
  .map(o => o.trim());

app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (like mobile apps or curl) or if origin is in whitelist
    if (!origin || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error('Cross-Origin Request Blocked by CORS Policy'));
  },
  credentials: true,
}));`;
    explanation = 'Replace wildcard origin ("*") with an explicit whitelist of trusted frontend domains loaded from configuration.';
    risks = 'Requests originating from non-whitelisted domains will be rejected by browsers.';
  } else if (ruleId === 'CONF-MISSING-HELMET') {
    fixedCode = `const helmet = require('helmet');

// Place helmet early in your middleware pipeline
app.use(helmet());`;
    explanation = 'Helmet automatically applies recommended HTTP security headers (CSP, HSTS, X-Content-Type-Options, etc.).';
    risks = 'Default Content-Security-Policy (CSP) may block inline scripts or CDNs unless explicitly configured.';
  } else if (ruleId === 'CONF-MISSING-RATE-LIMIT') {
    fixedCode = `const rateLimit = require('express-rate-limit');

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per 15 minutes
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error: { message: 'Too many requests, please try again later.', code: 'RATE_LIMIT_EXCEEDED' }
  }
});

app.use('/api/', generalLimiter);`;
    explanation = 'Add express-rate-limit to mitigate DoS, credential stuffing, and brute force attacks.';
    risks = 'Ensure app.set("trust proxy", 1) is enabled if running behind a reverse proxy (e.g. Nginx, Cloudflare).';
  } else if (ruleId === 'SA-WEAK-HASH-ALGO' || ruleId === 'PP-SAST-WEAK-HASH') {
    fixedCode = `// For Password Hashing (recommended):
const bcrypt = require('bcrypt');
const hashedPassword = await bcrypt.hash(plainTextPassword, 12);

// For Cryptographic Checksums (replace MD5/SHA1):
const crypto = require('crypto');
const checksum = crypto.createHash('sha256').update(fileData).digest('hex');`;
    explanation = 'Use bcrypt or argon2 for passwords, and SHA-256 / SHA-512 for data integrity checks.';
    risks = 'Legacy MD5 hashes in the database will need an automatic upgrade strategy upon next user authentication.';
  } else if (ruleId === 'SA-INSECURE-RANDOM' || ruleId === 'PP-SAST-INSECURE-RANDOM') {
    fixedCode = `const crypto = require('crypto');

// Generate secure random authentication token:
const secureToken = crypto.randomBytes(32).toString('hex');

// Or generate standard UUID v4:
const secureId = crypto.randomUUID();`;
    explanation = 'Replace Math.random() with Node.js crypto.randomBytes() or crypto.randomUUID() for CSPRNG guarantees.';
    risks = 'None.';
  } else if (ruleId === 'CONF-INSECURE-COOKIE') {
    fixedCode = `res.cookie('authToken', token, {
  httpOnly: true, // Prevents JavaScript access (mitigates XSS)
  secure: process.env.NODE_ENV === 'production', // Transmit only over HTTPS
  sameSite: 'lax', // CSRF mitigation
  maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
});`;
    explanation = 'Configure cookies with httpOnly: true, secure: true, and sameSite to protect against XSS and CSRF attacks.';
    risks = 'In development without HTTPS, secure: true prevents cookie delivery unless conditioned on NODE_ENV.';
  } else {
    // Default remediation template
    fixedCode = `// Remediation for rule ${ruleId}
// ${finding.remediation || 'Apply secure coding best practices'}`;
    explanation = finding.remediation || 'Review finding details and apply recommended secure coding patterns.';
    risks = 'Test changes thoroughly in development before deploying to production.';
  }

  // Update finding with proposed fix
  finding.fixedCode = fixedCode;
  if (finding.status === 'open') {
    finding.status = 'fix-proposed';
  }
  if (typeof finding.save === 'function') {
    await finding.save();
  }

  return {
    originalCode,
    fixedCode,
    explanation,
    risks,
  };
}

module.exports = {
  getFindingsByScan,
  getFindingById,
  updateFindingStatus,
  proposeFix,
};
