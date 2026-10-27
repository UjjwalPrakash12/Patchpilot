'use strict';

const fs = require('fs');
const path = require('path');
const {
  traverse,
  parseAst,
  isJsFile,
  unwrap,
  isMember,
  memberProp,
  dotted,
  isStaticString,
  staticStringValue,
  literalFragments,
  isDynamicString,
  callTarget,
  isUnboundGlobal,
  createTaintAnalysis,
} = require('../utils/jsAst');
const { splitLines, truncate } = require('../utils/text');
const { getProjectFiles, readFileSafe } = require('./scannerUtils');

const SCANNER = 'staticAnalysisScanner';
const MAX_PER_FILE = 60;

// ------------------------------------------------------------------------------------------------------
// Rule catalogue. Plain-English text is part of the product: it is what the user reads in the report.
// ------------------------------------------------------------------------------------------------------
const rule = (r) => ({ category: 'source-code', detection: 'heuristic', owasp: 'A03', ...r });

const RULES = {
  EVAL: rule({
    ruleId: 'PP-SAST-EVAL',
    title: 'Dynamic code execution (eval / new Function)',
    severity: 'critical',
    confidence: 'medium',
    cwe: 95,
    description: 'eval(), new Function() and similar calls turn a string into running code. If any part of that string comes from a user, the user can run their own code on your server or in other people’s browsers.',
    impact: 'Remote code execution on the server, or script execution in a visitor’s browser.',
    remediation: 'Remove dynamic code execution. Parse data with JSON.parse, look behaviour up in a fixed map of allowed functions, or use a purpose-built library for the job (maths expressions, templates).',
    example: '// Instead of: eval(userInput)\nconst data = JSON.parse(userInput); // data only, never code\n\nconst handlers = { add, remove };\nconst fn = handlers[action];\nif (!fn) throw new Error("Unknown action");\nfn(payload);',
  }),
  CMD: rule({
    ruleId: 'PP-SAST-CMD-INJECTION',
    title: 'OS command built from dynamic input',
    severity: 'critical',
    confidence: 'medium',
    cwe: 78,
    description: 'A shell command is built from a string that is not constant. exec() runs the whole string in a shell, so characters such as ; | && $( ) in the input become extra commands.',
    impact: 'An attacker can run arbitrary commands with your server’s permissions.',
    remediation: 'Avoid the shell: call execFile or spawn with the program name and an argument array (no shell option), and validate arguments against an allow-list.',
    example: 'const { execFile } = require("child_process");\nexecFile("convert", [inputPath, outputPath], (err, stdout) => { /* ... */ });',
  }),
  XSS_DOM: rule({
    ruleId: 'PP-SAST-XSS-DOM',
    title: 'Unsafe HTML insertion (DOM XSS)',
    severity: 'high',
    confidence: 'medium',
    cwe: 79,
    description: 'Assigning a string to innerHTML / outerHTML, insertAdjacentHTML or document.write makes the browser parse it as HTML, including scripts and event handlers.',
    impact: 'Cross-site scripting: an attacker’s script runs as the victim, so it can steal sessions, read private data or act on their behalf.',
    remediation: 'Use textContent for plain text. If you genuinely need HTML, sanitise it first with DOMPurify.sanitize().',
    example: 'el.textContent = userText;\n// when HTML is genuinely required:\nel.innerHTML = DOMPurify.sanitize(html);',
  }),
  XSS_REACT: rule({
    ruleId: 'PP-SAST-XSS-REACT',
    title: 'Unsanitised HTML rendered with dangerouslySetInnerHTML',
    severity: 'medium',
    confidence: 'medium',
    cwe: 79,
    description: 'dangerouslySetInnerHTML bypasses React’s automatic escaping. If the HTML comes from users, a CMS, markdown or an AI model and is not sanitised, it can carry scripts.',
    impact: 'Cross-site scripting: attacker-controlled script runs in your visitors’ browsers.',
    remediation: 'Sanitise before rendering (DOMPurify.sanitize), or render markdown with a library that escapes HTML by default.',
    example: '<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />',
  }),
  SQLI: rule({
    ruleId: 'PP-SAST-SQLI',
    title: 'SQL query built by string concatenation',
    severity: 'high',
    confidence: 'medium',
    cwe: 89,
    description: 'A SQL statement is assembled from text and variables. Anything inside those variables becomes part of the query itself.',
    impact: 'Attackers can read, change or delete database data and sometimes take over the database server.',
    remediation: 'Use parameterised queries (placeholders such as $1 or ?) or your ORM’s query builder. Never put variables inside the SQL string.',
    example: '// pg\nawait db.query("SELECT * FROM users WHERE id = $1", [id]);\n// mysql2\nawait db.execute("SELECT * FROM users WHERE id = ?", [id]);',
  }),
  NOSQLI: rule({
    ruleId: 'PP-SAST-NOSQLI',
    title: 'Request value used directly in a MongoDB query',
    severity: 'medium',
    confidence: 'medium',
    cwe: 943,
    description: 'A value from the request is placed straight into a query filter. JSON bodies can contain objects like {"$ne": null}, which change what the filter means (for example, matching any password).',
    impact: 'Authentication bypass and data exposure through query-operator injection.',
    remediation: 'Force the expected type before querying (String(x), Number(x)), validate input with a schema (zod / Joi), or strip $-operators with express-mongo-sanitize.',
    example: 'const email = String(req.body.email);\nconst user = await User.findOne({ email });',
  }),
  PATH: rule({
    ruleId: 'PP-SAST-PATH-TRAVERSAL',
    title: 'File path built from request input',
    severity: 'high',
    confidence: 'medium',
    cwe: 22,
    owasp: 'A01',
    description: 'A path that includes request input is passed to a file-system call. Input such as ../../etc/passwd climbs out of the intended folder.',
    impact: 'Attackers can read, overwrite or delete files outside the intended directory, such as source code, .env files and keys.',
    remediation: 'Accept only a validated file name (path.basename), join it to a fixed base folder, then check the resolved path still starts with that folder.',
    example: 'const base = path.resolve("uploads");\nconst target = path.resolve(base, path.basename(req.params.name));\nif (!target.startsWith(base + path.sep)) return res.sendStatus(400);\nres.sendFile(target);',
  }),
  SSRF: rule({
    ruleId: 'PP-SAST-SSRF',
    title: 'Server makes a request to a user-supplied URL',
    severity: 'high',
    confidence: 'medium',
    cwe: 918,
    owasp: null,
    description: 'The URL for a server-side HTTP request comes from the request. An attacker can point it at internal services or cloud metadata endpoints that are not reachable from the internet.',
    impact: 'Access to internal admin panels, databases and cloud credentials (for example the 169.254.169.254 metadata service).',
    remediation: 'Do not accept full URLs from users. Map an id to a fixed list of allowed hosts, or validate scheme and host against an allow-list and block private IP ranges (also after redirects).',
    example: 'const ALLOWED = new Set(["api.example.com"]);\nconst url = new URL(String(req.query.url));\nif (url.protocol !== "https:" || !ALLOWED.has(url.hostname)) return res.sendStatus(400);',
  }),
  REDIRECT: rule({
    ruleId: 'PP-SAST-OPEN-REDIRECT',
    title: 'Redirect to a user-supplied address',
    severity: 'medium',
    confidence: 'medium',
    cwe: 601,
    owasp: 'A01',
    description: 'The destination of a redirect comes from the request, so a link on your domain can send people to any website.',
    impact: 'Phishing: victims trust the link because it starts with your domain.',
    remediation: 'Redirect only to relative paths you control, or to an allow-list of known destinations.',
    example: 'const next = String(req.query.next || "/");\nres.redirect(next.startsWith("/") && !next.startsWith("//") ? next : "/");',
  }),
  WEAK_HASH: rule({
    ruleId: 'PP-SAST-WEAK-HASH',
    title: 'Weak hash algorithm (MD5 / SHA-1)',
    severity: 'medium',
    confidence: 'high',
    cwe: 328,
    owasp: 'A02',
    detection: 'confirmed',
    description: 'MD5 and SHA-1 are broken for security use: attackers can craft collisions, and unsalted hashes can be cracked extremely fast.',
    impact: 'Forged signatures or checksums, and fast offline password cracking if used for passwords.',
    remediation: 'Use SHA-256 or stronger for integrity checks. For passwords never use a plain hash: use bcrypt, scrypt or argon2.',
    example: 'crypto.createHash("sha256").update(data).digest("hex");\n// passwords:\nconst hash = await bcrypt.hash(password, 12);',
  }),
  WEAK_CIPHER: rule({
    ruleId: 'PP-SAST-WEAK-CIPHER',
    title: 'Weak or misused encryption',
    severity: 'medium',
    confidence: 'high',
    cwe: 327,
    owasp: 'A02',
    detection: 'confirmed',
    description: 'The code uses crypto.createCipher (no random IV, deprecated) or an unsafe algorithm or mode (ECB, DES, RC4).',
    impact: 'Encrypted data can leak patterns or be decrypted by an attacker.',
    remediation: 'Use AES-256-GCM with a fresh random 12-byte IV per message via crypto.createCipheriv, and store the IV and auth tag with the ciphertext.',
    example: 'const iv = crypto.randomBytes(12);\nconst cipher = crypto.createCipheriv("aes-256-gcm", key, iv);',
  }),
  RANDOM: rule({
    ruleId: 'PP-SAST-INSECURE-RANDOM',
    title: 'Predictable random number used for a security value',
    severity: 'medium',
    confidence: 'medium',
    cwe: 338,
    owasp: 'A02',
    description: 'Math.random() is not cryptographically secure; its output can be predicted from a few samples.',
    impact: 'Attackers can guess tokens, reset codes or session identifiers.',
    remediation: 'Use crypto.randomBytes, crypto.randomUUID or crypto.randomInt for anything security-related.',
    example: 'const token = crypto.randomBytes(32).toString("hex");\nconst code = crypto.randomInt(100000, 1000000);',
  }),
  JWT_NONE: rule({
    ruleId: 'PP-SAST-JWT-NONE',
    title: 'JWT signature check can be bypassed (algorithm "none")',
    severity: 'critical',
    confidence: 'high',
    cwe: 347,
    owasp: 'A07',
    detection: 'confirmed',
    description: 'The code allows the "none" algorithm, which means tokens without any signature are accepted.',
    impact: 'Anyone can forge a login token for any user.',
    remediation: 'Specify an explicit allow-list of real algorithms, for example { algorithms: ["HS256"] }.',
    example: 'jwt.verify(token, process.env.JWT_SECRET, { algorithms: ["HS256"] });',
  }),
  JWT_SECRET: rule({
    ruleId: 'PP-SAST-JWT-HARDCODED-SECRET',
    title: 'JWT signing secret written in the code',
    severity: 'high',
    confidence: 'high',
    cwe: 798,
    owasp: 'A07',
    detection: 'confirmed',
    description: 'The key that signs login tokens is a literal string in the source.',
    impact: 'Anyone who can read the code can mint valid tokens for any user, including admins.',
    remediation: 'Load a long random secret from an environment variable and fail at startup if it is missing.',
    example: 'const secret = process.env.JWT_SECRET;\nif (!secret) throw new Error("JWT_SECRET is required");',
  }),
  JWT_EXPIRY: rule({
    ruleId: 'PP-SAST-JWT-IGNORE-EXPIRY',
    title: 'JWT expiry is not enforced',
    severity: 'medium',
    confidence: 'high',
    cwe: 613,
    owasp: 'A07',
    detection: 'confirmed',
    description: 'jwt.verify is called with ignoreExpiration: true, so expired tokens keep working forever.',
    impact: 'A stolen token never stops being valid.',
    remediation: 'Remove ignoreExpiration, issue short-lived access tokens and refresh them.',
    example: 'jwt.sign(payload, secret, { expiresIn: "15m" });',
  }),
  ENV_FALLBACK: rule({
    ruleId: 'PP-SAST-ENV-FALLBACK-SECRET',
    title: 'Secret falls back to a hard-coded value',
    severity: 'high',
    confidence: 'high',
    cwe: 798,
    owasp: 'A07',
    detection: 'confirmed',
    description: 'The code reads a secret from an environment variable but uses a literal default when it is missing (process.env.X || "default"). If the variable is not set in production, the app silently runs with a value that is public in your source.',
    impact: 'A forgotten environment variable turns into a known, shared secret.',
    remediation: 'Remove the fallback and fail fast at startup when the variable is missing.',
    example: 'const JWT_SECRET = process.env.JWT_SECRET;\nif (!JWT_SECRET) throw new Error("JWT_SECRET is not set");',
  }),
  TLS: rule({
    ruleId: 'PP-SAST-TLS-DISABLED',
    title: 'TLS certificate verification is disabled',
    severity: 'high',
    confidence: 'high',
    cwe: 295,
    owasp: 'A02',
    detection: 'confirmed',
    description: 'rejectUnauthorized: false (or NODE_TLS_REJECT_UNAUTHORIZED=0) tells Node to accept any certificate, including an attacker’s.',
    impact: 'Man-in-the-middle attackers can read and modify traffic that looks encrypted.',
    remediation: 'Remove the override. If you use a private certificate authority, supply it with the ca option or NODE_EXTRA_CA_CERTS instead.',
    example: 'https.request({ host, ca: fs.readFileSync("internal-ca.pem") });',
  }),
  MASS: rule({
    ruleId: 'PP-SAST-MASS-ASSIGNMENT',
    title: 'Whole request body written to the database',
    severity: 'medium',
    confidence: 'medium',
    cwe: 915,
    owasp: 'A01',
    description: 'req.body is passed unfiltered to a create/update call. A client can add fields you never intended, such as role: "admin" or isVerified: true.',
    impact: 'Privilege escalation and tampering with protected fields.',
    remediation: 'Pick the allowed fields explicitly, or validate with a schema that strips unknown keys, before saving.',
    example: 'const { name, email } = req.body;\nawait User.create({ name, email });',
  }),
  PROTO: rule({
    ruleId: 'PP-SAST-PROTOTYPE-POLLUTION',
    title: 'User input merged into an object (prototype pollution)',
    severity: 'high',
    confidence: 'medium',
    cwe: 1321,
    description: 'A deep-merge or path-setter from lodash receives request data. Keys such as __proto__ can modify the base object that every object inherits from.',
    impact: 'Can change application behaviour globally, bypass checks or lead to code execution in some setups.',
    remediation: 'Keep lodash up to date, validate input against a schema, or copy only known keys instead of merging user objects.',
    example: 'const { theme, language } = req.body;\nObject.assign(settings, { theme, language });',
  }),
  DESERIALIZE: rule({
    ruleId: 'PP-SAST-UNSAFE-DESERIALIZATION',
    title: 'Unsafe deserialisation (node-serialize)',
    severity: 'critical',
    confidence: 'high',
    cwe: 502,
    owasp: 'A08',
    detection: 'confirmed',
    description: 'node-serialize can execute code embedded in the serialized text when it is unserialised.',
    impact: 'Remote code execution if an attacker can influence the serialized data.',
    remediation: 'Use JSON.parse for data exchange and never unserialise untrusted input with node-serialize.',
    example: 'const data = JSON.parse(input);',
  }),
  TOKEN_STORAGE: rule({
    ruleId: 'PP-SAST-TOKEN-IN-LOCALSTORAGE',
    title: 'Auth token stored in localStorage / sessionStorage',
    severity: 'low',
    confidence: 'medium',
    cwe: 922,
    owasp: 'A07',
    description: 'Anything in localStorage can be read by any script running on the page, so a single XSS bug exposes every user’s session.',
    impact: 'Session theft if the site has any cross-site scripting weakness, including through a third-party script.',
    remediation: 'Keep session tokens in HttpOnly, Secure, SameSite cookies set by the server.',
    example: 'res.cookie("session", token, { httpOnly: true, secure: true, sameSite: "lax" });',
  }),
  LOG_SECRET: rule({
    ruleId: 'PP-SAST-SECRET-IN-LOG',
    title: 'Credential written to logs',
    severity: 'low',
    confidence: 'medium',
    cwe: 532,
    owasp: null,
    description: 'A password, token or key is passed to console.log. Logs are copied to many systems that are protected less carefully than your database.',
    impact: 'Credentials leak to log files, log aggregators and anyone who can read them.',
    remediation: 'Remove the log statement, or log only a non-sensitive identifier (for example the user id).',
    example: 'console.log("login attempt for user", user.id);',
  }),
};

// ------------------------------------------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------------------------------------------
const SQL_RE = /\b(?:select|insert|update|delete|drop|where|values|union|from)\b/i;
const SQL_METHODS = new Set(['query', 'execute', 'raw', '$queryRawUnsafe', '$executeRawUnsafe', 'unsafe']);
const NOSQL_METHODS = new Set([
  'find', 'findOne', 'findOneAndUpdate', 'findOneAndDelete', 'findOneAndReplace', 'updateOne', 'updateMany',
  'deleteOne', 'deleteMany', 'countDocuments', 'replaceOne',
]);
const FS_FUNCS = new Set([
  'readFile', 'readFileSync', 'createReadStream', 'createWriteStream', 'writeFile', 'writeFileSync', 'appendFile',
  'appendFileSync', 'unlink', 'unlinkSync', 'readdir', 'readdirSync', 'rm', 'rmSync', 'rmdir', 'stat', 'statSync',
  'access', 'copyFile', 'rename', 'open', 'openSync',
]);
const FS_MODULES = new Set(['fs', 'fs/promises', 'fs-extra']);
const HTTP_MODULES = new Set(['axios', 'got', 'node-fetch', 'undici', 'request', 'superagent', 'needle', 'ky', 'http', 'https', 'cross-fetch']);
const HTTP_METHODS = new Set(['get', 'post', 'put', 'patch', 'delete', 'head', 'request', 'fetch', 'stream']);
const MASS_METHODS = new Set(['create', 'insertMany', 'findByIdAndUpdate', 'findOneAndUpdate', 'updateOne', 'updateMany', 'bulkCreate', 'upsert', 'update']);
const LODASH_MUTATORS = new Set(['merge', 'mergeWith', 'defaultsDeep', 'set', 'setWith', 'zipObjectDeep']);
const NOT_MODELS = new Set(['Date', 'Map', 'Set', 'WeakMap', 'WeakSet', 'URL', 'URLSearchParams', 'Error', 'Buffer', 'RegExp', 'Promise', 'Array', 'Object', 'FormData', 'Headers', 'Request', 'Response', 'String', 'Number', 'Boolean', 'Proxy', 'Intl']);
const SANITIZE_HTML = new Set(['DOMPurify.sanitize', 'sanitizeHtml', 'sanitize', 'xss', 'escapeHtml']);
const SECURITY_NAME_RE = /(?:token|secret|passw|otp|nonce|salt|session|csrf|api[_-]?key|reset|verification|invite|credential|auth)/i;
const TOKEN_KEY_RE = /(?:token|jwt|auth|session|secret|password|refresh)/i;
const LOG_SECRET_NAME_RE = /^(?:password|passwd|pwd|secret|apiKey|api_key|token|accessToken|refreshToken|privateKey|authorization|clientSecret)$/i;
const SECRET_ENV_RE = /^(?!.*PUBLIC)(?=.*(?:SECRET|PRIVATE|PASSWORD|PASSWD|TOKEN|API_?KEY|AUTH_?KEY|JWT|SIGNING|ENCRYPTION)).*$/;
const MIN_BODY_SOURCES = ['req.body', 'req.query', 'req.cookies', 'request.body', 'request.query', 'ctx.request.body', 'ctx.query', 'event.body'];

function propValue(objNode, key) {
  const o = unwrap(objNode);
  if (!o || o.type !== 'ObjectExpression') return null;
  for (const p of o.properties) {
    if (p.type !== 'ObjectProperty') continue;
    const k = p.key.type === 'Identifier' ? p.key.name : p.key.value;
    if (k === key) return p.value;
  }
  return null;
}

function isSanitized(node) {
  const u = unwrap(node);
  return !!u && u.type === 'CallExpression' && SANITIZE_HTML.has(dotted(u.callee));
}

function isRawBody(node) {
  const d = dotted(node);
  return !!d && (/^(?:req|request)\.body$/.test(d) || d === 'ctx.request.body');
}

function leftmost(node0) {
  let n = unwrap(node0);
  while (n && n.type === 'BinaryExpression' && n.operator === '+') n = unwrap(n.left);
  return n;
}

/** A redirect that starts with a literal "/" (and not "//") stays on the same site. */
function staysOnSite(node0) {
  const n = unwrap(node0);
  if (!n) return false;
  const d = dotted(n);
  if (d === 'req.originalUrl' || d === 'req.url' || d === 'request.url') return true;
  if (n.type === 'TemplateLiteral') {
    const first = n.quasis[0].value.cooked || '';
    return first.startsWith('/') && !first.startsWith('//');
  }
  const l = leftmost(n);
  if (l && l.type === 'StringLiteral') return l.value.startsWith('/') && !l.value.startsWith('//');
  if (l && l !== n) return staysOnSite(l);
  return false;
}

function securityContextName(path) {
  let cur = path.parentPath;
  for (let hops = 0; cur && hops < 8; hops += 1, cur = cur.parentPath) {
    const nd = cur.node;
    let name = null;
    if (nd.type === 'VariableDeclarator' && nd.id.type === 'Identifier') name = nd.id.name;
    else if (nd.type === 'AssignmentExpression') name = dotted(nd.left);
    else if (nd.type === 'ObjectProperty') name = nd.key.name || nd.key.value;
    else if ((nd.type === 'FunctionDeclaration' || nd.type === 'ClassMethod' || nd.type === 'ObjectMethod') && nd.id) name = nd.id.name;
    else if (nd.type === 'CallExpression') {
      const d = dotted(nd.callee);
      if (d) name = d.split('.').pop();
    }
    if (name && SECURITY_NAME_RE.test(String(name))) return name;
    if (nd.type === 'Program') break;
  }
  return null;
}

// ------------------------------------------------------------------------------------------------------
// Per-file AST Analysis
// ------------------------------------------------------------------------------------------------------
function analyzeFile(file, source, ast) {
  const findings = [];
  const lines = splitLines(source);
  const relPath = file.relativePath || file;

  const serverTaint = createTaintAnalysis(ast, source, { server: true });
  const objectTaint = createTaintAnalysis(ast, source, { server: true, serverSources: MIN_BODY_SOURCES });
  const anyTaint = createTaintAnalysis(ast, source, { server: true, client: true });

  const emit = (r, node, overrides = {}) => {
    if (findings.length >= MAX_PER_FILE) return;
    const start = (node.loc && node.loc.start) ? node.loc.start.line : 1;
    const end = (node.loc && node.loc.end) ? Math.min(node.loc.end.line, start + 3) : start;
    const snippetLines = lines.slice(Math.max(0, start - 2), Math.min(lines.length, end + 1));
    const codeSnippet = snippetLines.join('\n').trim();
    const lineEvidence = (lines[start - 1] || text(node)).trim();

    const merged = { ...r, ...overrides };
    findings.push({
      category: 'source-code',
      title: merged.title || r.title,
      severity: merged.severity || r.severity,
      confidence: merged.confidence || r.confidence,
      scanner: SCANNER,
      ruleId: merged.ruleId || r.ruleId,
      filePath: relPath,
      startLine: start,
      endLine: end,
      evidence: lineEvidence,
      description: merged.description || r.description,
      impact: merged.impact || r.impact,
      remediation: merged.remediation || r.remediation,
      codeSnippet: codeSnippet || lineEvidence,
      references: [
        merged.cwe ? `https://cwe.mitre.org/data/definitions/${merged.cwe}.html` : 'https://owasp.org/www-project-top-ten/',
        merged.owasp ? `https://owasp.org/Top10/${merged.owasp}/` : 'https://cheatsheetseries.owasp.org/',
      ],
    });
  };

  const text = (node) => truncate((source.slice(node.start || 0, node.end || 0) || '').replace(/\s+/g, ' '), 70);
  const traced = (r, argNode) => ({
    confidence: 'high',
    detection: 'confirmed',
    description: `${r.description}\n\nPatchPilot traced tainted input from the request into this call: \`${text(argNode)}\` is derived from user-controlled data.`,
  });

  function evalFinding(path, n, bodyNode, what) {
    if (!bodyNode) return;
    if (anyTaint.isTainted(bodyNode, path.scope)) {
      emit(RULES.EVAL, n, { ...traced(RULES.EVAL, bodyNode), severity: 'critical', title: `${what} executes user-controlled input` });
    } else if (isStaticString(bodyNode)) {
      emit(RULES.EVAL, n, { severity: 'low', confidence: 'high', title: `${what} used with a constant string` });
    } else {
      emit(RULES.EVAL, n, { title: `${what} executes a dynamic string` });
    }
  }

  function xssDom(path, n, arg, label) {
    if (isSanitized(arg)) return;
    if (anyTaint.isTainted(arg, path.scope)) {
      emit(RULES.XSS_DOM, n, { ...traced(RULES.XSS_DOM, arg), title: `User input inserted as HTML via ${label}` });
    } else {
      emit(RULES.XSS_DOM, n, { title: `Non-constant HTML inserted via ${label}`, severity: 'medium' });
    }
  }

  traverse(ast, {
    CallExpression(p) {
      const n = p.node;
      const scope = p.scope;
      const callee = unwrap(n.callee);
      const d = dotted(callee);
      const args = n.arguments;
      const a0 = args[0];
      const target = callTarget(scope, callee);
      const lastProp = isMember(callee) ? memberProp(callee) : callee.type === 'Identifier' ? callee.name : null;
      const TS = (node) => serverTaint.isTainted(node, scope);

      // --- dynamic code execution --------------------------------------------------------------------
      if ((callee.type === 'Identifier' && callee.name === 'eval' && isUnboundGlobal(scope, 'eval')) ||
          d === 'window.eval' || d === 'globalThis.eval') {
        evalFinding(p, n, a0, 'eval()');
      }
      if (target && target.module === 'vm' && /^(?:runIn(?:New|This)?Context|compileFunction)$/.test(target.name || '')) {
        evalFinding(p, n, a0, `vm.${target.name}()`);
      }
      if ((d === 'setTimeout' || d === 'setInterval') && isUnboundGlobal(scope, d) && a0) {
        const u = unwrap(a0);
        const stringy = u.type === 'StringLiteral' || u.type === 'TemplateLiteral' || (u.type === 'BinaryExpression' && u.operator === '+');
        if (stringy || anyTaint.isTainted(a0, scope)) {
          emit(RULES.EVAL, n, { title: `${d}() called with a string (behaves like eval)`, severity: 'medium' });
        }
      }

      // --- OS command injection ----------------------------------------------------------------------
      if (target && (target.module === 'child_process' || target.module === 'shelljs') && (target.name === 'exec' || target.name === 'execSync')) {
        if (a0 && !isStaticString(a0)) {
          if (TS(a0)) emit(RULES.CMD, n, { ...traced(RULES.CMD, a0), severity: 'critical' });
          else emit(RULES.CMD, n, { title: 'Shell command built from a dynamic string' });
        }
      }
      if (target && target.module === 'child_process' && ['spawn', 'spawnSync', 'execFile', 'execFileSync'].includes(target.name)) {
        const opts = args.find((a) => unwrap(a).type === 'ObjectExpression');
        const shell = opts && unwrap(propValue(opts, 'shell') || {}).type === 'BooleanLiteral' && unwrap(propValue(opts, 'shell')).value === true;
        const arr = args.find((a) => unwrap(a).type === 'ArrayExpression');
        const dynamicArg = (a0 && !isStaticString(a0)) || (arr && unwrap(arr).elements.some((el) => el && !isStaticString(el)));
        if (a0 && TS(a0)) {
          emit(RULES.CMD, n, { ...traced(RULES.CMD, a0), severity: 'critical', title: 'Program to execute is chosen by user input' });
        } else if (shell && dynamicArg) {
          emit(RULES.CMD, n, { title: `${target.name}() with shell: true and dynamic arguments` });
        }
      }

      // --- DOM XSS sinks (calls) ---------------------------------------------------------------------
      if (lastProp === 'insertAdjacentHTML' && isMember(callee) && args[1] && !isStaticString(args[1])) {
        xssDom(p, n, args[1], 'insertAdjacentHTML');
      }
      if ((d === 'document.write' || d === 'document.writeln') && a0 && !isStaticString(a0)) {
        xssDom(p, n, a0, d);
      }

      // --- SQL injection -----------------------------------------------------------------------------
      if (isMember(callee) && SQL_METHODS.has(lastProp) && a0) {
        const unsafeName = lastProp.endsWith('Unsafe') || lastProp === 'unsafe';
        if (isDynamicString(a0) && (SQL_RE.test(literalFragments(a0)) || unsafeName)) {
          if (TS(a0)) emit(RULES.SQLI, n, { ...traced(RULES.SQLI, a0), severity: 'high' });
          else emit(RULES.SQLI, n, {});
        } else if (unsafeName && !isStaticString(a0) && TS(a0)) {
          emit(RULES.SQLI, n, { ...traced(RULES.SQLI, a0), severity: 'high', title: `Request input passed to ${lastProp}()` });
        }
      }

      // --- NoSQL operator injection ------------------------------------------------------------------
      if (isMember(callee) && NOSQL_METHODS.has(lastProp) && a0) {
        const u = unwrap(a0);
        const OT = (node) => objectTaint.isTainted(node, scope);
        const direct = (v) => {
          const x = unwrap(v);
          return x && (x.type === 'Identifier' || isMember(x)) && OT(x);
        };
        if (direct(u)) {
          emit(RULES.NOSQLI, n, { ...traced(RULES.NOSQLI, u), severity: 'high', title: 'Entire MongoDB filter comes from the request' });
        } else if (u.type === 'ObjectExpression') {
          for (const prop of u.properties) {
            if (prop.type === 'SpreadElement' && OT(prop.argument)) {
              emit(RULES.NOSQLI, n, { ...traced(RULES.NOSQLI, prop.argument), severity: 'high', title: 'Request object spread into a MongoDB filter' });
              break;
            }
            if (prop.type !== 'ObjectProperty') continue;
            const key = prop.key.type === 'Identifier' ? prop.key.name : prop.key.value;
            if (key === '$where' && !isStaticString(prop.value)) {
              emit(RULES.NOSQLI, n, { severity: 'high', confidence: 'high', title: 'MongoDB $where with a dynamic value' });
              break;
            }
            if (direct(prop.value)) {
              emit(RULES.NOSQLI, n, traced(RULES.NOSQLI, prop.value));
              break;
            }
          }
        }
      }

      // --- path traversal ----------------------------------------------------------------------------
      if (target && FS_MODULES.has(target.module) && FS_FUNCS.has(target.name) && a0 && TS(a0)) {
        emit(RULES.PATH, n, traced(RULES.PATH, a0));
      }
      if (isMember(callee) && (lastProp === 'sendFile' || lastProp === 'download') && a0 && TS(a0)) {
        const opts = args.find((a, i) => i > 0 && unwrap(a).type === 'ObjectExpression');
        if (!(opts && propValue(opts, 'root'))) emit(RULES.PATH, n, traced(RULES.PATH, a0));
      }

      // --- SSRF --------------------------------------------------------------------------------------
      const isFetch = callee.type === 'Identifier' && callee.name === 'fetch' && isUnboundGlobal(scope, 'fetch');
      const isHttp = target && HTTP_MODULES.has(target.module) && (target.name === null || HTTP_METHODS.has(target.name));
      if ((isFetch || isHttp) && a0) {
        const u0 = unwrap(a0);
        const urlNode = u0.type === 'ObjectExpression' ? (propValue(u0, 'url') || propValue(u0, 'uri')) : a0;
        if (urlNode) {
          const u = unwrap(urlNode);
          let controlled = false;
          if (u.type === 'TemplateLiteral') controlled = u.quasis[0].value.cooked === '' && u.expressions.length > 0 && TS(u.expressions[0]);
          else if (u.type === 'BinaryExpression' && u.operator === '+') controlled = TS(leftmost(u));
          else controlled = TS(u);
          if (controlled) emit(RULES.SSRF, n, traced(RULES.SSRF, urlNode));
        }
      }

      // --- open redirect -----------------------------------------------------------------------------
      if (isMember(callee) && lastProp === 'redirect' && args.length) {
        const urlArg = args[args.length - 1];
        if (TS(urlArg) && !staysOnSite(urlArg)) emit(RULES.REDIRECT, n, traced(RULES.REDIRECT, urlArg));
      }

      // --- cryptography ------------------------------------------------------------------------------
      if (target && target.module === 'crypto') {
        if (target.name === 'createHash' && a0) {
          const algo = staticStringValue(a0);
          if (algo && /^(?:md5|md4|sha1)$/i.test(algo)) {
            const fn = p.getFunctionParent();
            const around = fn ? source.slice(fn.node.start, Math.min(fn.node.end, fn.node.start + 4000)) : '';
            const forPasswords = /pass(?:word|wd)|pwd/i.test(around);
            emit(RULES.WEAK_HASH, n, forPasswords
              ? { severity: 'high', title: `${algo.toUpperCase()} appears to be used for passwords` }
              : { title: `Weak hash algorithm (${algo.toUpperCase()})` });
          }
        }
        if (target.name === 'createCipher' || target.name === 'createDecipher') {
          emit(RULES.WEAK_CIPHER, n, { title: `crypto.${target.name} is deprecated and has no random IV` });
        }
        if ((target.name === 'createCipheriv' || target.name === 'createDecipheriv') && a0) {
          const algo = staticStringValue(a0);
          if (algo && /(?:-ecb$|^des|^rc4|^bf)/i.test(algo)) emit(RULES.WEAK_CIPHER, n, { title: `Weak cipher or mode (${algo})` });
        }
      }
      if (d === 'Math.random' && isUnboundGlobal(scope, 'Math')) {
        const ctxName = securityContextName(p);
        if (ctxName) emit(RULES.RANDOM, n, { title: `Math.random() used for "${truncate(ctxName, 30)}"` });
      }

      // --- JWT ---------------------------------------------------------------------------------------
      if (target && target.module === 'jsonwebtoken' && (target.name === 'sign' || target.name === 'verify')) {
        const sec = args[1] && unwrap(args[1]);
        if (sec && isStaticString(sec) && staticStringValue(sec).length > 0) emit(RULES.JWT_SECRET, n, {});
        const opts = [...args].reverse().find((a) => unwrap(a).type === 'ObjectExpression');
        if (opts) {
          const algs = propValue(opts, 'algorithms');
          const alg = propValue(opts, 'algorithm');
          const hasNone = (algs && unwrap(algs).type === 'ArrayExpression' && unwrap(algs).elements.some((e) => e && staticStringValue(e) && staticStringValue(e).toLowerCase() === 'none')) ||
            (alg && staticStringValue(alg) && staticStringValue(alg).toLowerCase() === 'none');
          if (hasNone) emit(RULES.JWT_NONE, n, {});
          const ign = propValue(opts, 'ignoreExpiration');
          if (target.name === 'verify' && ign && unwrap(ign).type === 'BooleanLiteral' && unwrap(ign).value === true) emit(RULES.JWT_EXPIRY, n, {});
        }
      }

      // --- mass assignment, prototype pollution, deserialisation -------------------------------------
      if (isMember(callee) && MASS_METHODS.has(lastProp)) {
        const bad = args.some((a) => {
          const u = unwrap(a);
          return isRawBody(u) || (u.type === 'ObjectExpression' && u.properties.some((pr) => pr.type === 'SpreadElement' && isRawBody(pr.argument)));
        });
        if (bad) emit(RULES.MASS, n, {});
      }
      if (d === 'Object.assign' && args.length > 1 && unwrap(args[0]).type === 'Identifier' && args.slice(1).some((a) => isRawBody(a))) {
        emit(RULES.MASS, n, { title: 'Request body copied onto an existing object' });
      }
      if (target && (target.module === 'lodash' || target.module.startsWith('lodash/'))) {
        const fn = target.name || target.module.split('/').pop();
        if (LODASH_MUTATORS.has(fn) && args.some((a) => TS(a))) emit(RULES.PROTO, n, { ...traced(RULES.PROTO, args.find((a) => TS(a))) });
      }
      if (target && target.module === 'node-serialize' && target.name === 'unserialize') emit(RULES.DESERIALIZE, n, {});

      // --- browser storage / logging -----------------------------------------------------------------
      if ((d === 'localStorage.setItem' || d === 'sessionStorage.setItem' || d === 'window.localStorage.setItem') && a0) {
        const key = staticStringValue(a0);
        if (key && TOKEN_KEY_RE.test(key)) emit(RULES.TOKEN_STORAGE, n, { title: `"${truncate(key, 30)}" stored in ${d.split('.').slice(-2, -1)[0]}` });
      }
      if (d && /^console\.(?:log|info|debug|warn|error|trace)$/.test(d)) {
        for (const a of args) {
          const u = unwrap(a);
          const nm = u.type === 'Identifier' ? u.name : isMember(u) ? memberProp(u) : null;
          if (nm && LOG_SECRET_NAME_RE.test(nm)) {
            emit(RULES.LOG_SECRET, n, { title: `"${nm}" written to the console` });
            break;
          }
        }
      }
    },

    NewExpression(p) {
      const n = p.node;
      const scope = p.scope;
      const callee = unwrap(n.callee);
      const d = dotted(callee);
      const args = n.arguments;
      if (callee.type === 'Identifier' && callee.name === 'Function' && isUnboundGlobal(scope, 'Function') && args.length) {
        evalFinding(p, n, args[args.length - 1], 'new Function()');
      }
      const target = callTarget(scope, callee);
      if (target && target.module === 'vm' && d && d.endsWith('Script') && args[0]) evalFinding(p, n, args[0], 'new vm.Script()');
      if (callee.type === 'Identifier' && /^[A-Z]/.test(callee.name) && !NOT_MODELS.has(callee.name) && args.length === 1 && isRawBody(args[0])) {
        emit(RULES.MASS, n, { title: `new ${callee.name}(req.body) saves every field the client sends` });
      }
    },

    AssignmentExpression(p) {
      const n = p.node;
      const scope = p.scope;
      const left = unwrap(n.left);
      const ld = dotted(left);
      const lp = isMember(left) ? memberProp(left) : null;
      if ((lp === 'innerHTML' || lp === 'outerHTML') && (n.operator === '=' || n.operator === '+=') && !isStaticString(n.right)) {
        xssDom(p, n, n.right, lp);
      }
      if (ld === 'process.env.NODE_TLS_REJECT_UNAUTHORIZED' && staticStringValue(n.right) === '0') emit(RULES.TLS, n, {});
      if (ld && /^(?:window\.|document\.)?location(?:\.href)?$/.test(ld) && anyTaint.isTainted(n.right, scope) && !staysOnSite(n.right)) {
        emit(RULES.REDIRECT, n, { ...traced(RULES.REDIRECT, n.right), title: 'Browser navigates to a user-supplied URL' });
      }
    },

    ObjectProperty(p) {
      const k = p.node.key;
      const name = k.type === 'Identifier' ? k.name : k.value;
      const v = unwrap(p.node.value);
      if (name === 'rejectUnauthorized' && v.type === 'BooleanLiteral' && v.value === false) emit(RULES.TLS, p.node, {});
    },

    JSXAttribute(p) {
      const attr = p.node;
      if (attr.name && attr.name.name === 'dangerouslySetInnerHTML' && attr.value && attr.value.type === 'JSXExpressionContainer') {
        const html = propValue(attr.value.expression, '__html');
        if (!html || isStaticString(html) || isSanitized(html)) return;
        if (anyTaint.isTainted(html, p.scope)) emit(RULES.XSS_REACT, attr, { ...traced(RULES.XSS_REACT, html), severity: 'high' });
        else emit(RULES.XSS_REACT, attr, {});
      }
    },

    LogicalExpression(p) {
      const { operator, left, right } = p.node;
      if (operator !== '||' && operator !== '??') return;
      const m = /^process\.env\.([A-Z0-9_]+)$/.exec(dotted(left) || '');
      if (m && SECRET_ENV_RE.test(m[1]) && isStaticString(right) && staticStringValue(right).length > 0) {
        emit(RULES.ENV_FALLBACK, p.node, { title: `${m[1]} falls back to a hard-coded value` });
      }
    },

    VariableDeclarator(p) {
      const { id, init } = p.node;
      if (id.type === 'ObjectPattern' && dotted(init) === 'process.env') {
        for (const prop of id.properties) {
          if (prop.type !== 'ObjectProperty' || prop.value.type !== 'AssignmentPattern') continue;
          const name = prop.key.name || prop.key.value;
          if (SECRET_ENV_RE.test(String(name)) && isStaticString(prop.value.right) && staticStringValue(prop.value.right).length > 0) {
            emit(RULES.ENV_FALLBACK, prop, { title: `${name} falls back to a hard-coded value` });
          }
        }
      }
    },
  });

  return findings;
}

// ------------------------------------------------------------------------------------------------------
// Primary scan entry point
// ------------------------------------------------------------------------------------------------------
async function scanStaticAnalysis(projectPath) {
  const findings = [];
  const files = getProjectFiles(projectPath, {
    extensions: ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'],
  });

  for (const file of files) {
    if (/\.d\.ts$|\.min\.[cm]?js$/.test(file.relativePath)) continue;

    const source = readFileSafe(file.absolutePath);
    if (!source) continue;

    const ast = parseAst(source, file.relativePath);
    if (!ast) continue;

    try {
      const fileFindings = analyzeFile(file, source, ast);
      findings.push(...fileFindings);
    } catch (err) {
      // Continue safely on any file-level analysis issue
      console.warn(`[SAST Warning] Analysis skipped on ${file.relativePath}:`, err.message);
    }
  }

  return findings;
}

module.exports = {
  scanStaticAnalysis,
  analyzeFile,
  RULES,
  SCANNER,
};
