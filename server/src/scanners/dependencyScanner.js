const fs = require('fs');
const path = require('path');
const { readFileSafe } = require('./scannerUtils');

/**
 * Known vulnerable packages database for static analysis
 */
const VULNERABLE_PACKAGES = [
  {
    name: 'lodash',
    fixedVersion: '4.17.21',
    severity: 'critical',
    cve: 'CVE-2021-23337 / CVE-2020-8203',
    description: 'Lodash versions prior to 4.17.21 are vulnerable to Command Injection and Prototype Pollution via zipObjectDeep and template functions.',
    remediation: 'Upgrade lodash to version 4.17.21 or higher.',
  },
  {
    name: 'express',
    fixedVersion: '4.17.3',
    severity: 'high',
    cve: 'CVE-2022-24999',
    description: 'Express versions prior to 4.17.3 contain qs and mime vulnerabilities allowing prototype pollution and open redirect behavior.',
    remediation: 'Upgrade express to version 4.17.3 or higher (or express 5.x).',
  },
  {
    name: 'jsonwebtoken',
    fixedVersion: '9.0.0',
    severity: 'critical',
    cve: 'CVE-2022-23529 / CVE-2022-23540',
    description: 'jsonwebtoken before 9.0.0 allows verification bypass and remote code execution through forged keys in insecure verification flows.',
    remediation: 'Upgrade jsonwebtoken to version 9.0.0 or higher.',
  },
  {
    name: 'axios',
    fixedVersion: '0.21.1',
    severity: 'high',
    cve: 'CVE-2020-28168',
    description: 'Axios before 0.21.1 leaks auth headers during cross-domain redirects and is vulnerable to SSRF.',
    remediation: 'Upgrade axios to version 0.21.1 or higher (or 1.x).',
  },
  {
    name: 'minimist',
    fixedVersion: '1.2.6',
    severity: 'high',
    cve: 'CVE-2020-7598',
    description: 'Minimist before 1.2.6 is vulnerable to Prototype Pollution via argument parsing.',
    remediation: 'Upgrade minimist to version 1.2.6 or higher.',
  },
  {
    name: 'shelljs',
    fixedVersion: '0.8.5',
    severity: 'critical',
    cve: 'CVE-2022-0144',
    description: 'ShellJS prior to 0.8.5 is vulnerable to Command Injection via untrusted input execution.',
    remediation: 'Upgrade shelljs to version 0.8.5 or higher.',
  },
  {
    name: 'moment',
    fixedVersion: '2.29.4',
    severity: 'high',
    cve: 'CVE-2022-31129',
    description: 'Moment before 2.29.4 is vulnerable to ReDoS and path traversal in locale handling.',
    remediation: 'Upgrade moment to version 2.29.4 or higher, or migrate to date-fns / dayjs.',
  },
  {
    name: 'vm2',
    fixedVersion: '3.9.19',
    severity: 'critical',
    cve: 'CVE-2023-37466',
    description: 'VM2 sandbox escape vulnerabilities allow arbitrary remote code execution on the host system.',
    remediation: 'Upgrade to 3.9.19 or migrate away from vm2 as it is discontinued.',
  },
  {
    name: 'handlebars',
    fixedVersion: '4.7.7',
    severity: 'high',
    cve: 'CVE-2021-23383',
    description: 'Handlebars before 4.7.7 allows prototype pollution and arbitrary code execution through template compilation.',
    remediation: 'Upgrade handlebars to version 4.7.7 or higher.',
  },
  {
    name: 'node-fetch',
    fixedVersion: '2.6.7',
    severity: 'high',
    cve: 'CVE-2022-0235',
    description: 'Node-fetch before 2.6.7 (and 3.x before 3.1.1) exposes sensitive cookies across redirect origins.',
    remediation: 'Upgrade node-fetch to 2.6.7+ (for v2) or 3.1.1+ (for v3).',
  },
];

/**
 * Parse a semver string into [major, minor, patch]
 * Strips ^, ~, >=, >, =, etc.
 * @param {string} ver
 * @returns {[number, number, number]|null}
 */
function parseSemver(ver) {
  if (!ver || typeof ver !== 'string') return null;
  const clean = ver.trim().replace(/^[^\d]*/, '').split('-')[0];
  const parts = clean.split('.').map((p) => parseInt(p, 10));
  if (parts.length === 0 || Number.isNaN(parts[0])) return null;
  return [parts[0] || 0, parts[1] || 0, parts[2] || 0];
}

/**
 * Compare two semvers: returns -1 if v1 < v2, 0 if v1 === v2, 1 if v1 > v2
 */
function compareSemver(v1, v2) {
  const p1 = parseSemver(v1);
  const p2 = parseSemver(v2);
  if (!p1 || !p2) return 0;

  for (let i = 0; i < 3; i++) {
    if (p1[i] < p2[i]) return -1;
    if (p1[i] > p2[i]) return 1;
  }
  return 0;
}

/**
 * Checks if a version range is suspiciously wide
 */
function isWideVersionRange(ver) {
  if (!ver || typeof ver !== 'string') return false;
  const v = ver.trim();
  return (
    v === '*' ||
    v === 'latest' ||
    v === 'x' ||
    v === 'X' ||
    /^>[=]?\s*0(\.0(\.0)?)?$/.test(v) ||
    /^[><]=?\s*\*$/.test(v)
  );
}

/**
 * Scans project for dependency vulnerabilities, missing lockfiles, and wide ranges
 * @param {string} projectPath
 * @returns {Promise<Array<Object>>}
 */
async function scanDependencies(projectPath) {
  const findings = [];
  const packageJsonPath = path.join(projectPath, 'package.json');
  const packageLockPath = path.join(projectPath, 'package-lock.json');
  const yarnLockPath = path.join(projectPath, 'yarn.lock');
  const pnpmLockPath = path.join(projectPath, 'pnpm-lock.yaml');

  if (!fs.existsSync(packageJsonPath)) {
    return findings;
  }

  let packageJson;
  const raw = readFileSafe(packageJsonPath);
  if (!raw) {
    return findings;
  }

  try {
    packageJson = JSON.parse(raw);
    if (!packageJson || typeof packageJson !== 'object') {
      throw new Error('package.json must contain a JSON object');
    }
  } catch (err) {
    findings.push({
      category: 'dependencies',
      title: 'Invalid package.json File',
      severity: 'high',
      confidence: 'high',
      scanner: 'dependencyScanner',
      ruleId: 'DEP-MALFORMED-PACKAGE-JSON',
      filePath: 'package.json',
      startLine: 1,
      endLine: 1,
      evidence: err.message,
      description: 'The package.json file could not be parsed as valid JSON.',
      impact: 'Build tools and dependency resolution will fail, preventing accurate security analysis and reproducible builds.',
      remediation: 'Fix JSON syntax errors in package.json.',
      codeSnippet: '',
      references: ['https://docs.npmjs.com/cli/v10/configuring-npm/package-json'],
    });
    return findings;
  }

  // 1. Check for missing lockfile
  const hasLockFile =
    fs.existsSync(packageLockPath) ||
    fs.existsSync(yarnLockPath) ||
    fs.existsSync(pnpmLockPath);

  if (!hasLockFile) {
    findings.push({
      category: 'dependencies',
      title: 'Missing Package Lockfile',
      severity: 'medium',
      confidence: 'high',
      scanner: 'dependencyScanner',
      ruleId: 'DEP-MISSING-LOCKFILE',
      filePath: 'package.json',
      startLine: 1,
      endLine: 1,
      evidence: 'No package-lock.json, yarn.lock, or pnpm-lock.yaml found in project root',
      description: 'The project does not commit a lockfile (package-lock.json or yarn.lock).',
      impact: 'Without a lockfile, builds are non-deterministic and can pull in malicious or breaking sub-dependencies automatically during install.',
      remediation: 'Run npm install and commit the generated package-lock.json to version control.',
      codeSnippet: '"name": "' + (packageJson.name || 'project') + '"',
      references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/NPM_Security_Cheat_Sheet.html',
        'https://docs.npmjs.com/cli/v10/configuring-npm/package-lock-json',
      ],
    });
  }

  // Also parse lockfile for resolved versions if package-lock exists
  let lockPackages = {};
  if (fs.existsSync(packageLockPath)) {
    try {
      const lockData = JSON.parse(readFileSafe(packageLockPath));
      // npm lockfile v2/v3 has .packages, v1 has .dependencies
      if (lockData.packages) {
        for (const [key, val] of Object.entries(lockData.packages)) {
          const pkgName = key.replace(/^node_modules\//, '');
          if (val && val.version) {
            lockPackages[pkgName] = val.version;
          }
        }
      }
      if (lockData.dependencies) {
        for (const [key, val] of Object.entries(lockData.dependencies)) {
          if (val && val.version && !lockPackages[key]) {
            lockPackages[key] = val.version;
          }
        }
      }
    } catch {
      // Ignore lock parse error
    }
  }

  const allDeps = {
    ...(packageJson.dependencies || {}),
    ...(packageJson.devDependencies || {}),
  };

  // 2. Check for wide version ranges
  for (const [pkgName, versionRange] of Object.entries(allDeps)) {
    if (typeof versionRange === 'string' && isWideVersionRange(versionRange)) {
      findings.push({
        category: 'dependencies',
        title: `Unrestricted Version Range for Dependency: ${pkgName}`,
        severity: 'medium',
        confidence: 'high',
        scanner: 'dependencyScanner',
        ruleId: 'DEP-WIDE-VERSION-RANGE',
        filePath: 'package.json',
        startLine: 1,
        endLine: 1,
        evidence: `"${pkgName}": "${versionRange}"`,
        description: `Package '${pkgName}' uses an overly broad version selector '${versionRange}'.`,
        impact: 'Permits silent automatic installation of untested or compromised future versions without developer intervention.',
        remediation: `Lock '${pkgName}' to a specific version or safe semver range (e.g. ^1.2.3).`,
        codeSnippet: `"${pkgName}": "${versionRange}"`,
        references: [
          'https://cheatsheetseries.owasp.org/cheatsheets/NPM_Security_Cheat_Sheet.html',
        ],
      });
    }
  }

  // 3. Check for known vulnerable packages
  for (const knownVuln of VULNERABLE_PACKAGES) {
    const declaredRange = allDeps[knownVuln.name];
    const resolvedVersion = lockPackages[knownVuln.name];
    const versionToCheck = resolvedVersion || declaredRange;

    if (versionToCheck && typeof versionToCheck === 'string') {
      const cmp = compareSemver(versionToCheck, knownVuln.fixedVersion);
      if (cmp < 0) {
        findings.push({
          category: 'dependencies',
          title: `Vulnerable Dependency: ${knownVuln.name} (${versionToCheck})`,
          severity: knownVuln.severity,
          confidence: 'high',
          scanner: 'dependencyScanner',
          ruleId: `DEP-VULNERABLE-${knownVuln.name.toUpperCase()}`,
          filePath: fs.existsSync(packageLockPath) ? 'package-lock.json' : 'package.json',
          startLine: 1,
          endLine: 1,
          evidence: `${knownVuln.name}@${versionToCheck} (requires >= ${knownVuln.fixedVersion}) [${knownVuln.cve}]`,
          description: knownVuln.description,
          impact: `Known vulnerabilities in ${knownVuln.name} can allow attackers to compromise the application. ${knownVuln.cve}`,
          remediation: knownVuln.remediation,
          codeSnippet: `"${knownVuln.name}": "${declaredRange || versionToCheck}"`,
          references: [
            `https://www.npmjs.com/package/${knownVuln.name}`,
            'https://cve.mitre.org/',
          ],
        });
      }
    }
  }

  return findings;
}

module.exports = {
  scanDependencies,
};
