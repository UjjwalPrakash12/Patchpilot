const { v4: uuidv4 } = require('uuid');
const { scanForSecrets } = require('./secretScanner');
const { scanDependencies } = require('./dependencyScanner');
const { scanStaticAnalysis } = require('./staticAnalysisScanner');
const { scanConfiguration } = require('./configurationScanner');
const { scanProjectSpecific } = require('./projectScanner');

/**
 * Orchestrates all scanners, handles errors gracefully, deduplicates, and normalizes findings
 * @param {string} projectPath - Path to the extracted codebase to scan
 * @returns {Promise<{ scannerResults: Object, findings: Array<Object> }>}
 */
async function runAllScanners(projectPath) {
  const scannerResults = {
    secrets: { status: 'pending', findingCount: 0, error: null },
    dependencies: { status: 'pending', findingCount: 0, error: null },
    staticAnalysis: { status: 'pending', findingCount: 0, error: null },
    configuration: { status: 'pending', findingCount: 0, error: null },
    projectSpecific: { status: 'pending', findingCount: 0, error: null },
  };

  const rawFindings = [];

  const scanners = [
    {
      key: 'secrets',
      name: 'secretScanner',
      run: () => scanForSecrets(projectPath),
    },
    {
      key: 'dependencies',
      name: 'dependencyScanner',
      run: () => scanDependencies(projectPath),
    },
    {
      key: 'staticAnalysis',
      name: 'staticAnalysisScanner',
      run: () => scanStaticAnalysis(projectPath),
    },
    {
      key: 'configuration',
      name: 'configurationScanner',
      run: () => scanConfiguration(projectPath),
    },
    {
      key: 'projectSpecific',
      name: 'projectScanner',
      run: () => scanProjectSpecific(projectPath),
    },
  ];

  // Run all scanners sequentially or concurrently
  for (const scanner of scanners) {
    try {
      scannerResults[scanner.key].status = 'running';
      const results = await scanner.run();
      const validResults = Array.isArray(results) ? results : [];

      scannerResults[scanner.key].status = 'completed';
      scannerResults[scanner.key].findingCount = validResults.length;
      scannerResults[scanner.key].error = null;

      for (const item of validResults) {
        rawFindings.push({
          ...item,
          scanner: item.scanner || scanner.name,
        });
      }
    } catch (err) {
      scannerResults[scanner.key].status = 'failed';
      scannerResults[scanner.key].error = err.message || 'Unknown scanner error';
      scannerResults[scanner.key].findingCount = 0;
    }
  }

  // Deduplicate findings by (ruleId + filePath + startLine)
  const seenKeys = new Set();
  const normalizedFindings = [];

  const VALID_CATEGORIES = new Set(['secrets', 'dependencies', 'source-code', 'configuration']);
  const VALID_SEVERITIES = new Set(['critical', 'high', 'medium', 'low', 'info']);
  const VALID_CONFIDENCES = new Set(['high', 'medium', 'low']);

  for (const finding of rawFindings) {
    const dedupKey = `${finding.ruleId || 'RULE'}|${finding.filePath || 'FILE'}|${finding.startLine || 1}`;
    if (seenKeys.has(dedupKey)) {
      continue;
    }
    seenKeys.add(dedupKey);

    const category = VALID_CATEGORIES.has(finding.category) ? finding.category : 'source-code';
    const severity = VALID_SEVERITIES.has(finding.severity) ? finding.severity : 'medium';
    const confidence = VALID_CONFIDENCES.has(finding.confidence) ? finding.confidence : 'medium';

    normalizedFindings.push({
      findingId: uuidv4(),
      title: finding.title || 'Security Finding',
      category,
      severity,
      confidence,
      status: 'open',
      scanner: finding.scanner || 'unknownScanner',
      ruleId: finding.ruleId || 'GENERIC-RULE',
      filePath: finding.filePath || 'unknown',
      startLine: typeof finding.startLine === 'number' ? finding.startLine : 1,
      endLine: typeof finding.endLine === 'number' ? finding.endLine : 1,
      evidence: finding.evidence || '',
      description: finding.description || '',
      impact: finding.impact || '',
      remediation: finding.remediation || '',
      codeSnippet: finding.codeSnippet || '',
      fixedCode: finding.fixedCode || null,
      references: Array.isArray(finding.references) ? finding.references : [],
      verificationStatus: 'not-checked',
    });
  }

  return {
    scannerResults,
    findings: normalizedFindings,
  };
}

module.exports = {
  runAllScanners,
  scanForSecrets,
  scanDependencies,
  scanStaticAnalysis,
  scanConfiguration,
  scanProjectSpecific,
};
