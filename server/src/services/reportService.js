const { Scan, Finding } = require('../models');

/**
 * Generates an aggregated summary of findings and metadata for a scan
 * @param {string} scanId
 * @returns {Promise<Object>}
 */
async function getScanSummary(scanId) {
  const scan = await Scan.findOne({ scanId });
  if (!scan) {
    throw new Error(`Scan not found with ID: ${scanId}`);
  }

  const findings = await Finding.find({ scanId });

  const categoryBreakdown = {
    secrets: 0,
    dependencies: 0,
    'source-code': 0,
    configuration: 0,
  };

  const statusBreakdown = {
    open: 0,
    'fix-proposed': 0,
    'fixed-verified': 0,
    'accepted-risk': 0,
    'false-positive': 0,
  };

  const fileFindingCounts = {};

  for (const f of findings) {
    if (categoryBreakdown[f.category] !== undefined) {
      categoryBreakdown[f.category]++;
    }
    if (statusBreakdown[f.status] !== undefined) {
      statusBreakdown[f.status]++;
    }
    fileFindingCounts[f.filePath] = (fileFindingCounts[f.filePath] || 0) + 1;
  }

  const topFiles = Object.entries(fileFindingCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([filePath, count]) => ({ filePath, count }));

  let durationSeconds = null;
  if (scan.startedAt && scan.completedAt) {
    durationSeconds = Math.round((new Date(scan.completedAt) - new Date(scan.startedAt)) / 1000);
  }

  return {
    scanId: scan.scanId,
    projectName: scan.projectName,
    submissionType: scan.submissionType,
    repositoryUrl: scan.repositoryUrl,
    status: scan.status,
    startedAt: scan.startedAt,
    completedAt: scan.completedAt,
    durationSeconds,
    totalFindings: scan.totalFindings,
    severity: {
      critical: scan.criticalCount,
      high: scan.highCount,
      medium: scan.mediumCount,
      low: scan.lowCount,
      info: scan.infoCount,
    },
    categoryBreakdown,
    statusBreakdown,
    topFiles,
    scannerResults: scan.scannerResults,
  };
}

/**
 * Generates a full JSON export report for a scan
 * @param {string} scanId
 * @returns {Promise<Object>}
 */
async function generateReport(scanId) {
  const summary = await getScanSummary(scanId);
  const findings = await Finding.find({ scanId }).sort({ severity: 1, filePath: 1 });

  return {
    version: '1.0.0',
    generatedAt: new Date().toISOString(),
    generator: 'PatchPilot Security Engine',
    scan: summary,
    findings,
  };
}

module.exports = {
  generateReport,
  getScanSummary,
};
