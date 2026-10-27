const fs = require('fs');
const { Scan, Finding } = require('../models');
const { runAllScanners } = require('../scanners');

/**
 * Orchestrates full lifecycle of a scan: preparing, scanning, analyzing, saving findings, cleanup
 * @param {string} scanId - Unique UUID of the scan
 * @param {string} projectDir - Path to extracted project code
 * @param {string} [cleanupDir] - Optional directory to purge after scan completion
 */
async function startScan(scanId, projectDir, cleanupDir = null) {
  let scan;
  try {
    scan = await Scan.findOne({ scanId });
    if (!scan) {
      throw new Error(`Scan not found with ID: ${scanId}`);
    }

    // Phase 1: Preparing
    scan.status = 'preparing';
    scan.startedAt = new Date();
    scan.errorMessage = null;
    await scan.save();

    if (!fs.existsSync(projectDir)) {
      throw new Error(`Project directory not accessible: ${projectDir}`);
    }

    // Phase 2: Scanning
    scan.status = 'scanning';
    await scan.save();

    const { scannerResults, findings } = await runAllScanners(projectDir);

    // Phase 3: Analyzing & Saving
    scan.status = 'analyzing';
    await scan.save();

    // Prepare findings with scanId
    const formattedFindings = findings.map((f) => ({
      ...f,
      scanId,
    }));

    if (formattedFindings.length > 0) {
      await Finding.insertMany(formattedFindings);
    }

    // Compute statistics
    let criticalCount = 0;
    let highCount = 0;
    let mediumCount = 0;
    let lowCount = 0;
    let infoCount = 0;

    for (const f of formattedFindings) {
      if (f.severity === 'critical') criticalCount++;
      else if (f.severity === 'high') highCount++;
      else if (f.severity === 'medium') mediumCount++;
      else if (f.severity === 'low') lowCount++;
      else if (f.severity === 'info') infoCount++;
    }

    scan.status = 'completed';
    scan.scannerResults = scannerResults;
    scan.totalFindings = formattedFindings.length;
    scan.criticalCount = criticalCount;
    scan.highCount = highCount;
    scan.mediumCount = mediumCount;
    scan.lowCount = lowCount;
    scan.infoCount = infoCount;
    scan.completedAt = new Date();
    await scan.save();

    // Phase 4: Cleanup
    if (cleanupDir && fs.existsSync(cleanupDir)) {
      try {
        fs.rmSync(cleanupDir, { recursive: true, force: true });
      } catch (cleanupErr) {
        console.warn(`Warning: Could not remove temporary scan directory ${cleanupDir}:`, cleanupErr.message);
      }
    }

    return scan;
  } catch (err) {
    if (scan) {
      scan.status = 'failed';
      scan.errorMessage = err.message || 'Scan process encountered an unexpected error';
      scan.completedAt = new Date();
      await scan.save();
    }

    if (cleanupDir && fs.existsSync(cleanupDir)) {
      try {
        fs.rmSync(cleanupDir, { recursive: true, force: true });
      } catch {}
    }

    throw err;
  }
}

module.exports = {
  startScan,
};
