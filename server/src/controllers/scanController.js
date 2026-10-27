const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const config = require('../config');
const { Scan, Finding } = require('../models');
const { archiveService, repositoryService, scanService, findingService, reportService } = require('../services');
const { validateGitHubUrl, validateUpload } = require('../validators/scanValidators');

/**
 * Initiates a new scan via ZIP archive upload
 */
async function uploadScan(req, res, next) {
  try {
    const uploadValidation = validateUpload(req.file);
    if (!uploadValidation.isValid) {
      // Clean up uploaded file if present
      if (req.file?.path && fs.existsSync(req.file.path)) {
        try { fs.unlinkSync(req.file.path); } catch {}
      }
      return res.status(400).json({
        success: false,
        error: { message: uploadValidation.error, code: 'INVALID_UPLOAD_FILE' },
      });
    }

    const scanId = uuidv4();
    const ownerToken = req.headers['x-owner-token'] || uuidv4();
    const baseProjectName = req.body.projectName || path.basename(req.file.originalname, '.zip') || 'uploaded-project';

    const scan = new Scan({
      scanId,
      projectName: baseProjectName.trim(),
      submissionType: 'zip',
      status: 'queued',
      ownerToken,
    });
    await scan.save();

    // Respond immediately to client
    res.status(201).json({
      success: true,
      data: scan,
      ownerToken,
    });

    // Run extraction and scan asynchronously in the background
    const scanWorkingDir = path.join(config.TEMP_DIR, `scan_${scanId}`);
    const extractDir = path.join(scanWorkingDir, 'extracted');
    const zipPath = req.file.path;

    (async () => {
      try {
        await archiveService.extractZip(zipPath, extractDir);
        // Remove uploaded zip once extracted
        try { if (fs.existsSync(zipPath)) fs.unlinkSync(zipPath); } catch {}
        await scanService.startScan(scanId, extractDir, scanWorkingDir);
      } catch (scanErr) {
        console.error(`[Background Error] Scan ${scanId} failed:`, scanErr.message);
        try {
          const failedScan = await Scan.findOne({ scanId });
          if (failedScan && failedScan.status !== 'completed') {
            failedScan.status = 'failed';
            failedScan.errorMessage = scanErr.message;
            failedScan.completedAt = new Date();
            await failedScan.save();
          }
        } catch {}
      }
    })();
  } catch (err) {
    next(err);
  }
}

/**
 * Initiates a new scan via a public GitHub repository URL
 */
async function githubScan(req, res, next) {
  try {
    const { repositoryUrl, projectName } = req.body || {};
    const validation = validateGitHubUrl(repositoryUrl);

    if (!validation.isValid) {
      return res.status(400).json({
        success: false,
        error: { message: validation.error, code: 'INVALID_GITHUB_URL' },
      });
    }

    const scanId = uuidv4();
    const ownerToken = req.headers['x-owner-token'] || uuidv4();
    const resolvedProjectName = projectName || validation.repo || 'github-project';

    const scan = new Scan({
      scanId,
      projectName: resolvedProjectName.trim(),
      submissionType: 'github',
      repositoryUrl: repositoryUrl.trim(),
      status: 'queued',
      ownerToken,
    });
    await scan.save();

    // Return immediate response
    res.status(201).json({
      success: true,
      data: scan,
      ownerToken,
    });

    // Run cloning and scanning in background
    const scanWorkingDir = path.join(config.TEMP_DIR, `scan_${scanId}`);

    (async () => {
      try {
        const repoDir = await repositoryService.cloneRepository(repositoryUrl.trim(), scanWorkingDir);
        await scanService.startScan(scanId, repoDir, scanWorkingDir);
      } catch (scanErr) {
        console.error(`[Background Error] GitHub scan ${scanId} failed:`, scanErr.message);
        try {
          const failedScan = await Scan.findOne({ scanId });
          if (failedScan && failedScan.status !== 'completed') {
            failedScan.status = 'failed';
            failedScan.errorMessage = scanErr.message;
            failedScan.completedAt = new Date();
            await failedScan.save();
          }
        } catch {}
      }
    })();
  } catch (err) {
    next(err);
  }
}

/**
 * Retrieves list of scans, optionally filtered by owner token
 */
async function getScans(req, res, next) {
  try {
    const ownerToken = req.headers['x-owner-token'] || req.query.ownerToken;
    const query = {};

    if (ownerToken) {
      query.ownerToken = ownerToken;
    }

    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 20));
    const skip = (page - 1) * limit;

    const [scans, total] = await Promise.all([
      Scan.find(query).sort({ createdAt: -1 }).skip(skip).limit(limit),
      Scan.countDocuments(query),
    ]);

    res.json({
      success: true,
      data: scans,
      pagination: {
        total,
        page,
        totalPages: Math.ceil(total / limit) || 1,
      },
    });
  } catch (err) {
    next(err);
  }
}

/**
 * Retrieves a single scan by scanId
 */
async function getScan(req, res, next) {
  try {
    // If verified by ownershipMiddleware, req.scan is already attached
    const scan = req.scan || (await Scan.findOne({ scanId: req.params.scanId }));
    if (!scan) {
      return res.status(404).json({
        success: false,
        error: { message: `Scan not found with ID: ${req.params.scanId}`, code: 'SCAN_NOT_FOUND' },
      });
    }

    res.json({
      success: true,
      data: scan,
    });
  } catch (err) {
    next(err);
  }
}

/**
 * Retrieves findings associated with a scan
 */
async function getScanFindings(req, res, next) {
  try {
    const { scanId } = req.params;
    const result = await findingService.getFindingsByScan(scanId, req.query);

    res.json({
      success: true,
      data: result.findings,
      pagination: {
        total: result.total,
        page: result.page,
        totalPages: result.totalPages,
      },
    });
  } catch (err) {
    next(err);
  }
}

/**
 * Deletes a scan and its associated findings
 */
async function deleteScan(req, res, next) {
  try {
    const { scanId } = req.params;
    await Promise.all([
      Scan.deleteOne({ scanId }),
      Finding.deleteMany({ scanId }),
    ]);

    res.json({
      success: true,
      message: `Scan ${scanId} and all associated findings were successfully deleted.`,
    });
  } catch (err) {
    next(err);
  }
}

/**
 * Exports full scan results and findings as JSON
 */
async function exportScan(req, res, next) {
  try {
    const { scanId } = req.params;
    const report = await reportService.generateReport(scanId);

    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="patchpilot-scan-${scanId}.json"`);
    res.json(report);
  } catch (err) {
    next(err);
  }
}

/**
 * Triggers a rescan from the original source
 */
async function rescan(req, res, next) {
  try {
    const existingScan = req.scan || (await Scan.findOne({ scanId: req.params.scanId }));
    if (!existingScan) {
      return res.status(404).json({
        success: false,
        error: { message: 'Original scan not found', code: 'SCAN_NOT_FOUND' },
      });
    }

    if (existingScan.submissionType === 'github' && existingScan.repositoryUrl) {
      const newScanId = uuidv4();
      const ownerToken = req.headers['x-owner-token'] || existingScan.ownerToken || uuidv4();

      const newScan = new Scan({
        scanId: newScanId,
        projectName: existingScan.projectName,
        submissionType: 'github',
        repositoryUrl: existingScan.repositoryUrl,
        status: 'queued',
        ownerToken,
      });
      await newScan.save();

      res.status(201).json({
        success: true,
        data: newScan,
        ownerToken,
      });

      // Background scan
      const scanWorkingDir = path.join(config.TEMP_DIR, `scan_${newScanId}`);
      (async () => {
        try {
          const repoDir = await repositoryService.cloneRepository(existingScan.repositoryUrl, scanWorkingDir);
          await scanService.startScan(newScanId, repoDir, scanWorkingDir);
        } catch (scanErr) {
          console.error(`[Background Error] Rescan ${newScanId} failed:`, scanErr.message);
          try {
            const failed = await Scan.findOne({ scanId: newScanId });
            if (failed) {
              failed.status = 'failed';
              failed.errorMessage = scanErr.message;
              failed.completedAt = new Date();
              await failed.save();
            }
          } catch {}
        }
      })();
    } else {
      return res.status(400).json({
        success: false,
        error: {
          message: 'Rescan is supported directly for GitHub repositories. For ZIP archives, please upload the archive again.',
          code: 'RESCAN_UNSUPPORTED_FOR_ZIP',
        },
      });
    }
  } catch (err) {
    next(err);
  }
}

module.exports = {
  uploadScan,
  githubScan,
  getScans,
  getScan,
  getScanFindings,
  deleteScan,
  exportScan,
  rescan,
};
