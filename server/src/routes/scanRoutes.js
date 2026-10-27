const express = require('express');
const router = express.Router();
const upload = require('../config/multer');
const scanController = require('../controllers/scanController');
const { scanRateLimiter } = require('../middleware/rateLimiter');
const { verifyScanOwnership } = require('../middleware/ownershipMiddleware');

const uploadArchive = (req, res, next) => {
  upload.any()(req, res, (err) => {
    if (err) return next(err);
    if (req.files && req.files.length > 0) {
      req.file = req.files[0];
    }
    next();
  });
};

// Upload a ZIP archive to scan
router.post('/upload', scanRateLimiter, uploadArchive, scanController.uploadScan);

// Scan a public GitHub repository
router.post('/github', scanRateLimiter, scanController.githubScan);

// List scans (guest or owner filtered)
router.get('/', scanController.getScans);

// Get a single scan by scanId
router.get('/:scanId', verifyScanOwnership, scanController.getScan);

// Get findings for a scan (with filters)
router.get('/:scanId/findings', verifyScanOwnership, scanController.getScanFindings);

// Delete a scan and its findings
router.delete('/:scanId', verifyScanOwnership, scanController.deleteScan);

// Export scan as JSON report
router.get('/:scanId/export', verifyScanOwnership, scanController.exportScan);

// Trigger a rescan from source
router.post('/:scanId/rescan', verifyScanOwnership, scanController.rescan);

module.exports = router;
