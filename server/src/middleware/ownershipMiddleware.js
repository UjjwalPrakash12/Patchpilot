const { Scan } = require('../models');

/**
 * Middleware to verify that the requestor owns the target scan using x-owner-token header
 */
async function verifyScanOwnership(req, res, next) {
  try {
    const { scanId } = req.params;
    if (!scanId) {
      return res.status(400).json({
        success: false,
        error: { message: 'Scan ID parameter is required', code: 'MISSING_SCAN_ID' },
      });
    }

    const scan = await Scan.findOne({ scanId });
    if (!scan) {
      return res.status(404).json({
        success: false,
        error: { message: `Scan not found with ID: ${scanId}`, code: 'SCAN_NOT_FOUND' },
      });
    }

    const headerToken = req.headers['x-owner-token'];

    // If the scan was created with an ownerToken, enforce token match
    if (scan.ownerToken) {
      if (!headerToken || headerToken !== scan.ownerToken) {
        return res.status(403).json({
          success: false,
          error: {
            message: 'Access denied: invalid or missing x-owner-token header for this scan',
            code: 'FORBIDDEN_SCAN_ACCESS',
          },
        });
      }
    }

    // Attach pre-fetched scan to request for controller efficiency
    req.scan = scan;
    next();
  } catch (err) {
    next(err);
  }
}

/**
 * Middleware to verify that the requestor owns the target finding via its parent scan
 */
async function verifyFindingOwnership(req, res, next) {
  try {
    const { findingId } = req.params;
    if (!findingId) {
      return res.status(400).json({
        success: false,
        error: { message: 'Finding ID parameter is required', code: 'MISSING_FINDING_ID' },
      });
    }

    const { Finding } = require('../models');
    const finding = await Finding.findOne({ findingId });
    if (!finding) {
      return res.status(404).json({
        success: false,
        error: { message: `Finding not found with ID: ${findingId}`, code: 'FINDING_NOT_FOUND' },
      });
    }

    const scan = await Scan.findOne({ scanId: finding.scanId });
    if (!scan) {
      return res.status(404).json({
        success: false,
        error: { message: 'Parent scan not found for this finding', code: 'SCAN_NOT_FOUND' },
      });
    }

    const headerToken = req.headers['x-owner-token'];
    if (scan.ownerToken) {
      if (!headerToken || headerToken !== scan.ownerToken) {
        return res.status(403).json({
          success: false,
          error: {
            message: 'Access denied: invalid or missing x-owner-token header for this finding',
            code: 'FORBIDDEN_FINDING_ACCESS',
          },
        });
      }
    }

    req.finding = finding;
    req.scan = scan;
    next();
  } catch (err) {
    next(err);
  }
}

/**
 * Helper to retrieve owner token from header
 */
function getOwnerToken(req) {
  return req.headers['x-owner-token'] || null;
}

module.exports = {
  verifyScanOwnership,
  verifyFindingOwnership,
  getOwnerToken,
};
