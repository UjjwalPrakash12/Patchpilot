const { findingService } = require('../services');

/**
 * Retrieves details for a specific finding
 */
async function getFinding(req, res, next) {
  try {
    const { findingId } = req.params;
    const finding = await findingService.getFindingById(findingId);

    res.json({
      success: true,
      data: finding,
    });
  } catch (err) {
    next(err);
  }
}

/**
 * Generates an automated remediation code proposal and explanation for a finding
 */
async function proposeFix(req, res, next) {
  try {
    const { findingId } = req.params;
    const fix = await findingService.proposeFix(findingId);

    res.json({
      success: true,
      data: fix,
    });
  } catch (err) {
    next(err);
  }
}

/**
 * Updates the status of a finding (e.g., mark as false-positive, fixed-verified, accepted-risk)
 */
async function updateFindingStatus(req, res, next) {
  try {
    const { findingId } = req.params;
    const { status } = req.body || {};

    if (!status) {
      return res.status(400).json({
        success: false,
        error: { message: 'Status field is required in request body', code: 'MISSING_STATUS' },
      });
    }

    const updatedFinding = await findingService.updateFindingStatus(findingId, status);

    res.json({
      success: true,
      data: updatedFinding,
    });
  } catch (err) {
    next(err);
  }
}

module.exports = {
  getFinding,
  proposeFix,
  updateFindingStatus,
};
