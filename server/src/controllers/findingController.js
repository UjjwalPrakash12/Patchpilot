const { findingService } = require('../services');

/**
 * Retrieves details for a specific finding
 */
async function getFinding(req, res, next) {
  try {
    const finding = req.finding || (await findingService.getFindingById(req.params.findingId));

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
    const finding = req.finding || (await findingService.getFindingById(req.params.findingId));
    const fix = await findingService.proposeFix(finding);

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

    if (!status || typeof status !== 'string') {
      return res.status(400).json({
        success: false,
        error: { message: 'Status field must be a valid string', code: 'INVALID_STATUS' },
      });
    }

    const updatedFinding = await findingService.updateFindingStatus(findingId, status.trim());

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
