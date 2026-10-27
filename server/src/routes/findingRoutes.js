const express = require('express');
const router = express.Router();
const findingController = require('../controllers/findingController');
const { verifyFindingOwnership } = require('../middleware/ownershipMiddleware');
const { fixRateLimiter } = require('../middleware/rateLimiter');

// Get finding by findingId
router.get('/:findingId', verifyFindingOwnership, findingController.getFinding);

// Propose remediation fix for finding
router.post('/:findingId/propose-fix', fixRateLimiter, verifyFindingOwnership, findingController.proposeFix);

// Update status of finding (open, fix-proposed, fixed-verified, accepted-risk, false-positive)
router.patch('/:findingId/status', verifyFindingOwnership, findingController.updateFindingStatus);

module.exports = router;
