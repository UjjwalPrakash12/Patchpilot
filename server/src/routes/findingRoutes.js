const express = require('express');
const router = express.Router();
const findingController = require('../controllers/findingController');

// Get finding by findingId
router.get('/:findingId', findingController.getFinding);

// Propose remediation fix for finding
router.post('/:findingId/propose-fix', findingController.proposeFix);

// Update status of finding (open, fix-proposed, fixed-verified, accepted-risk, false-positive)
router.patch('/:findingId/status', findingController.updateFindingStatus);

module.exports = router;
