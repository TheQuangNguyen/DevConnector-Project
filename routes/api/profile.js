const express = require("express");
const router = express.Router();

// @route     GET api/profiule
// @desc      Test route
// @access    Public
router.get("/", (req, res) => res.send("Profile route"));

module.exports = router;
