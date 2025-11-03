const { Router } = require("express");
const { requireAuth, errorHandler } = require("../../middlewares/auth");
const { updateProfileRules } = require("../validators/profile.validators");
const ctrl = require("../controllers/profile.controller");

const router = Router();

router.get("/", requireAuth, ctrl.getMeProfile);
router.put("/", requireAuth, updateProfileRules, ctrl.updateMeProfile);

// keep last
router.use(errorHandler);

module.exports = router;
