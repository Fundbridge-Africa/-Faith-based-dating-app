const { Router } = require("express");
const { register, login, me, refresh, logout } = require("../controllers/auth.controller");
const { requireAuth, errorHandler } = require("../../middlewares/auth");
const { loginRules, registerRules } = require("../validators/auth.validators");

const router = Router();

router.post("/register", registerRules, register);
router.post("/login",    loginRules,    login);
router.get("/me", requireAuth, me);
router.post("/refresh", refresh);
router.post("/logout", requireAuth, logout);

// keep last
router.use(errorHandler);

module.exports = router;
