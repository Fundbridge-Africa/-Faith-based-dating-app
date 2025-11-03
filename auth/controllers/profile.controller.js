const { validationResult } = require("express-validator");
const User = require("../models/User");
const { requireAuth, errorHandler } = require("../../middlewares/auth");

function ensureValid(req) {
  const result = validationResult(req);
  if (!result.isEmpty()) {
    const err = new Error(result.array().map(e => e.msg).join(", "));
    err.status = 400;
    throw err;
  }
}

async function getMeProfile(req, res, next) {
  try {
    const user = await User.findById(req.user.sub).select("profile email name role createdAt updatedAt");
    if (!user) { const e = new Error("User not found"); e.status = 404; throw e; }
    res.json({ profile: user.profile, meta: { email: user.email, name: user.name, role: user.role } });
  } catch (e) { next(e); }
}

async function updateMeProfile(req, res, next) {
  try {
    ensureValid(req);
    const update = {};
    [
      "displayName","gender","birthdate","faith","denomination","values",
      "bio","photos","onboardingCompleted"
    ].forEach(k => { if (k in req.body) update[`profile.${k}`] = req.body[k]; });
    if (req.body.location) {
      ["city","country","lat","lng"].forEach(k => {
        if (k in req.body.location) update[`profile.location.${k}`] = req.body.location[k];
      });
    }
    const user = await User.findByIdAndUpdate(req.user.sub, { $set: update }, { new: true })
      .select("profile");
    if (!user) { const e = new Error("User not found"); e.status = 404; throw e; }
    res.json({ profile: user.profile });
  } catch (e) { next(e); }
}

module.exports = { getMeProfile, updateMeProfile };
