const { validationResult } = require("express-validator");
const Auth = require("../services/auth.service");
const { accessOpts, refreshOpts, clearOpts } = require("../../utils/cookies");

function ensureValid(req) {
  const result = validationResult(req);
  if (!result.isEmpty()) {
    const err = new Error(result.array().map(e => e.msg).join(", "));
    err.status = 400;
    throw err;
  }
}
async function register(req, res, next) {
  try {
    ensureValid(req);
    const meta = { ua: req.headers['user-agent'], ip: req.ip };
    const { user, accessToken, refreshToken } = await Auth.register(req.body, meta);
    res.cookie("accessToken", accessToken, accessOpts);
    res.cookie("refreshToken", refreshToken, refreshOpts);
    res.status(201).json({ user, accessToken, refreshToken });
  } catch (e) { next(e); }
}
async function login(req, res, next) {
  try {
    ensureValid(req);
    const meta = { ua: req.get('user-agent') || '', ip: req.ip };
    const { user, accessToken, refreshToken } =
      await Auth.login(req.body.email, req.body.password /*, meta */);
    res.cookie('accessToken', accessToken, accessOpts);
    res.cookie('refreshToken', refreshToken, refreshOpts);
    res.json({ user });
  } catch (e) { next(e); }
}

async function me(req, res, next) {
  try {
    const user = await Auth.me(req.user.sub);
    res.json({ user });
  } catch (e) { next(e); }
}

async function refresh(req, res, next) {
  try {
    const token = req.cookies?.refreshToken || req.body?.refreshToken;
    if (!token) { const err = new Error("refreshToken is required"); err.status = 400; throw err; }
    const { accessToken, refreshToken } = await Auth.refresh(token);
    res.cookie("accessToken", accessToken, accessOpts);
    res.cookie("refreshToken", refreshToken, refreshOpts);
    res.json({ accessToken, refreshToken });
  } catch (e) { next(e); }
}

async function logout(req, res, next) {
  try {
    await Auth.logout(req.cookies?.refreshToken);
    res.clearCookie("accessToken", clearOpts);
    res.clearCookie("refreshToken", { ...clearOpts, path: "/api/auth/refresh" });
    res.json({ success: true });
  } catch (e) { next(e); }
}
module.exports = { register, login, me, refresh, logout };
