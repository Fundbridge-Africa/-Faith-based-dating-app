const jwt = require("jsonwebtoken");
const { verifyAccessToken, verifyRefreshToken } = require("../utils/jwt");
const Auth = require('../auth/services/auth.service');
const { accessOpts, refreshOpts } = require("../utils/cookies");

const tokenFromReq = (req) => {
  const h = req.headers.authorization || "";
  const p = h.split(" ");
  if (p.length===2 && p[0]==="Bearer") return p[1];
  return req.cookies?.accessToken || null;
};

async function requireAuth(req,res,next){
  const access = tokenFromReq(req);
  const rCookie = req.cookies?.refreshToken;
  if(!access){
    if(!rCookie) return next(Object.assign(new Error("Missing Bearer token"),{status:401}));
    return refreshAndNext(req,res,next,rCookie);
  }
  try{
    req.user = verifyAccessToken(access);
    return next();
  }catch(e){
    const expired = e instanceof jwt.TokenExpiredError;
    if(expired && rCookie) return refreshAndNext(req,res,next,rCookie);
    return next(Object.assign(new Error("Invalid or expired token"),{status:401}));
  }
}
function requireAuth(req, res, next) {
  const token = req.cookies?.accessToken || (req.headers.authorization || '').replace(/^Bearer\s+/,'');
  if (!token) return res.status(401).json({ message: 'Unauthorized' });
  try {
    const payload = verifyAccessToken(token);
    req.user = payload; // { sub, email, role, ... }
    next();
  } catch {
    res.status(401).json({ message: 'Invalid token' });
  }
}
async function refreshAndNext(req,res,next,rCookie){
  try{
    verifyRefreshToken(rCookie);
    const { accessToken, refreshToken } = await Auth.refresh(rCookie);
    res.cookie("accessToken", accessToken, accessOpts);
    res.cookie("refreshToken", refreshToken, refreshOpts);
    req.user = jwt.decode(accessToken);
    return next();
  }catch{
    return next(Object.assign(new Error("Invalid refresh token"),{status:401}));
  }
}

function errorHandler(err, _req, res, _next) {
  const status = err.status || 500;
  res.status(status).json({ message: err.message || 'Server error' });
}
module.exports = { requireAuth, errorHandler };
