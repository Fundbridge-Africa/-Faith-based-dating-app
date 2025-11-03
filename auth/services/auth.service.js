const bcrypt = require("bcrypt");
const crypto = require("crypto");
const User = require("../models/User");
const Session = require("../models/Session");
const { signAccessToken, signRefreshToken, verifyRefreshToken } = require("../../utils/jwt");

const SALT_ROUNDS = 10;

const sanitize = u => ({ 
  id:u.id, 
  email:u.email, 
  name:u.name, 
  role:u.role, 
  createdAt:u.createdAt, 
  updatedAt:u.updatedAt 
});

function sha256(s) { 
  return crypto.createHash('sha256').update(s).digest('hex'); }

function refreshExpiryDate() {
  const ttl = process.env.REFRESH_TOKEN_TTL || '7d';
  const n = parseInt(ttl); const unit = ttl.replace(n, '');
  const ms = unit === 'd' ? n*864e5 : unit === 'h' ? n*36e5 : unit === 'm' ? n*6e4 : n*1e3;
  return new Date(Date.now() + ms);
}

async function issueTokens(user, reqMeta){
  const accessToken  = signAccessToken({ sub:user.id, email:user.email, role:user.role });
  const refreshToken = signRefreshToken({ sub:user.id });
  // create/record a device session for THIS refresh token
  await Session.create({
    userId: user.id,
    tokenHash: sha256(refreshToken),
    userAgent: reqMeta?.ua,
    ip: reqMeta?.ip,
    expiresAt: refreshExpiryDate()
  });
  return { accessToken, refreshToken };
}

async function register({ email, password, name }, reqMeta){
  const exists = await User.findOne({ email: String(email).trim().toLowerCase() });
  if (exists) { const e = new Error("Email already in use"); e.status = 409; throw e; }
  const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
  const user = await User.create({ email, passwordHash, name });
  const tokens = await issueTokens(user, reqMeta);
  return { user: sanitize(user), ...tokens };
}

async function login({ email, password }, reqMeta){
  const user = await User.findOne({ email: String(email).trim().toLowerCase() });
  if (!user) { const e = new Error("Invalid credentials"); e.status = 401; throw e; }
  const ok = typeof user.comparePassword === 'function'
    ? await user.comparePassword(password)
    : await bcrypt.compare(password, user.passwordHash);
  if (!ok) { const e = new Error("Invalid credentials"); e.status = 401; throw e; }
  const tokens = await issueTokens(user, reqMeta);
  return { user: sanitize(user), ...tokens };
}
async function me(userId){
  const user = await User.findById(userId);
  if(!user){ const e=new Error("User not found"); e.status=404; throw e; }
  return sanitize(user);
}

async function refresh(refreshToken){
  const { sub } = verifyRefreshToken(refreshToken);
  const user = await User.findById(sub);
  if(!user) { const e=new Error("Invalid refresh token"); e.status=401; throw e; }

  const h = sha256(refreshToken);
  const session = await Session.findOne({ userId: user.id, tokenHash: h });
  if(!session) { const e=new Error("Invalid refresh token"); e.status=401; throw e; }
  const { accessToken, refreshToken: newRt } = await issueTokens(user, { ua: session.userAgent, ip: session.ip });
  await Session.deleteOne({ _id: session._id });
  return { accessToken, refreshToken: newRt };
}

async function logout(refreshToken){
  if (!refreshToken) return { success: true };          
  try {
    const h = sha256(refreshToken);
    await Session.deleteOne({ tokenHash: h });        
  } catch (_) { /* ignore */ }
  return { success: true };
}

async function logoutAll(userId){
  await Session.deleteMany({ userId });
  return { success: true };
}

module.exports = { register, login, me, refresh, logout, logoutAll };
