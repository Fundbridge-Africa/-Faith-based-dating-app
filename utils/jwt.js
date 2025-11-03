const jwt = require('jsonwebtoken');

const ACCESS_SECRET  = process.env.JWT_ACCESS_SECRET;
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;

function signAccessToken(payload) {
  return jwt.sign(payload, ACCESS_SECRET,  { 
    expiresIn: process.env.ACCESS_TOKEN_TTL  || '15m'  });
}
function signRefreshToken(payload) {
  return jwt.sign(payload, ACCESS_SECRET,  { 
    expiresIn: process.env.ACCESS_TOKEN_TTL  || '15m' });
}
function verifyAccessToken(token)  {
     return jwt.verify(token,  ACCESS_SECRET); }
function verifyRefreshToken(token) {
     return jwt.verify(token, REFRESH_SECRET); }

module.exports = { signAccessToken, signRefreshToken, verifyAccessToken, verifyRefreshToken };
