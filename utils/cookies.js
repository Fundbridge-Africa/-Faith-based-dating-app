const isProd = process.env.NODE_ENV === "production";
const domain = process.env.COOKIE_DOMAIN || "localhost";

// Access token 
const accessOpts = {
  httpOnly: true,
  secure: isProd,    
  sameSite: "lax",
  domain,                  
  path: "/",              
  maxAge: 15 * 60 * 1000,
};

// Refresh token
const refreshOpts = {
  httpOnly: true,
  secure: isProd,
  sameSite: "lax",
  domain,
  path: "/api/auth/refresh",  
  maxAge: 7 * 24 * 60 * 60 * 1000, 
};

const clearOpts = {
  httpOnly: true,
  secure: isProd,
  sameSite: "lax",
  domain,
  path: "/",
};

module.exports = { accessOpts, refreshOpts, clearOpts };
