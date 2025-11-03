
function requireRole(...roles) {
  return (req, _res, next) => {
    const role = req.user?.role;
    if (!role || !roles.includes(role)) {
      const e = new Error("Forbidden");
      e.status = 403;
      return next(e);
    }
    next();
  };
}

module.exports = { requireRole };