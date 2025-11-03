const { body } = require("express-validator");

const updateProfileRules = [
  body("displayName").optional().isString().trim(),
  body("gender").optional().isIn(["male", "female", "other"]),
  body("birthdate").optional().isISO8601().toDate(),
  body("faith").optional().isString().trim(),
  body("denomination").optional().isString().trim(),
  body("values").optional().isArray(),
  body("bio").optional().isString().isLength({ max: 1000 }),
  body("location").optional().isObject(),
  body("location.city").optional().isString(),
  body("location.country").optional().isString(),
  body("location.lat").optional().isFloat({ min: -90, max: 90 }),
  body("location.lng").optional().isFloat({ min: -180, max: 180 }),
  body("photos").optional().isArray(),
  body("onboardingCompleted").optional().isBoolean(),
];

module.exports = { updateProfileRules };
