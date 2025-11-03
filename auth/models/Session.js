const { Schema, model } = require('mongoose');

const sessionSchema = new Schema({
  userId:   { type: Schema.Types.ObjectId, ref: 'User', index: true, required: true },
  tokenHash:{ type: String, required: true, unique: true },  // SHA-256 of the refresh token
  userAgent:String,
  ip:       String,
  expiresAt:{ type: Date, index: true }
}, { timestamps: true });

// TTL index: MongoDB will auto-delete expired sessions
sessionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

module.exports = model('Session', sessionSchema);