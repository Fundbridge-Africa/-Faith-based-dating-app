require("dotenv").config();
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const morgan = require("morgan");
const rateLimit = require("express-rate-limit");
const cookieParser = require("cookie-parser");
const { connectDB } = require("./config/db");
const authRouter = require("./auth/routes/auth.routes");
const profileRouter = require("./auth/routes/profile.routes");

const app = express();

app.use(helmet());
app.use(morgan("dev"));
app.use(cookieParser());
app.use(express.json());

const ALLOWED_ORIGINS = (process.env.CORS_ORIGINS || "http://localhost:5173")
  .split(",")
  .map(s => s.trim());

app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin || ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
      return cb(new Error("Not allowed by CORS"));
    },
    credentials: true,
  })
);

app.get(['/api/health', '/health'],
  (_req, res) => res.status(200).json({ ok: true })
);
app.head(['/api/health', '/health'],
  rateLimit({
    windowMs: 10 * 60 * 1000,
    max: 100,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: "Too many requests, please try again later." },
    statusCode: 429,
    handler: (_req, res) => res.status(429).json({ error: "Too many requests" }),
    keyGenerator: (req) => req.ip
      + req.headers['x-forwarded-for']
      + req.headers['x-real-ip']
      + req.connection.remoteAddress,
      skipFailedRequests: true,
      skipSuccessfulRequests: false,
      requestWasSuccessful: (_req, res) => res.statusCode < 400,  
      skip: (_req, res) => res.statusCode === 429 
        || res.statusCode === 404
        || res.statusCode === 502
        || res.statusCode === 503
        || res.statusCode === 504
        || res.statusCode === 505
  }), (_req, res) => res.status(200).json({ ok: true }));

const authLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use("/api/auth", authLimiter);

app.use("/api/auth", authRouter);
app.use("/api/profile", profileRouter);

const PORT = process.env.PORT || 5000;
(async () => {
  try {
    await connectDB();
    app.listen(PORT, () => console.log(`✅ Backend on http://localhost:${PORT}`));
  } catch (e) {
    console.error("DB connect failed:", e.message);
    process.exit(1);
  }
})();
