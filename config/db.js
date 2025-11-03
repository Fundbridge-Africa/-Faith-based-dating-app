const mongoose = require("mongoose");

async function connectDB() {
  const uri = process.env.MONGO_URI;
  if (!uri) throw new Error("MONGO_URI missing");

  mongoose.connection.on("connected", () => {
    const { host, name } = mongoose.connection;
    console.log(`✅ MongoDB connected → host=${host}, db=${name}`);
  });
  mongoose.connection.on("error", (err) => console.error("❌ MongoDB error:", err.message));
  mongoose.connection.on("disconnected", () => console.warn("⚠️ MongoDB disconnected"));

  await mongoose.connect(uri, {
    serverSelectionTimeoutMS: 10000,
  });
}

module.exports = { connectDB };