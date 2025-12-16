import express from "express";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import cors from "cors";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();
const app = express();

/* ---------- MIDDLEWARE ---------- */
app.use(cors());
app.use(express.json());

/* ---------- MONGODB CONNECTION ---------- */
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB Connected"))
  .catch((err) => console.log("❌ MongoDB Error:", err));

/* ---------- USER SCHEMA ---------- */
const userSchema = new mongoose.Schema({
  username: String,
  email: { type: String, unique: true },
  password: String
}, { timestamps: true });

const User = mongoose.model("User", userSchema);

/* ---------- FEEDBACK SCHEMA ---------- */
const feedbackSchema = new mongoose.Schema({
  name: String,
  experience: String,
  problems: String,
  suggestions: String,
  createdAt: { type: Date, default: Date.now }
});

const Feedback = mongoose.model("Feedback", feedbackSchema);

/* ---------- REGISTER ---------- */
app.post("/register", async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password)
    return res.json({ success: false });

  const exists = await User.findOne({ email });
  if (exists) return res.json({ success: false });

  const hash = await bcrypt.hash(password, 10);
  await User.create({ username, email, password: hash });

  res.json({ success: true });
});

/* ---------- LOGIN ---------- */
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email });
  if (!user) return res.json({ success: false });

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.json({ success: false });

  const token = jwt.sign(
    { id: user._id, username: user.username },
    process.env.JWT_SECRET,
    { expiresIn: "1h" }
  );

  res.json({ success: true, token });
});

/* ---------- AUTH ---------- */
const auth = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({});

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({});
  }
};

/* ---------- PROFILE ---------- */
app.get("/profile", auth, async (req, res) => {
  const user = await User.findById(req.user.id).select("-password");
  res.json({ success: true, user });
});

/* ---------- USERS COUNT ---------- */
app.get("/users/count", async (req, res) => {
  const count = await User.countDocuments();
  res.json({ count });
});

/* ================= FEEDBACK API ================= */

/* USER SUBMIT FEEDBACK */
app.post("/feedback", async (req, res) => {
  await Feedback.create(req.body);
  res.json({ success: true });
});

/* ADMIN VIEW FEEDBACK */
app.get("/feedback/admin", async (req, res) => {
  const adminSecret = req.headers["admin-secret"];

  if (adminSecret !== process.env.ADMIN_SECRET) {
    return res.status(403).json({ message: "Unauthorized" });
  }

  const data = await Feedback.find().sort({ createdAt: -1 });
  res.json(data);
});

/* ---------- SERVER ---------- */
const PORT = process.env.PORT || 5000;
app.listen(PORT, () =>
  console.log(`🚀 Server running on port ${PORT}`)
);
