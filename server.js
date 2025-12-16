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
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB Connected"))
  .catch(err => console.log("❌ MongoDB Error:", err));

/* ---------- USER SCHEMA ---------- */
const userSchema = new mongoose.Schema({
  username: String,
  email: { type: String, unique: true },
  password: String
});
const User = mongoose.model("User", userSchema);

/* ---------- FEEDBACK SCHEMA ---------- */
const feedbackSchema = new mongoose.Schema({
  email: { type: String, required: true },
  name: { type: String, required: true },
  experience: String,
  problems: String,
  suggestions: String,
  createdAt: { type: Date, default: Date.now }
});
const Feedback = mongoose.model("Feedback", feedbackSchema);

/* ---------- REGISTER ---------- */
app.post("/register", async (req, res) => {
  const { username, email, password } = req.body;

  const hash = await bcrypt.hash(password, 10);
  await User.create({ username, email, password: hash });

  res.json({ success: true });
});

/* ---------- LOGIN ---------- */
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email });
  if (!user) return res.status(401).json({});

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(401).json({});

  const token = jwt.sign(
    { id: user._id, email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: "1h" }
  );

  res.json({ token });
});

/* ---------- AUTH ---------- */
const auth = (req, res, next) => {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({});

  try {
    const token = header.split(" ")[1];
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({});
  }
};

/* ---------- FEEDBACK SUBMIT ---------- */
app.post("/feedback", auth, async (req, res) => {
  const { name, experience, problems, suggestions } = req.body;

  const feedback = await Feedback.create({
    email: req.user.email,
    name,
    experience,
    problems,
    suggestions
  });

  res.json({ success: true, createdAt: feedback.createdAt });
});

/* ---------- ADMIN VIEW ---------- */
app.get("/feedback/admin", async (req, res) => {
  if (req.headers["admin-secret"] !== process.env.ADMIN_SECRET)
    return res.status(403).json({});

  const data = await Feedback.find().sort({ createdAt: -1 });
  res.json(data);
});

/* ---------- SERVER ---------- */
app.listen(5000, () =>
  console.log("🚀 Server running on port 5000")
);
