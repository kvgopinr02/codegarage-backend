import express from "express";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import cors from "cors";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();
const app = express();

// ---------- MIDDLEWARE ----------
app.use(cors());
app.use(express.json());

// ---------- MONGODB CONNECTION ----------
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB Connected"))
  .catch((err) => console.log("❌ MongoDB Error:", err));

// ---------- USER SCHEMA ----------
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true }
});

const User = mongoose.model("User", userSchema);

// ---------- REGISTER ----------
app.post("/register", async (req, res) => {
  try {
    const { email, password } = req.body;

    const exists = await User.findOne({ email });
    if (exists) {
      return res.json({ success: false, message: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await User.create({ email, password: hashedPassword });

    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// ---------- LOGIN (JWT) ----------
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.json({ success: false });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.json({ success: false });
    }

    const token = jwt.sign(
      { id: user._id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({ success: true, token });
  } catch (error) {
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// ---------- JWT AUTH MIDDLEWARE ----------
const auth = (req, res, next) => {
  const token = req.headers.authorization;

  if (!token) {
    return res.status(401).json({ message: "No token provided" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ message: "Invalid token" });
  }
};

// ---------- PROFILE ----------
app.get("/profile", auth, (req, res) => {
  res.json({
    id: req.user.id,
    email: req.user.email
  });
});

// ---------- TOTAL USERS COUNT ----------
app.get("/users/count", async (req, res) => {
  try {
    const count = await User.countDocuments();
    res.json({ count });
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
});

// ---------- SERVER START ----------
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
