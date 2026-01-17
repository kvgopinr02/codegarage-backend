import express from "express";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import cors from "cors";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();

/* ---------- ENV CHECK ---------- */
if (!process.env.MONGO_URI || !process.env.JWT_SECRET) {
  console.error("❌ Missing environment variables");
  process.exit(1);
}

const app = express();

/* ---------- MIDDLEWARE ---------- */
app.use(cors({
  origin: "*",
  credentials: true
}));
app.use(express.json());

/* ---------- HEALTH CHECK ---------- */
app.get("/", (req, res) => {
  res.send("🚀 Backend is running successfully");
});

/* ---------- MONGODB CONNECTION ---------- */
mongoose
  .connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
  })
  .then(() => console.log("✅ MongoDB Connected"))
  .catch((err) => {
    console.error("❌ MongoDB Error:", err);
    process.exit(1);
  });

/* ---------- USER SCHEMA ---------- */
const userSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: true,
      trim: true
    },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true
    },
    password: {
      type: String,
      required: true
    }
  },
  { timestamps: true }
);

const User = mongoose.model("User", userSchema);

/* ---------- REGISTER ---------- */
app.post("/register", async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.json({ success: false, message: "All fields required" });
    }

    const exists = await User.findOne({ email });
    if (exists) {
      return res.json({ success: false, message: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({
      username,
      email,
      password: hashedPassword
    });

    await user.save();

    res.json({ success: true, message: "User registered successfully" });

  } catch (error) {
    console.error("REGISTER ERROR:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

/* ---------- LOGIN ---------- */
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.json({ success: false, message: "User not found" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.json({ success: false, message: "Invalid credentials" });
    }

    const token = jwt.sign(
      {
        id: user._id,
        email: user.email,
        username: user.username
      },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({
      success: true,
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email
      }
    });

  } catch (error) {
    console.error("LOGIN ERROR:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

/* ---------- JWT AUTH MIDDLEWARE ---------- */
const auth = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ message: "No token provided" });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ message: "Invalid token" });
  }
};

/* ---------- PROFILE ---------- */
app.get("/profile", auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password");

    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    res.json({
      success: true,
      user: {
        username: user.username,
        email: user.email
      }
    });

  } catch (error) {
    res.status(500).json({ success: false, message: "Server error" });
  }
});

/* ---------- TOTAL USERS COUNT ---------- */
app.get("/users/count", async (req, res) => {
  try {
    const count = await User.countDocuments();
    res.json({ success: true, count });
  } catch (error) {
    res.status(500).json({ success: false, message: "Server error" });
  }
});

/* ---------- SERVER START ---------- */
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
