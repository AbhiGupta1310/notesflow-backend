//server.js

const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || "notesflow_secret";

// Middleware
app.use(cors());
app.use(bodyParser.json());

// Connect to MongoDB
const dbURI = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/notesDB";
mongoose.connect(dbURI);

// Schemas & Models
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

const noteSchema = new mongoose.Schema({
  title: String,
  content: String,
  owner: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  createdAt: { type: Date, default: Date.now },
});

const User = mongoose.model("User", userSchema);
const Note = mongoose.model("Note", noteSchema);

// Listen for successful MongoDB connection
mongoose.connection.on("connected", () => {
  console.log("Connected to MongoDB");
});

// Listen for MongoDB connection errors
mongoose.connection.on("error", (err) => {
  console.error("MongoDB connection error:", err);
});

// Auth helpers
function generateToken(user) {
  return jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, {
    expiresIn: "7d",
  });
}

async function hashPassword(password) {
  const salt = await bcrypt.genSalt(10);
  return bcrypt.hash(password, salt);
}

async function comparePassword(password, hash) {
  return bcrypt.compare(password, hash);
}

// Auth middleware
function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith("Bearer "))
    return res.status(401).json({ message: "Unauthorized" });
  const token = auth.split(" ")[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = { id: decoded.id, email: decoded.email };
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid token" });
  }
}

// Routes
app.get("/", (req, res) => {
  res.send("Hello, NotesFlow server is running.");
});

// Register
app.post("/api/auth/register", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ message: "Email and password required" });
  try {
    const exists = await User.findOne({ email });
    if (exists) return res.status(409).json({ message: "User already exists" });
    const hashed = await hashPassword(password);
    const user = new User({ email, password: hashed });
    await user.save();
    const token = generateToken(user);
    res.status(201).json({ token, user: { _id: user._id, email: user.email } });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Login
app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ message: "Email and password required" });
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ message: "Invalid credentials" });
    const ok = await comparePassword(password, user.password);
    if (!ok) return res.status(401).json({ message: "Invalid credentials" });
    const token = generateToken(user);
    res.json({ token, user: { _id: user._id, email: user.email } });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Password Reset Request
app.post("/api/auth/forgot-password", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ message: "Email required" });

  try {
    const user = await User.findOne({ email });
    if (!user) {
      // Don't reveal whether a user exists
      return res.json({
        message: "If the email exists, instructions will be sent",
      });
    }

    // Generate reset token (expires in 1 hour)
    const resetToken = jwt.sign({ id: user._id }, JWT_SECRET, {
      expiresIn: "1h",
    });

    // In a real application, you would send an email here with a link containing the reset token
    // For demo purposes, we'll just return success
    console.log(`Reset token for ${email}: ${resetToken}`);

    res.json({ message: "If the email exists, instructions will be sent" });
  } catch (err) {
    res.status(500).json({ message: "Internal server error" });
  }
});

// Reset Password
app.post("/api/auth/reset-password", async (req, res) => {
  const { token, password } = req.body;
  if (!token || !password) {
    return res.status(400).json({ message: "Token and password required" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.id);

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const hashed = await hashPassword(password);
    user.password = hashed;
    await user.save();

    res.json({ message: "Password updated successfully" });
  } catch (err) {
    if (err.name === "JsonWebTokenError") {
      return res.status(401).json({ message: "Invalid or expired token" });
    }
    res.status(500).json({ message: "Could not reset password" });
  }
});

// Get current user
app.get("/api/auth/me", authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("_id email");
    res.json({ user });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Notes (protected)
app.get("/api/notes", authMiddleware, async (req, res) => {
  try {
    const notes = await Note.find({ owner: req.user.id }).sort({
      createdAt: -1,
    });
    res.json(notes);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.post("/api/notes", authMiddleware, async (req, res) => {
  const { title, content } = req.body;
  if (!title || !content)
    return res.status(400).json({ message: "Title and content required" });
  try {
    const note = new Note({ title, content, owner: req.user.id });
    const newNote = await note.save();
    res.status(201).json(newNote);
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

app.put("/api/notes/:id", authMiddleware, async (req, res) => {
  const { title, content } = req.body;
  const noteId = req.params.id;
  try {
    const note = await Note.findOne({ _id: noteId, owner: req.user.id });
    if (!note) return res.status(404).json({ message: "Note not found" });
    note.title = title;
    note.content = content;
    await note.save();
    res.json(note);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.delete("/api/notes/:id", authMiddleware, async (req, res) => {
  const noteId = req.params.id;
  try {
    const note = await Note.findOneAndDelete({
      _id: noteId,
      owner: req.user.id,
    });
    if (!note) return res.status(404).json({ message: "Note not found" });
    res.json({ message: "Note deleted successfully" });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
