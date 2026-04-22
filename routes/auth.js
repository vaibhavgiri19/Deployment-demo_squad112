const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../models/User");
const auth = require("../middleware/authMiddleware");

const router = express.Router();

// Register
router.post("/register", async (req, res) => {
  const { name, email, password } = req.body;

  try {
    let user = await User.findOne({ email });
    if (user) return res.status(400).json({ msg: "User exists" });

    const hashed = await bcrypt.hash(password, 10);

    user = new User({ name, email, password: hashed });
    await user.save();

    res.json({ msg: "User registered" });
  } catch (err) {
    res.status(500).json(err);
  }
});

// Login
router.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ msg: "Invalid credentials" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ msg: "Invalid credentials" });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "1d"
    });

    res.json({ token });
  } catch (err) {
    res.status(500).json(err);
  }
});

// Protected route
router.get("/profile", auth, async (req, res) => {
  res.json({ msg: "Welcome user", user: req.user });
});

module.exports = router;