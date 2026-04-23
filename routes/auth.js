router.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });

    // ✅ check user first
    if (!user) {
      return res.status(400).json({ msg: "User not found" });
    }

    // ✅ check password exists
    if (!user.password) {
      return res.status(500).json({ msg: "Password missing in DB" });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(400).json({ msg: "Invalid credentials" });
    }

    const token = jwt.sign(
      { id: user._id },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );

    res.json({ token });

  } catch (err) {
    console.error(err); // 🔥 VERY IMPORTANT
    res.status(500).json({ msg: "Server error" });
  }
});