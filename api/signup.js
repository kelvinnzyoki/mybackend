const { getPool } = require('./_lib/db');
const bcrypt = require('bcryptjs');

// Import the codes map from send-code
const { codes } = require('./send-code');

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ message: 'Method not allowed' });
  }

  console.log("👤 /signup called");

  const { email, code, username, password, dob } = req.body;

  if (!email || !username || !password || !dob || !code) {
    return res.status(400).json({ message: "All fields required" });
  }

  if (password.length < 8) {
    return res.status(400).json({ message: "Password must be at least 8 characters" });
  }

  try {
    // Verify code
    const storedData = codes.get(email);

    if (!storedData) {
      console.log("❌ No code found");
      return res.status(400).json({ message: "Code not found or expired" });
    }

    if (Date.now() - storedData.timestamp > 300000) {
      codes.delete(email);
      return res.status(400).json({ message: "Code expired" });
    }

    if (storedData.code !== code) {
      console.log("❌ Invalid code");
      return res.status(400).json({ message: "Invalid code" });
    }

    console.log("✅ Code verified");

    const hashedPassword = await bcrypt.hash(password, 10);
    const pool = getPool();

    await pool.query(
      `INSERT INTO users (username, email, password, dob) VALUES ($1, $2, $3, $4)`,
      [username, email, hashedPassword, dob]
    );

    codes.delete(email);

    console.log("✅ User created");

    res.status(200).json({ success: true });

  } catch (err) {
    console.error("❌ Error:", err);

    if (err.code === '23505') {
      res.status(409).json({ message: "Email or username already exists" });
    } else {
      res.status(500).json({ message: "Database error" });
    }
  }
};
