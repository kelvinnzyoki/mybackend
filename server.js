require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");
const { Resend } = require('resend');

const app = express();

// Middleware
app.use(helmet());
app.use(cors({
  origin: "*", // ⚠️ TEMPORARY - Allow all origins for testing
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());

// PostgreSQL Pool with better error handling
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  },
  max: 10, // Reduced for serverless
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

pool.on('error', (err) => {
  console.error('Unexpected DB error:', err);
});

// Resend client
const resend = new Resend(process.env.RESEND_API_KEY);

// In-memory store for verification codes (since Redis won't work reliably on Vercel)
// For production, use Vercel KV or Upstash Redis REST API
const verificationCodes = new Map();

// Helper functions
function isValidScore(value) {
  const num = parseInt(value, 10);
  return Number.isInteger(num) && num >= 0 && num <= 200000;
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

// Clean up old verification codes every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [email, data] of verificationCodes.entries()) {
    if (now - data.timestamp > 300000) { // 5 minutes
      verificationCodes.delete(email);
    }
  }
}, 300000);

// Root endpoint
app.get("/", (req, res) => {
  res.json({ 
    status: "online", 
    message: "🚀 Backend is live",
    timestamp: new Date().toISOString()
  });
});

// Health check
app.get("/health", async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ 
      status: "healthy", 
      database: "connected",
      resend: !!process.env.RESEND_API_KEY
    });
  } catch (err) {
    res.status(500).json({ 
      status: "unhealthy", 
      error: err.message 
    });
  }
});

// SEND VERIFICATION CODE
app.post("/send-code", async (req, res) => {
  console.log("📧 /send-code called");
  
  const { email } = req.body;
  
  if (!email || !isValidEmail(email)) {
    console.log("❌ Invalid email");
    return res.status(400).json({ message: "Valid email required" });
  }

  const code = Math.floor(100000 + Math.random() * 900000).toString();
  
  try {
    console.log("📨 Sending email to:", email);
    
    // ⚠️ CRITICAL: Make sure this email is verified in Resend dashboard
    const result = await resend.emails.send({
      from: "onboarding@resend.dev", // ✅ Use Resend's default for testing
      // Change to "noreply@cctamcc.site" after domain verification
      to: email,
      subject: "Your Verification Code",
      html: `
        <h2>Verification Code</h2>
        <p>Your verification code is: <strong style="font-size: 24px; color: #4CAF50;">${code}</strong></p>
        <p>This code will expire in 5 minutes.</p>
      `
    });

    console.log("✅ Email sent:", result);

    // Store code in memory with timestamp
    verificationCodes.set(email, {
      code: code,
      timestamp: Date.now()
    });

    console.log("✅ Code stored for:", email);

    res.json({ success: true, message: "Code sent successfully" });
    
  } catch (err) {
    console.error("❌ Send code error:", err);
    res.status(500).json({ 
      message: "Failed to send verification code",
      error: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
  }
});

// SIGNUP
app.post("/signup", async (req, res) => {
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
    const storedData = verificationCodes.get(email);
    
    if (!storedData) {
      console.log("❌ No code found for:", email);
      return res.status(400).json({ message: "Code expired or not found" });
    }

    // Check if code expired (5 minutes)
    if (Date.now() - storedData.timestamp > 300000) {
      verificationCodes.delete(email);
      return res.status(400).json({ message: "Code expired" });
    }

    if (storedData.code !== code) {
      console.log("❌ Invalid code");
      return res.status(400).json({ message: "Invalid verification code" });
    }

    console.log("✅ Code verified");

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert user
    await pool.query(
      `INSERT INTO users (username, email, password, dob) VALUES ($1, $2, $3, $4)`,
      [username, email, hashedPassword, dob]
    );

    // Clean up code
    verificationCodes.delete(email);

    console.log("✅ User created:", email);

    res.json({ success: true, message: "Account created successfully" });
    
  } catch (err) {
    console.error("❌ Signup error:", err);
    
    if (err.code === '23505') {
      res.status(409).json({ message: "Email or username already exists" });
    } else {
      res.status(500).json({ message: "Database error" });
    }
  }
});

// LOGIN
app.post("/login", async (req, res) => {
  console.log("🔐 /login called");
  
  const { email, password } = req.body;
  
  if (!email || !password) {
    return res.status(400).json({ message: "Email and password required" });
  }

  try {
    const result = await pool.query(
      "SELECT * FROM users WHERE email = $1", 
      [email]
    );

    if (!result.rows.length) {
      console.log("❌ User not found");
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      console.log("❌ Password mismatch");
      return res.status(400).json({ message: "Invalid credentials" });
    }

    console.log("✅ Login successful");

    res.json({ 
      success: true, 
      user: { 
        email: user.email, 
        username: user.username 
      } 
    });
    
  } catch (err) {
    console.error("❌ Login error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Score endpoints (keeping your existing ones)
app.post("/addictions", async (req, res) => {
  const { email, score, date } = req.body;
  if (!email || !isValidEmail(email)) return res.status(400).json({ message: "Valid email required" });
  if (!isValidScore(score)) return res.status(400).json({ message: "Invalid score" });

  const recordDate = date ? new Date(date) : new Date();

  try {
    const result = await pool.query(
      `INSERT INTO addictions (email, date, score) VALUES ($1, $2, $3)
       ON CONFLICT (email, date) DO UPDATE SET score = EXCLUDED.score RETURNING *`,
      [email, recordDate, parseInt(score, 10)]
    );
    res.status(201).json({ success: true, data: result.rows[0] });
  } catch (err) {
    console.error("Addiction record error:", err);
    res.status(500).json({ message: "Database error" });
  }
});

app.post("/pushups", async (req, res) => {
  const { email, score, date } = req.body;
  if (!email || !isValidEmail(email)) return res.status(400).json({ message: "Valid email required" });
  if (!isValidScore(score)) return res.status(400).json({ message: "Invalid score" });

  const recordDate = date ? new Date(date) : new Date();

  try {
    const result = await pool.query(
      `INSERT INTO pushups (email, date, score) VALUES ($1, $2, $3)
       ON CONFLICT (email, date) DO UPDATE SET score = EXCLUDED.score RETURNING *`,
      [email, recordDate, parseInt(score, 10)]
    );
    res.status(201).json({ success: true, data: result.rows[0] });
  } catch (err) {
    console.error("Push-ups record error:", err);
    res.status(500).json({ message: "Database error" });
  }
});

app.post("/situps", async (req, res) => {
  const { email, score, date } = req.body;
  if (!email || !isValidEmail(email)) return res.status(400).json({ message: "Valid email required" });
  if (!isValidScore(score)) return res.status(400).json({ message: "Invalid score" });

  const recordDate = date ? new Date(date) : new Date();

  try {
    const result = await pool.query(
      `INSERT INTO situps (email, date, score) VALUES ($1, $2, $3)
       ON CONFLICT (email, date) DO UPDATE SET score = EXCLUDED.score RETURNING *`,
      [email, recordDate, parseInt(score, 10)]
    );
    res.status(201).json({ success: true, data: result.rows[0] });
  } catch (err) {
    console.error("Sit-ups record error:", err);
    res.status(500).json({ message: "Database error" });
  }
});

app.post("/squats", async (req, res) => {
  const { email, score, date } = req.body;
  if (!email || !isValidEmail(email)) return res.status(400).json({ message: "Valid email required" });
  if (!isValidScore(score)) return res.status(400).json({ message: "Invalid score" });

  const recordDate = date ? new Date(date) : new Date();

  try {
    const result = await pool.query(
      `INSERT INTO squats (email, date, score) VALUES ($1, $2, $3)
       ON CONFLICT (email, date) DO UPDATE SET score = EXCLUDED.score RETURNING *`,
      [email, recordDate, parseInt(score, 10)]
    );
    res.status(201).json({ success: true, data: result.rows[0] });
  } catch (err) {
    console.error("Squats record error:", err);
    res.status(500).json({ message: "Database error" });
  }
});

app.post("/steps", async (req, res) => {
  const { email, score, date } = req.body;
  if (!email || !isValidEmail(email)) return res.status(400).json({ message: "Valid email required" });
  if (!isValidScore(score)) return res.status(400).json({ message: "Invalid score" });

  const recordDate = date ? new Date(date) : new Date();

  try {
    const result = await pool.query(
      `INSERT INTO steps (email, date, score) VALUES ($1, $2, $3)
       ON CONFLICT (email, date) DO UPDATE SET score = EXCLUDED.score RETURNING *`,
      [email, recordDate, parseInt(score, 10)]
    );
    res.status(201).json({ success: true, data: result.rows[0] });
  } catch (err) {
    console.error("Steps record error:", err);
    res.status(500).json({ message: "Database error" });
  }
});

app.get("/total-score", async (req, res) => {
  const { email } = req.query;
  if (!email) return res.status(400).json({ message: "Email required" });

  try {
    const query = `
      SELECT SUM(score::int) AS total_score FROM (
        SELECT DISTINCT ON (date) score FROM pushups WHERE email = $1
        UNION ALL SELECT DISTINCT ON (date) score FROM situps WHERE email = $1
        UNION ALL SELECT DISTINCT ON (date) score FROM squats WHERE email = $1
        UNION ALL SELECT DISTINCT ON (date) score FROM steps WHERE email = $1
        UNION ALL SELECT DISTINCT ON (date) score FROM addictions WHERE email = $1
      ) s;
    `;
    const result = await pool.query(query, [email]);
    const total = result.rows[0]?.total_score || 0;
    res.json({ success: true, total_score: parseInt(total) });
  } catch (err) {
    console.error("Total score error:", err);
    res.status(500).json({ success: false, message: "Error calculating score" });
  }
});

app.get("/leaderboard", async (_, res) => {
  try {
    const result = await pool.query(`
      SELECT email, SUM(score::int) AS total_score FROM (
        SELECT DISTINCT ON (email, date) email, score FROM pushups
        UNION ALL SELECT DISTINCT ON (email, date) email, score FROM situps
        UNION ALL SELECT DISTINCT ON (email, date) email, score FROM squats
        UNION ALL SELECT DISTINCT ON (email, date) email, score FROM steps
        UNION ALL SELECT DISTINCT ON (email, date) email, score FROM addictions
      ) s GROUP BY email ORDER BY total_score DESC LIMIT 10;
    `);
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Leaderboard error" });
  }
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ message: "Endpoint not found" });
});

// Error handler
app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  res.status(500).json({ message: "Internal server error" });
});

// Export for Vercel
module.exports = app;

// Local server (won't run on Vercel)
if (require.main === module) {
  const PORT = process.env.PORT || 8080;
  app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
}
