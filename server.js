require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");
const { createClient } = require("redis");
const nodemailer = require("nodemailer");

const app = express();

/**********************************
 * MIDDLEWARE
 **********************************/
app.use(helmet());
app.use(cors({
  origin: [
    "https://kelvinnzyoki.github.io",
    "https://kelvinnzyoki.github.io/TAM",
    "http://localhost:5500",  // For local testing
    "http://127.0.0.1:5500"
  ], 
  credentials: true
}));
app.use(express.json());

/**********************************
 * DATABASE (PostgreSQL)
 **********************************/
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: true } // Set to true for production if cert trusted
});

/**********************************
 * REDIS
 **********************************/
const redisClient = createClient({
  url: process.env.REDIS_URL,
  socket: {
    connectTimeout: 10000
  }
});

redisClient.on('error', (err) => console.log('❌ Redis Error:', err));

async function connectRedis() {
  try {
    if (!redisClient.isOpen) {
      await redisClient.connect();
      console.log("✅ Redis connected successfully");
    }
  } catch (err) {
    console.error("❌ Redis connection failed. Check your REDIS_URL variable.", err);
    // Optional: process.exit(1); to crash if critical
  }
}

/**********************************
 * MAILER
 **********************************/
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

async function verifyTransporter() {
  try {
    await transporter.verify();
    console.log("✅ Email transporter ready");
  } catch (err) {
    console.error("❌ Email setup failed. Check EMAIL_USER/PASS (use App Password for Gmail).", err);
  }
}

/**********************************
 * HELPERS
 **********************************/
function isValidScore(value) {
  const num = parseInt(value, 10);
  return Number.isInteger(num) && num >= 0 && num <= 200000;
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

/**********************************
 * ROUTES
 **********************************/

app.get("/", (_, res) => res.send("🚀 Backend is live"));

// PHASE 1: SEND EMAIL CODE
app.post("/send-code", async (req, res) => {
  const { email } = req.body;
  if (!email || !isValidEmail(email)) return res.status(400).json({ message: "Valid email required" });

  const code = Math.floor(100000 + Math.random() * 900000).toString();

  try {
    await redisClient.set(email, code, { EX: 600 });

    await transporter.sendMail({
      from: `"TAM Evolution" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "Verification Code",
      text: `Your verification code is: ${code}`
    });

    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Email or Redis error" });
  }
});

// PHASE 2: SIGNUP
app.post("/signup", async (req, res) => {
  const { email, code, username, password, dob } = req.body;
  if (!email || !username || !password || !dob || !code) return res.status(400).json({ message: "All fields required" });
  if (password.length < 8) return res.status(400).json({ message: "Password must be at least 8 characters" });
  // Add DOB validation if needed (e.g., Date.parse(dob))

  try {
    const storedCode = await redisClient.get(email);
    if (!storedCode || storedCode !== code) {
      return res.status(400).json({ message: "Invalid or expired code" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await pool.query(
      `INSERT INTO users (username, email, password, dob) VALUES ($1, $2, $3, $4)`,
      [username, email, hashedPassword, dob]
    );

    await redisClient.del(email);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    if (err.code === '23505') { // PG unique violation
      res.status(409).json({ message: "Email or username already exists" });
    } else {
      res.status(500).json({ message: "Database error" });
    }
  }
});

// LOGIN
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ message: "Email and password required" });

  try {
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (!result.rows.length) return res.status(400).json({ message: "Invalid credentials" });

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ message: "Invalid credentials" });

    res.json({ success: true, user: { email: user.email, username: user.username } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

/**********************************
 * SCORE & LEADERBOARD
 **********************************/
app.post("/record-score", async (req, res) => {
  const { email, score, date, table } = req.body;
  if (!email || !isValidScore(score) || !table) return res.status(400).json({ message: "Invalid input" });

  const allowedTables = ['pushups', 'situps', 'squats', 'steps', '"Addictions"'];
  if (!allowedTables.includes(table)) return res.status(400).json({ message: "Invalid table" });

  try {
    const query = `INSERT INTO ${table} (email, date, score) VALUES ($1, $2, $3) RETURNING *`;
    const result = await pool.query(query, [email, date || new Date().toISOString(), parseInt(score, 10)]);
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Database error" });
  }
});

app.get("/leaderboard", async (_, res) => {
  try {
    const result = await pool.query(`
      SELECT email, SUM(score::int) AS total_score
      FROM (
        SELECT DISTINCT ON (email, date) email, score FROM pushups
        UNION ALL
        SELECT DISTINCT ON (email, date) email, score FROM situps
        UNION ALL
        SELECT DISTINCT ON (email, date) email, score FROM squats
        UNION ALL
        SELECT DISTINCT ON (email, date) email, score FROM steps
        UNION ALL
        SELECT DISTINCT ON (email, date) email, score FROM "Addictions"
      ) s
      GROUP BY email ORDER BY total_score DESC LIMIT 10;
    `);
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Leaderboard error" });
  }
});

// Startup
(async () => {
  await connectRedis();
  await verifyTransporter();
  const PORT = process.env.PORT || 8080;
  app.listen(PORT, "0.0.0.0", () => console.log(`🚀 Server on port ${PORT}`));
})();
