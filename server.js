/**********************************
 * ENV + IMPORTS
 **********************************/
require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");
const redis = require("redis");
const nodemailer = require("nodemailer");

const app = express();

/**********************************
 * MIDDLEWARE
 **********************************/
app.use(helmet());
app.use(cors({
  // Removed trailing slash and subfolder to ensure GitHub Pages broad compatibility
  origin: ["https://kelvinnzyoki.github.io/TAM/"], 
  credentials: true
}));
app.use(express.json());

/**********************************
 * DATABASE (PostgreSQL)
 **********************************/
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

/**********************************
 * REDIS
 **********************************/
const redisClient = redis.createClient({
  url: process.env.REDIS_URL
});

redisClient.on("error", err => console.error("❌ Redis Error:", err));

(async () => {
  try {
    await redisClient.connect();
    console.log("✅ Redis connected");
  } catch (err) {
    console.error("❌ Redis connection failed:", err);
  }
})();

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

/**********************************
 * HELPERS
 **********************************/
function isValidScore(value) {
  return Number.isInteger(value) && value >= 0 && value <= 200000;
}

/**********************************
 * ROUTES
 **********************************/

app.get("/", (_, res) => res.send("🚀 Backend is live"));

// PHASE 1: SEND EMAIL CODE
app.post("/send-code", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ message: "Email required" });

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
    res.status(500).json({ message: "Database error" });
  }
});

// LOGIN
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (!result.rows.length) return res.status(400).json({ message: "Invalid credentials" });

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ message: "Invalid credentials" });

    res.json({ success: true, user: { email: user.email, username: user.username } });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

/**********************************
 * SCORE & LEADERBOARD
 **********************************/
app.post("/record-score", async (req, res) => {
    const { email, score, date, table } = req.body; // Pass table name from frontend
    if (!email || !isValidScore(Number(score))) return res.status(400).json({ message: "Invalid input" });

    // Use a whitelist for table names to prevent SQL injection
    const allowedTables = ['pushups', 'situps', 'squats', 'steps', '"Addictions"'];
    if (!allowedTables.includes(table)) return res.status(400).json({ message: "Invalid table" });

    try {
        const query = `INSERT INTO ${table} (email, date, score) VALUES ($1, $2, $3) RETURNING *`;
        const result = await pool.query(query, [email, date || new Date(), score]);
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
    res.status(500).json({ message: "Leaderboard error" });
  }
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, "0.0.0.0", () => console.log(`🚀 Server on port ${PORT}`));
