require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const cors = require("cors");

const authRoutes = require("./routes/auth.routes");
const scoreRoutes = require("./routes/score.routes");
const leaderboardRoutes = require("./routes/leaderboard.routes");

const app = express();

app.use(helmet());
app.use(cors({
  origin: ["https://kelvinnzyoki.github.io"],
  credentials: true
}));

app.use(express.json());

app.get("/", (_, res) => res.send("🚀 Backend is live"));

app.use("/auth", authRoutes);
app.use("/scores", scoreRoutes);
app.use("/leaderboard", leaderboardRoutes);

module.exports = app;

const app = require("./app");

const PORT = process.env.PORT || 8080;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
const { Pool } = require("pg");

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

pool.on("connect", () => console.log("✅ PostgreSQL connected"));

module.exports = pool;
const redis = require("redis");

const redisClient = redis.createClient({
  url: process.env.REDIS_URL
});

redisClient.on("error", err => console.error("❌ Redis Error", err));

(async () => {
  await redisClient.connect();
  console.log("✅ Redis connected");
})();

module.exports = redisClient;
const nodemailer = require("nodemailer");

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

module.exports = transporter;
const express = require("express");
const bcrypt = require("bcryptjs");
const pool = require("../config/db");
const redis = require("../config/redis");
const mailer = require("../config/mailer");

const router = express.Router();

/**
 * SEND CODE
 */
router.post("/send-code", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ message: "Email required" });

  const code = Math.floor(100000 + Math.random() * 900000).toString();

  try {
    await redis.set(email, code, { EX: 600 });

    await mailer.sendMail({
      from: `"TAM Evolution" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "Verification Code",
      text: `Your verification code is: ${code}`
    });

    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ message: "Email error" });
  }
});

/**
 * SIGNUP
 */
router.post("/signup", async (req, res) => {
  const { email, code, username, password, dob } = req.body;

  const storedCode = await redis.get(email);
  if (!storedCode || storedCode !== code) {
    return res.status(400).json({ message: "Invalid code" });
  }

  const hash = await bcrypt.hash(password, 10);

  await pool.query(
    `INSERT INTO users (username,email,password,dob,created_at)
     VALUES ($1,$2,$3,$4,NOW())`,
    [username, email, hash, dob]
  );

  await redis.del(email);
  res.json({ success: true });
});

/**
 * LOGIN
 */
router.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const result = await pool.query(
    "SELECT * FROM users WHERE email=$1",
    [email]
  );

  if (!result.rows.length) {
    return res.status(400).json({ message: "Invalid credentials" });
  }

  const user = result.rows[0];
  const match = await bcrypt.compare(password, user.password);

  if (!match) {
    return res.status(400).json({ message: "Invalid credentials" });
  }

  res.json({ success: true, user: { email, username: user.username } });
});

module.exports = router;
exports.isValidScore = value =>
  Number.isInteger(value) && value >= 0 && value <= 20000;
const express = require("express");
const pool = require("../config/db");
const { isValidScore } = require("../utils/validators");

const router = express.Router();

router.post("/:type", async (req, res) => {
  const { email, score, date } = req.body;
  const { type } = req.params;

  if (!email || score === undefined || !isValidScore(Number(score))) {
    return res.status(400).json({ message: "Invalid input" });
  }

  const query = `
    INSERT INTO ${type} (email, date, score)
    VALUES ($1, $2, $3)
    RETURNING *;
  `;

  const result = await pool.query(query, [
    email,
    date || new Date(),
    score
  ]);

  res.status(201).json(result.rows[0]);
});

module.exports = router;
const express = require("express");
const pool = require("../config/db");

const router = express.Router();

router.get("/", async (_, res) => {
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
    GROUP BY email
    ORDER BY total_score DESC
    LIMIT 10
  `);

  res.json(result.rows);
});

module.exports = router;

