require("dotenv").config();

const express = require("express");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const cookieParser = require("cookie-parser");
const rateLimit = require("express-rate-limit");
const csurf = require("csurf");
const crypto = require("crypto");
const { Pool } = require("pg");
const { createClient } = require("redis");
const { Resend } = require("resend");

const app = express();

/* ===================== SECURITY MIDDLEWARE ===================== */
app.use(helmet());
app.use(cookieParser());
app.use(express.json());

app.use(cors({
  origin: [
    "https://kelvinnzyoki.github.io",
    "https://kelvinnzyoki.github.io/TAM",
    "http://localhost:5500"
  ],
  credentials: true
}));

app.use(csurf({ cookie: true }));

/* ===================== DATABASE ===================== */
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: true },
  connectionTimeoutMillis: 10000,
  idleTimeoutMillis: 30000,
  max: 20
});

/* ===================== REDIS ===================== */
const redis = createClient({ url: process.env.REDIS_URL });

(async () => {
  await redis.connect();
  console.log("✅ Redis Connected");
})();

/* ===================== MAIL ===================== */
const resend = new Resend(process.env.RESEND_API_KEY);

/* ===================== TOKEN HELPERS ===================== */
const cookieOptions = {
  httpOnly: true,
  secure: true,
  sameSite: "Strict",
  domain: process.env.COOKIE_DOMAIN
};

const createAccessToken = (user) =>
  jwt.sign({ id: user.id, role: user.role }, process.env.JWT_ACCESS_SECRET, { expiresIn: "10m" });

const createRefreshToken = (user) =>
  jwt.sign({ id: user.id }, process.env.JWT_REFRESH_SECRET, { expiresIn: "14d" });

/* ===================== AUTH MIDDLEWARE ===================== */
const authenticate = async (req, res, next) => {
  const token = req.cookies.access_token;
  if (!token) return res.status(401).json({ message: "Not authenticated" });

  jwt.verify(token, process.env.JWT_ACCESS_SECRET, async (err, user) => {
    if (err) return res.status(403).json({ message: "Token expired" });

    // Device fingerprint check
    const storedFP = await redis.get(`fp:${user.id}`);
    const currentFP = req.headers["user-agent"] + req.ip;
    if (storedFP && storedFP !== currentFP) {
      return res.status(403).json({ message: "Device mismatch" });
    }

    req.user = user;
    next();
  });
};

/* ===================== RATE LIMIT LOGIN ===================== */
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: "Too many login attempts"
});

/* ===================== HEALTH CHECK ===================== */
app.get("/", (_, res) => res.send("🚀 Secure Backend Live"));

/* ===================== EMAIL CODE ===================== */
app.post("/send-code", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ message: "Email required" });

  const code = Math.floor(100000 + Math.random() * 900000).toString();
  const key = crypto.createHash("sha256").update(email).digest("hex");

  await resend.emails.send({
    from: "noreply@cctamcc.site",
    to: email,
    subject: "Verification Code",
    html: `<strong>${code}</strong>`
  });

  await redis.setEx(`verify:${key}`, 300, code);

  res.json({ success: true });
});

/* ===================== SIGNUP ===================== */
app.post("/signup", async (req, res) => {
  const { email, code, username, password, dob } = req.body;
  const key = crypto.createHash("sha256").update(email).digest("hex");

  const stored = await redis.get(`verify:${key}`);
  if (!stored || stored !== code) {
    return res.status(400).json({ message: "Invalid or expired code" });
  }

  const hashed = await bcrypt.hash(password, 12);

  try {
    await pool.query(
      `INSERT INTO users (username, email, password, dob) VALUES ($1,$2,$3,$4)`,
      [username, email, hashed, dob]
    );

    await redis.del(`verify:${key}`);
    res.json({ success: true });

  } catch {
    res.status(409).json({ message: "User already exists" });
  }
});

/* ===================== LOGIN ===================== */
app.post("/login", loginLimiter, async (req, res) => {
  const { email, password } = req.body;

  const result = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
  if (!result.rows.length) return res.status(400).json({ message: "Invalid credentials" });

  const user = result.rows[0];
  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(400).json({ message: "Invalid credentials" });

  const accessToken = createAccessToken(user);
  const refreshToken = createRefreshToken(user);

  // Store refresh token & fingerprint
  await redis.set(refreshToken, user.id, { EX: 60 * 60 * 24 * 14 });
  await redis.set(`fp:${user.id}`, req.headers["user-agent"] + req.ip);

  res.cookie("access_token", accessToken, { ...cookieOptions, maxAge: 10 * 60 * 1000 });
  res.cookie("refresh_token", refreshToken, { ...cookieOptions, maxAge: 14 * 24 * 60 * 60 * 1000 });

  res.json({ success: true, user: { email: user.email, username: user.username } });
});

/* ===================== REFRESH TOKEN ROTATION ===================== */
app.post("/auth/refresh", async (req, res) => {
  const refreshToken = req.cookies.refresh_token;
  if (!refreshToken) return res.sendStatus(401);

  const exists = await redis.get(refreshToken);
  if (!exists) return res.sendStatus(403);

  jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET, async (err, user) => {
    if (err) return res.sendStatus(403);

    await redis.del(refreshToken);

    const newAccess = createAccessToken(user);
    const newRefresh = createRefreshToken(user);

    await redis.set(newRefresh, user.id, { EX: 60 * 60 * 24 * 14 });

    res.cookie("access_token", newAccess, { ...cookieOptions, maxAge: 10 * 60 * 1000 });
    res.cookie("refresh_token", newRefresh, { ...cookieOptions, maxAge: 14 * 24 * 60 * 60 * 1000 });

    res.json({ success: true });
  });
});

/* ===================== LOGOUT ===================== */
app.post("/logout", async (req, res) => {
  const token = req.cookies.refresh_token;
  if (token) await redis.del(token);

  res.clearCookie("access_token", cookieOptions);
  res.clearCookie("refresh_token", cookieOptions);

  res.json({ success: true });
});

/* ===================== SECURE SCORE ROUTES ===================== */
async function saveScore(table, req, res) {
  const { score, date } = req.body;
  if (!Number.isInteger(score)) return res.status(400).json({ message: "Invalid score" });

  const result = await pool.query(
    `
    INSERT INTO ${table} (user_id, date, score)
    VALUES ($1, $2, $3)
    ON CONFLICT (user_id, date)
    DO UPDATE SET score = EXCLUDED.score
    RETURNING *
    `,
    [req.user.id, date || new Date(), score]
  );

  res.json({ success: true, data: result.rows[0] });
}

app.post("/pushups", authenticate, (req, res) => saveScore("pushups", req, res));
app.post("/situps", authenticate, (req, res) => saveScore("situps", req, res));
app.post("/squats", authenticate, (req, res) => saveScore("squats", req, res));
app.post("/steps", authenticate, (req, res) => saveScore("steps", req, res));
app.post("/addictions", authenticate, (req, res) => saveScore("addictions", req, res));

/* ===================== TOTAL SCORE ===================== */
app.get("/total-score", authenticate, async (req, res) => {
  const result = await pool.query(`
    SELECT SUM(score) AS total_score FROM (
      SELECT score FROM pushups WHERE user_id=$1
      UNION ALL SELECT score FROM situps WHERE user_id=$1
      UNION ALL SELECT score FROM squats WHERE user_id=$1
      UNION ALL SELECT score FROM steps WHERE user_id=$1
      UNION ALL SELECT score FROM addictions WHERE user_id=$1
    ) s;
  `, [req.user.id]);

  res.json({ total_score: result.rows[0]?.total_score || 0 });
});

/* ===================== LEADERBOARD ===================== */
app.get("/leaderboard", async (req, res) => {
  const result = await pool.query(`
    SELECT u.username, SUM(score) AS total_score FROM (
      SELECT user_id, score FROM pushups
      UNION ALL SELECT user_id, score FROM situps
      UNION ALL SELECT user_id, score FROM squats
      UNION ALL SELECT user_id, score FROM steps
      UNION ALL SELECT user_id, score FROM addictions
    ) s
    JOIN users u ON u.id = s.user_id
    GROUP BY u.username
    ORDER BY total_score DESC
    LIMIT 10;
  `);

  res.json({ success: true, data: result.rows });
});






app.post('/api/audit/load', authenticate, async (req, res) => {
  const { victory, defeat } = req.body;

  if (typeof victory !== "string" || typeof defeat !== "string") {
    return res.status(400).json({ message: "Invalid input" });
  }

  try {
    await pool.query(
      `
      INSERT INTO audits (user_id, victory, defeat, updated_at)
      VALUES ($1, $2, $3, NOW())
      ON CONFLICT (user_id)
      DO UPDATE SET 
        victory = EXCLUDED.victory,
        defeat = EXCLUDED.defeat,
        updated_at = NOW()
      `,
      [req.user.id, victory, defeat]
    );

    res.json({ success: true, message: "Audit Synced" });

  } catch (err) {
    console.error("Audit save error:", err);
    res.status(500).json({ message: "Database Error" });
  }
});


app.post('/api/user/recovery', authenticate, async (req, res) => {
  const { sleep, hydration, stress, score } = req.body;

  const valid =
    Number.isInteger(sleep) &&
    Number.isInteger(hydration) &&
    Number.isInteger(stress) &&
    Number.isInteger(score);

  if (!valid) {
    return res.status(400).json({ message: "Invalid recovery data" });
  }

  try {
    await pool.query(
      `
      INSERT INTO recovery_logs (user_id, sleep, hydration, stress, readiness_score, date)
      VALUES ($1, $2, $3, $4, $5, CURRENT_DATE)
      ON CONFLICT (user_id, date)
      DO UPDATE SET
        sleep = EXCLUDED.sleep,
        hydration = EXCLUDED.hydration,
        stress = EXCLUDED.stress,
        readiness_score = EXCLUDED.readiness_score
      `,
      [req.user.id, sleep, hydration, stress, score]
    );

    res.json({ success: true, message: "Biometrics Archived" });

  } catch (err) {
    console.error("Recovery save error:", err);
    res.status(500).json({ message: "Database Error" });
  }
});



app.get('/api/user/recovery', authenticate, async (req, res) => {
  
  broadcastRecoveryUpdate(req.user.id, {
  sleep, hydration, stress, score
});
  try {
    const result = await pool.query(
      `
      SELECT sleep, hydration, stress, readiness_score, date
      FROM recovery_logs 
      WHERE user_id = $1 
      ORDER BY date DESC 
      LIMIT 1
      `,
      [req.user.id]
    );

    res.json(result.rows[0] || null);

  } 
  
  
  
  
  catch (err) {
    console.error("Recovery fetch error:", err);
    res.status(500).json({ message: "Sync Failed" });
  }
});


app.get('/api/audit/save', authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT victory, defeat 
      FROM audits 
      WHERE user_id = $1
      `,
      [req.user.id]
    );

    res.json(result.rows[0] || { victory: "", defeat: "" });

  } catch (err) {
    console.error("Audit fetch error:", err);
    res.status(500).json({ message: "Failed to load audit" });
  }
});



/* ===================== START SERVER ===================== */
const PORT = process.env.PORT || 8080;
app.listen(PORT, "0.0.0.0", () => console.log(`🚀 Secure Server Running on ${PORT}`));


