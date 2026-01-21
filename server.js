require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");
const { createClient } = require("redis");
const nodemailer = require("nodemailer");
const { Resend } = require('resend');

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
 * DATABASE (PostgreSQL) - Neon.tech
 **********************************/

let pool;

try {
  // Option A: Preferred - rely on query params in DATABASE_URL (most stable with Neon)
  // Make sure your env var looks like:
  // postgresql://user:pass@ep-xxx-xxx.aws.neon.tech/dbname?sslmode=require
  //    or even better: ?sslmode=require&channel_binding=require  (Neon dashboard sometimes includes this now)
  pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    // Only add ssl override if needed (usually not when using ?sslmode= in string)
    // ssl: { rejectUnauthorized: false }   // ← fallback only if you get SSL handshake errors
    // connectionTimeoutMillis: 10000,      // optional: prevent hanging forever
    // idleTimeoutMillis: 30000,            // optional
    // max: 20,                             // optional: limit pool size on Railway free tier
  });

  // Option B: Explicit config (use if you split env vars or have issues with connection string)
  // pool = new Pool({
  //   host: process.env.PGHOST,
  //   database: process.env.PGDATABASE,
  //   user: process.env.PGUSER,
  //   password: process.env.PGPASSWORD,
  //   port: 5432,
  //   ssl: {
  //     require: true,
  //     rejectUnauthorized: false   // ← most common working setting for Neon in 2025/2026
  //   },
  // });

  // ────────────────────────────────────────────────
  // Test & log connection status on startup (very important!)
  // ────────────────────────────────────────────────
  (async () => {
    try {
      const client = await pool.connect();
      console.log("✅ PostgreSQL (Neon) connection established successfully");

      // Optional: quick version check to confirm it's really Neon/Postgres
      const res = await client.query("SELECT version()");
      console.log("PostgreSQL version:", res.rows[0].version);

      // Optional: Neon-specific endpoint check
      const endpointRes = await client.query("SELECT current_setting('server_version')");
      console.log("Server info:", endpointRes.rows[0]);

      client.release();
    } catch (err) {
      console.error("❌ PostgreSQL connection failed:", err.message);
      console.error("Full error:", err);
      // Optionally: process.exit(1); // crash app if DB is critical
    }
  })();

} catch (setupErr) {
  console.error("PostgreSQL pool setup failed:", setupErr);
}

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

const resend = new Resend(process.env.RESEND_API_KEY);


(async () => {
  try {
    if (!process.env.RESEND_API_KEY) {
      console.error("❌ RESEND_API_KEY is missing or empty in environment variables");
      return;
    }

    console.log("🔑 Resend API Key loaded (first 5 chars only for security):", 
      process.env.RESEND_API_KEY.substring(0, 5) + "...");

    // Optional: simple test ping to Resend (not sending email yet)
    // Resend doesn't have a /ping endpoint, but we can catch initialization errors
    console.log("✅ Resend client initialized successfully");

  } catch (err) {
    console.error("❌ Failed to initialize Resend client:", err.message);
  }
})();



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
  await resend.emails.send({
    from: "onboarding@resend.dev",
    to: email,
    subject: "Verification Code",
    text: `Your code is: ${code}`,
  });

  await redisClient.setEx(email, 300, code); // store code for 5 min

  res.json({ success: true });
} catch (err) {
  console.error("Send code error:", err);
  res.status(500).json({ message: "Failed to send code" });
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

    /*Addiction*/
app.post("/addictions", async (req, res) => {
  const { email, score, date } = req.body;

  if (!email || !isValidEmail(email)) {
    return res.status(400).json({ message: "Valid email required" });
  }

  if (!isValidScore(score)) {
    return res.status(400).json({ message: "Invalid score" });
  }

  const recordDate = date ? new Date(date) : new Date();

  try {
    const result = await pool.query(
      `
      INSERT INTO addictions (email, date, score)
      VALUES ($1, $2, $3)
      ON CONFLICT (email, date)
      DO UPDATE SET score = EXCLUDED.score
      RETURNING *
      `,
      [email, recordDate, parseInt(score, 10)]
    );

    res.status(201).json({
      success: true,
      data: result.rows[0]
    });

  } catch (err) {
    console.error("Addiction record error:", err);
    res.status(500).json({ message: "Database error" });
  }
});




    
/*pushups*/
app.post("/pushups", async (req, res) => {
  const { email, score, date } = req.body;

  if (!email || !isValidEmail(email)) {
    return res.status(400).json({ message: "Valid email required" });
  }

  if (!isValidScore(score)) {
    return res.status(400).json({ message: "Invalid score" });
  }

  const recordDate = date ? new Date(date) : new Date();

  try {
    const result = await pool.query(
      `
      INSERT INTO pushups (email, date, score)
      VALUES ($1, $2, $3)
      ON CONFLICT (email, date)
      DO UPDATE SET score = EXCLUDED.score
      RETURNING *
      `,
      [email, recordDate, parseInt(score, 10)]
    );

    res.status(201).json({
      success: true,
      data: result.rows[0]
    });

  } catch (err) {
    console.error("Push-ups record error:", err);
    res.status(500).json({ message: "Database error" });
  }
});


/*Situps*/
app.post("/situps", async (req, res) => {
  const { email, score, date } = req.body;

  if (!email || !isValidEmail(email)) {
    return res.status(400).json({ message: "Valid email required" });
  }

  if (!isValidScore(score)) {
    return res.status(400).json({ message: "Invalid score" });
  }

  const recordDate = date ? new Date(date) : new Date();

  try {
    const result = await pool.query(
      `
      INSERT INTO situps (email, date, score)
      VALUES ($1, $2, $3)
      ON CONFLICT (email, date)
      DO UPDATE SET score = EXCLUDED.score
      RETURNING *
      `,
      [email, recordDate, parseInt(score, 10)]
    );

    res.status(201).json({
      success: true,
      data: result.rows[0]
    });

  } catch (err) {
    console.error("Sit-ups record error:", err);
    res.status(500).json({ message: "Database error" });
  }
});
    

/*Squats*/
app.post("/squats", async (req, res) => {
  const { email, score, date } = req.body;

  if (!email || !isValidEmail(email)) {
    return res.status(400).json({ message: "Valid email required" });
  }

  if (!isValidScore(score)) {
    return res.status(400).json({ message: "Invalid score" });
  }

  const recordDate = date ? new Date(date) : new Date();

  try {
    const result = await pool.query(
      `
      INSERT INTO squats (email, date, score)
      VALUES ($1, $2, $3)
      ON CONFLICT (email, date)
      DO UPDATE SET score = EXCLUDED.score
      RETURNING *
      `,
      [email, recordDate, parseInt(score, 10)]
    );

    res.status(201).json({
      success: true,
      data: result.rows[0]
    });

  } catch (err) {
    console.error("Squats record error:", err);
    res.status(500).json({ message: "Database error" });
  }
});


    /*Steps*/
    
app.post("/steps", async (req, res) => {
  const { email, score, date } = req.body;

  if (!email || !isValidEmail(email)) {
    return res.status(400).json({ message: "Valid email required" });
  }

  if (!isValidScore(score)) {
    return res.status(400).json({ message: "Invalid score" });
  }

  const recordDate = date ? new Date(date) : new Date();

  try {
    const result = await pool.query(
      `
      INSERT INTO steps (email, date, score)
      VALUES ($1, $2, $3)
      ON CONFLICT (email, date)
      DO UPDATE SET score = EXCLUDED.score
      RETURNING *
      `,
      [email, recordDate, parseInt(score, 10)]
    );

    res.status(201).json({
      success: true,
      data: result.rows[0]
    });

  } catch (err) {
    console.error("Steps record error:", err);
    res.status(500).json({ message: "Database error" });
  }
});
    

  /*Current Total Score*/
app.get("/total-score", async (req, res) => {
  const { email } = req.query;
  if (!email) return res.status(400).json({ message: "Email required" });

  try {
    const query = `
      SELECT SUM(score::int) AS total_score
      FROM (
        SELECT DISTINCT ON (date) score FROM pushups WHERE email = $1
        UNION ALL
        SELECT DISTINCT ON (date) score FROM situps WHERE email = $1
        UNION ALL
        SELECT DISTINCT ON (date) score FROM squats WHERE email = $1
        UNION ALL
        SELECT DISTINCT ON (date) score FROM steps WHERE email = $1
        UNION ALL
        SELECT DISTINCT ON (date) score FROM addictions WHERE email = $1
      ) s;
    `;
    const result = await pool.query(query, [email]);
    
    // If no scores exist, result.rows[0].total_score will be null. 
    // We use || 0 to return 0 instead.
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
        SELECT DISTINCT ON (email, date) email, score FROM addictions
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
  const PORT = process.env.PORT || 8080;
  app.listen(PORT, "0.0.0.0", () => console.log(`🚀 Server on port ${PORT}`));
})();
