require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");
const { createClient } = require("redis");
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
  
  pool = new Pool({
    connectionString: process.env.DATABASE_URL,

    ssl: { rejectUnauthorized: true },   // ← fallback only if you get SSL handshake errors
     connectionTimeoutMillis: 10000,      // optional: prevent hanging forever
     idleTimeoutMillis: 30000,            // optional
     max: 20,                             // optional: limit pool size on Railway free tier
  });


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
  console.log("📧 /send-code called with:", req.body);
  
  const { email } = req.body;
  if (!email || !isValidEmail(email)) {
    console.log("❌ Invalid email:", email);
    return res.status(400).json({ message: "Valid email required" });
  }

  const code = Math.floor(100000 + Math.random() * 900000).toString();
  console.log("🔑 Generated code for", email, ":", code);

  try {
    // Check Redis connection first
    if (!redisClient.isOpen) {
      console.log("⚠️ Redis not connected, attempting to connect...");
      await connectRedis();
    }

    // Send email
    console.log("📨 Attempting to send email via Resend...");
    const emailResult = await resend.emails.send({
      from: "noreply@cctamcc.site", // ✅ MAKE SURE THIS IS VERIFIED IN RESEND
      to: email,
      subject: "Verification Code",
      html: `<p>Your verification code is: <strong>${code}</strong></p>`,
    });
    
    console.log("✅ Email sent successfully:", emailResult);

    // Store in Redis
    console.log("💾 Storing code in Redis...");
    await redisClient.setEx(email, 300, code);
    console.log("✅ Code stored in Redis");

    res.json({ success: true });
  } catch (err) {
    console.error("❌ Send code error:", err);
    console.error("Error details:", {
      message: err.message,
      stack: err.stack,
      response: err.response?.data
    });
    res.status(500).json({ 
      message: "Failed to send code",
      error: err.message // Only in development, remove in production
    });
  }
});

    


    
// PHASE 2: SIGNUP
app.post("/signup", async (req, res) => {
  console.log("👤 /signup called");
  console.log("Request body:", req.body);
  
  const { email, code, username, password, dob } = req.body;
  
  if (!email || !username || !password || !dob || !code) {
    console.log("❌ Missing fields");
    return res.status(400).json({ message: "All fields required" });
  }

  if (password.length < 8) {
    return res.status(400).json({ message: "Password must be at least 8 characters" });
  }

  // ✅ NEW: Validate date format
  const dateRegex = /^\d{4}-\d{2}-\d{2}$/;
  if (!dateRegex.test(dob)) {
    console.log("❌ Invalid date format:", dob);
    return res.status(400).json({ 
      message: "Invalid date format. Please use YYYY-MM-DD format (e.g., 2002-05-15)" 
    });
  }

  // ✅ NEW: Validate it's a real date
  const dobDate = new Date(dob);
  if (isNaN(dobDate.getTime())) {
    console.log("❌ Invalid date value:", dob);
    return res.status(400).json({ message: "Invalid date of birth" });
  }

  // ✅ NEW: Check age (must be at least 13 years old, for example)
  const today = new Date();
  const age = today.getFullYear() - dobDate.getFullYear();
  if (age < 13) {
    return res.status(400).json({ message: "You must be at least 13 years old" });
  }

  try {
    // Verify code
    const storedData = verificationCodes.get(email);
    
    if (!storedData) {
      console.log("❌ No code found for:", email);
      return res.status(400).json({ message: "Code expired or not found" });
    }

    if (Date.now() - storedData.timestamp > 300000) {
      verificationCodes.delete(email);
      console.log("❌ Code expired");
      return res.status(400).json({ message: "Code expired" });
    }

    if (storedData.code !== code) {
      console.log("❌ Invalid code. Expected:", storedData.code, "Got:", code);
      return res.status(400).json({ message: "Invalid verification code" });
    }

    console.log("✅ Code verified");

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    console.log("✅ Password hashed");

    // Insert user
    console.log("💾 Inserting user with DOB:", dob);
    
    const result = await pool.query(
      `INSERT INTO users (username, email, password, dob) 
       VALUES ($1, $2, $3, $4) 
       RETURNING id, username, email, created_at`,
      [username, email, hashedPassword, dob]
    );

    console.log("✅ User created successfully:", result.rows[0]);

    // Clean up code
    verificationCodes.delete(email);

    res.json({ 
      success: true, 
      message: "Account created successfully"
    });
    
  } catch (err) {
    console.error("❌ Signup error:");
    console.error("Error code:", err.code);
    console.error("Error message:", err.message);
    console.error("Full error:", err);
    
    if (err.code === '23505') {
      res.status(409).json({ message: "Email or username already exists" });
    } else if (err.code === '42P01') {
      res.status(500).json({ message: "Database table does not exist" });
    } else if (err.code === '22007') {
      res.status(400).json({ message: "Invalid date format. Please check your date of birth" });
    } else {
      res.status(500).json({ 
        message: "Database error",
        error: process.env.NODE_ENV !== 'production' ? err.message : undefined
      });
    }
  }
});


// LOGIN
app.post("/login", async (req, res) => {
  console.log("🔐 /login called with email:", req.body.email);
  
  const { email, password } = req.body;
  if (!email || !password) {
    console.log("❌ Missing credentials");
    return res.status(400).json({ message: "Email and password required" });
  }

  try {
    console.log("🔍 Querying database for user...");
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    
    if (!result.rows.length) {
      console.log("❌ User not found:", email);
      return res.status(400).json({ message: "Invalid credentials" });
    }

    console.log("✅ User found, checking password...");
    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password);
    
    if (!match) {
      console.log("❌ Password mismatch");
      return res.status(400).json({ message: "Invalid credentials" });
    }

    console.log("✅ Login successful for:", email);
    res.json({ success: true, user: { email: user.email, username: user.username } });
  } catch (err) {
    console.error("❌ Login error:", err);
    res.status(500).json({ message: "Server error", error: err.message });
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
      SELECT SUM(score) AS total_score
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
    
    // If no scores exist, total_score will be null
    const total = result.rows[0]?.total_score || 0;
    
    res.json({ success: true, total_score: total });
  } catch (err) {
    console.error("Total score error:", err);
    res.status(500).json({ success: false, message: "Error calculating score" });
  }
});


app.get("/leaderboard", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT email, SUM(score) AS total_score 
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
      GROUP BY email 
      ORDER BY total_score DESC 
      LIMIT 10;
    `);
    res.json(result.rows);
  } catch (err) {
    console.error("Leaderboard error:", err);
    res.status(500).json({ message: "Leaderboard error" });
  }
});


// Startup
(async () => {
  await connectRedis();
  const PORT = process.env.PORT || 8080;
  app.listen(PORT, "0.0.0.0", () => console.log(`🚀 Server on port ${PORT}`));
})();
