require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const bcrypt = require("bcryptjs"); // Using bcryptjs for stability
const { Pool } = require("pg");

const app = express();

/* 1. MIDDLEWARE & CORS CONFIG */
// Helmet for security headers
app.use(helmet());

// Improved CORS to allow your GitHub Pages site
app.use(cors({
  origin: ["https://kelvinnzyoki.github.io"], 
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Handle Preflight for ALL routes
app.options('*', cors()); 

// Body Parsers
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

/* 2. DATABASE CONNECTION */
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false, // Required for Railway/Render
  },
});

pool.on("connect", () => console.log("✅ PostgreSQL connected"));
pool.on("error", (err) => console.error("❌ PostgreSQL error:", err));

/* 3. ROUTES */

// Health Check
app.get("/", (req, res) => res.send("🚀 Backend is live!"));

// SIGNUP
app.post("/signup", async (req, res) => {
  const { username, email, password, dob } = req.body;

  if (!username || !email || !password || !dob) {
    return res.status(400).json({ message: "All fields are required" });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const query = `
      INSERT INTO users (username, email, password, dob)
      VALUES ($1, $2, $3, $4)
      RETURNING id, username, email
    `;
    const values = [username, email, hashedPassword, dob];

    const result = await pool.query(query, values);
    res.status(201).json({
      success: true,
      message: "Account created successfully!",
      user: result.rows[0]
    });
  } catch (error) {
    if (error.code === '23505') {
      return res.status(409).json({ message: "Username or email already exists" });
    }
    console.error("Signup Error:", error);
    res.status(500).json({ message: "Server error during signup" });
  }
});

// LOGIN (With Hash Verification)
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);

    if (result.rows.length === 0) {
      return res.status(400).json({ message: "Invalid email or password" });
    }

    const user = result.rows[0];
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(400).json({ message: "Invalid email or password" });
    }

    res.json({
      success: true,
      message: "Login successful",
      user: { username: user.username, email: user.email }
    });
  } catch (err) {
    console.error("Login Error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// GET ALL USERS (Example)
app.get("/users", async (req, res) => {
  try {
    const result = await pool.query("SELECT id, username, email FROM users");
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});


// dataToRecord endpoint
app.post('/record', async (req, res) => {
    try {
        const { email, date, score } = req.body;
        
        if (!email || !date || score === undefined) {
            return res.status(400).json({ 
                success: false,
                error: 'Missing required fields' 
            });
        }

        if (![5, 90].includes(score)) {
            return res.status(400).json({ 
                success: false,
                error: 'Invalid score' 
            });
        }

        // Insert into PostgreSQL
        const result = await pool.query(
            'INSERT INTO Records (email, date, score) VALUES ($1, $2, $3) RETURNING *',
            [email, new Date().toISOString(), score]
        );

        res.status(201).json({
            success: true,
            message: 'Score recorded successfully',
            data: result.rows[0]
        });

    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ 
            success: false,
            error: 'Internal server error' 
        });
    }
});




/* 4. SERVER START */
const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
