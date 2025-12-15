console.log("🚀 Server file loaded"); /* For debugging */



require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const { Pool } = require("pg");

const app = express();

/* -------------------- CONFIG -------------------- */
const PORT = process.env.PORT;

const corsOptions = {
  origin: "https://kelvinnzyoki.github.io/TAM/",
  optionsSuccessStatus: 200,
};

/* -------------------- DATABASE POOL -------------------- */
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
  },
});

pool.on("connect", () => {
  console.log("✅ PostgreSQL connected");
});

pool.on("error", (err) => {
  console.error("❌ PostgreSQL error:", err);
  process.exit(1);
});

module.exports = pool;

/* -------------------- MIDDLEWARE -------------------- */
app.use(cors(corsOptions));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(helmet());

/* -------------------- ROUTES -------------------- */
app.get("/", (req, res) => {
  res.send("Hello backend");
});

/* ---------- SIGNUP ---------- */
app.post("/signup", async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ message: "All fields required" });
  }

  try {
    const exists = await pool.query(
      "SELECT id FROM users WHERE email = $1",
      [email]
    );

    if (exists.rows.length > 0) {
      return res.status(400).json({ message: "Email already registered" });
    }

    const result = await pool.query(
      `INSERT INTO users (username, email, password)
       VALUES ($1, $2, $3)
       RETURNING id, username, email`,
      [username, email, password]
    );

    res.status(201).json({
      message: "Signup successful",
      user: result.rows[0],
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

/* ---------- LOGIN ---------- */
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const result = await pool.query(
      "SELECT id, username FROM users WHERE email = $1 AND password = $2",
      [email, password]
    );

    if (result.rows.length === 0) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    res.json({
      message: "Login successful",
      user: result.rows[0],
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

/* ---------- GET USERS ---------- */
app.get("/users", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, username, email FROM users"
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

/* ---------- RECORD POINTS ---------- */
app.post("/record", async (req, res) => {
  const { user_id, points } = req.body;

  if (!user_id || points === undefined) {
    return res.status(400).json({ message: "Missing data" });
  }

  try {
    await pool.query(
      "INSERT INTO scores (user_id, points) VALUES ($1, $2)",
      [user_id, points]
    );

    res.json({ message: "Points recorded successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

/* -------------------- START SERVER -------------------- */
app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
