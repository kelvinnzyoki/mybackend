require("dotenv").config();
const express = require("express");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const cookieParser = require("cookie-parser");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const { Pool } = require("pg");
const { createClient } = require("redis");
const { Resend } = require("resend");

const app = express();
app.set("trust proxy", 1);

/* ===================== SECURITY & CONFIG ===================== */
app.use(helmet());
app.use(cookieParser());
app.use(express.json());

// Strict CORS for Production
app.use(cors({
    origin: ["https://kelvinnzyoki.github.io", "http://localhost:5500"],
    credentials: true
}));

const cookieOptions = {
    httpOnly: true,
    secure: true, // Required for HTTPS
    sameSite: "None", // Required for cross-domain cookies (GitHub Pages)
    domain: process.env.COOKIE_DOMAIN || undefined,
    path: "/"
};

/* ===================== DATABASE CONNECTIONS ===================== */
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: true }
});

const redis = createClient({ url: process.env.REDIS_URL });
redis.on('error', (err) => console.log('Redis Error', err));
(async () => { await redis.connect(); console.log("✅ Redis Online"); })();

const resend = new Resend(process.env.RESEND_API_KEY);

/* ===================== AUTH HELPERS ===================== */
const createAccessToken = (user) =>
    jwt.sign({ id: user.id, role: user.role || 'user' }, process.env.JWT_ACCESS_SECRET, { expiresIn: "15m" });

const createRefreshToken = (user) =>
    jwt.sign({ id: user.id }, process.env.JWT_REFRESH_SECRET, { expiresIn: "14d" });

const getHash = (data) => crypto.createHash("sha256").update(data).digest("hex");

/* ===================== AUTH MIDDLEWARE ===================== */
const authenticate = async (req, res, next) => {
    const token = req.cookies.access_token;
    if (!token) return res.status(401).json({ message: "Unauthenticated" });

    jwt.verify(token, process.env.JWT_ACCESS_SECRET, async (err, decoded) => {
        if (err) return res.status(403).json({ message: "Session Expired" });

        try {
            const storedFP = await redis.get(`fp:${decoded.id}`);
            const currentFP = req.headers["user-agent"] + req.ip;
            if (storedFP && storedFP !== currentFP) {
                return res.status(403).json({ message: "Security Mismatch" });
            }
            req.user = decoded;
            next();
        } catch (e) { res.status(500).json({ message: "Auth Error" }); }
    });
};

/* ===================== AUTH ROUTES ===================== */

app.post("/send-code", rateLimit({ windowMs: 15*60*1000, max: 3 }), async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ message: "Email required" });

    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const key = getHash(email);

    try {
        await resend.emails.send({
            from: "noreply@cctamcc.site",
            to: email,
            subject: "Alpha Protocol Code",
            html: `Your verification code is: <strong>${code}</strong>`
        });
        await redis.setEx(`verify:${key}`, 300, code);
        res.json({ success: true });
    } catch (err) { res.status(500).json({ message: "Email failed" }); }
});

app.post("/signup", async (req, res) => {
    const { email, code, username, password, dob } = req.body;
    const key = getHash(email);

    try {
        const storedCode = await redis.get(`verify:${key}`);
        if (!storedCode || storedCode !== code) return res.status(400).json({ message: "Invalid Code" });

        const hashed = await bcrypt.hash(password, 12);
        await pool.query(
            "INSERT INTO users (username, email, password, dob) VALUES ($1, $2, $3, $4)",
            [username, email, hashed, dob]
        );
        await redis.del(`verify:${key}`);
        res.json({ success: true });
    } catch (err) { res.status(409).json({ message: "User already exists" }); }
});

app.post("/login", async (req, res) => {
    const { email, password } = req.body;
    const result = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
    const user = result.rows[0];

    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).json({ message: "Invalid credentials" });
    }

    const access = createAccessToken(user);
    const refresh = createRefreshToken(user);

    await redis.set(`ref:${refresh}`, user.id, { EX: 1209600 });
    await redis.set(`fp:${user.id}`, req.headers["user-agent"] + req.ip);

    res.cookie("access_token", access, { ...cookieOptions, maxAge: 900000 });
    res.cookie("refresh_token", refresh, { ...cookieOptions, maxAge: 1209600000 });
    res.json({ success: true, user: { username: user.username } });
});

/* ===================== ALPHA DATA ROUTES ===================== */

// STOIC AUDITS
app.post('/api/audit/save', authenticate, async (req, res) => {
    const { victory, defeat } = req.body;
    await pool.query(
        "INSERT INTO audits (user_id, victory, defeat, updated_at) VALUES ($1, $2, $3, NOW()) ON CONFLICT (user_id) DO UPDATE SET victory=$2, defeat=$3, updated_at=NOW()",
        [req.user.id, victory, defeat]
    );
    res.json({ success: true });
});

app.get('/api/audit/load', authenticate, async (req, res) => {
    const result = await pool.query("SELECT victory, defeat FROM audits WHERE user_id = $1", [req.user.id]);
    res.json(result.rows[0] || { victory: "", defeat: "" });
});

// RECOVERY LOGS
app.post('/api/user/recovery', authenticate, async (req, res) => {
    const { sleep, hydration, stress, score } = req.body;
    await pool.query(
        "INSERT INTO recovery_logs (user_id, sleep, hydration, stress, readiness_score, date) VALUES ($1, $2, $3, $4, $5, CURRENT_DATE) ON CONFLICT (user_id, date) DO UPDATE SET sleep=$2, hydration=$3, stress=$4, readiness_score=$5",
        [req.user.id, sleep, hydration, stress, score]
    );
    res.json({ success: true });
});

app.get('/api/user/recovery', authenticate, async (req, res) => {
    const result = await pool.query("SELECT sleep, hydration, stress, readiness_score FROM recovery_logs WHERE user_id = $1 ORDER BY date DESC LIMIT 1", [req.user.id]);
    res.json(result.rows[0] || null);
});

/* ===================== SCORES & LEADERBOARD ===================== */

const scoreTables = ["pushups", "situps", "squats", "steps", "addictions"];

scoreTables.forEach(table => {
    app.post(`/${table}`, authenticate, async (req, res) => {
        const { score, date } = req.body;
        await pool.query(
            `INSERT INTO ${table} (user_id, date, score) VALUES ($1, $2, $3) ON CONFLICT (user_id, date) DO UPDATE SET score=EXCLUDED.score`,
            [req.user.id, date || new Date(), score]
        );
        res.json({ success: true });
    });
});

app.get("/total-score", authenticate, async (req, res) => {
    const result = await pool.query(`
        SELECT SUM(score) as total FROM (
            ${scoreTables.map(t => `SELECT score FROM ${t} WHERE user_id=$1`).join(" UNION ALL ")}
        ) s`, [req.user.id]);
    res.json({ total_score: result.rows[0].total || 0 });
});

app.get("/leaderboard", async (req, res) => {
    const result = await pool.query(`
        SELECT u.username, SUM(s.score) as total_score 
        FROM (
            ${scoreTables.map(t => `SELECT user_id, score FROM ${t}`).join(" UNION ALL ")}
        ) s JOIN users u ON u.id = s.user_id 
        GROUP BY u.username ORDER BY total_score DESC LIMIT 10`);
    res.json({ success: true, data: result.rows });
});

/* ===================== LOGOUT ===================== */
app.post("/logout", async (req, res) => {
    const ref = req.cookies.refresh_token;
    if (ref) await redis.del(`ref:${ref}`);
    res.clearCookie("access_token", cookieOptions);
    res.clearCookie("refresh_token", cookieOptions);
    res.json({ success: true });
});

app.listen(8080, "0.0.0.0", () => console.log("🚀 Server Protocol Engaged on 8080"));
