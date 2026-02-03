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
app.use(helmet({
    crossOriginResourcePolicy: { policy: "cross-origin" }
}));
app.use(cookieParser());
app.use(express.json());

// CRITICAL FIX: CORS Configuration for api.cctamcc.site → cctamcc.site
app.use(cors({
    origin: function(origin, callback) {
        const allowed = [
            "https://cctamcc.site",           // Your GitHub Pages custom domain
            "http://cctamcc.site",            // HTTP version
            "https://www.cctamcc.site",       // WWW subdomain
            "http://localhost:5500",          // Local development
            "http://127.0.0.1:5500"           // Local development alternative
        ];
        
        // Allow requests with no origin (mobile apps, Postman, curl)
        if (!origin) {
            return callback(null, true);
        }
        
        if (allowed.includes(origin)) {
            callback(null, true);
        } else {
            console.error('❌ CORS blocked origin:', origin);
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"],
    exposedHeaders: ["Set-Cookie"],
    preflightContinue: false,
    optionsSuccessStatus: 204
}));

// CRITICAL FIX: Cookie Configuration for cross-subdomain
const cookieOptions = {
    httpOnly: true,
    secure: true,              // HTTPS only
    sameSite: "None",          // CRITICAL: Must be "None" for cross-subdomain
    domain: ".cctamcc.site",   // Leading dot allows all subdomains
    path: "/"
};

/* ===================== DATABASE CONNECTIONS ===================== */
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: true }
});

const redis = createClient({ url: process.env.REDIS_URL });
redis.on('error', (err) => console.log('Redis Error', err));
(async () => { 
    await redis.connect(); 
    console.log("✅ Redis Online"); 
})();

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
    
    if (!token) {
        console.log("❌ No access token in cookies");
        return res.status(401).json({ message: "Unauthenticated" });
    }

    jwt.verify(token, process.env.JWT_ACCESS_SECRET, async (err, decoded) => {
        if (err) {
            console.log("❌ JWT verification failed:", err.message);
            return res.status(403).json({ message: "Session Expired" });
        }

        try {
            const storedFP = await redis.get(`fp:${decoded.id}`);
            const currentFP = req.headers["user-agent"] + req.ip;
            
            if (storedFP && storedFP !== currentFP) {
                console.log("❌ Fingerprint mismatch");
                return res.status(403).json({ message: "Security Mismatch" });
            }
            
            req.user = decoded;
            next();
        } catch (e) { 
            console.error("Auth middleware error:", e);
            res.status(500).json({ message: "Auth Error" }); 
        }
    });
};

/* ===================== HEALTH CHECK ===================== */
app.get("/", (req, res) => {
    res.status(200).json({
        status: "Online",
        message: "Alpha Protocol Backend is fully operational",
        timestamp: new Date().toISOString(),
        server: "api.cctamcc.site"
    });
});

/* ===================== AUTH ROUTES ===================== */

app.post("/send-code", rateLimit({ windowMs: 15*60*1000, max: 3 }), async (req, res) => {
    const { email } = req.body;
    
    if (!email) return res.status(400).json({ message: "Email required" });

    try {
        // Check if email already exists
        const existingUser = await pool.query(
            "SELECT id FROM users WHERE email = $1",
            [email]
        );

        if (existingUser.rows.length > 0) {
            return res.status(409).json({ 
                success: false,
                message: "This email is already registered. Please login instead." 
            });
        }

        // Generate and send code
        const code = Math.floor(100000 + Math.random() * 900000).toString();
        const key = getHash(email);

        await resend.emails.send({
            from: "noreply@cctamcc.site",
            to: email,
            subject: "Alpha Protocol Code",
            html: `Your verification code is: <strong>${code}</strong>`
        });
        
        await redis.setEx(`verify:${key}`, 300, code);
        
        console.log(`✅ Verification code sent to ${email}`);
        res.json({ success: true });

    } catch (err) {
        console.error("Send code error:", err);
        res.status(500).json({ success: false, message: "Email failed" });
    }
});

app.post("/signup", async (req, res) => {
    const { email, code, username, password, dob } = req.body;
    const key = getHash(email);

    try {
        // 1. Verify code
        const storedCode = await redis.get(`verify:${key}`);
        if (!storedCode || storedCode !== code) {
            return res.status(400).json({ message: "Invalid or expired verification code" });
        }

        // 2. Check if email already exists
        const existingEmail = await pool.query(
            "SELECT id FROM users WHERE email = $1",
            [email]
        );

        if (existingEmail.rows.length > 0) {
            await redis.del(`verify:${key}`);
            return res.status(409).json({ 
                success: false, 
                message: "This email is already registered. Please login instead." 
            });
        }

        // 3. Check if username already exists
        const existingUsername = await pool.query(
            "SELECT id FROM users WHERE username = $1",
            [username]
        );

        if (existingUsername.rows.length > 0) {
            return res.status(409).json({ 
                success: false, 
                message: "Username already taken. Please choose another." 
            });
        }

        // 4. Create new user
        const hashed = await bcrypt.hash(password, 12);
        
        const newUser = await pool.query(
            "INSERT INTO users (username, email, password, dob) VALUES ($1, $2, $3, $4) RETURNING id, username",
            [username, email, hashed, dob]
        );
        
        // 5. Delete verification code
        await redis.del(`verify:${key}`);

        // 6. Create tokens
        const access = createAccessToken(newUser.rows[0]);
        const refresh = createRefreshToken(newUser.rows[0]);

        // 7. Store tokens in Redis
        await redis.set(`ref:${refresh}`, newUser.rows[0].id, { EX: 1209600 });
        await redis.set(`fp:${newUser.rows[0].id}`, req.headers["user-agent"] + req.ip);

        // 8. Set cookies
        res.cookie("access_token", access, { ...cookieOptions, maxAge: 900000 });
        res.cookie("refresh_token", refresh, { ...cookieOptions, maxAge: 1209600000 });

        console.log(`✅ User created: ${username}`);
        res.json({ 
            success: true, 
            message: "Account created successfully!",
            user: { username: newUser.rows[0].username }
        });

    } catch (err) {
        console.error("Signup error:", err);
        
        if (err.code === '23505') {
            return res.status(409).json({ 
                success: false, 
                message: "Email or username already exists" 
            });
        }
        
        res.status(500).json({ 
            success: false, 
            message: "Server error. Please try again." 
        });
    }
});

app.post("/login", async (req, res) => {
    const { email, password } = req.body;
    
    try {
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
        
        console.log(`✅ User logged in: ${user.username}`);
        res.json({ success: true, user: { username: user.username } });
    } catch (err) {
        console.error("Login error:", err);
        res.status(500).json({ message: "Server error" });
    }
});

app.post("/auth/refresh", async (req, res) => {
    const refresh = req.cookies.refresh_token;
    
    if (!refresh) {
        console.log("❌ No refresh token in cookies");
        return res.status(401).json({ message: "No refresh token" });
    }

    try {
        const userId = await redis.get(`ref:${refresh}`);
        
        if (!userId) {
            console.log("❌ Invalid refresh token");
            return res.status(403).json({ message: "Invalid refresh token" });
        }

        const result = await pool.query("SELECT * FROM users WHERE id=$1", [userId]);
        const user = result.rows[0];
        
        if (!user) {
            console.log("❌ User not found");
            return res.status(403).json({ message: "User not found" });
        }

        const newAccess = createAccessToken(user);
        res.cookie("access_token", newAccess, { ...cookieOptions, maxAge: 900000 });
        
        console.log(`✅ Token refreshed for user: ${user.username}`);
        res.json({ success: true });
    } catch (err) {
        console.error("Refresh error:", err);
        res.status(500).json({ message: "Refresh failed" });
    }
});

/* ===================== PROTECTED ROUTES ===================== */

// Total score
app.get("/total-score", authenticate, async (req, res) => {
    try {
        const scoreTables = ["addictions", "pushups", "situps", "squats", "steps"];
        const result = await pool.query(`
            SELECT SUM(score) as total FROM (
                ${scoreTables.map(t => `SELECT score FROM ${t} WHERE user_id=$1`).join(" UNION ALL ")}
            ) s`, [req.user.id]);
        res.json({ total_score: result.rows[0].total || 0 });
    } catch (err) {
        console.error("Total score error:", err);
        res.status(500).json({ error: "Failed to fetch score" });
    }
});

// Score tracking routes
const scoreTables = ["addictions", "pushups", "situps", "squats", "steps"];

scoreTables.forEach(table => {
    app.post(`/${table}`, authenticate, async (req, res) => {
        const { score, date } = req.body;
        
        if (score === undefined || isNaN(score)) {
            return res.status(400).json({ success: false, message: "Valid score required" });
        }

        try {
            await pool.query(
                `INSERT INTO ${table} (user_id, date, score) 
                 VALUES ($1, $2, $3) 
                 ON CONFLICT (user_id, date) 
                 DO UPDATE SET score = EXCLUDED.score`,
                [req.user.id, date || new Date(), parseInt(score)]
            );

            res.json({ success: true, message: `${table} score synced` });
        } catch (err) {
            console.error(`Error in /${table}:`, err);
            res.status(500).json({ success: false, message: "Database Error" });
        }
    });
});

// Leaderboard
app.get("/leaderboard", authenticate, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT u.username, SUM(s.score) AS total_score 
            FROM (
                SELECT user_id, score FROM pushups
                UNION ALL SELECT user_id, score FROM situps
                UNION ALL SELECT user_id, score FROM squats
                UNION ALL SELECT user_id, score FROM steps
                UNION ALL SELECT user_id, score FROM addictions
            ) s
            JOIN users u ON u.id = s.user_id
            GROUP BY u.username
            ORDER BY total_score DESC
            LIMIT 10
        `);

        res.json({ 
            success: true, 
            data: result.rows 
        });
    } catch (error) {
        console.error("Leaderboard error:", error);
        res.status(500).json({ 
            success: false, 
            message: "Failed to fetch leaderboard" 
        });
    }
});

// Feed
app.get("/feed", authenticate, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT 
                u.username,
                ap.post_text,
                ap.created_at,
                COALESCE((
                    SELECT SUM(score) 
                    FROM (
                        SELECT score FROM pushups WHERE user_id = u.id
                        UNION ALL SELECT score FROM situps WHERE user_id = u.id
                        UNION ALL SELECT score FROM squats WHERE user_id = u.id
                        UNION ALL SELECT score FROM steps WHERE user_id = u.id
                        UNION ALL SELECT score FROM addictions WHERE user_id = u.id
                    ) scores
                ), 0) as total_score
            FROM arena_posts ap
            JOIN users u ON u.id = ap.user_id
            ORDER BY ap.created_at DESC
            LIMIT 50
        `);
        
        res.json({ success: true, data: result.rows });
    } catch (err) {
        console.error("Feed error:", err);
        res.status(500).json({ success: false, message: "Failed to load feed" });
    }
});

// Logout
app.post("/logout", async (req, res) => {
    const ref = req.cookies.refresh_token;
    if (ref) await redis.del(`ref:${ref}`);
    
    res.clearCookie("access_token", cookieOptions);
    res.clearCookie("refresh_token", cookieOptions);
    
    console.log("✅ User logged out");
    res.json({ success: true });
});

/* ===================== START SERVER ===================== */
const PORT = process.env.PORT || 8080;
app.listen(PORT, "0.0.0.0", () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📡 API: https://api.cctamcc.site`);
    console.log(`🌐 Frontend: https://cctamcc.site`);
});
