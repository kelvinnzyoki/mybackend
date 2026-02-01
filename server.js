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
    origin: function(origin, callback) {
        const allowed = [
            "https://kelvinnzyoki.github.io",
            "http://localhost:5500"
        ];
        // Allow requests with no origin (mobile apps, curl, etc)
        if (!origin || allowed.some(url => origin.startsWith(url))) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ["GET", "POST", "OPTIONS"]
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




app.get("/", (req, res) => {
    res.status(200).json({
        status: "Online",
        message: "Alpha Protocol Backend is fully operational",
        timestamp: new Date().toISOString()
    });
});




app.post("/send-code", rateLimit({ windowMs: 15*60*1000, max: 3 }), async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ message: "Email required" });

    try {
        // ✅ CHECK IF EMAIL ALREADY EXISTS
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

        // Generate and send code only if email is available
        const code = Math.floor(100000 + Math.random() * 900000).toString();
        const key = getHash(email);

        await resend.emails.send({
            from: "noreply@cctamcc.site",
            to: email,
            subject: "Alpha Protocol Code",
            html: `Your verification code is: <strong>${code}</strong>`
        });
        
        await redis.setEx(`verify:${key}`, 300, code);
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
        // 1. VERIFY CODE FIRST
        const storedCode = await redis.get(`verify:${key}`);
        if (!storedCode || storedCode !== code) {
            return res.status(400).json({ message: "Invalid or expired verification code" });
        }

        // 2. CHECK IF EMAIL ALREADY EXISTS (CRITICAL FIX)
        const existingEmail = await pool.query(
            "SELECT id FROM users WHERE email = $1",
            [email]
        );

        if (existingEmail.rows.length > 0) {
            await redis.del(`verify:${key}`); // Clean up the code
            return res.status(409).json({ 
                success: false, 
                message: "This email is already registered. Please login instead." 
            });
        }

        // 3. CHECK IF USERNAME ALREADY EXISTS
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

        // 4. CREATE NEW USER
        const hashed = await bcrypt.hash(password, 12);
        
        const newUser = await pool.query(
            "INSERT INTO users (username, email, password, dob) VALUES ($1, $2, $3, $4) RETURNING id, username",
            [username, email, hashed, dob]
        );
        
        // 5. DELETE VERIFICATION CODE
        await redis.del(`verify:${key}`);

        // 6. CREATE TOKENS
        const access = createAccessToken(newUser.rows[0]);
        const refresh = createRefreshToken(newUser.rows[0]);

        // 7. STORE TOKENS IN REDIS
        await redis.set(`ref:${refresh}`, newUser.rows[0].id, { EX: 1209600 });
        await redis.set(`fp:${newUser.rows[0].id}`, req.headers["user-agent"] + req.ip);

        // 8. SET COOKIES
        res.cookie("access_token", access, { ...cookieOptions, maxAge: 900000 });
        res.cookie("refresh_token", refresh, { ...cookieOptions, maxAge: 1209600000 });

        res.json({ 
            success: true, 
            message: "Account created successfully!",
            user: { username: newUser.rows[0].username }
        });

    } catch (err) {
        console.error("Signup error:", err);
        
        // Handle unique constraint violation (database level)
        if (err.code === '23505') { // PostgreSQL unique violation code
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



app.post("/auth/refresh", async (req, res) => {
    const refresh = req.cookies.refresh_token;
    if (!refresh) return res.status(401).json({ message: "No refresh token" });

    try {
        const userId = await redis.get(`ref:${refresh}`);
        if (!userId) return res.status(403).json({ message: "Invalid refresh token" });

        const result = await pool.query("SELECT * FROM users WHERE id=$1", [userId]);
        const user = result.rows[0];
        if (!user) return res.status(403).json({ message: "User not found" });

        const newAccess = createAccessToken(user);
        res.cookie("access_token", newAccess, { ...cookieOptions, maxAge: 900000 });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ message: "Refresh failed" });
    }
});

/* ===================== ALPHA DATA ROUTES ===================== */

// STOIC AUDITS
app.post("/api/audit/save", authenticate, async (req, res) => {
    const { victory, defeat } = req.body;
    try {
        await pool.query(`
            INSERT INTO audits (user_id, victory, defeat, updated_at)
            VALUES ($1, $2, $3, NOW())
            ON CONFLICT (user_id) 
            DO UPDATE SET victory = EXCLUDED.victory, defeat = EXCLUDED.defeat, updated_at = NOW()
        `, [req.user.id, victory, defeat]);
        
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false });
    }
});


app.get('/api/audit/load', authenticate, async (req, res) => {
    try {
        const result = await pool.query(
            "SELECT victory, defeat, focus, ego_control FROM audits WHERE user_id = $1", 
            [req.user.id]
        );

        // If no record exists, return a complete default object
        const data = result.rows[0] || { 
            victory: "", 
            defeat: "", 
            focus: 50, 
            ego_control: 50 
        };

        res.json(data);
    } catch (err) {
        console.error("Audit load error:", err);
        res.status(500).json({ error: "Failed to load audit data" });
    }
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
    const result = await pool.query(
        "SELECT sleep, hydration, stress, readiness_score FROM recovery_logs WHERE user_id = $1 ORDER BY date DESC LIMIT 1", 
        [req.user.id]
    );
    res.json(result.rows[0] || { sleep: 0, hydration: 0, stress: 5, readiness_score: 0 });
});

/* ===================== SCORES & LEADERBOARD ===================== */
/* ===================== SCORE TRACKING ROUTES ===================== */
const scoreTables = ["addictions", "pushups", "situps", "squats", "steps"];

scoreTables.forEach(table => {
    // Each route is generated: e.g., app.post("/pushups", ...)
    app.post(`/${table}`, authenticate, async (req, res) => {
        const { score, date } = req.body;
        
        // 1. Validation: Ensure score is a valid number
        if (score === undefined || isNaN(score)) {
            return res.status(400).json({ success: false, message: "Valid score required" });
        }

        try {
            // 2. Database Operation: Identify user by req.user.id from JWT
            await pool.query(
                `INSERT INTO ${table} (user_id, date, score) 
                 VALUES ($1, $2, $3) 
                 ON CONFLICT (user_id, date) 
                 DO UPDATE SET score = EXCLUDED.score`,
                [
                    req.user.id,             // Extracted from verified token
                    date || new Date(),      // Use provided date or today
                    parseInt(score)          // Ensure integer format
                ]
            );

            res.json({ success: true, message: `${table} score synced` });

        } catch (err) {
            console.error(`Error in /${table}:`, err);
            res.status(500).json({ success: false, message: "Database Error" });
        }
    });
});


// POST a public victory to the arena (separate from mental audit)
app.post("/arena/post", authenticate, async (req, res) => {
    const { victory_text } = req.body;
    
    if (!victory_text || victory_text.trim() === "") {
        return res.status(400).json({ success: false, message: "Victory text required" });
    }

    try {
        await pool.query(
            "INSERT INTO arena_posts (user_id, victory_text) VALUES ($1, $2)",
            [req.user.id, victory_text.trim()]
        );
        
        res.json({ success: true, message: "Victory posted to arena" });
    } catch (err) {
        console.error("Arena post error:", err);
        res.status(500).json({ success: false, message: "Failed to post" });
    }
});

// GET public arena feed (updated to use arena_posts table)
app.get("/feed", authenticate, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT 
                u.username,
                ap.victory_text,
                ap.created_at,
                (
                    SELECT COALESCE(SUM(score), 0) 
                    FROM (
                        SELECT score FROM pushups WHERE user_id = u.id
                        UNION ALL SELECT score FROM situps WHERE user_id = u.id
                        UNION ALL SELECT score FROM squats WHERE user_id = u.id
                        UNION ALL SELECT score FROM steps WHERE user_id = u.id
                        UNION ALL SELECT score FROM addictions WHERE user_id = u.id
                    ) sub
                ) as total_score
            FROM users u
            JOIN arena_posts ap ON u.id = ap.user_id
            WHERE ap.victory_text IS NOT NULL AND ap.victory_text != ''
            ORDER BY ap.created_at DESC
            LIMIT 20
        `);
        
        res.json({ success: true, data: result.rows });
    } catch (err) {
        console.error("Feed error:", err);
        res.status(500).json({ success: false, message: "Database Error" });
    }
});


app.get("/total-score", authenticate, async (req, res) => {
    const result = await pool.query(`
        SELECT SUM(score) as total FROM (
            ${scoreTables.map(t => `SELECT score FROM ${t} WHERE user_id=$1`).join(" UNION ALL ")}
        ) s`, [req.user.id]);
    res.json({ total_score: result.rows[0].total || 0 });
});



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

        // Check if we have data
        if (result.rows.length === 0) {
            return res.json({ 
                success: true, 
                data: [],
                message: "No users found yet" 
            });
        }

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


/* ===================== LOGOUT ===================== */
app.post("/logout", async (req, res) => {
    const ref = req.cookies.refresh_token;
    if (ref) await redis.del(`ref:${ref}`);
    res.clearCookie("access_token", cookieOptions);
    res.clearCookie("refresh_token", cookieOptions);
    res.json({ success: true });
});


  const PORT = process.env.PORT || 8080;
  app.listen(PORT, "0.0.0.0", () => console.log(`🚀 Server on port ${PORT}`));
