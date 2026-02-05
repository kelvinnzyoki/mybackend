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

// CORS
app.use(cors({
    origin: function(origin, callback) {
        const allowed = [
            "https://cctamcc.site",
            "https://www.cctamcc.site",
            "http://localhost:5500",
            "https://admin.cctamcc.site"
        ];
        
        if (!origin || allowed.includes(origin)) {
            callback(null, true);
        } else {
            console.error('CORS blocked origin:', origin);
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ["GET", "POST", "DELETE", "PUT", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    exposedHeaders: ["Set-Cookie"],
    preflightContinue: false,
    optionsSuccessStatus: 204
}));

// Cookies
const cookieOptions = {
    httpOnly: true,
    secure: true,
    sameSite: "Lax",
    domain: ".cctamcc.site", 
    path: "/"
};

/* ===================== DATABASE PSTG and REDIS ===================== */
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: true }
});

const redis = createClient({ url: process.env.REDIS_URL });
redis.on('error', (err) => console.log('Redis Error', err));
(async () => { await redis.connect(); console.log("Redis Online"); })();

const resend = new Resend(process.env.RESEND_API_KEY);

/* ===================== AUTH HELPERS ===================== */
const createAccessToken = (user) =>
    jwt.sign({ id: user.id, role: user.role || 'user' }, process.env.JWT_ACCESS_SECRET, { expiresIn: "15m" });

const createRefreshToken = (user) =>
    jwt.sign({ id: user.id }, process.env.JWT_REFRESH_SECRET, { expiresIn: "14d" });

const getHash = (data) => crypto.createHash("sha256").update(data).digest("hex");

/* ===================== MIDDLEWARE ===================== */
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

// My Panel authentication middleware
const authenticateAdmin = async (req, res, next) => {
    const token = req.cookies.access_token;
    if (!token) return res.status(401).json({ message: "Unauthenticated" });

    jwt.verify(token, process.env.JWT_ACCESS_SECRET, async (err, decoded) => {
        if (err) return res.status(403).json({ message: "Session Expired" });

        try {
            const result = await pool.query("SELECT role FROM users WHERE id = $1", [decoded.id]);
            if (!result.rows[0] || result.rows[0].role !== 'admin') {
                return res.status(403).json({ message: "Admin access required" });
            }
            req.user = decoded;
            next();
        } catch (e) { 
            res.status(500).json({ message: "Auth Error" }); 
        }
    });
};

//  Activity logging helper
const logActivity = async (userId, action, details = {}) => {
    try {
        await pool.query(
            `INSERT INTO activity_logs (user_id, action, details, timestamp) 
             VALUES ($1, $2, $3, NOW())`,
            [userId, action, JSON.stringify(details)]
        );
        
        // Store in Redis for real-time access (last 100 activities)
        const activityData = JSON.stringify({
            user_id: userId,
            action,
            details,
            timestamp: new Date().toISOString()
        });
        
        await redis.lPush('recent_activities', activityData);
        await redis.lTrim('recent_activities', 0, 99); // Keep only last 100
    } catch (err) {
        console.error('Activity logging error:', err);
    }
};

/* ===================== ROUTES ===================== */
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
        const existingUser = await pool.query("SELECT id FROM users WHERE email = $1", [email]);
        if (existingUser.rows.length > 0) {
            return res.status(409).json({ success: false, message: "This email is already registered. Please login instead." });
        }

        const code = Math.floor(100000 + Math.random() * 900000).toString();
        const key = getHash(email);

        await resend.emails.send({
            from: "tam@cctamcc.site",
            to: email,
            subject: "To Alpha Man Code",
            html: `Your TAM verification code is: <strong>${code}</strong>`
        });
        
        await redis.setEx(`verify:${key}`, 300, code);
        
        // Log verification email sent
        await logActivity(null, 'verification_email_sent', { email });
        
        res.json({ success: true });
    } catch (err) {
        console.error("Send code error:", err);
        res.status(500).json({ success: false, message: "Email failed" });
    }
});

app.post("/signup", async (req, res) => {
    const { email, code, username, password, dob } = req.body;

    // 1. Validation (Must be first!)
    if (!username || username.length < 3) {
        return res.status(400).json({ success: false, message: 'Username must be at least 3 characters' });
    }
    if (!password || password.length < 6) {
        return res.status(400).json({ success: false, message: 'Password too weak' });
    }

    const key = getHash(email);

    try {
        // 2. Verify Redis Code
        const storedCode = await redis.get(`verify:${key}`);
        if (!storedCode || storedCode !== code) {
            return res.status(400).json({ message: "Invalid or expired verification code" });
        }

        // 3. Check for existing user (Using 'pool' per your config)
        const existingEmail = await pool.query("SELECT id FROM users WHERE email = $1", [email]);
        if (existingEmail.rows.length > 0) {
            await redis.del(`verify:${key}`);
            return res.status(409).json({ success: false, message: "This email is already registered." });
        }

        const existingUsername = await pool.query("SELECT id FROM users WHERE LOWER(username) = LOWER($1)", [username]);
        if (existingUsername.rows.length > 0) {
            return res.status(409).json({ success: false, message: "Username already taken." });
        }

        // 4. Create User
        const hashed = await bcrypt.hash(password, 12);
        const newUser = await pool.query(
            "INSERT INTO users (username, email, password, dob) VALUES ($1, $2, $3, $4) RETURNING id, username",
            [username, email, hashed, dob]
        );
        
        const user = newUser.rows[0];

        // 5. Cleanup & Tokens
        await redis.del(`verify:${key}`);
        const access = createAccessToken(user);
        const refresh = createRefreshToken(user);

        await redis.set(`ref:${refresh}`, user.id, { EX: 1209600 });
        await redis.set(`fp:${user.id}`, req.headers["user-agent"] + req.ip);

        // 6. Set Cookies
        res.cookie("access_token", access, { ...cookieOptions, maxAge: 900000 });
        res.cookie("refresh_token", refresh, { ...cookieOptions, maxAge: 1209600000 });

        // 7. Log Activity (Make sure logActivity is defined in server.js)
        if (typeof logActivity === 'function') {
            await logActivity(user.id, 'user_signup', { username, email });
        }

        // 8. Final Success Response (Only one response!)
        res.json({ 
            success: true, 
            message: "Account created successfully!", 
            user: { username: user.username }
        });

    } catch (err) {
        console.error("Signup error:", err);
        if (err.code === '23505') {
            return res.status(409).json({ success: false, message: "Email or username already exists" });
        }
        res.status(500).json({ success: false, message: "Server error during registration." });
    }
});

// Check username availability
app.post('/check-username', async (req, res) => {
    const { username } = req.body;
    
    if (!username || username.length < 3) {
        return res.json({ available: false, message: 'Username too short' });
    }
    
    try {
        const result = await db.query(
            'SELECT id FROM users WHERE LOWER(username) = LOWER($1)',
            [username]
        );
        
        res.json({ available: result.rows.length === 0 });
    } catch (err) {
        console.error('Username check error:', err);
        res.status(500).json({ available: null, message: 'Error checking username' });
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
    
    // Log login activity
    await logActivity(user.id, 'user_login', { username: user.username });
    
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

app.post('/api/user/recovery', authenticate, async (req, res) => {
    const { sleep, hydration, stress, score } = req.body;
    await pool.query(
        "INSERT INTO recovery_logs (user_id, sleep, hydration, stress, readiness_score, date) VALUES ($1, $2, $3, $4, $5, CURRENT_DATE) ON CONFLICT (user_id, date) DO UPDATE SET sleep=$2, hydration=$3, stress=$4, readiness_score=$5",
        [req.user.id, sleep, hydration, stress, score]
    );
    
    //  Log recovery data entry
    await logActivity(req.user.id, 'recovery_log_updated', { sleep, hydration, stress, score });
    
    res.json({ success: true });
});

app.get('/api/user/recovery', authenticate, async (req, res) => {
    const result = await pool.query(
        "SELECT sleep, hydration, stress, readiness_score FROM recovery_logs WHERE user_id = $1 ORDER BY date DESC LIMIT 1", 
        [req.user.id]
    );
    res.json(result.rows[0] || { sleep: 0, hydration: 0, stress: 5, readiness_score: 0 });
});

const scoreTables = ["addictions", "pushups", "situps", "squats", "steps"];

scoreTables.forEach(table => {
    app.post(`/${table}`, authenticate, async (req, res) => {
        const { score, date } = req.body;
        
        const cleanDate = date ? date : new Date().toISOString().split('T')[0];

        if (score === undefined || isNaN(score)) {
            return res.status(400).json({ success: false, message: "Valid score required" });
        }

        try {
            await pool.query(
                `INSERT INTO ${table} (user_id, date, score) 
                 VALUES ($1, $2, $3) 
                 ON CONFLICT (user_id, date) 
                 DO UPDATE SET score = EXCLUDED.score`,
                [req.user.id, cleanDate, parseInt(score)]
            );
            
            //  Log score update
            await logActivity(req.user.id, `${table}_score_updated`, { score, date: cleanDate });
            
            res.json({ success: true, message: `${table} score synced` });
        } catch (err) {
            console.error(`❌ Error in /${table}:`, err.message);
            res.status(500).json({ success: false, message: "Database Error" });
        }
    });
});

app.post("/arena/post", authenticate, async (req, res) => {
    const { victory_text } = req.body;
    if (!victory_text || victory_text.trim() === "") {
        return res.status(400).json({ success: false, message: "Post text required" });
    }
    if (victory_text.length > 500) {
        return res.status(400).json({ success: false, message: "Post too long (max 500 chars)" });
    }

    try {
        await pool.query(
            "INSERT INTO arena_posts (user_id, post_text, created_at) VALUES ($1, $2, NOW())",
            [req.user.id, victory_text.trim()]
        );
        
        //  Log arena post
        await logActivity(req.user.id, 'arena_post_created', { post_length: victory_text.length });
        
        res.json({ success: true, message: "Posted to arena" });
    } catch (err) {
        console.error("Arena post error:", err);
        res.status(500).json({ success: false, message: "Failed to post" });
    }
});

app.get("/feed", authenticate, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT u.username, ap.post_text, ap.created_at,
                COALESCE((SELECT SUM(score) FROM (
                    SELECT score FROM pushups WHERE user_id = u.id
                    UNION ALL SELECT score FROM situps WHERE user_id = u.id
                    UNION ALL SELECT score FROM squats WHERE user_id = u.id
                    UNION ALL SELECT score FROM steps WHERE user_id = u.id
                    UNION ALL SELECT score FROM addictions WHERE user_id = u.id
                ) scores), 0) as total_score
            FROM arena_posts ap
            JOIN users u ON u.id = ap.user_id
            ORDER BY ap.created_at DESC LIMIT 50
        `);
        res.json({ success: true, data: result.rows });
    } catch (err) {
        console.error("Feed error:", err);
        res.status(500).json({ success: false, message: "Failed to load feed" });
    }
});

app.post("/api/audit/save", authenticate, async (req, res) => {
    const { victory, defeat } = req.body;
    try {
        await pool.query(`
            INSERT INTO audits (user_id, victory, defeat, updated_at) VALUES ($1, $2, $3, NOW())
            ON CONFLICT (user_id) DO UPDATE SET victory = EXCLUDED.victory, defeat = EXCLUDED.defeat, updated_at = NOW()
        `, [req.user.id, victory, defeat]);
        
        // Log audit save
        await logActivity(req.user.id, 'audit_updated', { victory_length: victory?.length, defeat_length: defeat?.length });
        
        res.json({ success: true });
    } catch (err) {
        console.error("Audit save error:", err);
        res.status(500).json({ success: false });
    }
});

app.get('/api/audit/load', authenticate, async (req, res) => {
    try {
        const result = await pool.query(
            "SELECT victory, defeat, focus, ego_control FROM audits WHERE user_id = $1", 
            [req.user.id]
        );
        const data = result.rows[0] || { victory: "", defeat: "", focus: 50, ego_control: 50 };
        res.json(data);
    } catch (err) {
        console.error("Audit load error:", err);
        res.status(500).json({ error: "Failed to load audit data" });
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
            ORDER BY total_score DESC LIMIT 10
        `);
        res.json({ success: true, data: result.rows });
    } catch (error) {
        console.error("Leaderboard error:", error);
        res.status(500).json({ success: false, message: "Failed to fetch leaderboard" });
    }
});

/* ===================== ADMIN ENDPOINTS ===================== */

// Get dashboard stats
app.get("/admin/stats", authenticateAdmin, async (req, res) => {
    try {
        const [users, recovery, audits, activities] = await Promise.all([
            pool.query("SELECT COUNT(*) FROM users"),
            pool.query("SELECT COUNT(*) FROM recovery_logs"),
            pool.query("SELECT COUNT(*) FROM audits"),
            pool.query("SELECT COUNT(*) FROM activity_logs")
        ]);

        res.json({
            total_users: parseInt(users.rows[0].count),
            total_recovery: parseInt(recovery.rows[0].count),
            total_audits: parseInt(audits.rows[0].count),
            total_activities: parseInt(activities.rows[0].count)
        });
    } catch (err) {
        console.error("Admin stats error:", err);
        res.status(500).json({ message: "Failed to fetch stats" });
    }
});

//  Get all audits
app.get("/admin/audits", authenticateAdmin, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT a.user_id, a.victory, a.defeat, a.updated_at, u.username
            FROM audits a
            JOIN users u ON u.id = a.user_id
            ORDER BY a.updated_at DESC
        `);
        res.json(result.rows);
    } catch (err) {
        console.error("Admin audits error:", err);
        res.status(500).json({ message: "Failed to fetch audits" });
    }
});

//  Delete audit
app.delete("/admin/audit/:userId", authenticateAdmin, async (req, res) => {
    try {
        await pool.query("DELETE FROM audits WHERE user_id = $1", [req.params.userId]);
        await logActivity(req.user.id, 'admin_audit_deleted', { deleted_user_id: req.params.userId });
        res.json({ success: true, message: "Audit deleted" });
    } catch (err) {
        console.error("Admin delete audit error:", err);
        res.status(500).json({ message: "Failed to delete audit" });
    }
});

// Get recent activities (live tracking)
app.get("/admin/activities", authenticateAdmin, async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 50;
        const result = await pool.query(`
            SELECT al.*, u.username
            FROM activity_logs al
            LEFT JOIN users u ON u.id = al.user_id
            ORDER BY al.timestamp DESC
            LIMIT $1
        `, [limit]);
        
        res.json(result.rows);
    } catch (err) {
        console.error("Admin activities error:", err);
        res.status(500).json({ message: "Failed to fetch activities" });
    }
});

//  Get real-time activities from Redis
app.get("/admin/activities/realtime", authenticateAdmin, async (req, res) => {
    try {
        const activities = await redis.lRange('recent_activities', 0, 49);
        const parsed = activities.map(a => JSON.parse(a));
        res.json(parsed);
    } catch (err) {
        console.error("Real-time activities error:", err);
        res.status(500).json({ message: "Failed to fetch real-time activities" });
    }
});

//  Get user list with stats
app.get("/admin/users", authenticateAdmin, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT 
                u.id, 
                u.username, 
                u.email, 
                u.created_at,
                u.role,
                COALESCE((SELECT SUM(score) FROM (
                    SELECT score FROM pushups WHERE user_id = u.id
                    UNION ALL SELECT score FROM situps WHERE user_id = u.id
                    UNION ALL SELECT score FROM squats WHERE user_id = u.id
                    UNION ALL SELECT score FROM steps WHERE user_id = u.id
                    UNION ALL SELECT score FROM addictions WHERE user_id = u.id
                ) scores), 0) as total_score,
                (SELECT COUNT(*) FROM arena_posts WHERE user_id = u.id) as post_count,
                (SELECT MAX(timestamp) FROM activity_logs WHERE user_id = u.id) as last_active
            FROM users u
            ORDER BY u.created_at DESC
        `);
        res.json(result.rows);
    } catch (err) {
        console.error("Admin users error:", err);
        res.status(500).json({ message: "Failed to fetch users" });
    }
});

// Delete user (moderation)
app.delete("/admin/user/:userId", authenticateAdmin, async (req, res) => {
    try {
        const userId = req.params.userId;
        
        // Delete user and cascade
        await pool.query("DELETE FROM users WHERE id = $1", [userId]);
        
        await logActivity(req.user.id, 'admin_user_deleted', { deleted_user_id: userId });
        res.json({ success: true, message: "User deleted" });
    } catch (err) {
        console.error("Admin delete user error:", err);
        res.status(500).json({ message: "Failed to delete user" });
    }
});

// Get activity stats by type
app.get("/admin/activity-stats", authenticateAdmin, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT 
                action, 
                COUNT(*) as count,
                MAX(timestamp) as last_occurrence
            FROM activity_logs
            WHERE timestamp > NOW() - INTERVAL '7 days'
            GROUP BY action
            ORDER BY count DESC
        `);
        res.json(result.rows);
    } catch (err) {
        console.error("Activity stats error:", err);
        res.status(500).json({ message: "Failed to fetch activity stats" });
    }
});

// Get user growth over time
app.get("/admin/user-growth", authenticateAdmin, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT 
                DATE(created_at) as date,
                COUNT(*) as signups
            FROM users
            WHERE created_at > NOW() - INTERVAL '30 days'
            GROUP BY DATE(created_at)
            ORDER BY date ASC
        `);
        res.json(result.rows);
    } catch (err) {
        console.error("User growth error:", err);
        res.status(500).json({ message: "Failed to fetch user growth" });
    }
});

app.post("/logout", async (req, res) => {
    const ref = req.cookies.refresh_token;
    if (ref) await redis.del(`ref:${ref}`);
    res.clearCookie("access_token", cookieOptions);
    res.clearCookie("refresh_token", cookieOptions);
    res.json({ success: true });
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, "0.0.0.0", () => console.log(`Server on port ${PORT}`));
