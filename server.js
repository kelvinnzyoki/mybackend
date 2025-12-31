require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const bcrypt = require("bcryptjs"); // Using bcryptjs for stability
const { Pool } = require("pg");
const nodemailer = require('nodemailer');

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



// SIGN UP 

const redis = require('redis');

// 1. Initialize Redis Client
// Replace with your actual Redis URL (from Railway, Render, or local)
const redisClient = redis.createClient({
    url: process.env.REDIS_URL || 'redis://localhost:6379'
});

redisClient.on('error', (err) => console.log('Redis Client Error', err));

(async () => {
    await redisClient.connect();
    console.log("Connected to Redis System");
})();

/**
 * PHASE 1: Send and Store Code in Redis
 */
app.post('/send-code', async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ message: "Email required" });

    const code = Math.floor(100000 + Math.random() * 900000).toString();

    try {
        // Store code in Redis with an Expiration of 600 seconds (10 minutes)
        // 'EX' sets the time-to-live automatically
        await redisClient.set(email, code, {
            EX: 600
        });

        // ... existing Nodemailer transporter.sendMail logic here ...
        // 2. Nodemailer Configuration
// Note: Use an "App Password" if using Gmail
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'your-email@gmail.com',
        pass: 'your-app-password'
    }
});
        
        res.json({ success: true, message: "Code stored in Redis and sent" });
    } catch (error) {
        res.status(500).json({ success: false, message: "Redis/Mail Error" });
    }
});

/**
 * PHASE 2: Verify Code from Redis
 */
app.post('/signup', async (req, res) => {
    const { email, code, username, password, dob } = req.body;

    try {
        // Retrieve the code from Redis
        const storedCode = await redisClient.get(email);

        if (!storedCode || storedCode !== code) {
            return res.status(400).json({ success: false, message: "Invalid or expired code" });
        }

        // ... existing Password Hashing and PostgreSQL INSERT logic here ...
        try {
        // 2. Hash Password
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // 3. Insert into Database
        const query = `
            INSERT INTO users (username, email, password, dob, created_at)
            VALUES ($1, $2, $3, $4, NOW())
            RETURNING id, username, email;
        `;
        const values = [username, email, hashedPassword, dob];
        
        const result = await pool.query(query, values);
            

        // Cleanup: Remove code from Redis immediately after successful signup
        await redisClient.del(email);

        res.json({ success: true, message: "Verified and User Created" });

    } catch (error) {
        res.status(500).json({ success: false, message: "Server error" });
    }
});



        
        


// LOGIN
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
        }); // FIXED: Added closing brace and semicolon

    } catch (err) {
        console.error("Login Error:", err);
        res.status(500).json({ message: "Server error" });
    }
});

// GET ALL USERS (Example)
app.get("/users",) => {
    try {
        const result = await pool.query("SELECT id, username, email FROM users");
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ message: "Server error" });
    }
});

// dataToRecord endpoint
function isValidScore(value) {
    return Number.isInteger(value) && value >= 0 && value <= 20000;
};
app.post('/record', async (req, res) => {
    try {
        const { email, date, score } = req.body;

        if (!email || !date || score === undefined) {
            return res.status(400).json({
                success: false,
                error: 'Missing required fields'
            });
        }

        
        const currentScore = Number(req.body.score);
        
        if (!isValidScore(currentScore)) {
    return res.status(400).json({ error: "Invalid score value" });
}


        // Insert into PostgreSQL
        const result = await pool.query(
            'INSERT INTO "Addictions" (email, date, score) VALUES ($1, $2, $3) RETURNING *',
            [email, date, score]
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




// POST endpoint to record push-ups data
app.post('/pushup', async (req, res) => {
    try {
        const { email, date, score } = req.body;

        // 1. Basic Validation
        if (!email || score === undefined) {
            return res.status(400).json({ 
                success: false, 
                message: "Missing email or score data." 
            });
        }

        // 2. Validate that the score is one of your allowed values (20, 50, or 70)
        
        const currentScore = Number(req.body.score);
        
        if (!isValidScore(currentScore)) {
    return res.status(400).json({ error: "Invalid score value" });
}

        // 3. Database Insertion
        // Note: entry_date defaults to NOW() if date is not provided
        const query = `
            INSERT INTO pushups (email, date, score) 
            VALUES ($1, $2, $3) 
            RETURNING *;
        `;
        const values = [
            email,
            date || new Date(),
            score
        ];

        const result = await pool.query(query, values);

        // 4. Success Response
        res.status(201).json({
            success: true,
            message: "Daily Push-ups saved successfully!",
            data: result.rows[0]
        });

    } catch (error) {
        console.error("Database Error:", error);
        res.status(500).json({ 
            success: false, 
            message: "Internal server error. Could not save record." 
        });
    }
});




// POST endpoint to record sit-ups data
app.post('/situps', async (req, res) => {
    try {
        const { email, date, score } = req.body;

        // 1. Basic Validation
        if (!email || score === undefined) {
            return res.status(400).json({ 
                success: false, 
                message: "Missing email or score data." 
            });
        }

        // 2. Validate that the score is one of your allowed values (20, 50, or 70)
        
        const currentScore = Number(req.body.score);
        
        if (!isValidScore(currentScore)) {
    return res.status(400).json({ error: "Invalid score value" });
}


        // 3. Database Insertion
        // Note: entry_date defaults to NOW() if date is not provided
        const query = `
            INSERT INTO situps (email, date, score) 
            VALUES ($1, $2, $3) 
            RETURNING *;
        `;
        const values = [
            email,
            date || new Date(),
            score
        ];

        const result = await pool.query(query, values);

        // 4. Success Response
        res.status(201).json({
            success: true,
            message: "Daily sit-ups saved successfully!",
            data: result.rows[0]
        });

    } catch (error) {
        console.error("Database Error:", error);
        res.status(500).json({ 
            success: false, 
            message: "Internal server error. Could not save record." 
        });
    }
});



// POST endpoint to record Squats data
app.post('/squats', async (req, res) => {
    try {
        const { email, date, score } = req.body;

        // 1. Basic Validation
        if (!email || score === undefined) {
            return res.status(400).json({ 
                success: false, 
                message: "Missing email or score data." 
            });
        }

        // 2. Validate that the score is one of your allowed values (20, 50, or 70)
        
        const currentScore = Number(req.body.score);
        
        if (!isValidScore(currentScore)) {
    return res.status(400).json({ error: "Invalid score value" });
}


        // 3. Database Insertion
        // Note: entry_date defaults to NOW() if date is not provided
        const query = `
            INSERT INTO squats (email, date, score) 
            VALUES ($1, $2, $3) 
            RETURNING *;
        `;
        const values = [
            email,
            date || new Date(),
            score
        ];

        const result = await pool.query(query, values);

        // 4. Success Response
        res.status(201).json({
            success: true,
            message: "Daily Squats saved successfully!",
            data: result.rows[0]
        });

    } catch (error) {
        console.error("Database Error:", error);
        res.status(500).json({ 
            success: false, 
            message: "Internal server error. Could not save record." 
        });
    }
});




        // POST endpoint to record Steps data
app.post('/steps', async (req, res) => {
    try {
        const { email, date, score } = req.body;

        // 1. Basic Validation
        if (!email || score === undefined) {
            return res.status(400).json({ 
                success: false, 
                message: "Missing email or score data." 
            });
        }

        // 2. Validate that the score is one of your allowed values (20, 50, or 70)
        
        const currentScore = Number(req.body.score);
        
        if (!isValidScore(currentScore)) {
    return res.status(400).json({ error: "Invalid score value" });
}


        // 3. Database Insertion
        // Note: entry_date defaults to NOW() if date is not provided
        const query = `
            INSERT INTO steps (email, date, score) 
            VALUES ($1, $2, $3) 
            RETURNING *;
        `;
        const values = [
            email,
            date || new Date(),
            score
        ];

        const result = await pool.query(query, values);

        // 4. Success Response
        res.status(201).json({
            success: true,
            message: "Daily Steps saved successfully!",
            data: result.rows[0]
        });

    } catch (error) {
        console.error("Database Error:", error);
        res.status(500).json({ 
            success: false, 
            message: "Internal server error. Could not save record." 
        });
    }
});


//User Total Score endpoint 
app.get('/total-score', async (req, res) => {
    const userEmail = req.query.email;

    try {
        const query = `
            SELECT SUM(score_as_int) as total 
            FROM (
                (SELECT DISTINCT ON (email) score::integer as score_as_int FROM pushups WHERE email = $1 ORDER BY email, date DESC)
                UNION ALL
                (SELECT DISTINCT ON (email) score::integer as score_as_int FROM situps WHERE email = $1 ORDER BY email, date DESC)
                UNION ALL
                (SELECT DISTINCT ON (email) score::integer as score_as_int FROM squats WHERE email = $1 ORDER BY email, date DESC)
                UNION ALL
                (SELECT DISTINCT ON (email) score::integer as score_as_int FROM steps WHERE email = $1 ORDER BY email, date DESC)
                UNION ALL
                (SELECT DISTINCT ON (email) score::integer as score_as_int FROM "Addictions" WHERE email = $1 ORDER BY email, date DESC)
            ) AS user_latest;
        `;

        const result = await pool.query(query, [userEmail]);
        const total = result.rows[0].total || 0;

        res.json({ success: true, total_score: parseInt(total) });

    } catch (error) {
        console.error("Aggregation Error:", error);
        res.status(500).json({ success: false, message: "Database error" });
    }
});




// Global Leaderboard Endpoint
app.get('/leaderboard', async (req, res) => {
    try {
        const query = `
            SELECT email, SUM(score_as_int) as total_score
            FROM (
                (SELECT DISTINCT ON (email) email, score::integer as score_as_int FROM pushups ORDER BY email, date DESC)
                UNION ALL
                (SELECT DISTINCT ON (email) email, score::integer as score_as_int FROM situps ORDER BY email, date DESC)
                UNION ALL
                (SELECT DISTINCT ON (email) email, score::integer as score_as_int FROM squats ORDER BY email, date DESC)
                UNION ALL
                (SELECT DISTINCT ON (email) email, score::integer as score_as_int FROM steps ORDER BY email, date DESC)
                UNION ALL
                (SELECT DISTINCT ON (email) email, score::integer as score_as_int FROM "Addictions" ORDER BY email, date DESC)
            ) AS all_latest
            GROUP BY email
            ORDER BY total_score DESC
            LIMIT 10;
        `;

        const result = await pool.query(query);
        res.json({ success: true, data: result.rows });
    } catch (error) {
        console.error("Leaderboard Error:", error);
        res.status(500).json({ success: false, message: "Database error" });
    }
});

        


/* 4. SERVER START */
const PORT = process.env.PORT;
app.listen(PORT, "0.0.0.0", () => {
    console.log(`🚀 Server running on port ${PORT}`); // FIXED: Added backticks
});
