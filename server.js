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
        const query = `INSERT INTO users (username, email, password, dob) VALUES ($1, $2, $3, $4) RETURNING id, username, email`; // FIXED: Added backticks
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
        }); // FIXED: Added closing brace and semicolon

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

        if (![5, 50].includes(score)) {
            return res.status(400).json({
                success: false,
                error: 'Invalid score'
            });
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
        const allowedScores = [20, 50, 70];
        if (!allowedScores.includes(Number(score))) {
            return res.status(400).json({ 
                success: false, 
                message: "Invalid score value received." 
            });
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
        const allowedScores = [20, 50, 70];
        if (!allowedScores.includes(Number(score))) {
            return res.status(400).json({ 
                success: false, 
                message: "Invalid score value received." 
            });
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
        const allowedScores = [20, 50, 70];
        if (!allowedScores.includes(Number(score))) {
            return res.status(400).json({ 
                success: false, 
                message: "Invalid score value received." 
            });
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
        const allowedScores = [20, 50, 70];
        if (!allowedScores.includes(Number(score))) {
            return res.status(400).json({ 
                success: false, 
                message: "Invalid score value received." 
            });
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
app.get('/api/total-score/:email', async (req, res) => {
    const userEmail = req.params.email;

    try {
        const query = `
            SELECT SUM(score) as total 
            FROM (
                SELECT DISTINCT ON (email) score FROM pushups WHERE email = $1 ORDER BY email, entry_date DESC
                UNION ALL
                SELECT DISTINCT ON (email) score FROM situps WHERE email = $1 ORDER BY email, entry_date DESC
                UNION ALL
                SELECT DISTINCT ON (email) score FROM squats WHERE email = $1 ORDER BY email, entry_date DESC
                UNION ALL
                SELECT DISTINCT ON (email) score FROM steps WHERE email = $1 ORDER BY email, entry_date DESC
                UNION ALL
                SELECT DISTINCT ON (email) score FROM "Addictions" WHERE email = $1 ORDER BY email, entry_date DESC
            ) AS user_latest;
        `;

        const result = await pool.query(query, [userEmail]);
        
        res.json({
            success: true,
            email: userEmail,
            total_score: result.rows[0].total || 0
        });

    } catch (error) {
        console.error("Aggregation Error:", error);
        res.status(500).json({ success: false, message: "Error calculating total score" });
    }
});
    


/* 4. SERVER START */
const PORT = process.env.PORT;
app.listen(PORT, "0.0.0.0", () => {
    console.log(`🚀 Server running on port ${PORT}`); // FIXED: Added backticks
});
