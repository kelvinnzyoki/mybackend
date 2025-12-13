// 1. DEFINE PORT AND IMPORT CORE MODULES
const PORT = process.env.PORT || 5432; // FIX: Define PORT
const { createTables, pool } = require('./db/init'); // FIX: Import pool and createTables from a consolidated file
const app = require('./app'); // Your Express app instance (where you have app.use(express.json()) and CORS)

// 2. DATABASE INITIALIZATION AND SERVER STARTUP
createTables()
    .then(() => {
        console.log('Database tables initialized successfully.');
        
        // 3. DEFINE ROUTES *AFTER* INITIALIZATION
        
        // Route: Get all users
        app.get("/users", async (req, res) => {
            try {
                const result = await pool.query(`SELECT * FROM users`);
                res.json(result.rows);
            } catch (err) {
                console.error("Error fetching users:", err); // Better logging
                res.status(500).json({ error: "Internal Server Error" }); // More generic error for frontend
            }
        });

        // Route: Get 1 user by email
        app.get("/user/:email", async (req, res) => {
            const email = req.params.email;
            try {
                const result = await pool.query(`SELECT * FROM users WHERE email = $1`, [email]);
                const user = result.rows[0];

                if (!user) {
                    return res.status(404).json({ message: "User not found" }); // Return 404 for clarity
                }

                res.json(user);
            } catch (err) {
                console.error("Error fetching user by email:", err);
                res.status(500).json({ error: "Internal Server Error" });
            }
        });

        // 4. START SERVER
        app.listen(PORT, () => {
            console.log(`Server running on port ${PORT}`);
        });
    })
    .catch((err) => {
        console.error('CRITICAL ERROR: Failed to start server due to database initialization failure.', err);
        process.exit(1);
    });
