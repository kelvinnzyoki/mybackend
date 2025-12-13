// server.js (Main Application File)

const { createTables } = require('./db/init');
const app = require('./app'); // Your Express app setup

const PORT = process.env.PORT || 3000;

// Immediately call the function to ensure the database schema is set up
createTables()
    .then(() => {
        // Only start the HTTP server if the database connection and tables are successful
        app.listen(PORT, () => {
            console.log(`Server running on port ${PORT}`);
        });
    })
    .catch((err) => {
        console.error('CRITICAL ERROR: Failed to start server due to database initialization failure.', err);
        // Exit the process if the database cannot be set up
        process.exit(1); 
    });

const { pool } = require('./db'); // Import the pg pool

// Route: Get all users
app.get("/users", async (req, res) => {
  try {
    // pool.query() returns a promise that resolves to a result object
    const result = await pool.query(`SELECT * FROM users`);
    // Rows are in the result.rows property
    res.json(result.rows); 
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Route: Get 1 user by email
app.get("/user/:email", async (req, res) => {
  const email = req.params.email;

  try {
    // 1. Use '$1' for the first parameter
    // 2. Pass the parameters in the second argument array
    const result = await pool.query(`SELECT * FROM users WHERE email = $1`, [email]);
    
    const user = result.rows[0]; // PostgreSQL returns an array of rows

    if (!user) {
      return res.json({}); // Return empty object if not found
    }

    res.json(user);

  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});
