const { Pool } = require('pg');

// 1. Get the connection string from environment variables
const connectionString = process.env.DATABASE_URL; 

if (!connectionString) {
    throw new Error('DATABASE_URL environment variable is not set.');
}

// 2. The 'pg' Pool object will use the connectionString
// or the individual PG* variables automatically.
const pool = new Pool({
    connectionString: connectionString, 
    // You may need to add an SSL configuration for production:
    ssl: {
        rejectUnauthorized: false 
    }
});

module.exports = {
    query: (text, params) => pool.query(text, params),
}



// Create a table
db.run(
  `CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT,
      email TEXT UNIQUE,
      password TEXT
   )`,
  (err) => {
    if (err) console.error("Error creating table:", err.message);
  }
);

module.exports = db;

// Route: Get all users
app.get("/users", (req, res) => {
  db.all(`SELECT * FROM users`, [], (err, rows) => {
    if (err) {
      return res.status(400).json({ error: err.message });
    }
    res.json(rows);
  });
});

// Route: Get 1 user by email
app.get("/user/:email", (req, res) => {
  const email = req.params.email;

  db.get(`SELECT * FROM users WHERE email = ?`, [email], (err, row) => {
    if (err) return res.status(400).json({ error: err.message });

    res.json(row || {});
    res.json({ message: "Signup successful", user: { username, email } });
  });
});
