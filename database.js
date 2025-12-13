require("dotenv").config();

const sqlite3 = require("sqlite3").verbose();

// Create or open the database file
const db = new sqlite3.Database(process.env.DB_PATH, (err) => {
  if (err) {
    console.error("Error opening database:", err.message);
  } else {
    console.log("Connected to SQLite database");
  }
});

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