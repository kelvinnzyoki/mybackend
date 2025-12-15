
const PORT = process.env.PORT || 5432;
const express = require("express");
const app = express();
const cors = require('cors');
const helmet = require("helmet");
// Configuration to allow requests from your specific domain
const corsOptions = {
  origin: 'https://kelvinnzyoki.github.io', 
  optionsSuccessStatus: 200 // For legacy browser support
}

app.use(cors());
app.use(cors(corsOptions));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(helmet());

app.get("/", (req, res) => {
  res.send("Hello backend");
});


// -------------------------------------
// SIGN UP ENDPOINT
// -------------------------------------

let users = [];
let scores = [];

app.post("/signup", (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ message: "All fields required" });
  }

  const exists = users.find(u => u.email === email);

  if (exists) {
    return res.status(400).json({ message: "Email already registered" });
  }

  users.push({ username, email, password });

  res.json({ message: "Signup successful", user: { username, email } });
});

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


// -------------------------------------
// LOGIN ENDPOINT
// -------------------------------------

app.post("/login", (req, res) => {
  const { username, password } = req.body;

  const user = users.find(
    u => u.username === username && u.password === password
  );

  if (!user) {
    return res.status(400).json({ message: "Invalid email or password" });
  }

  res.json({ message: "Login successful", username: user.username });
});

// -------------------------------------
// RECORD POINTS ENDPOINT
// -------------------------------------

app.post("/record", (req, res) => {
  const { dataToRecord } = req.body;

  if (dataToRecord === undefined) {
    return res.status(400).json({ message: "Missing username or points" });
  }

  scores.push({ dataToRecord });

  res.json({
    message: "Points recorded successfully",
    data: { dataToRecord }
  });
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
