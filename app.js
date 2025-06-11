// backend/index.js
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
require('dotenv').config();


const app = express();
const port = process.env.PORT || 3001;
const jwtSecret = process.env.JWT_SECRET || "supersecretkey";

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

app.use(cors());
app.use(express.json());

// Middleware to check JWT
const authMiddleware = async (req, res, next) => {
  const authHeader = req.headers["authorization"];
  if (!authHeader) return res.status(401).json({ error: "Brak tokenu" });

  const token = authHeader.split(" ")[1];
  try {
    const payload = jwt.verify(token, jwtSecret);
    req.user = payload;
    next();
  } catch (err) {
    res.status(401).json({ error: "Nieprawidłowy token" });
  }
};

// Rejestracja
app.post("/register", async (req, res) => {
  const { email, password } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  try {
    const result = await pool.query(
      "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id",
      [email, hashed]
    );
    res.status(201).json({ userId: result.rows[0].id });
  } catch (err) {
    res.status(400).json({ error: "Email jest już zajęty" });
  }
});

// Logowanie
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const result = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
  if (result.rowCount === 0) return res.status(400).json({ error: "Nieprawidłowe dane" });

  const user = result.rows[0];
  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(400).json({ error: "Nieprawidłowe dane" });

  const token = jwt.sign({ id: user.id }, jwtSecret, { expiresIn: "7d" });
  res.json({ token });
});

// Pobierz wydatki
app.get("/expenses", async (req, res) => {
  const userId = req.user?.id;
  const result = userId
    ? await pool.query("SELECT * FROM expenses WHERE user_id = $1 ORDER BY date DESC", [userId])
    : await pool.query("SELECT * FROM expenses WHERE user_id IS NULL ORDER BY date DESC");
  res.json(result.rows);
});

// Dodaj wydatek
app.post("/expenses", async (req, res) => {
  const { amount, description, category, date } = req.body;
  const userId = req.user?.id || null;
  const result = await pool.query(
    "INSERT INTO expenses (user_id, amount, description, category, date) VALUES ($1, $2, $3, $4, $5) RETURNING *",
    [userId, amount, description, category, date]
  );
  res.status(201).json(result.rows[0]);
});

// Edytuj wydatek
app.put("/expenses/:id", authMiddleware, async (req, res) => {
  const { id } = req.params;
  const { amount, description, category, date } = req.body;
  const userId = req.user.id;

  const result = await pool.query(
    `UPDATE expenses SET amount=$1, description=$2, category=$3, date=$4
     WHERE id=$5 AND user_id=$6 RETURNING *`,
    [amount, description, category, date, id, userId]
  );
  res.json(result.rows[0]);
});

// Usuń wydatek
app.delete("/expenses/:id", authMiddleware, async (req, res) => {
  const { id } = req.params;
  const userId = req.user.id;

  await pool.query("DELETE FROM expenses WHERE id=$1 AND user_id=$2", [id, userId]);
  res.sendStatus(204);
});

// Usuń konto
app.delete("/me", authMiddleware, async (req, res) => {
  const userId = req.user.id;
  await pool.query("DELETE FROM expenses WHERE user_id=$1", [userId]);
  await pool.query("DELETE FROM users WHERE id=$1", [userId]);
  res.sendStatus(204);
});

// Inicjalizacja tabel
(async () => {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS expenses (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      amount NUMERIC NOT NULL,
      description TEXT,
      category TEXT,
      date DATE NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

  console.log("Baza danych gotowa.");
})();

app.listen(port, () => console.log(`Server listening on port ${port}`));
