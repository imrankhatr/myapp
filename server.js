const express = require('express');
const bcrypt = require('bcrypt');
const cors = require('cors');
const { Pool } = require('pg');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function init() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);
}
init();

app.post('/api/register', async (req, res) => {
  const { username, email, password } = req.body;
  try {
    const exists = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
    if (exists.rows.length > 0)
      return res.status(400).json({ error: 'Email already registered' });
    const hashed = await bcrypt.hash(password, 10);
    await pool.query(
      'INSERT INTO users (username, email, password) VALUES ($1,$2,$3)',
      [username, email, hashed]
    );
    res.json({ message: 'Account created!' });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
    if (result.rows.length === 0)
      return res.status(401).json({ error: 'Invalid email or password' });
    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match)
      return res.status(401).json({ error: 'Invalid email or password' });
    res.json({ message: 'Login successful', username: user.username });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/users', async (req, res) => {
  if (req.query.key !== 'imran1234')
    return res.status(401).json({ error: 'Access denied!' });
  const result = await pool.query('SELECT id, username, email, created_at FROM users');
  res.json(result.rows);
});

app.listen(3000, () => console.log('Server running!'));
