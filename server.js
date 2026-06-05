const express = require('express');
const bcrypt = require('bcrypt');
const cors = require('cors');
const fs = require('fs');
const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

function getUsers() {
  if (!fs.existsSync('users.json')) return [];
  return JSON.parse(fs.readFileSync('users.json', 'utf8'));
}
function saveUsers(u) {
  fs.writeFileSync('users.json', JSON.stringify(u, null, 2));
}

app.post('/api/register', async (req, res) => {
  const { username, email, password } = req.body;
  const users = getUsers();
  if (users.find(u => u.email === email))
    return res.status(400).json({ error: 'Email already registered' });
  const hashed = await bcrypt.hash(password, 10);
  users.push({ username, email, password: hashed });
  saveUsers(users);
  res.json({ message: 'Account created!' });
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const users = getUsers();
  const user = users.find(u => u.email === email);
  if (!user) return res.status(401).json({ error: 'Invalid email or password' });
  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(401).json({ error: 'Invalid email or password' });
  res.json({ message: 'Login successful', username: user.username });
});

app.listen(3000, () => console.log('Server running!'));
