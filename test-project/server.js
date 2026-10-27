const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { hashPassword, generateResetToken } = require('./utils/auth');
const config = require('./config');

const app = express();

// Vulnerable: Permissive CORS configuration with wildcard *
app.use(cors({ origin: '*' }));

// Vulnerable: Express body parser without explicit size limit
app.use(express.json());

// Notice: Helmet is NOT used here!
// Notice: Rate limiting is NOT used here!

// Vulnerable: Hardcoded JWT secret
const JWT_SECRET = 'myHardcodedSuperSecretJwtKey2026!';

// Vulnerable: Logging sensitive password directly to stdout
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  console.log('Login attempt for username:', username, 'with password:', password);

  if (username === 'admin') {
    const token = jwt.sign({ username, role: 'admin' }, JWT_SECRET);
    res.cookie('auth_cookie', token); // Vulnerable: missing httpOnly and secure flags
    return res.json({ success: true, token });
  }

  res.status(401).json({ error: 'Invalid credentials' });
});

// Vulnerable: Arbitrary code execution via eval()
app.post('/api/calculate', (req, res) => {
  const formula = req.body.formula;
  try {
    const result = eval(formula);
    res.json({ result });
  } catch (err) {
    res.status(500).json({ error: err.message, stack: err.stack }); // Vulnerable: Stack trace leak
  }
});

// Vulnerable: SQL injection through string concatenation
app.get('/api/users', (req, res) => {
  const role = req.query.role;
  const sqlQuery = "SELECT id, username, email FROM users WHERE role = '" + role + "'";
  // Mock db.query
  console.log('Executing query:', sqlQuery);
  res.json({ query: sqlQuery });
});

// Vulnerable: Unvalidated redirect
app.get('/api/redirect', (req, res) => {
  const target = req.query.url;
  res.redirect(target);
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Vulnerable test server running at http://localhost:${PORT}`);
});
