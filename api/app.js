/**
 * DVWA - Vulnerable REST API
 * OWASP API Security Top 10 (2023)
 * FOR EDUCATIONAL/SECURITY TESTING PURPOSES ONLY - DO NOT DEPLOY IN PRODUCTION
 */

const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const axios = require('axios');
const cors = require('cors');

const app = express();

// VULN: CORS wildcard - accepts requests from any origin
app.use(cors({ origin: '*', credentials: true }));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// VULN: Weak, hardcoded JWT secret
const JWT_SECRET = 'secret123';

// ── Database Setup ─────────────────────────────────────────────────────────────
const db = new sqlite3.Database(':memory:');
db.serialize(() => {
  db.run(`CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT, password TEXT,
    email TEXT, role TEXT,
    balance REAL, ssn TEXT, api_key TEXT
  )`);
  db.run(`INSERT INTO users VALUES (1,'admin','admin123','admin@corp.local','admin',99999.00,'111-22-3333','sk-admin-key-abc123')`);
  db.run(`INSERT INTO users VALUES (2,'alice','password1','alice@corp.local','user',500.00,'444-55-6666','sk-alice-key-def456')`);
  db.run(`INSERT INTO users VALUES (3,'bob','letmein','bob@corp.local','user',250.00,'777-88-9999','sk-bob-key-ghi789')`);
  db.run(`INSERT INTO users VALUES (4,'charlie','charlie1','charlie@corp.local','user',100.00,'000-11-2222','sk-charlie-key-jkl000')`);

  db.run(`CREATE TABLE orders (
    id INTEGER PRIMARY KEY, user_id INTEGER,
    item TEXT, amount REAL, status TEXT, notes TEXT
  )`);
  db.run(`INSERT INTO orders VALUES (1,1,'Admin Server License',9999.99,'paid','Internal use only')`);
  db.run(`INSERT INTO orders VALUES (2,2,'Widget A',49.99,'pending','Ship to home')`);
  db.run(`INSERT INTO orders VALUES (3,3,'Widget B',29.99,'paid','')`);
  db.run(`INSERT INTO orders VALUES (4,4,'Widget C',9.99,'pending','')`);

  db.run(`CREATE TABLE admin_logs (
    id INTEGER PRIMARY KEY, action TEXT, ts TEXT
  )`);
  db.run(`INSERT INTO admin_logs VALUES (1,'User alice created','2024-01-01T00:00:00Z')`);
  db.run(`INSERT INTO admin_logs VALUES (2,'Config key rotated','2024-01-02T00:00:00Z')`);
});

// ── Helpers ────────────────────────────────────────────────────────────────────
// VULN: No expiry on tokens, no audience/issuer validation
const signToken = (user) => jwt.sign({ id: user.id, role: user.role }, JWT_SECRET);

// Weak auth middleware — only checks token exists and is signed, no role enforcement
const authenticate = (req, res, next) => {
  const auth = req.headers['authorization'];
  if (!auth) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(auth.replace('Bearer ', ''), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// ── API1: Broken Object Level Authorization (BOLA / IDOR) ─────────────────────
// Any authenticated user can read any other user's profile by changing the id
app.get('/api/v1/users/:id', authenticate, (req, res) => {
  // VULNERABLE: no check that req.user.id === req.params.id
  db.get('SELECT * FROM users WHERE id = ?', [req.params.id], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!row) return res.status(404).json({ error: 'Not found' });
    res.json(row); // VULNERABLE: returns SSN, api_key, password in response
  });
});

// BOLA on orders — any user can see any order
app.get('/api/v1/orders/:id', authenticate, (req, res) => {
  // VULNERABLE: no ownership check
  db.get('SELECT * FROM orders WHERE id = ?', [req.params.id], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(row);
  });
});

// ── API2: Broken Authentication ────────────────────────────────────────────────
app.post('/api/v1/auth/login', (req, res) => {
  const { username, password } = req.body;
  // VULNERABLE: plaintext password comparison, no rate limiting, verbose errors
  db.get('SELECT * FROM users WHERE username = ? AND password = ?',
    [username, password],
    (err, user) => {
      if (!user) return res.status(401).json({ error: `User '${username}' not found or wrong password` });
      res.json({ token: signToken(user), user }); // VULNERABLE: returns full user object including ssn
    }
  );
});

// VULN: Password reset via predictable token (just base64 of username)
app.post('/api/v1/auth/reset-password', (req, res) => {
  const { username } = req.body;
  const resetToken = Buffer.from(username).toString('base64');
  res.json({ resetToken, message: 'Use this token to reset your password' });
});

app.post('/api/v1/auth/reset-password/confirm', (req, res) => {
  const { resetToken, newPassword } = req.body;
  // VULNERABLE: predictable token — just decode base64 to get username
  const username = Buffer.from(resetToken, 'base64').toString('utf8');
  db.run('UPDATE users SET password = ? WHERE username = ?', [newPassword, username], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: `Password updated for ${username}` });
  });
});

// ── API3: Broken Object Property Level Authorization (Mass Assignment) ─────────
app.put('/api/v1/users/:id', authenticate, (req, res) => {
  // VULNERABLE: blindly accepts all body fields including role, balance, ssn
  const { username, email, role, balance, ssn, api_key } = req.body;
  // No check that req.user.id === req.params.id, no field allowlist
  db.run(
    'UPDATE users SET username=COALESCE(?,username), email=COALESCE(?,email), role=COALESCE(?,role), balance=COALESCE(?,balance), ssn=COALESCE(?,ssn), api_key=COALESCE(?,api_key) WHERE id=?',
    [username, email, role, balance, ssn, api_key, req.params.id],
    (err) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ message: 'User updated' });
    }
  );
});

// ── API4: Unrestricted Resource Consumption ────────────────────────────────────
// No pagination limits, no rate limiting, no max page size
app.get('/api/v1/users', authenticate, (req, res) => {
  const limit = req.query.limit || 999999; // VULNERABLE: caller controls limit
  const offset = req.query.offset || 0;
  // VULNERABLE: no max limit enforced
  db.all(`SELECT * FROM users LIMIT ${limit} OFFSET ${offset}`, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows); // VULNERABLE: returns all sensitive fields
  });
});

// VULN: No rate limiting on expensive search
app.get('/api/v1/search', authenticate, (req, res) => {
  const q = req.query.q || '';
  // VULNERABLE: SQL injection + no rate limit
  const query = `SELECT * FROM users WHERE username LIKE '%${q}%' OR email LIKE '%${q}%'`;
  db.all(query, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// ── API5: Broken Function Level Authorization ──────────────────────────────────
// Admin endpoints reachable by any authenticated user — no role check
app.get('/api/v1/admin/users', authenticate, (req, res) => {
  // VULNERABLE: should require role === 'admin', but doesn't check
  db.all('SELECT * FROM users', (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.delete('/api/v1/admin/users/:id', authenticate, (req, res) => {
  // VULNERABLE: any authenticated user can delete any user
  db.run('DELETE FROM users WHERE id = ?', [req.params.id], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: `User ${req.params.id} deleted` });
  });
});

app.get('/api/v1/admin/logs', authenticate, (req, res) => {
  // VULNERABLE: no role check
  db.all('SELECT * FROM admin_logs', (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// ── API6: Unrestricted Access to Sensitive Business Flows ─────────────────────
// Transfer endpoint with no velocity checks or fraud controls
app.post('/api/v1/transfer', authenticate, (req, res) => {
  const { to_user_id, amount } = req.body;
  // VULNERABLE: no velocity limit, no fraud check, no confirmation step
  // Attacker can drain accounts in a loop
  db.get('SELECT balance FROM users WHERE id = ?', [req.user.id], (err, sender) => {
    if (!sender) return res.status(404).json({ error: 'Sender not found' });
    db.run('UPDATE users SET balance = balance - ? WHERE id = ?', [amount, req.user.id]);
    db.run('UPDATE users SET balance = balance + ? WHERE id = ?', [amount, to_user_id]);
    res.json({ message: `Transferred ${amount} to user ${to_user_id}` });
  });
});

// ── API7: Server-Side Request Forgery (SSRF) ──────────────────────────────────
app.post('/api/v1/webhook/test', authenticate, (req, res) => {
  const { url } = req.body;
  // VULNERABLE: fetches any user-supplied URL including internal services
  axios.get(url, { timeout: 5000 })
    .then(r => res.json({ status: r.status, data: r.data }))
    .catch(e => res.status(500).json({ error: e.message, url }));
});

// ── API8: Security Misconfiguration ───────────────────────────────────────────
// Debug endpoint left exposed
app.get('/api/v1/debug', (req, res) => {
  // VULNERABLE: exposes internal state, env vars, db path
  res.json({
    env: process.env,
    uptime: process.uptime(),
    memoryUsage: process.memoryUsage(),
    jwt_secret: JWT_SECRET,
    nodeVersion: process.version,
  });
});

// VULN: Verbose stack traces in errors
app.use((err, req, res, next) => {
  res.status(500).json({ error: err.message, stack: err.stack });
});

// ── API9: Improper Inventory Management ───────────────────────────────────────
// Old v0 API still active — no auth required
app.get('/api/v0/users/:id', (req, res) => {
  // VULNERABLE: legacy endpoint, no authentication at all
  db.get('SELECT * FROM users WHERE id = ?', [req.params.id], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(row);
  });
});

// Undocumented internal endpoint
app.get('/internal/config', (req, res) => {
  res.json({
    db: 'sqlite3',
    jwt_secret: JWT_SECRET,
    admin_password: 'admin123',
    internal_api_key: 'internal-key-xyz-9999',
  });
});

// ── API10: Unsafe Consumption of APIs ─────────────────────────────────────────
// Fetches third-party data and passes it directly to eval/exec
app.post('/api/v1/calculate', authenticate, (req, res) => {
  const { expression } = req.body;
  // VULNERABLE: unsafe eval of user-supplied string
  try {
    const result = eval(expression); // nosec
    res.json({ result });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Vulnerable REST API running on http://localhost:${PORT}`);
  console.log('OWASP API Security Top 10 - FOR SECURITY TESTING ONLY');
});
