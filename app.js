/**
 * DVWA Security Lab - Intentionally Vulnerable Web Application
 * FOR EDUCATIONAL/SECURITY TESTING PURPOSES ONLY
 * DO NOT DEPLOY IN PRODUCTION
 */

const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static('public'));

// In-memory SQLite DB
const db = new sqlite3.Database(':memory:');
db.serialize(() => {
  db.run("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT)");
  db.run("INSERT INTO users VALUES (1, 'admin', 'admin123', 'admin@lab.local')");
  db.run("INSERT INTO users VALUES (2, 'alice', 'password1', 'alice@lab.local')");
  db.run("INSERT INTO users VALUES (3, 'bob', 'letmein', 'bob@lab.local')");
  db.run("CREATE TABLE notes (id INTEGER PRIMARY KEY, user_id INTEGER, content TEXT)");
  db.run("INSERT INTO notes VALUES (1, 1, 'Secret admin note: flag{sql_injection_found}')");
  db.run("INSERT INTO notes VALUES (2, 2, 'Alice private note')");
});

// Home
app.get('/', (req, res) => {
  res.render('index');
});

// VULN 1: SQL Injection - user input concatenated directly into query
app.get('/user', (req, res) => {
  const id = req.query.id || '1';
  // VULNERABLE: direct string concatenation
  const query = "SELECT * FROM users WHERE id = " + id;
  db.all(query, (err, rows) => {
    if (err) return res.send(`Error: ${err.message}`);
    res.render('user', { rows, query });
  });
});

// VULN 2: Reflected XSS - unsanitized input rendered in response
app.get('/search', (req, res) => {
  const q = req.query.q || '';
  // VULNERABLE: user input rendered without escaping
  res.send(`<h1>Search Results for: ${q}</h1><a href="/">Back</a>`);
});

// VULN 3: Insecure Direct Object Reference (IDOR) - no auth check
app.get('/notes/:id', (req, res) => {
  const id = req.params.id;
  // VULNERABLE: no ownership check, any user can read any note
  db.get("SELECT * FROM notes WHERE id = ?", [id], (err, row) => {
    if (err) return res.send(`Error: ${err.message}`);
    res.render('note', { note: row });
  });
});

// VULN 4: Command Injection via child_process with user input
app.get('/ping', (req, res) => {
  const { exec } = require('child_process');
  const host = req.query.host || 'localhost';
  // VULNERABLE: user input passed to shell
  exec(`ping -n 1 ${host}`, (err, stdout, stderr) => {
    res.send(`<pre>${stdout || stderr || err}</pre><a href="/">Back</a>`);
  });
});

// VULN 5: Insecure deserialization
app.post('/deserialize', (req, res) => {
  const nodeSerialize = require('node-serialize');
  const data = req.body.data;
  // VULNERABLE: deserializing untrusted user data
  try {
    const obj = nodeSerialize.unserialize(data);
    res.send(`Deserialized: ${JSON.stringify(obj)}`);
  } catch (e) {
    res.send(`Error: ${e.message}`);
  }
});

// VULN 6: Sensitive data exposure - hardcoded secrets
const SECRET_KEY = "hardcoded_jwt_secret_1234";
const DB_PASSWORD = "superSecretDBPass!";
const API_KEY = "sk-prod-abc123xyz789-REAL-KEY";

app.get('/config', (req, res) => {
  // VULNERABLE: exposing internal config
  res.json({ secret: SECRET_KEY, db: DB_PASSWORD, api: API_KEY });
});

// VULN 7: Path traversal
app.get('/file', (req, res) => {
  const fs = require('fs');
  const filename = req.query.name || 'readme.txt';
  // VULNERABLE: no path sanitization
  const filePath = path.join(__dirname, 'files', filename);
  try {
    const content = fs.readFileSync(filePath, 'utf8');
    res.send(`<pre>${content}</pre>`);
  } catch (e) {
    res.send(`Error reading file: ${e.message}`);
  }
});

// VULN 8: Weak session token (predictable)
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.get("SELECT * FROM users WHERE username = ? AND password = ?", [username, password], (err, row) => {
    if (row) {
      // VULNERABLE: predictable session token
      const token = Buffer.from(`${username}:${Date.now()}`).toString('base64');
      res.cookie('session', token, { httpOnly: false, secure: false });
      res.redirect('/');
    } else {
      res.send('Invalid credentials. <a href="/">Back</a>');
    }
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`DVWA Security Lab running on http://localhost:${PORT}`);
});
