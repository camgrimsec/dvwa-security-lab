/**
 * DVWA - Vulnerable GraphQL API
 * FOR EDUCATIONAL/SECURITY TESTING PURPOSES ONLY - DO NOT DEPLOY IN PRODUCTION
 *
 * Vulnerabilities demonstrated:
 *  - Introspection enabled (schema disclosure)
 *  - No query depth/complexity limits (DoS)
 *  - IDOR on queries (no ownership checks)
 *  - SQL injection via GraphQL arguments
 *  - Batching / alias-based brute force
 *  - Sensitive data exposure in schema
 *  - Unauthenticated mutations
 *  - Verbose error messages with stack traces
 *  - SSRF via fetch mutation
 *  - Mass assignment via updateUser mutation
 */

const express = require('express');
const { graphqlHTTP } = require('express-graphql');
const { buildSchema } = require('graphql');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const axios = require('axios');

const app = express();

// VULN: Weak hardcoded secret
const JWT_SECRET = 'graphql_secret_123';

// ── Database ───────────────────────────────────────────────────────────────────
const db = new sqlite3.Database(':memory:');
const dbGet  = (sql, p=[]) => new Promise((res,rej) => db.get(sql,p,(e,r)=>e?rej(e):res(r)));
const dbAll  = (sql, p=[]) => new Promise((res,rej) => db.all(sql,p,(e,r)=>e?rej(e):res(r)));
const dbRun  = (sql, p=[]) => new Promise((res,rej) => db.run(sql,p,(e)=>e?rej(e):res()));

db.serialize(() => {
  db.run(`CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT, password TEXT,
    email TEXT, role TEXT,
    credit_card TEXT, ssn TEXT, api_key TEXT
  )`);
  db.run(`INSERT INTO users VALUES (1,'admin','admin123','admin@corp.local','admin','4111-1111-1111-1111','111-22-3333','admin-gql-key-abc')`);
  db.run(`INSERT INTO users VALUES (2,'alice','pass1','alice@corp.local','user','4222-2222-2222-2222','444-55-6666','alice-gql-key-def')`);
  db.run(`INSERT INTO users VALUES (3,'bob','pass2','bob@corp.local','user','4333-3333-3333-3333','777-88-9999','bob-gql-key-ghi')`);

  db.run(`CREATE TABLE posts (
    id INTEGER PRIMARY KEY, user_id INTEGER,
    title TEXT, body TEXT, private INTEGER
  )`);
  db.run(`INSERT INTO posts VALUES (1,1,'Admin Private Note','flag{graphql_idor_found}',1)`);
  db.run(`INSERT INTO posts VALUES (2,2,'Alice Public Post','Hello world!',0)`);
  db.run(`INSERT INTO posts VALUES (3,3,'Bob Private Draft','Internal only content',1)`);

  db.run(`CREATE TABLE messages (
    id INTEGER PRIMARY KEY, from_id INTEGER,
    to_id INTEGER, body TEXT
  )`);
  db.run(`INSERT INTO messages VALUES (1,1,2,'Admin to Alice: here is your secret key')`);
  db.run(`INSERT INTO messages VALUES (2,2,3,'Alice to Bob: see you later')`);
});

// ── Schema ─────────────────────────────────────────────────────────────────────
// VULN: Schema exposes sensitive fields (credit_card, ssn, api_key, password)
// VULN: Introspection not disabled — full schema enumerable by anyone
const schema = buildSchema(`
  type User {
    id: ID
    username: String
    password: String
    email: String
    role: String
    credit_card: String
    ssn: String
    api_key: String
    posts: [Post]
    messages: [Message]
  }

  type Post {
    id: ID
    user_id: ID
    title: String
    body: String
    private: Boolean
  }

  type Message {
    id: ID
    from_id: ID
    to_id: ID
    body: String
  }

  type AuthPayload {
    token: String
    user: User
  }

  type MutationResult {
    success: Boolean
    message: String
  }

  type FetchResult {
    status: Int
    body: String
  }

  type Query {
    # VULN: IDOR - any user can query any user by id
    user(id: ID!): User

    # VULN: no auth required to list all users including sensitive fields
    users: [User]

    # VULN: SQL injection via raw string interpolation
    searchUsers(term: String!): [User]

    # VULN: IDOR on posts - private posts visible to all
    post(id: ID!): Post
    posts: [Post]

    # VULN: IDOR on messages - any user can read any message
    message(id: ID!): Message

    # VULN: exposes internal server config
    serverInfo: String

    # Deeply nestable - no complexity/depth limit (DoS vector)
    # Query: { users { posts { ... } messages { ... } } }
  }

  type Mutation {
    # VULN: no rate limiting, verbose error on wrong password
    login(username: String!, password: String!): AuthPayload

    # VULN: unauthenticated, mass assignment - caller sets any field including role
    createUser(username: String!, password: String!, email: String!, role: String): User

    # VULN: no auth check, mass assignment - can promote self to admin
    updateUser(id: ID!, username: String, email: String, role: String, password: String, credit_card: String, ssn: String): User

    # VULN: no auth, no ownership check
    deletePost(id: ID!): MutationResult

    # VULN: SSRF - fetches any URL the caller provides
    fetchUrl(url: String!): FetchResult
  }
`);

// ── Resolvers ──────────────────────────────────────────────────────────────────
const root = {
  // ── Queries ──────────────────────────────────────────────────────────────
  user: async ({ id }) => {
    // VULNERABLE: no ownership or auth check
    const u = await dbGet('SELECT * FROM users WHERE id = ?', [id]);
    if (!u) return null;
    u.posts    = () => dbAll('SELECT * FROM posts WHERE user_id = ?', [id]);
    u.messages = () => dbAll('SELECT * FROM messages WHERE from_id = ? OR to_id = ?', [id, id]);
    return u;
  },

  users: async () => {
    // VULNERABLE: no auth required, returns all sensitive data
    const rows = await dbAll('SELECT * FROM users');
    return rows.map(u => ({
      ...u,
      posts:    () => dbAll('SELECT * FROM posts WHERE user_id = ?', [u.id]),
      messages: () => dbAll('SELECT * FROM messages WHERE from_id = ? OR to_id = ?', [u.id, u.id]),
    }));
  },

  searchUsers: async ({ term }) => {
    // VULNERABLE: SQL injection via string concatenation
    const query = `SELECT * FROM users WHERE username LIKE '%${term}%' OR email LIKE '%${term}%'`;
    return dbAll(query);
  },

  post: async ({ id }) => {
    // VULNERABLE: private posts visible to anyone with the id
    return dbGet('SELECT * FROM posts WHERE id = ?', [id]);
  },

  posts: async () => {
    // VULNERABLE: returns private posts without auth
    return dbAll('SELECT * FROM posts');
  },

  message: async ({ id }) => {
    // VULNERABLE: any message readable by anyone
    return dbGet('SELECT * FROM messages WHERE id = ?', [id]);
  },

  serverInfo: () => {
    // VULNERABLE: exposes internal runtime info
    return JSON.stringify({
      nodeVersion: process.version,
      jwt_secret: JWT_SECRET,
      env: process.env.NODE_ENV || 'development',
      pid: process.pid,
    });
  },

  // ── Mutations ─────────────────────────────────────────────────────────────
  login: async ({ username, password }) => {
    // VULNERABLE: no rate limit, verbose error, plaintext compare
    const user = await dbGet(
      'SELECT * FROM users WHERE username = ? AND password = ?',
      [username, password]
    );
    if (!user) throw new Error(`Invalid credentials for user '${username}'`);
    const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET);
    user.posts    = () => dbAll('SELECT * FROM posts WHERE user_id = ?', [user.id]);
    user.messages = () => dbAll('SELECT * FROM messages WHERE from_id = ?', [user.id]);
    return { token, user };
  },

  createUser: async ({ username, password, email, role }) => {
    // VULNERABLE: unauthenticated, mass assignment (role can be set to 'admin')
    await dbRun(
      'INSERT INTO users (username, password, email, role) VALUES (?,?,?,?)',
      [username, password, email, role || 'user']
    );
    return dbGet('SELECT * FROM users WHERE username = ?', [username]);
  },

  updateUser: async ({ id, username, email, role, password, credit_card, ssn }) => {
    // VULNERABLE: no auth check, can set role='admin', update any user
    await dbRun(
      `UPDATE users SET
        username=COALESCE(?,username),
        email=COALESCE(?,email),
        role=COALESCE(?,role),
        password=COALESCE(?,password),
        credit_card=COALESCE(?,credit_card),
        ssn=COALESCE(?,ssn)
       WHERE id=?`,
      [username, email, role, password, credit_card, ssn, id]
    );
    const u = await dbGet('SELECT * FROM users WHERE id = ?', [id]);
    if (!u) return null;
    u.posts    = () => dbAll('SELECT * FROM posts WHERE user_id = ?', [id]);
    u.messages = () => dbAll('SELECT * FROM messages WHERE from_id = ?', [id]);
    return u;
  },

  deletePost: async ({ id }) => {
    // VULNERABLE: no auth, no ownership check
    await dbRun('DELETE FROM posts WHERE id = ?', [id]);
    return { success: true, message: `Post ${id} deleted` };
  },

  fetchUrl: async ({ url }) => {
    // VULNERABLE: SSRF - attacker can target internal services (169.254.x, 10.x, etc.)
    try {
      const r = await axios.get(url, { timeout: 5000 });
      return { status: r.status, body: JSON.stringify(r.data).substring(0, 2000) };
    } catch (e) {
      return { status: 0, body: e.message };
    }
  },
};

// ── Middleware ─────────────────────────────────────────────────────────────────
app.use('/graphql', graphqlHTTP({
  schema,
  rootValue: root,
  // VULN: GraphiQL enabled (interactive UI exposed in "production")
  graphiql: true,
  // VULN: Full error details including stack traces returned to client
  customFormatErrorFn: (err) => ({
    message: err.message,
    locations: err.locations,
    stack: err.originalError ? err.originalError.stack : null,
    path: err.path,
  }),
}));

// VULN: Batch query endpoint - enables alias-based brute force and DoS
// POST /graphql-batch with array of query objects, no limit on array size
app.use('/graphql-batch', require('body-parser').json(), async (req, res) => {
  const { graphql } = require('graphql');
  const queries = req.body; // expects an array
  if (!Array.isArray(queries)) return res.status(400).json({ error: 'Expected array' });
  // VULNERABLE: no limit on batch size - 1000+ queries in one request
  const results = await Promise.all(
    queries.map(({ query, variables }) => graphql({ schema, source: query, rootValue: root, variableValues: variables }))
  );
  res.json(results);
});

const PORT = process.env.PORT || 3002;
app.listen(PORT, () => {
  console.log(`Vulnerable GraphQL API running on http://localhost:${PORT}/graphql`);
  console.log('GraphiQL available at http://localhost:' + PORT + '/graphql');
  console.log('FOR SECURITY TESTING ONLY');
});
