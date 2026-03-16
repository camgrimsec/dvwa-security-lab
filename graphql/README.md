# Vulnerable GraphQL API

> **FOR EDUCATIONAL/SECURITY TESTING PURPOSES ONLY**

Runs on port **3002** (`npm start`) — GraphiQL UI available at `http://localhost:3002/graphql`

## Vulnerabilities

| Category | Description |
|----------|-------------|
| Introspection Enabled | Full schema enumerable by anyone — reveals sensitive field names |
| No Query Depth Limit | Deeply nested queries cause DoS: `{users{posts{...}messages{...}}}` |
| IDOR on Queries | `user(id:1)` readable by any user, including `credit_card`, `ssn`, `password` |
| SQL Injection | `searchUsers(term: "' OR '1'='1")` |
| Batching / Alias Brute Force | `/graphql-batch` accepts unlimited array; alias trick bypasses rate limits |
| Unauthenticated Mutations | `createUser(role:"admin")`, `updateUser(id:2,role:"admin")` require no auth |
| Mass Assignment | `updateUser` accepts `role`, `credit_card`, `ssn` with no restriction |
| SSRF | `fetchUrl(url:"http://169.254.169.254/...")` mutation |
| Sensitive Data in Schema | `password`, `ssn`, `credit_card`, `api_key` exposed in User type |
| Verbose Errors | Stack traces returned to client in error responses |

## Quick Test

```graphql
# Introspect the schema
{ __schema { types { name fields { name } } } }

# IDOR - read admin's credit card and SSN as unauthenticated user
{ user(id: 1) { username credit_card ssn api_key password } }

# SQL injection
{ searchUsers(term: "' OR '1'='1' --") { id username email } }

# Privilege escalation via mass assignment
mutation { updateUser(id: 2, role: "admin") { id username role } }

# SSRF
mutation { fetchUrl(url: "http://169.254.169.254/latest/meta-data/") { status body } }
```

### Alias-based brute force (batching)
```bash
curl -X POST http://localhost:3002/graphql-batch \
  -H "Content-Type: application/json" \
  -d '[
    {"query":"mutation{login(username:\"admin\",password:\"pass1\"){token}}"},
    {"query":"mutation{login(username:\"admin\",password:\"pass2\"){token}}"},
    {"query":"mutation{login(username:\"admin\",password:\"admin123\"){token}}"}
  ]'
```
