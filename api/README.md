# Vulnerable REST API

> **FOR EDUCATIONAL/SECURITY TESTING PURPOSES ONLY**

OWASP API Security Top 10 (2023) — all 10 categories deliberately implemented.

Runs on port **3001** (`npm start`)

## Vulnerabilities

| OWASP | Category | Endpoint |
|-------|----------|----------|
| API1 | Broken Object Level Authorization (BOLA) | `GET /api/v1/users/:id`, `GET /api/v1/orders/:id` |
| API2 | Broken Authentication | `POST /api/v1/auth/login`, `POST /api/v1/auth/reset-password` |
| API3 | Broken Object Property Level Authorization | `PUT /api/v1/users/:id` (mass assignment) |
| API4 | Unrestricted Resource Consumption | `GET /api/v1/users?limit=999999`, `GET /api/v1/search` |
| API5 | Broken Function Level Authorization | `GET /api/v1/admin/*` (no role check) |
| API6 | Unrestricted Access to Sensitive Flows | `POST /api/v1/transfer` (no velocity limit) |
| API7 | Server-Side Request Forgery (SSRF) | `POST /api/v1/webhook/test` |
| API8 | Security Misconfiguration | `GET /api/v1/debug`, CORS wildcard, verbose errors |
| API9 | Improper Inventory Management | `GET /api/v0/users/:id`, `GET /internal/config` |
| API10 | Unsafe Consumption of APIs | `POST /api/v1/calculate` (eval injection) |

## Quick Test

```bash
# Login
curl -X POST http://localhost:3001/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password1"}'

# BOLA - access admin's data as alice
TOKEN=<token_from_above>
curl http://localhost:3001/api/v1/users/1 -H "Authorization: Bearer $TOKEN"

# SSRF
curl -X POST http://localhost:3001/api/v1/webhook/test \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"url":"http://169.254.169.254/latest/meta-data/"}'
```
