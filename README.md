# DVWA Security Lab

> **FOR EDUCATIONAL AND SECURITY TESTING PURPOSES ONLY. DO NOT DEPLOY IN PRODUCTION.**

An intentionally vulnerable Node.js/Express web application for practicing security scanning and vulnerability research.

## Vulnerabilities Included

| # | Vulnerability | Endpoint |
|---|---------------|----------|
| 1 | SQL Injection | `GET /user?id=` |
| 2 | Reflected XSS | `GET /search?q=` |
| 3 | IDOR | `GET /notes/:id` |
| 4 | Command Injection | `GET /ping?host=` |
| 5 | Insecure Deserialization | `POST /deserialize` |
| 6 | Sensitive Data Exposure | `GET /config` |
| 7 | Path Traversal | `GET /file?name=` |
| 8 | Weak Session Token | `POST /login` |

## Setup

```bash
npm install
npm start
```

App runs at `http://localhost:3000`

## Security Scanning

This repo uses [Snyk](https://snyk.io) for dependency and code vulnerability scanning.
