# ShieldAuth — Secure Login and Authentication System

A complete, production-grade, responsive authentication website built with **Python (Flask)**, **Argon2id**, **SQLite**, and modern **vanilla HTML5/CSS3/JavaScript**.

ShieldAuth enforces modern cybersecurity defenses according to OWASP guidelines, including memory-hard password hashing, Synchronizer Token Pattern CSRF protection, brute-force rate limiting, automatic account lockouts, timing-attack mitigation, secure session regeneration, single-use hashed password reset tokens, and comprehensive HTTP security headers.

---

## 1. Project Architecture & Folder Structure

```
secure-login-system/
├── app.py                     # Main Flask application & routes with defensive middleware
├── config.py                  # Environment-aware configuration & security defaults
├── requirements.txt           # Python dependencies (Flask, argon2-cffi, python-dotenv, pytest)
├── .env.example               # Template documenting all environment variables
├── .env                       # Pre-configured local development settings
├── .gitignore                 # Excludes bytecode, secrets, and database files
├── README.md                  # Comprehensive setup, architecture, and security manual
├── database/
│   ├── __init__.py            # Database module exports
│   ├── db.py                  # Safe SQLite connection manager & parameterized queries
│   └── schema.sql             # SQL schema (users, password_resets, audit_logs, rate_limits)
├── instance/
│   └── secure_auth.sqlite3    # Local SQLite database (auto-created)
├── security/
│   ├── __init__.py            # Security module exports
│   ├── hasher.py              # Argon2id password hashing and timing-safe dummy verification
│   ├── csrf.py                # Synchronizer Token Pattern CSRF protection
│   ├── rate_limiter.py        # Sliding-window IP rate limiter and account lockout logic
│   ├── tokens.py              # Cryptographically secure SHA-256 hashed single-use reset tokens
│   └── validators.py          # Strict server-side regex & policy validation rules
├── static/
│   ├── css/
│   │   └── style.css          # Glassmorphic, modern CSS with Dark/Light mode & responsive grid
│   └── js/
│       └── script.js          # Password toggle, live strength meter, match validator & spinner
├── templates/
│   ├── base.html              # Responsive base layout with theme toggle & alerts
│   ├── login.html             # Login form with CSRF, password toggle & security highlights
│   ├── register.html          # Registration form with real-time strength meter & checklist
│   ├── forgot_password.html   # Password reset request with Dev Mailbox Simulator
│   ├── reset_password.html    # Single-use token password reset form
│   ├── dashboard.html         # Protected user dashboard with security audit log & password change
│   └── errors/
│       ├── 400.html           # Bad Request / CSRF failure handler
│       ├── 404.html           # Not Found error page
│       ├── 429.html           # Rate limit & lockout warning page
│       └── 500.html           # Internal Server Error page (no stack trace leakage)
└── tests/
    ├── __init__.py
    ├── conftest.py            # Pytest fixtures and temporary database setup
    ├── test_auth.py           # Registration, login, logout, validation, and dashboard tests
    ├── test_security.py       # Argon2id, CSRF, lockout, SQLi, XSS, headers, session fixation tests
    └── test_password_reset.py # Token expiration, single-use enforcement, and non-enumeration tests
```

---

## 2. Installation and Quickstart (Windows)

### Prerequisites
- Python 3.10+ installed (`python --version`)
- Windows PowerShell or Command Prompt

### Step 1: Open PowerShell and Navigate to the Directory
```powershell
cd "c:\Users\CFS\Downloads\secure login system"
```

### Step 2: (Optional but Recommended) Create and Activate a Virtual Environment
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```
*(If PowerShell restricts script execution, run: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned`)*

### Step 3: Install Required Dependencies
```powershell
pip install -r requirements.txt
```

### Step 4: Initialize the SQLite Database
```powershell
flask init-db
```
*(Alternatively, simply running `python app.py` will automatically initialize the database schema if not present.)*

### Step 5: Start the Flask Development Server
```powershell
python app.py
```

### Step 6: Access the Application
Open your web browser and navigate to:
```
http://127.0.0.1:5000
```

---

## 3. Automated Testing Suite

The project includes an automated test suite verifying both functional and cybersecurity behaviors using `pytest`.

To execute all tests:
```powershell
python -m pytest tests/ -v
```

### Test Coverage Highlights:
- **Registration**: Correct account creation, case-insensitive duplicate username/email rejection, validation rules.
- **Authentication**: Valid login, incorrect password handling, unknown account handling, generic error messages.
- **Session Management**: Session fixation prevention (session ID regeneration upon login), logout invalidation, unauthorized dashboard redirect.
- **Password Hashing**: Verification that stored hashes use the `$argon2id$` format, random salts per hash, and proper verification.
- **CSRF Defense**: Automatic rejection of state-changing POST requests when tokens are missing or forged.
- **Brute Force & Lockouts**: Account lockout after consecutive failed attempts, refusal of valid passwords during lockout duration.
- **Password Resets**: Timing-safe requests (non-enumeration), single-use token invalidation, expired token rejection.
- **Injection & XSS**: SQL injection payload resilience, XSS input rejection and autoescaping in templates.
- **Defensive Headers**: Enforcement of `Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`.

---

## 4. Cybersecurity Controls Implemented

| Security Threat | Implemented Countermeasure | Location in Code |
| :--- | :--- | :--- |
| **Password Cracking (GPU / ASIC)** | **Argon2id** memory-hard password hashing with per-user salt (time cost: 3, memory cost: 64 MiB, parallelism: 2). | [`security/hasher.py`](file:///c:/Users/CFS/Downloads/secure%20login%20system/security/hasher.py) |
| **User Enumeration / Timing Attacks** | Generic error messages for failed logins & password resets. Pre-computed dummy Argon2id hash verification balances response time for non-existent users. | [`security/hasher.py`](file:///c:/Users/CFS/Downloads/secure%20login%20system/security/hasher.py), [`app.py`](file:///c:/Users/CFS/Downloads/secure%20login%20system/app.py) |
| **Cross-Site Request Forgery (CSRF)** | Synchronizer Token Pattern with cryptographically secure per-session tokens (`secrets.token_hex(32)`) validated using timing-safe `hmac.compare_digest`. | [`security/csrf.py`](file:///c:/Users/CFS/Downloads/secure%20login%20system/security/csrf.py) |
| **Brute-Force & Credential Stuffing** | Automatic account lockout after 5 consecutive failures for 15 minutes. Sliding-window IP rate limiting on `/login`, `/register`, and `/forgot-password`. | [`security/rate_limiter.py`](file:///c:/Users/CFS/Downloads/secure%20login%20system/security/rate_limiter.py) |
| **Session Fixation & Hijacking** | Complete session regeneration (`session.clear()`) on authentication. `HttpOnly=True` and `SameSite='Lax'` cookie flags prevent JavaScript exfiltration. | [`app.py`](file:///c:/Users/CFS/Downloads/secure%20login%20system/app.py), [`config.py`](file:///c:/Users/CFS/Downloads/secure%20login%20system/config.py) |
| **SQL Injection (SQLi)** | 100% Parameterized queries with SQLite DB driver (`?` bind parameters). Zero dynamic SQL concatenation. | [`database/db.py`](file:///c:/Users/CFS/Downloads/secure%20login%20system/database/db.py), [`app.py`](file:///c:/Users/CFS/Downloads/secure%20login%20system/app.py) |
| **Cross-Site Scripting (XSS)** | Jinja2 autoescaping, strict input regex validation, and strict `Content-Security-Policy` header forbidding unauthorized inline scripts. | [`app.py`](file:///c:/Users/CFS/Downloads/secure%20login%20system/app.py), [`security/validators.py`](file:///c:/Users/CFS/Downloads/secure%20login%20system/security/validators.py) |
| **Token Compromise in DB Leaks** | Password reset tokens are hashed with SHA-256 before storage in SQLite. If the database is compromised, reset links cannot be redeemed. | [`security/tokens.py`](file:///c:/Users/CFS/Downloads/secure%20login%20system/security/tokens.py) |
| **Clickjacking & MIME-Sniffing** | `X-Frame-Options: DENY` and `X-Content-Type-Options: nosniff` headers applied to all responses. | [`app.py`](file:///c:/Users/CFS/Downloads/secure%20login%20system/app.py) |
| **Information Leakage** | Production-ready custom error pages (400, 404, 429, 500) that suppress stack traces, database schema details, and server versions. | [`templates/errors/`](file:///c:/Users/CFS/Downloads/secure%20login%20system/templates/errors) |
| **Security Audit Trail** | Dedicated `audit_logs` table tracking registrations, logins, lockouts, password resets, and changes without storing passwords. | [`database/schema.sql`](file:///c:/Users/CFS/Downloads/secure%20login%20system/database/schema.sql) |

---

## 5. User Interface Features

- **Responsive Design**: Adapts smoothly to mobile, tablet, and desktop viewports.
- **Dark & Light Mode**: Accessible toggle with local storage persistence and system preference detection.
- **Interactive Password Visibility**: Accessible eye/eye-off SVG buttons on password inputs.
- **Dynamic Password Strength Meter**: Real-time 4-tier visual progress bar with an interactive checklist checking minimum length (10+), uppercase, lowercase, numbers, and special symbols.
- **Live Password Confirmation**: Instant visual matching feedback.
- **Development Mailbox Simulator**: When `DEV_EMAIL_SIMULATOR=true`, password reset requests generate a 1-click test link on screen and in server terminal output for effortless zero-config local testing.
- **Security Activity Dashboard**: Displays recent security events for the logged-in user in a formatted audit table.

---

## 6. Production Deployment Checklist & Limitations

Before deploying this application to a public production environment:

1. **Enable HTTPS / SSL/TLS**:
   - Set `SESSION_COOKIE_SECURE=true` in `.env`.
   - Configure a reverse proxy (Nginx, Cloudflare, or AWS ALB) terminating SSL/TLS with modern cipher suites.
2. **Production WSGI Server**:
   - Replace Flask's development server with a production WSGI server such as `Gunicorn` (Linux) or `Waitress` (Windows):
     ```bash
     pip install gunicorn
     gunicorn -w 4 -b 0.0.0.0:5000 app:app
     ```
3. **Database Migration to PostgreSQL or MySQL**:
   - SQLite is ideal for development and single-instance deployments. For high-concurrency or multi-server deployments, configure a dedicated database with connection pooling.
4. **Distributed Rate Limiting (Redis)**:
   - For multi-instance load-balanced web servers, move the rate-limiting tracking from local SQLite to Redis with `Flask-Limiter`.
5. **Real Email Service Integration**:
   - Replace the Dev Mailbox Simulator (`DEV_EMAIL_SIMULATOR=false`) with an SMTP server or transactional email provider (SendGrid, AWS SES, Resend) using encrypted credentials.
6. **Multi-Factor Authentication (MFA / 2FA)**:
   - Implement TOTP (Time-Based One-Time Passwords via authenticator apps) or WebAuthn / FIDO2 security keys for additional login defense.

---

## 7. Troubleshooting Common Issues

- **Port 5000 Already in Use**:
  Set another port in `.env` or run:
  ```powershell
  $env:PORT=5001; python app.py
  ```
- **CSRF Token Mismatch Error (400)**:
  Ensure your browser accepts session cookies and is not blocking cookies in Private/Incognito mode.
- **Locked Out During Testing**:
  Wait for the lockout duration (configured as 15 minutes by default) or reset failed attempts in the database:
  ```powershell
  python -c "from app import app; from database.db import execute_db; execute_db('UPDATE users SET failed_login_attempts=0, lockout_until=NULL')"
  ```
