# Qode Auth Services — Documentation

## Table of Contents

1. [Overview](#overview)
2. [Tech Stack](#tech-stack)
3. [Project Structure](#project-structure)
4. [Architecture](#architecture)
5. [Database Models](#database-models)
6. [Configuration & Environment](#configuration--environment)
7. [API Endpoints](#api-endpoints)
8. [Authentication Flows](#authentication-flows)
9. [Services](#services)
10. [Utilities](#utilities)
11. [Middleware](#middleware)
12. [Database Migrations](#database-migrations)
13. [Running the Server](#running-the-server)

---

## Overview

**Qode Auth Services** is a FastAPI-based authentication backend that supports multi-application user management. It provides:

- Email/password authentication
- OAuth login (Google, GitHub, Facebook, Microsoft)
- OTP-based login via 2factor.in
- JWT-based session management (RS256)
- Admin bypass login
- Multi-application user scoping
- Service-to-service authentication

The service runs on port `8080` and connects to three separate PostgreSQL databases.

---

## Tech Stack

| Category | Technology |
|----------|-----------|
| Framework | FastAPI 0.128.0 |
| Server | Uvicorn 0.40.0 (ASGI) |
| ORM | SQLAlchemy 2.0.45 |
| Database | PostgreSQL (psycopg2) |
| Cache | Redis 7.1.0 |
| JWT | PyJWT 2.10.1 (RS256) |
| Password Hashing | bcrypt 5.0.0 (12 rounds) |
| Validation | Pydantic 2.12.5 |
| OTP Provider | 2factor.in API |
| CSV Ingestion | Pandas 2.3.3 |

---

## Project Structure

```
authServices/
├── main.py                        # App entry point, middleware, lifespan
├── requirements.txt               # Python dependencies
├── alembic.ini                    # Alembic migration config
├── pms_clients_master.csv         # Bulk user import source
│
├── api/v1/
│   ├── auth_router.py             # Auth endpoints (/auth/*)
│   ├── profile_router.py          # Profile endpoints (/profile/*)
│   └── admin_router.py            # Admin endpoints (/admin/*)
│
├── config/
│   ├── settings.py                # All settings via pydantic-settings
│   └── database.py                # SQLAlchemy engine + Base
│
├── db/
│   ├── session.py                 # 3 DB session factories
│   ├── redis.py                   # Redis singleton connection
│   └── migrations/versions/       # Alembic migration files
│
├── models/
│   ├── models.py                  # SQLAlchemy ORM models (12 tables)
│   └── schemas.py                 # Pydantic request/response schemas
│
├── services/
│   ├── auth_service.py            # Core auth business logic
│   ├── jwt_service.py             # Token creation, verification, revocation
│   ├── password_service.py        # Hashing, verification, strength check
│   ├── otp_service.py             # OTP send/verify via 2factor.in
│   └── user_service.py            # User profile updates
│
└── utils/
    ├── dependencies.py            # FastAPI dependency injectors
    ├── client_utils.py            # App/service seeding utilities
    └── ingest_pms_clients.py      # Bulk CSV user import
```

---

## Architecture

### Multi-Database Setup

The service connects to **three PostgreSQL databases**:

| Name | Env Variable | Purpose |
|------|-------------|---------|
| Auth DB | `DATABASE_URL` | All auth data (users, sessions, tokens) |
| QodeInvest DB | `DB_URL_QODEINVEST` | Investment portfolio service |
| QodePortfolio DB | `DB_URL_QODEPORTFOLIO` | Portfolio service |

Each has its own SQLAlchemy engine and session factory in `db/session.py`. Connection pool settings: `pool_size=10`, `max_overflow=20`, `timeout=30s`.

### Redis

Redis is used for:
- OTP session tracking (`otp:session:{phone}`, 5-min TTL)
- Phone verification state (`phone:verified:{phone}`, 10-min TTL)

### Multi-Application User Scoping

A single `User` row can be linked to multiple applications via `UserApplication`. This means:
- One email can have separate accounts in QodePulseApp, MyQodeApp, etc.
- Each application link has its own auth methods and credentials

### Request Headers

| Header | Required For | Purpose |
|--------|-------------|---------|
| `X-Client-Id` | Most endpoints | Identifies which application is making the request |
| `Authorization: Bearer {token}` | Authenticated endpoints | JWT access token |
| `X-Admin-Auth-Id` | Admin endpoints | Admin secret key |

---

## Database Models

### Entity Relationships

```
Application ──< UserApplication >── User
                      │
                  AuthMethod
                 /          \
        UserCredential    OAuthAccount
                              │
                         (OAuth tokens)

User ──< UserSession          (refresh token sessions)
User ──< JWTBlacklist         (revoked access tokens)

Application ──< ApplicationService >── Service
ServiceAccount ──< ServiceAccountPermission >── Service
```

### Tables

#### `users`
Master user record shared across applications.

| Column | Type | Notes |
|--------|------|-------|
| id | Integer PK | |
| uuid | UUID | Unique identifier |
| email | String | Unique |
| username | String | Unique |
| full_name | String | |
| phone_code | String | Country code |
| phonenumber | String | |
| pancard | String | |
| is_active | Boolean | Default: true |
| is_verified | Boolean | Default: false |
| created_at / updated_at | DateTime | |

#### `applications`
Registered frontend apps that consume the auth service.

| Column | Type | Notes |
|--------|------|-------|
| id | Integer PK | |
| name | String | Unique |
| client_id | String | Unique, used in X-Client-Id header |
| client_secret | String | |
| is_active | Boolean | |

#### `user_applications`
Scopes a user to a specific application.

| Column | Type | Notes |
|--------|------|-------|
| id | Integer PK | |
| user_id | FK → users | |
| application_id | FK → applications | |
| (user_id, application_id) | Unique | |

#### `auth_methods`
One per authentication provider per user-application link.

| Column | Type | Notes |
|--------|------|-------|
| id | Integer PK | |
| user_application_id | FK → user_applications | |
| provider | Enum | LOCAL, GOOGLE, GITHUB, FACEBOOK |
| provider_user_id | String | Provider's user ID |
| is_primary | Boolean | |

#### `user_credentials`
Stores the bcrypt password hash for LOCAL auth.

| Column | Type | Notes |
|--------|------|-------|
| auth_method_id | FK (unique) | One-to-one with auth_method |
| password_hash | String | bcrypt hash |
| password_algo | String | Default: "bcrypt" |
| failed_attempts | Integer | Lock after 5 |
| is_locked | Boolean | |

#### `oauth_accounts`
Stores OAuth provider tokens and payload.

| Column | Type | Notes |
|--------|------|-------|
| auth_method_id | FK (unique) | |
| access_token | String | |
| refresh_token | String | |
| expires_at | DateTime | |
| provider_payload | JSONB | Full provider response |

#### `user_sessions`
Tracks active refresh token sessions.

| Column | Type | Notes |
|--------|------|-------|
| id | Integer PK | |
| user_id | FK → users | |
| refresh_token_hash | String | Unique, SHA256 of token |
| expires_at | DateTime | 7 days |
| ip_address | String | |
| user_agent | String | |
| is_revoked | Boolean | |
| revoked_at | DateTime | |

#### `jwt_blacklist`
Tracks revoked access tokens until they expire.

| Column | Type | Notes |
|--------|------|-------|
| jti | UUID PK | Token's JTI claim |
| user_id | FK → users | |
| expires_at | DateTime | Access token expiry |
| revoked_at | DateTime | |

#### `services`
Backend services that applications can access.

| Column | Type | Notes |
|--------|------|-------|
| id | Integer PK | |
| name | String | Unique |
| service_key | String | Unique |
| is_active | Boolean | |

#### `application_services`
Many-to-many: links applications to allowed services.

#### `service_accounts`
Machine-to-machine auth credentials for backend services.

#### `service_account_permissions`
Many-to-many: links service accounts to their permitted services.

---

## Configuration & Environment

All config lives in `config/settings.py` using pydantic-settings. Create a `.env` file:

```env
# --- Databases ---
DATABASE_URL=postgresql://user:pass@host:5432/auth_db
DB_URL_QODEINVEST=postgresql://user:pass@host:5432/qodeinvest_db
DB_URL_QODEPORTFOLIO=postgresql://user:pass@host:5432/qodeportfolio_db

# --- JWT (RS256 keys) ---
JWT_PRIVATE_KEY=<RSA_PRIVATE_KEY_PEM>
JWT_PUBLIC_KEY=<RSA_PUBLIC_KEY_PEM>

# --- Redis ---
REDIS_URL=redis://localhost:6379

# --- Admin ---
ADMIN_AUTH_ID=<random_secret_string>

# --- OTP ---
TWO_FACTOR_API_KEY=<2factor.in_api_key>

# --- OAuth (optional) ---
MICROSOFT_CLIENT_ID=
MICROSOFT_CLIENT_SECRET=
MICROSOFT_TENANT_ID=

# --- Email (optional) ---
RESEND_API_KEY=
```

### Token Expiry

| Token | Expiry |
|-------|--------|
| Access Token | 1 minute |
| Refresh Token | 7 days |

---

## API Endpoints

Base path: `/api/v1`

### Authentication — `/auth`

| Method | Path | Auth Required | Description |
|--------|------|--------------|-------------|
| POST | `/auth/register/` | `X-Client-Id` | Register a new user |
| POST | `/auth/login/` | `X-Client-Id` | Email/password login |
| POST | `/auth/oauth-login/` | `X-Client-Id` | OAuth provider login/signup |
| POST | `/auth/otp/send/` | `X-Client-Id` | Send OTP to phone number |
| POST | `/auth/otp/verify/` | `X-Client-Id` | Verify OTP and get tokens |
| POST | `/auth/change-password/` | JWT | Change logged-in user's password |
| POST | `/auth/set-password/` | `X-Client-Id` | Set/reset password by email |
| POST | `/auth/unlock-account/` | `X-Client-Id` | Unlock a locked account |
| POST | `/auth/refresh-token/` | None | Get new access token from refresh token |
| POST | `/auth/logout/` | JWT | Revoke a specific session |
| POST | `/auth/logout-all/` | JWT | Revoke all sessions for current user |
| GET | `/auth/me/` | JWT | Get current authenticated user's info |
| GET | `/auth/sessions` | JWT | List all active sessions |

### Profile — `/profile`

| Method | Path | Auth Required | Description |
|--------|------|--------------|-------------|
| POST | `/profile/update/` | `X-Client-Id` | Update user profile fields |

### Admin — `/admin`

| Method | Path | Auth Required | Description |
|--------|------|--------------|-------------|
| POST | `/admin/admin-login/` | `X-Client-Id` + `X-Admin-Auth-Id` | Login as any user without password |

### Health

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check |
| GET | `/` | Root |

### Request/Response Examples

**Register:**
```json
POST /api/v1/auth/register/
Headers: X-Client-Id: <client_id>

Body:
{
  "email": "user@example.com",
  "username": "johndoe",
  "password": "Password123",
  "full_name": "John Doe"
}

Response:
{
  "message": "User registered successfully",
  "data": { "user_id": 1, "user_application_id": 1 }
}
```

**Login:**
```json
POST /api/v1/auth/login/
Headers: X-Client-Id: <client_id>

Body:
{
  "email": "user@example.com",
  "password": "Password123"
}

Response:
{
  "access_token": "<jwt>",
  "refresh_token": "<jwt>",
  "token_type": "bearer",
  "expires_in": 60,
  "user": { "id": 1, "email": "...", ... }
}
```

---

## Authentication Flows

### 1. Email/Password Login

```
Client → POST /auth/login/ (X-Client-Id, email, password)
  │
  ├─ Verify application via X-Client-Id
  ├─ Find User by email
  ├─ Find UserApplication (user_id + application_id)
  ├─ Find AuthMethod (provider=LOCAL)
  ├─ Find UserCredential → verify bcrypt hash
  ├─ Check: account locked? (is_locked = true) → 400 error
  ├─ Failed? increment failed_attempts → lock after 5
  │
  └─ Success:
       ├─ create_access_token (expires 1 min, RS256)
       ├─ create_refresh_token (expires 7 days, RS256)
       └─ store refresh_token hash in UserSession
```

### 2. OAuth Login

```
Client → POST /auth/oauth-login/ (provider, provider_user_id, email, ...)
  │
  ├─ Verify application
  ├─ Find or create User by email/username
  ├─ Find or create UserApplication
  ├─ Find or create AuthMethod (provider=GOOGLE/GITHUB/etc)
  ├─ Upsert OAuthAccount (tokens, provider_payload)
  │
  └─ Issue access + refresh tokens
```

### 3. OTP Login

```
Step 1: POST /auth/otp/send/ (phone_code, phone_number)
  ├─ Find or create User by phone number
  ├─ Call 2factor.in API → generate OTP
  └─ Store session_id in Redis: otp:session:{phone} (5 min TTL)

Step 2: POST /auth/otp/verify/ (phone_code, phone_number, otp)
  ├─ Call 2factor.in API to verify OTP
  ├─ Mark phone verified in Redis: phone:verified:{phone} (10 min TTL)
  └─ Issue access + refresh tokens
```

### 4. Token Refresh

```
Client → POST /auth/refresh-token/ (refresh_token)
  │
  ├─ Verify token signature (RS256) and type = "refresh"
  ├─ Hash token → look up UserSession
  ├─ Check: not revoked, not expired
  │
  └─ Issue new access_token (same refresh_token returned)
```

### 5. Logout

```
Single session:
  POST /auth/logout/ (refresh_token)
  → Hash refresh_token → mark UserSession.is_revoked = true

All sessions:
  POST /auth/logout-all/
  → Revoke all UserSession rows for current user
```

### 6. Admin Bypass Login

```
POST /admin/admin-login/ (email)
Headers: X-Client-Id + X-Admin-Auth-Id

  ├─ Verify X-Admin-Auth-Id matches ADMIN_AUTH_ID setting
  ├─ Find User by email
  └─ Issue tokens without password check
```

---

## Services

### AuthService (`services/auth_service.py`)

Core orchestration layer. Key methods:

| Method | Description |
|--------|-------------|
| `register_user(email, username, password, full_name, application_id)` | Create user, UserApplication, AuthMethod, UserCredential |
| `authenticate_user(email, password, application_id)` | Verify credentials, handle lockout |
| `auth_login(provider, provider_user_id, ...)` | OAuth user creation/lookup |
| `otp_auth_send(phone_code, phonenumber, application_id)` | Trigger OTP send |
| `otp_auth_verify(phone_code, phonenumber, application_id, otp)` | Verify OTP |
| `change_password(user_id, application_id, old, new)` | Change with old password verification |
| `set_password(email, new_password, application_id)` | Reset password directly |
| `unlock_user_account(user_id, application_id)` | Reset is_locked and failed_attempts |
| `admin_by_pass_login(email, application_id)` | Admin login without password |

### JWTService (`services/jwt_service.py`)

Handles all token lifecycle. Key methods:

| Method | Description |
|--------|-------------|
| `create_access_token(user_id, application_id, ...)` | RS256 JWT, 1-min expiry |
| `create_refresh_token(user_id, ip_address, user_agent)` | RS256 JWT + store session hash |
| `verify_token(token, token_type)` | Verify signature, check blacklist/session |
| `revoke_access_token(token, user_id)` | Add JTI to jwt_blacklist |
| `revoke_refresh_token(token)` | Mark UserSession revoked |
| `revoke_all_user_sessions(user_id)` | Bulk revoke all sessions |
| `cleanup_expired_tokens()` | Delete expired blacklist rows and sessions |

**Access token claims:**
```json
{
  "sub": "<user_id>",
  "application_id": "<id>",
  "user_application_id": "<id>",
  "type": "access",
  "jti": "<uuid>",
  "iat": ...,
  "exp": ...
}
```

### PasswordService (`services/password_service.py`)

| Method | Description |
|--------|-------------|
| `hash_password(password)` | bcrypt with 12 rounds |
| `verify_password(plain, hashed)` | bcrypt comparison |
| `validate_password_strength(password)` | Min 8 chars, 1 upper, 1 lower, 1 digit |

### OTPService (`services/otp_service.py`)

Wraps the 2factor.in API:

| Method | Description |
|--------|-------------|
| `send_otp()` | `GET https://2factor.in/API/V1/{key}/SMS/{phone}/AUTOGEN` |
| `verify_otp(otp)` | Verify via 2factor.in |
| `is_phone_verified()` | Check `phone:verified:{phone}` in Redis |
| `clear_phone_verification()` | Delete Redis verification key |

### UserService (`services/user_service.py`)

| Method | Description |
|--------|-------------|
| `update_profile(data, application_id)` | Update user fields (full_name, username, etc.) |

---

## Utilities

### `utils/dependencies.py` — FastAPI Dependency Injectors

| Dependency | Resolves |
|-----------|---------|
| `get_auth_service(db)` | `AuthService` instance |
| `get_jwt_service(db)` | `JWTService` instance |
| `get_current_user(credentials, db)` | `User` from Bearer token |
| `get_current_user_optional(...)` | `User` or `None` |
| `verify_application(x_client_id, db)` | `Application` from header |
| `verify_admin(x_admin_auth_id)` | Validates admin secret |
| `verify_service_token(credentials, db)` | Service-to-service auth |

### `utils/client_utils.py` — Seed Data

Populates the database with default applications and services on first run:

**Applications seeded:** QodePulseApp, MyQodeApp, MyQode, Qode360
**Services seeded:** QodePulseService, MyQodeService, Qode360Service
**All applications are linked to all services** (full mesh).

Generates:
- `client_id` — SHA256(name + timestamp)
- `client_secret` — 64-byte URL-safe random token
- `service_key` — SHA256(name)

### `utils/ingest_pms_clients.py` — Bulk CSV Import

Imports users from `pms_clients_master.csv`:

| CSV Column | Maps To |
|------------|--------|
| email | User.email |
| clientname | User.username |
| firstname + lastname | User.full_name |
| password | UserCredential.password_hash (pre-hashed bcrypt) |

Each user is linked to application IDs `2` and `3`. Rows with missing or default passwords are skipped.

---

## Middleware

Defined in `main.py`:

1. **CORSMiddleware** — Allows all origins, credentials, methods, and headers.
   > In production, restrict `allow_origins` to your domains.

2. **TrustedHostMiddleware** — Enabled only in production mode.

3. **Custom Timing Middleware** — Adds `X-Process-Time` header to every response.

**Lifespan events:**
- **Startup**: Initializes Redis connection, logs startup message.
- **Shutdown**: Closes Redis connection.

---

## Database Migrations

Managed via **Alembic** (`alembic.ini`). Migration files are in `db/migrations/versions/`.

| Migration ID | Change |
|-------------|--------|
| `a5595839b186` | Initial schema — all tables |
| `c8cef5241d72` | Add `phone_code`, `phone_number` to users |
| `59c7e6305636` | Add `pancard` column |
| `909bc30a6a94` | Alter nullable constraints on user table |
| `1d56edc9b2ae` | Phone code/number column alterations |
| `d1a8e23a3a7a` | Alter unique constraints |

**Common commands:**
```bash
# Apply all pending migrations
alembic upgrade head

# Create a new migration
alembic revision --autogenerate -m "description"

# Rollback one step
alembic downgrade -1
```

---

## Running the Server

**Install dependencies:**
```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

**Set up environment:**
```bash
cp .env.example .env
# Fill in all required values
```

**Apply migrations:**
```bash
alembic upgrade head
```

**Start the server:**
```bash
# Direct
python main.py

# Or with uvicorn
uvicorn main:app --host 0.0.0.0 --port 8080 --reload
```

**Seed default apps/services** (run once):
```python
# In a Python shell or startup script
from utils.client_utils import populate_applications_and_services
populate_applications_and_services(db)
```

The API will be available at `http://localhost:8080`
Interactive docs: `http://localhost:8080/docs`
