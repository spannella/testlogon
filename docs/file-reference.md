# File Reference

This document lists each file in the repository with a short description of its purpose. Use it as a map when you need to locate a specific feature or component.

## Root

| Path | Purpose |
| --- | --- |
| `README.md` | Quick start instructions, required environment variables, and optional configuration notes. |
| `requirements.txt` | Python dependencies for the FastAPI service and related tooling. |
| `ref/index.full.v11.html` | Legacy full HTML reference from the original single-file version. |
| `ref/main.cleaned.cognito.v16.py` | Legacy Python reference for the original single-file server (Cognito-focused). |

## Application package (`app/`)

| Path | Purpose |
| --- | --- |
| `app/__init__.py` | Package marker for the FastAPI app. |
| `app/main.py` | FastAPI application factory, router registration, CORS, and static file mounting. |
| `app/models.py` | Pydantic request/response models used by the API endpoints. |

### Authentication (`app/auth/`)

| Path | Purpose |
| --- | --- |
| `app/auth/__init__.py` | Package marker for authentication helpers. |
| `app/auth/deps.py` | Authentication dependency placeholder (raise 501 until real auth is wired). |

### Core utilities (`app/core/`)

| Path | Purpose |
| --- | --- |
| `app/core/__init__.py` | Package marker for shared core helpers. |
| `app/core/aws.py` | AWS client/session helpers (DynamoDB, KMS, optional SES/Twilio). |
| `app/core/crypto.py` | Crypto helpers (hashing, KMS encrypt/decrypt, WS token HMAC). |
| `app/core/cursor.py` | DynamoDB pagination cursor encoding/decoding helpers. |
| `app/core/normalize.py` | Input normalization and validation (email, phone, CIDR, IP extraction). |
| `app/core/settings.py` | Environment-backed configuration values. |
| `app/core/tables.py` | DynamoDB table handles wired from settings. |
| `app/core/time.py` | Timestamp helper (`now_ts`). |

### Services (`app/services/`)

| Path | Purpose |
| --- | --- |
| `app/services/__init__.py` | Package marker for service-layer helpers. |
| `app/services/alerts.py` | Alert storage, SSE fanout, alert preferences, and outbound alert delivery helpers. |
| `app/services/api_keys.py` | API key generation, storage, and enforcement of CIDR allow/deny rules. |
| `app/services/mfa.py` | MFA operations (TOTP enrollment, SMS/email verification, recovery codes). |
| `app/services/push.py` | Push notification registration and FCM delivery helpers. |
| `app/services/rate_limit.py` | Rate limit checks for MFA and alert channels. |
| `app/services/sessions.py` | UI session creation, step-up challenges, and session revocation helpers. |
| `app/services/ttl.py` | TTL utilities for DynamoDB items. |

### Routers (`app/routers/`)

| Path | Purpose |
| --- | --- |
| `app/routers/__init__.py` | Package marker for API routers. |
| `app/routers/alerts.py` | Alert history, preferences, SSE streaming, and alert delivery routes. |
| `app/routers/api_keys.py` | API key CRUD routes and IP allow/deny management. |
| `app/routers/mfa_devices.py` | Device management routes for TOTP, SMS, email, and recovery codes. |
| `app/routers/misc.py` | Miscellaneous routes (health ping, WS token mint). |
| `app/routers/push.py` | Push device registration and test push routes. |
| `app/routers/recovery.py` | Recovery code verification routes. |
| `app/routers/ui_mfa.py` | UI step-up MFA routes for TOTP/SMS/email challenges. |
| `app/routers/ui_session.py` | UI session start/finalize, list, and revoke endpoints. |

### Static web UI (`app/static/`)

| Path | Purpose |
| --- | --- |
| `app/static/index.html` | Static control panel UI for managing sessions, MFA, and alerts. |
| `app/static/main.js` | Client-side logic for the control panel UI (API calls, SSE/WS toasts). |
| `app/static/styles.css` | Styles for the control panel UI. |
