# File Reference

This document lists each file in the repository with a short description of its purpose. Use it as a map when you need to locate a specific feature or component.

## Root

| Path | Purpose |
| --- | --- |
| `README.md` | Quick start instructions, required environment variables, and optional configuration notes. |
| `requirements.txt` | Python dependencies for the FastAPI service and related tooling. |
| `docs/` | Operational and integration documentation. |
| `tests/` | Pytest suite for API routes, billing flows, and helpers. |

## Documentation (`docs/`)

| Path | Purpose |
| --- | --- |
| `docs/run-deploy.md` | Local run, deployment, and Stripe/PayPal billing setup notes. |
| `docs/architecture.md` | System architecture overview. |
| `docs/dynamodb.md` | DynamoDB table setup and configuration. |
| `docs/aws-services.md` | AWS services used by the application. |
| `docs/twilio.md` | Twilio SMS integration details. |
| `docs/ccbill.md` | CCBill billing integration details. |
| `docs/stripe.md` | Stripe billing integration details. |
| `docs/paypal.md` | PayPal billing integration details. |
| `docs/ups.md` | UPS integration notes. |
| `docs/file-reference.md` | Repository file map. |

## Application package (`app/`)

| Path | Purpose |
| --- | --- |
| `app/__init__.py` | Package marker for the FastAPI app. |
| `app/main.py` | FastAPI application factory, router registration, CORS, and static file mounting. |
| `app/models.py` | Pydantic request/response models used by the API endpoints. |
| `app/metrics.py` | Metrics helper utilities for request tracking. |

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
| `app/services/account.py` | Account profile and lifecycle helpers. |
| `app/services/account_state.py` | Account state transitions and storage. |
| `app/services/addresses.py` | Address storage helpers. |
| `app/services/alerts.py` | Alert storage, SSE fanout, alert preferences, and outbound alert delivery helpers. |
| `app/services/api_keys.py` | API key generation, storage, and enforcement of CIDR allow/deny rules. |
| `app/services/billing_ccbill.py` | CCBill billing integration helpers. |
| `app/services/billing_shared.py` | Shared billing helpers (table access, common transforms). |
| `app/services/cognito.py` | Cognito token helpers. |
| `app/services/filemanager.py` | File upload/download helpers. |
| `app/services/mfa.py` | MFA operations (TOTP enrollment, SMS/email verification, recovery codes). |
| `app/services/profile.py` | User profile helpers. |
| `app/services/purchase_history.py` | Purchase history data helpers. |
| `app/services/push.py` | Push notification registration and FCM delivery helpers. |
| `app/services/rate_limit.py` | Rate limit checks for MFA and alert channels. |
| `app/services/sessions.py` | UI session creation, step-up challenges, and session revocation helpers. |
| `app/services/shoppingcart.py` | Shopping cart helpers. |
| `app/services/ttl.py` | TTL utilities for DynamoDB items. |

### Routers (`app/routers/`)

| Path | Purpose |
| --- | --- |
| `app/routers/__init__.py` | Package marker for API routers. |
| `app/routers/account.py` | Account read/update routes. |
| `app/routers/account_state.py` | Account state management routes. |
| `app/routers/addresses.py` | Address CRUD routes. |
| `app/routers/alerts.py` | Alert history, preferences, SSE streaming, and alert delivery routes. |
| `app/routers/api_keys.py` | API key CRUD routes and IP allow/deny management. |
| `app/routers/billing.py` | Shared billing routes (config, balance, payment methods). |
| `app/routers/billing_ccbill.py` | CCBill-specific billing routes. |
| `app/routers/calendar.py` | Calendar event routes. |
| `app/routers/catalog.py` | Catalog browsing and product detail routes. |
| `app/routers/filemanager.py` | File manager routes. |
| `app/routers/messaging.py` | Messaging routes. |
| `app/routers/mfa_devices.py` | Device management routes for TOTP, SMS, email, and recovery codes. |
| `app/routers/misc.py` | Miscellaneous routes (health ping, WS token mint). |
| `app/routers/newsfeed.py` | Newsfeed routes and startup tasks. |
| `app/routers/password_recovery.py` | Password recovery routes. |
| `app/routers/paypal.py` | PayPal billing routes and webhooks. |
| `app/routers/profile.py` | Profile routes. |
| `app/routers/purchase_history.py` | Purchase history routes. |
| `app/routers/push.py` | Push device registration and test push routes. |
| `app/routers/recovery.py` | Recovery code verification routes. |
| `app/routers/shoppingcart.py` | Shopping cart routes. |
| `app/routers/ui_mfa.py` | UI step-up MFA routes for TOTP/SMS/email challenges. |
| `app/routers/ui_session.py` | UI session start/finalize, list, and revoke endpoints. |

### Static web UI (`app/static/`)

| Path | Purpose |
| --- | --- |
| `app/static/index.html` | Static control panel UI for managing sessions, MFA, and alerts. |
| `app/static/main.js` | Client-side logic for the control panel UI (API calls, SSE/WS toasts). |
| `app/static/styles.css` | Styles for the control panel UI. |

## Tests (`tests/`)

| Path | Purpose |
| --- | --- |
| `tests/conftest.py` | Shared fixtures and FastAPI test client configuration. |
| `tests/test_account_closure.py` | Account closure workflows. |
| `tests/test_account_state.py` | Account state transition coverage. |
| `tests/test_address_routes.py` | Address route coverage. |
| `tests/test_billing.py` | Shared billing helper coverage. |
| `tests/test_billing_ccbill.py` | CCBill billing workflow coverage. |
| `tests/test_billing_routes.py` | Billing endpoint tests. |
| `tests/test_calendar_routes.py` | Calendar route coverage. |
| `tests/test_auth_cognito.py` | Cognito auth helper coverage. |
| `tests/test_auth_deps.py` | Auth dependency behavior coverage. |
| `tests/test_filemanager_routes.py` | File manager route coverage. |
| `tests/test_filemanager_service.py` | File manager service helper coverage. |
| `tests/test_messaging_routes.py` | Messaging route coverage. |
| `tests/test_normalize.py` | Input normalization coverage. |
| `tests/test_paypal_helpers.py` | PayPal helper coverage. |
| `tests/test_paypal_routes.py` | PayPal route coverage. |
| `tests/test_profile_routes.py` | Profile route coverage. |
| `tests/test_routes.py` | General route coverage. |
| `tests/test_sessions.py` | Session workflow coverage. |
