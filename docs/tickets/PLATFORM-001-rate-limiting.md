# PLATFORM-001: API Rate Limiting & Abuse Prevention

**Ticket**: PLATFORM-001
**Author**: Engineering
**Status**: Done
**Date**: 2026-05-27
**Priority**: High
**Estimated effort**: 10-14 days

---

## 1. Executive Summary

The platform has ad-hoc rate limiting scattered across specific flows but no unified, configurable rate-limiting middleware. The existing `app/services/rate_limit.py` (~380 lines) contains individual rate-limit functions for MFA codes, login attempts, admin actions, profile lookups, feed queries, and file mount operations, all storing state in `T.sessions` via the `_bucket_limit()` helper. However, many critical endpoints (messaging, file upload, billing, calendar, contacts, catalog, tickets) have no rate limiting at all, and there is no global IP-based throttle to block abusive traffic before it reaches the application layer.

This feature implements a three-layer rate limiting system: Layer 1 is a global IP rate limit applied as FastAPI middleware to every request (300 req/min default), Layer 2 is a per-endpoint-group rate limit injected as a FastAPI dependency after authentication (configurable per group: auth, messaging, billing, file_upload, etc.), and Layer 3 preserves the existing business-logic rate limits for sensitive operations. The new layers use a dedicated `rate_limits` DynamoDB table (avoiding hot partitions on `T.sessions`), include `Retry-After` and `X-RateLimit-*` headers on all responses, support admin/root role bypass, and provide an admin monitoring dashboard with top offender tracking.

The design is deliberately DynamoDB-native (no Redis dependency) for consistency with the existing infrastructure. A clean abstraction layer in `rate_limit_store.py` allows swapping to Redis or ElastiCache in the future if DDB latency becomes a bottleneck at high scale. Rate limit events are logged to a separate `rate_limit_events` table for the admin dashboard, written asynchronously to avoid adding latency to the request path.

---

## 2. Detailed Problem Analysis

### 2.1 Existing Rate Limiting (`app/services/rate_limit.py`)

The file contains ~380 lines of individual rate-limit functions:

| Function | Scope | Storage |
|----------|-------|---------|
| `rate_limit_or_429()` (line 17) | MFA send codes | `T.sessions` with `rl#{factor}` SK | <!-- VERIFIED -->
| `rate_limit_login_attempt()` (line 163) | Login per-user + per-IP | `T.sessions` via `_bucket_limit()` | <!-- VERIFIED -->
| `rate_limit_admin_action()` (line 170) | Admin actions | `T.sessions` via `_bucket_limit()` | <!-- VERIFIED -->
| `rate_limit_mfa_verify()` (line 175) | MFA verification per-user + per-IP | `T.sessions` via `_bucket_limit()` | <!-- VERIFIED -->
| `rate_limit_password_recovery()` (line 182) | Password recovery | `T.sessions` via `_bucket_limit()` | <!-- VERIFIED -->
| `rate_limit_profile_lookup()` (line 198) | Profile lookups (auth + anon tiers) | `T.sessions` via `_bucket_limit()` | <!-- VERIFIED -->
| `rate_limit_feed_query()` (line 227) | Newsfeed queries | `T.sessions` via `_bucket_limit()` | <!-- VERIFIED -->
| `rate_limit_filemgr_mount_*()` (lines 340-370) | File mount operations (4 functions) | `T.sessions` via `_bucket_limit()` | <!-- VERIFIED -->
| `enforce_lockout()` (line 247) | Progressive lockout for brute force | `T.sessions` with `lockout#` prefix | <!-- VERIFIED -->
| `can_send_alert_channel()` (line 321) | Alert channel (email/SMS/push/webhook) | `T.sessions` via `_bucket_limit()` | <!-- VERIFIED -->
| `can_send_verification()` (line 314) | Verification email/SMS | `T.sessions` via `_bucket_limit()` | <!-- VERIFIED -->

### 2.2 What's Missing

1. **No global middleware**: Each endpoint must manually call a rate-limit function. Many endpoints have no rate limiting at all.
2. **No per-endpoint configuration**: Limits are hardcoded per function. No central registry of endpoint limits.
3. **No IP-based global rate limiting**: Unauthenticated endpoints (login, register, public profile) have no global throttle.
4. **No `Retry-After` header on most 429 responses**: Only `rate_limit_profile_lookup()` and `rate_limit_feed_query()` include `Retry-After`. <!-- CORRECTED: was "Only rate_limit_profile_lookup()", but rate_limit_feed_query() (line 241) also includes Retry-After header. -->
5. **No admin/root bypass**: Admin and root users are subject to the same limits as regular users.
6. **No monitoring dashboard**: No visibility into which endpoints are being rate-limited.
7. **DDB hot partition risk**: All rate limit state on `T.sessions` adds latency and creates partition pressure.

### 2.3 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Platform | Protect against DDoS and brute-force attacks | Global IP limit blocks abusive traffic before routing |
| Platform | Prevent message spam | Messaging endpoints have per-user limits |
| Admin | Monitor rate limit activity in real-time | Dashboard shows 429 counts, top offenders, endpoint distribution |
| Admin | Configure rate limits without code deployment | PUT endpoint updates limits; changes take effect immediately |
| Admin | Whitelist trusted IPs | Allowlist bypasses global IP limit |
| Admin | Block known bad actors | Blocklist immediately rejects all requests from an IP |
| Root | Bypass all rate limits for debugging | Root role exempt from all limits |
| Developer | See clear 429 response with retry guidance | All 429s include Retry-After header and structured error body |

### 2.4 Competitive Analysis

| Platform | Rate Limit Approach | Storage | Headers | Admin Controls |
|----------|-------------------|---------|---------|----------------|
| GitHub API | Fixed window per user/IP | Redis + Memcached | Yes (X-RateLimit-*) | No self-service |
| Stripe API | Sliding window | Redis | Yes (Retry-After) | Dashboard only |
| Twitter/X API | Token bucket per app | Redis | Yes (X-Rate-Limit-*) | No |
| AWS API Gateway | Token bucket | In-memory + DDB | Yes | Console UI |
| **This platform** | **Ad-hoc per function** | **DDB T.sessions** | **Partial** | **None** |

---

## 3. Technical Architecture

### 3.1 System Diagram

```
Incoming Request
       |
       v
+-------------------------------+
| Layer 1: Global IP Rate Limit |   <-- FastAPI middleware (before routing)
| (app/middleware/rate_limit.py) |
|                                |
| Token bucket per IP            |
| DDB: rate_limits table         |
| Bypass: allowlisted IPs        |
| Block: blocklisted IPs         |
+-------------------------------+
       |
       | (passes if allowed)
       v
+-------------------------------+
| FastAPI Router                 |
| (auth + route matching)       |
+-------------------------------+
       |
       v
+-------------------------------+
| Layer 2: Endpoint Group Limit  |   <-- FastAPI Depends() on router groups
| (rate_limit_dependency(group)) |
|                                |
| Per-user + per-IP sliding window|
| DDB: rate_limits table         |
| Bypass: admin/root roles       |
| Config: DDB or env vars        |
+-------------------------------+
       |
       | (passes if allowed)
       v
+-------------------------------+
| Layer 3: Business Logic Limits |   <-- Existing functions (unchanged)
| (app/services/rate_limit.py)   |
|                                |
| MFA, login, admin, lockout     |
| DDB: T.sessions (unchanged)   |
+-------------------------------+
       |
       | (passes if allowed)
       v
+-------------------------------+
| Request Handler                |
| (actual endpoint logic)        |
+-------------------------------+
       |
       v
+-------------------------------+
| Response with Headers          |
| X-RateLimit-Limit: 120        |
| X-RateLimit-Remaining: 73     |
| X-RateLimit-Reset: 1748381860 |
| Retry-After: 30 (429 only)    |
+-------------------------------+
```

### 3.2 Data Flow -- Rate Limit Check

1. Request arrives at middleware
2. Extract client IP via `client_ip_from_request()` from `app/core/normalize.py` (line 9) <!-- CORRECTED: The function does NOT respect `TRUSTED_PROXY_CIDRS`. It simply returns the first X-Forwarded-For entry or `request.client.host`. The ticket should note this as a gap that needs to be fixed as part of this feature. -->
3. Check IP against blocklist (reject immediately if blocked)
4. Check IP against allowlist (skip Layer 1 if allowlisted)
5. Layer 1: Read `IP#{ip}/GLOBAL` from `rate_limits` table. If count >= limit, return 429.
6. Layer 1: Increment counter atomically. Set `ttl_epoch` for auto-cleanup.
7. Request proceeds to routing and auth.
8. Layer 2: Auth context provides `user_sub` and `role`. Match request path to endpoint group.
9. Layer 2: If role in `bypass_roles`, skip.
10. Layer 2: Read `ENDPOINT#{group}#USER#{user_sub}` and `ENDPOINT#{group}#IP#{ip}`. Check against group limits.
11. Layer 2: Increment counters. Set headers.
12. Request proceeds to handler.
13. Asynchronously log rate limit event to `rate_limit_events` table (fire-and-forget).

---

## 4. Data Model Deep Dive

### 4.1 New Table: `rate_limits`

```python
# scripts/local-ddb-init.py
TableDef(
    _resolve_table_name(S.rate_limits_table_name, "rate_limits"),
    "pk",
    "sk",
),
```

Dedicated table for rate limit state. Uses on-demand billing mode.

| Attribute | Type | Description | Example |
|-----------|------|-------------|---------|
| `pk` | S | Identity key | `"IP#203.0.113.42"` |
| `sk` | S | Window key | `"GLOBAL"` or `"WINDOW#1748380800"` |
| `count` | N | Request count in current window | `42` |
| `window_start` | N | Unix timestamp of window start | `1748380800` |
| `timestamps` | L | Request timestamps (sliding window, capped at limit+1) | `[1748380800, 1748380801, ...]` |
| `ttl_epoch` | N | DDB TTL; auto-cleanup of expired windows | `1748384400` |

**Example items:**

Global IP counter:
```json
{
  "pk": "IP#203.0.113.42",
  "sk": "GLOBAL",
  "count": 42,
  "window_start": 1748380800,
  "ttl_epoch": 1748384400
}
```

Per-endpoint per-user counter:
```json
{
  "pk": "ENDPOINT#messaging#USER#alice@test.local",
  "sk": "GLOBAL",
  "count": 15,
  "window_start": 1748380800,
  "ttl_epoch": 1748384400
}
```

Allowlist entry:
```json
{
  "pk": "ALLOWLIST#IP",
  "sk": "203.0.113.0/24",
  "added_by": "root.admin@testdev.local",
  "added_at": 1748380800,
  "reason": "Office IP range"
}
```

Blocklist entry:
```json
{
  "pk": "BLOCKLIST#IP",
  "sk": "198.51.100.42",
  "added_by": "root.admin@testdev.local",
  "added_at": 1748380800,
  "reason": "DDoS source",
  "ttl_epoch": 1749590400
}
```

Config override:
```json
{
  "pk": "CONFIG#global",
  "sk": "GROUP#messaging",
  "window_seconds": 60,
  "max_requests_per_user": 120,
  "max_requests_per_ip": 200,
  "bypass_roles": ["root", "admin"],
  "updated_by": "root.admin@testdev.local",
  "updated_at": 1748380800
}
```

### 4.2 New Table: `rate_limit_events`

```python
TableDef(
    _resolve_table_name(S.rate_limit_events_table_name, "rate_limit_events"),
    "pk",
    "sk",
),
```

| Attribute | Type | Description | Example |
|-----------|------|-------------|---------|
| `pk` | S | `DATE#{YYYY-MM-DD}` | `"DATE#2026-05-27"` |
| `sk` | S | `{timestamp}#{event_id}` | `"1748380800#evt_abc123"` |
| `endpoint_group` | S | Rate limit group that triggered | `"messaging"` |
| `identity_type` | S | `ip`, `user`, `endpoint` | `"user"` |
| `identity_value` | S | IP address or user_sub | `"alice@test.local"` |
| `endpoint` | S | Request path | `"/ui/messaging/conversations"` |
| `method` | S | HTTP method | `"POST"` |
| `status` | S | `allowed` or `rejected` | `"rejected"` |
| `count` | N | Current counter value | `121` |
| `limit` | N | Configured limit | `120` |
| `ttl_epoch` | N | Auto-expire after 30 days | `1750972800` |

### 4.3 Access Patterns

| Access Pattern | Table/Index | Key Condition |
|---------------|-------------|---------------|
| Get IP rate limit counter | rate_limits PK/SK | `pk = IP#{ip}, sk = GLOBAL` |
| Get user endpoint counter | rate_limits PK/SK | `pk = ENDPOINT#{group}#USER#{sub}, sk = GLOBAL` |
| Check allowlist | rate_limits PK | `pk = ALLOWLIST#IP`, scan for CIDR match |
| Check blocklist | rate_limits PK/SK | `pk = BLOCKLIST#IP, sk = {ip}` |
| Get config override | rate_limits PK/SK | `pk = CONFIG#global, sk = GROUP#{name}` |
| Query events for dashboard | rate_limit_events PK | `pk = DATE#{YYYY-MM-DD}`, sort by sk |
| Top offenders | rate_limit_events PK | Query today's date, aggregate by identity_value |

### 4.4 Settings in `app/core/settings.py`

```python
# Rate limiting
rate_limits_table_name: str = os.environ.get("RATE_LIMITS_TABLE_NAME", "rate_limits")
rate_limit_events_table_name: str = os.environ.get("RATE_LIMIT_EVENTS_TABLE_NAME", "rate_limit_events")
rate_limit_global_enabled: bool = os.environ.get("RATE_LIMIT_GLOBAL_ENABLED", "1") not in ("0", "false", "False")
rate_limit_per_endpoint_enabled: bool = os.environ.get("RATE_LIMIT_PER_ENDPOINT_ENABLED", "1") not in ("0", "false", "False")
rate_limit_global_ip_window_seconds: int = int(os.environ.get("RATE_LIMIT_GLOBAL_IP_WINDOW_SECONDS", "60"))
rate_limit_global_ip_max_requests: int = int(os.environ.get("RATE_LIMIT_GLOBAL_IP_MAX_REQUESTS", "300"))
rate_limit_events_ttl_days: int = int(os.environ.get("RATE_LIMIT_EVENTS_TTL_DAYS", "30"))
rate_limit_dashboard_enabled: bool = os.environ.get("RATE_LIMIT_DASHBOARD_ENABLED", "1") not in ("0", "false", "False")
rate_limit_fail_open: bool = os.environ.get("RATE_LIMIT_FAIL_OPEN", "1") not in ("0", "false", "False")
```

### 4.5 Table Handles in `app/core/tables.py`

```python
# Add to Tables dataclass:
rate_limits: Any
rate_limit_events: Any

# Add to T initialization:
rate_limits=ddb.Table(S.rate_limits_table_name),
rate_limit_events=ddb.Table(S.rate_limit_events_table_name),
```

---

## 5. API Contract Design

### 5.1 Response Headers (All API Responses)

```
X-RateLimit-Limit: 120
X-RateLimit-Remaining: 73
X-RateLimit-Reset: 1748381860
```

On 429 responses:
```
Retry-After: 30
X-RateLimit-Limit: 120
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1748381860
```

### 5.2 429 Response Body

```json
{
  "detail": {
    "code": "rate_limited",
    "group": "messaging",
    "retry_after": 30,
    "message": "Too many requests. Please wait 30 seconds before retrying."
  }
}
```

### 5.3 Admin Endpoints (root role via require_ui_session) <!-- CORRECTED: There is no `require_root_session` function in the codebase. Use `require_ui_session` and check `ctx["role"] == "root"`. -->

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/ui/admin/rate-limits/config` | root | Get current rate limit configuration |
| PUT | `/ui/admin/rate-limits/config` | root | Update rate limit configuration |
| GET | `/ui/admin/rate-limits/events` | root | Query rate limit events (dashboard data) |
| GET | `/ui/admin/rate-limits/top-offenders` | root | Top IPs/users hitting limits |
| POST | `/ui/admin/rate-limits/allowlist` | root | Add IP/CIDR to bypass list |
| DELETE | `/ui/admin/rate-limits/allowlist/{entry_id}` | root | Remove from bypass list |
| POST | `/ui/admin/rate-limits/blocklist` | root | Manually block an IP |
| DELETE | `/ui/admin/rate-limits/blocklist/{entry_id}` | root | Unblock |

### 5.4 GET `/ui/admin/rate-limits/config`

**Response (200):**

```json
{
  "global_ip": {
    "window_seconds": 60,
    "max_requests": 300,
    "enabled": true
  },
  "groups": {
    "auth": {
      "description": "Authentication endpoints",
      "paths": ["/ui/login", "/ui/register", "/ui/password-recovery/*"],
      "window_seconds": 900,
      "max_requests_per_user": 10,
      "max_requests_per_ip": 20,
      "bypass_roles": [],
      "is_override": false
    },
    "messaging": {
      "description": "Messaging send/read endpoints",
      "paths": ["/messaging/*", "/ui/messaging/*"],
      "window_seconds": 60,
      "max_requests_per_user": 120,
      "max_requests_per_ip": 200,
      "bypass_roles": ["root", "admin"],
      "is_override": false
    }
  }
}
```

### 5.5 PUT `/ui/admin/rate-limits/config`

**Request:**

```json
{
  "group": "messaging",
  "window_seconds": 60,
  "max_requests_per_user": 150,
  "max_requests_per_ip": 250,
  "bypass_roles": ["root", "admin"]
}
```

**Response (200):**

```json
{
  "ok": true,
  "group": "messaging",
  "previous": {"max_requests_per_user": 120, "max_requests_per_ip": 200},
  "updated": {"max_requests_per_user": 150, "max_requests_per_ip": 250}
}
```

### 5.6 GET `/ui/admin/rate-limits/top-offenders`

**Query parameters:**
- `hours` (int, default 1): Lookback window
- `limit` (int, default 20): Number of offenders

**Response (200):**

```json
{
  "top_ips": [
    {"ip": "203.0.113.42", "rejected_count": 1500, "last_seen": 1748380800},
    {"ip": "198.51.100.10", "rejected_count": 320, "last_seen": 1748380750}
  ],
  "top_users": [
    {"user_sub": "spammer@example.com", "rejected_count": 250, "last_seen": 1748380800}
  ]
}
```

### 5.7 POST `/ui/admin/rate-limits/blocklist`

**Request:**

```json
{
  "ip": "198.51.100.42",
  "reason": "DDoS source identified in logs",
  "expires_in_hours": 24
}
```

**Response (201):**

```json
{
  "ok": true,
  "entry_id": "198.51.100.42",
  "expires_at": 1748467200
}
```

---

## 6. Rate Limit Configuration

### 6.1 Endpoint Groups

```python
# app/services/rate_limit_config.py

ENDPOINT_GROUPS = {
    "global_ip": {
        "description": "Global per-IP rate limit applied to all requests",
        "window_seconds": 60,
        "max_requests": 300,
        "applies_to": "ip",
        "bypass_roles": ["root"],
    },
    "auth": {
        "description": "Authentication endpoints (login, register, password reset)",
        "paths": ["/ui/login", "/ui/register", "/ui/password-recovery/*"],
        "window_seconds": 900,
        "max_requests_per_user": 10,
        "max_requests_per_ip": 20,
        "bypass_roles": [],
    },
    "messaging": {
        "description": "Messaging send/read endpoints",
        "paths": ["/messaging/*", "/ui/messaging/*"],
        "window_seconds": 60,
        "max_requests_per_user": 120,
        "max_requests_per_ip": 200,
        "bypass_roles": ["root", "admin"],
    },
    "file_upload": {
        "description": "File upload endpoints",
        "paths": ["/ui/files/upload", "/ui/files/*/content"],
        "window_seconds": 300,
        "max_requests_per_user": 50,
        "max_requests_per_ip": 100,
        "bypass_roles": ["root", "admin"],
    },
    "billing": {
        "description": "Billing and payment endpoints",
        "paths": ["/ui/billing/*", "/ui/wallet/*"],
        "window_seconds": 60,
        "max_requests_per_user": 30,
        "max_requests_per_ip": 60,
        "bypass_roles": ["root"],
    },
    "admin": {
        "description": "Admin and root endpoints",
        "paths": ["/ui/admin/*", "/internal/*"],
        "window_seconds": 60,
        "max_requests_per_user": 200,
        "max_requests_per_ip": 300,
        "bypass_roles": ["root"],
    },
    "newsfeed": {
        "description": "Newsfeed read/write endpoints",
        "paths": ["/ui/feed/*", "/ui/posts/*"],
        "window_seconds": 60,
        "max_requests_per_user": 180,
        "max_requests_per_ip": 300,
        "bypass_roles": ["root", "admin"],
    },
    "search": {
        "description": "Search endpoints",
        "paths": ["/ui/search/*", "/ui/users/search"],
        "window_seconds": 60,
        "max_requests_per_user": 60,
        "max_requests_per_ip": 100,
        "bypass_roles": ["root", "admin"],
    },
    "api_public": {
        "description": "Public API endpoints accessed via API keys",
        "paths": ["/api/*"],
        "window_seconds": 60,
        "max_requests_per_user": 60,
        "max_requests_per_ip": 120,
        "bypass_roles": ["root"],
    },
}
```

### 6.2 Configuration Override via DDB

Admins can override defaults by writing to the `rate_limits` table:

```
pk: CONFIG#global
sk: GROUP#{group_name}
```

The `get_group_config(group)` function checks DDB for an override first, then falls back to the in-code default. Overrides are cached in-memory for 60 seconds to reduce DDB reads.

---

## 7. Middleware Implementation

### 7.1 Layer 1: Global IP Rate Limit

```python
# app/middleware/rate_limit.py

async def rate_limit_middleware(request: Request, call_next):
    if not S.rate_limit_global_enabled:
        return await call_next(request)

    ip = _extract_client_ip(request)

    # Check blocklist
    if _is_ip_blocklisted(ip):
        return JSONResponse(status_code=403, content={"detail": "Forbidden"})

    # Check allowlist
    if not _is_ip_allowlisted(ip):
        try:
            allowed, remaining, reset = check_rate_limit(
                pk=f"IP#{ip}",
                window_seconds=S.rate_limit_global_ip_window_seconds,
                max_requests=S.rate_limit_global_ip_max_requests,
            )
        except Exception:
            if S.rate_limit_fail_open:
                allowed, remaining, reset = True, -1, 0
            else:
                return JSONResponse(status_code=503, content={"detail": "Rate limit service unavailable"})

        if not allowed:
            _log_event_async("global_ip", "ip", ip, request.url.path, request.method, "rejected")
            return JSONResponse(
                status_code=429,
                content={"detail": {"code": "rate_limited", "group": "global_ip", "retry_after": max(1, reset - now_ts())}},
                headers={
                    "Retry-After": str(max(1, reset - now_ts())),
                    "X-RateLimit-Limit": str(S.rate_limit_global_ip_max_requests),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(reset),
                },
            )

    response = await call_next(request)
    return response
```

### 7.2 Layer 2: Per-Endpoint Group Check

```python
def rate_limit_dependency(group: str):
    def _check(request: Request, ctx: dict = Depends(require_ui_session)):
        if not S.rate_limit_per_endpoint_enabled:
            return

        user_sub = ctx.get("user_sub", "")
        role = ctx.get("role", "user")
        ip = _extract_client_ip(request)

        config = get_group_config(group)

        if str(role) in config.get("bypass_roles", []):
            return

        # Per-user check
        if user_sub:
            allowed, remaining, reset = check_rate_limit(
                pk=f"ENDPOINT#{group}#USER#{user_sub}",
                window_seconds=config["window_seconds"],
                max_requests=config["max_requests_per_user"],
            )
            if not allowed:
                _log_event_async(group, "user", user_sub, request.url.path, request.method, "rejected")
                raise HTTPException(
                    status_code=429,
                    detail={"code": "rate_limited", "group": group, "retry_after": max(1, reset - now_ts())},
                    headers={"Retry-After": str(max(1, reset - now_ts()))},
                )

        # Per-IP check
        allowed, remaining, reset = check_rate_limit(
            pk=f"ENDPOINT#{group}#IP#{ip}",
            window_seconds=config["window_seconds"],
            max_requests=config["max_requests_per_ip"],
        )
        if not allowed:
            _log_event_async(group, "ip", ip, request.url.path, request.method, "rejected")
            raise HTTPException(
                status_code=429,
                detail={"code": "rate_limited", "group": group, "retry_after": max(1, reset - now_ts())},
                headers={"Retry-After": str(max(1, reset - now_ts()))},
            )
    return Depends(_check)
```

### 7.3 Rate Limit Store (`app/services/rate_limit_store.py`)

```python
def check_rate_limit(pk: str, window_seconds: int, max_requests: int) -> tuple[bool, int, int]:
    """
    Check and increment rate limit counter.
    Returns (allowed: bool, remaining: int, reset_timestamp: int).
    Uses fixed-window counter for simplicity and DDB efficiency.
    """
    now = now_ts()
    window_start = now - (now % window_seconds)  # Align to window boundary
    reset = window_start + window_seconds

    try:
        result = T.rate_limits.update_item(
            Key={"pk": pk, "sk": "GLOBAL"},
            UpdateExpression="SET #cnt = if_not_exists(#cnt, :zero) + :one, window_start = :ws, ttl_epoch = :ttl",
            ConditionExpression="attribute_not_exists(window_start) OR window_start = :ws",
            ExpressionAttributeNames={"#cnt": "count"},
            ExpressionAttributeValues={
                ":zero": 0, ":one": 1,
                ":ws": window_start,
                ":ttl": reset + 3600,
            },
            ReturnValues="ALL_NEW",
        )
        count = int(result["Attributes"]["count"])
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            # Window rolled over; reset counter
            result = T.rate_limits.put_item(
                Item={"pk": pk, "sk": "GLOBAL", "count": 1, "window_start": window_start, "ttl_epoch": reset + 3600},
            )
            count = 1
        else:
            raise

    allowed = count <= max_requests
    remaining = max(0, max_requests - count)
    return allowed, remaining, reset
```

### 7.4 IP Extraction

Reuse the existing `client_ip_from_request()` from `app/core/normalize.py` (line 9). <!-- CORRECTED: The function currently does NOT respect `TRUSTED_PROXY_CIDRS`. It returns the first X-Forwarded-For entry or `request.client.host` without CIDR validation. This must be enhanced as part of this feature to check trusted proxy CIDRs before trusting X-Forwarded-For. -->

---

## 8. Frontend Component Design

### 8.1 Component Tree

```
RateLimitDashboard (/admin/rate-limits)
  |-- SummaryCards
  |     |-- Total429sLastHour
  |     |-- TopOffendingIP
  |     |-- TopOffendingUser
  |     |-- MostLimitedGroup
  |-- TimeSeriesChart
  |     |-- Hourly 429 counts (last 24 hours)
  |     |-- Stacked by endpoint group
  |-- TopOffendersTable
  |     |-- Columns: IP/User, Rejected Count, Last Seen, Actions
  |     |-- BlockButton (for IPs)
  |-- EndpointGroupBreakdown
  |     |-- Bar chart: 429s per endpoint group
  |-- RateLimitConfigPanel
        |-- GroupConfigTable
        |     |-- Columns: Group, Window, Per-User Limit, Per-IP Limit, Bypass Roles
        |     |-- InlineEditButton
        |-- AllowlistTable
        |     |-- Columns: IP/CIDR, Reason, Added By, Actions
        |     |-- AddButton, RemoveButton
        |-- BlocklistTable
              |-- Columns: IP, Reason, Expires, Added By, Actions
              |-- AddButton, RemoveButton
```

### 8.2 New Files

| File | Purpose |
|------|---------|
| `frontend/src/pages/admin/RateLimitDashboard.tsx` | Admin monitoring page |
| `frontend/src/pages/admin/RateLimitConfigPanel.tsx` | Admin configuration UI |
| `frontend/src/api/endpoints/adminRateLimits.ts` | Axios wrappers |

### 8.3 React Query Hooks

```typescript
export const useRateLimitConfig = () => useQuery({
  queryKey: ["admin", "rate-limits", "config"],
  queryFn: () => client.get("/ui/admin/rate-limits/config").then(r => r.data),
});

export const useRateLimitEvents = (hours = 1) => useQuery({
  queryKey: ["admin", "rate-limits", "events", hours],
  queryFn: () => client.get("/ui/admin/rate-limits/events", { params: { hours } }).then(r => r.data),
  refetchInterval: 30_000,  // Refresh every 30 seconds
});

export const useTopOffenders = (hours = 1) => useQuery({
  queryKey: ["admin", "rate-limits", "top-offenders", hours],
  queryFn: () => client.get("/ui/admin/rate-limits/top-offenders", { params: { hours } }).then(r => r.data),
  refetchInterval: 30_000,
});

export const useUpdateConfig = () => useMutation({
  mutationFn: (body: UpdateConfigBody) => client.put("/ui/admin/rate-limits/config", body),
  onSuccess: () => queryClient.invalidateQueries(["admin", "rate-limits", "config"]),
});
```

### 8.4 Route

```typescript
// App.tsx
{ path: "/admin/rate-limits", element: <RateLimitDashboard /> }
```

---

## 9. Security & Privacy Considerations

### 9.1 Authentication

- Rate limit config/dashboard endpoints require `require_ui_session` with root role check (only root can modify limits). <!-- CORRECTED: was `require_root_session`, which does not exist -->
- Layer 1 runs before authentication (must work on unauthenticated requests).
- Layer 2 runs after authentication and uses role information for bypass logic.

### 9.2 Fail-Open vs Fail-Closed

If the `rate_limits` DDB table is unreachable, the middleware should **fail-open** (allow all requests) by default. This prevents a rate-limit infrastructure failure from causing a full platform outage. Configurable via `RATE_LIMIT_FAIL_OPEN`.

A metric `rate_limit_store_error_total` is emitted when the store is unreachable, triggering an alert.

### 9.3 IP Spoofing Prevention

The IP extraction should rely on `TRUSTED_PROXY_CIDRS` to determine which `X-Forwarded-For` entries to trust. If no trusted proxies are configured, the middleware uses `request.client.host` directly. This prevents attackers from spoofing their IP via headers. <!-- CORRECTED: The current `client_ip_from_request()` does NOT implement TRUSTED_PROXY_CIDRS validation. This logic must be added as part of this feature. -->

### 9.4 Blocklist Security

- Blocklist entries include an optional `ttl_epoch` for automatic expiry (e.g., 24-hour blocks).
- All blocklist/allowlist changes are logged in the audit trail.
- Blocklist check runs before rate limit check (blocked IPs get 403, not 429).

---

## 10. Performance & Scalability

### 10.1 DDB Latency Impact

| Operation | DDB Calls | Added Latency |
|-----------|----------|---------------|
| Layer 1 (IP check) | 1 conditional update | ~5ms |
| Layer 2 (user + IP) | 2 conditional updates | ~10ms |
| Blocklist check | 1 get_item | ~3ms |
| Config override check | 1 get_item (cached 60s) | ~0ms (cache hit) |
| Event logging | 1 put_item (async) | ~0ms (fire-and-forget) |
| **Total added per request** | | **~15-18ms** |

### 10.2 DDB Capacity Planning

- **rate_limits table**: One item per IP per window + one item per user-endpoint per window.
- At 1000 concurrent users sending 100 req/min each: ~2000 items active, ~100K writes/min.
- On-demand DDB handles this easily. Cost: ~$1.25/day for 100K writes/min.

### 10.3 Hot Partition Risk

- `IP#{ip}` keys distribute naturally across DDB partitions (many different IPs).
- `ENDPOINT#{group}#USER#{sub}` keys also distribute well (many different users).
- Unlike `T.sessions` (which has other workloads), the `rate_limits` table is dedicated, avoiding contention.

### 10.4 Known Bottlenecks

- **DDB conditional update latency**: Each rate limit check adds ~5ms per DDB call. Under extreme load, this may become noticeable. Mitigation: the rate_limit_store abstraction can be swapped to Redis/ElastiCache for sub-millisecond checks.
- **Event logging volume**: At 10K requests/second, the events table receives ~10K writes/second. This is within DDB on-demand limits but generates significant write cost. Mitigation: sample events (log only rejected requests, or 1% of allowed requests).

---

## 11. Migration & Rollback Plan

### 11.1 Feature Flags

- `RATE_LIMIT_GLOBAL_ENABLED`: Toggle Layer 1 (default true)
- `RATE_LIMIT_PER_ENDPOINT_ENABLED`: Toggle Layer 2 (default true)
- `RATE_LIMIT_DASHBOARD_ENABLED`: Toggle admin dashboard (default true)
- `RATE_LIMIT_FAIL_OPEN`: Fail-open behavior (default true)

### 11.2 Incremental Deployment

1. **Phase 1**: Deploy `rate_limits` and `rate_limit_events` tables. Deploy middleware with `RATE_LIMIT_GLOBAL_ENABLED=false`.
2. **Phase 2**: Enable Layer 1 with a high limit (1000 req/min) to catch only extreme abuse.
3. **Phase 3**: Enable Layer 2 for `auth` and `billing` groups first (most sensitive endpoints).
4. **Phase 4**: Enable Layer 2 for all groups. Deploy admin dashboard.
5. **Phase 5**: Tighten limits based on observed traffic patterns from the dashboard.

### 11.3 Rollback

- Set `RATE_LIMIT_GLOBAL_ENABLED=false` and `RATE_LIMIT_PER_ENDPOINT_ENABLED=false`.
- All requests pass through without rate limiting (same as current behavior).
- Layer 3 (existing business logic limits in `app/services/rate_limit.py`) continues to function independently.
- No data migration needed. The `rate_limits` table items auto-expire via TTL.

### 11.4 Migration from T.sessions

**Recommendation**: Keep Layer 3 on `T.sessions` (no migration risk). Only Layer 1 and Layer 2 use the new `rate_limits` table. The existing `_bucket_limit()` and individual rate limit functions in `app/services/rate_limit.py` remain unchanged.

---

## 12. Testing Strategy

### 12.1 Unit Tests (pytest)

| # | Test | File |
|---|------|------|
| 1 | `check_rate_limit` allows requests below limit | `tests/test_rate_limit_store.py` |
| 2 | `check_rate_limit` rejects requests above limit | `tests/test_rate_limit_store.py` |
| 3 | Counter resets after window expires | `tests/test_rate_limit_store.py` |
| 4 | `_extract_client_ip` uses X-Forwarded-For with trusted proxy | `tests/test_rate_limit_middleware.py` |
| 5 | Layer 1 middleware returns 429 with correct headers | `tests/test_rate_limit_middleware.py` |
| 6 | Layer 2 dependency bypasses admin role | `tests/test_rate_limit_middleware.py` |
| 7 | Layer 2 dependency bypasses root role | `tests/test_rate_limit_middleware.py` |
| 8 | Blocklisted IP gets 403 | `tests/test_rate_limit_middleware.py` |
| 9 | Allowlisted IP bypasses Layer 1 | `tests/test_rate_limit_middleware.py` |
| 10 | Config override from DDB takes precedence | `tests/test_rate_limit_config.py` |
| 11 | Fail-open allows request when DDB is unreachable | `tests/test_rate_limit_store.py` |
| 12 | Event logging writes to rate_limit_events | `tests/test_rate_limit_store.py` |

### 12.2 E2E Tests

**File:** `frontend/e2e/rate-limiting.spec.ts`

**Section A: Global IP Rate Limit (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 1 | Requests below global limit succeed | Send N requests; all return 200 |
| 2 | Requests exceeding global limit return 429 | Flood endpoint; verify 429 response |
| 3 | 429 response includes Retry-After header | Parse header; verify integer value |
| 4 | Rate limit resets after window expires | Wait for window; verify requests succeed again |

**Section B: Per-Endpoint Group Limits (5 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 5 | Messaging endpoint respects per-user limit | Send max+1 requests as Alice; verify 429 |
| 6 | Different users have independent limits | Alice at limit, Bob still allowed |
| 7 | Admin user bypasses messaging rate limit | Charlie (admin) exceeds limit; still 200 |
| 8 | Root user bypasses all rate limits | Root exceeds global IP + endpoint limits |
| 9 | Auth endpoints have no role bypass | Admin login attempts still rate-limited |

**Section C: Rate Limit Headers (3 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 10 | Successful response includes X-RateLimit-* headers | Verify Limit, Remaining, Reset |
| 11 | Remaining decrements with each request | Send 3 requests; verify Remaining decreases |
| 12 | Reset header shows correct window expiry | Verify Reset > now |

**Section D: Admin Dashboard API (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 13 | Admin can view rate limit configuration | GET config returns endpoint groups |
| 14 | Admin can update rate limit for a group | PUT config; verify new limits apply |
| 15 | Admin can add IP to allowlist | POST allowlist; verify IP bypasses limits |
| 16 | Admin can view top offenders | Trigger rate limits; query top offenders |

**Section E: Admin Dashboard UI (3 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 17 | Dashboard loads with summary cards | Navigate to `/admin/rate-limits`; verify cards visible |
| 18 | Endpoint group config table renders | Verify all groups listed with limits |
| 19 | Non-root user cannot access rate limit dashboard | Alice gets 403 |

---

## 13. Monitoring & Alerting

### 13.1 Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `rate_limit_check_total` | Counter | `layer` (1/2/3), `result` (allowed/rejected) | All rate limit checks |
| `rate_limit_429_total` | Counter | `group`, `identity_type` (ip/user) | 429 responses by group |
| `rate_limit_store_latency_ms` | Histogram | `operation` (read/write) | DDB operation latency |
| `rate_limit_store_error_total` | Counter | - | DDB errors (fail-open triggered) |
| `rate_limit_blocklist_hit_total` | Counter | - | Requests blocked by blocklist |
| `rate_limit_config_override_active` | Gauge | `group` | Groups with active DDB overrides |

### 13.2 Dashboard Queries

- **429 rate**: `rate(rate_limit_429_total[5m])` -- 429s per second
- **Layer distribution**: `sum by (layer)(rate(rate_limit_429_total[1h]))` -- which layer is rejecting most
- **Store health**: `rate(rate_limit_store_error_total[5m])` -- should be 0

### 13.3 Alert Thresholds

| Alert | Condition | Severity |
|-------|-----------|----------|
| Rate limit store failures | `rate_limit_store_error_total` > 0 for 5 minutes | Critical |
| High 429 rate | `rate(rate_limit_429_total[5m])` > 100/s | Warning |
| Single IP flooding | One IP generating > 1000 429s/hour | Warning |
| All traffic rate-limited | 429 rate > 50% of total requests for 1 minute | Critical |
| Config override changed | `rate_limit_config_override_active` changed | Info |

---

## 14. Open Questions & Risks

### 14.1 Unresolved Decisions

1. **Redis vs DDB**: At very high scale, DDB adds ~5ms per check. Redis would reduce to <1ms. Should `rate_limit_store.py` support both backends from day one? Recommendation: start with DDB, add Redis as a future optimization if p99 latency exceeds 20ms.
2. **WebSocket/SSE rate limiting**: The platform uses SSE for real-time messaging. Should SSE connection attempts be rate-limited? Should message frequency over SSE be throttled? Recommendation: rate-limit SSE connection setup (Layer 1 + 2), but not individual SSE messages (handled by application logic).
3. **Rate limit key for API key auth**: When requests come via Bearer token, should the limit key be the API key ID, the user_sub, or both? Recommendation: use user_sub (one user may have multiple API keys; limits should aggregate).
4. **Event sampling**: At high traffic, logging every rate limit event is expensive. Should we sample? Recommendation: log all rejected events (429s), sample 1% of allowed events.

### 14.2 Technical Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| DDB conditional update hot partition | Low | Medium | Dedicated table; on-demand billing; natural key distribution |
| Middleware adds too much latency | Medium | Medium | Measure p99; fail-open; swap to Redis if needed |
| Allowlist CIDR matching is slow | Low | Low | Linear scan of allowlist entries; cache result for 60s per IP |
| Race condition on counter increment | Low | Low | DDB conditional expressions ensure atomicity; worst case: one extra request allowed |
| Event table write cost at scale | Medium | Medium | Sample events; 30-day TTL auto-cleanup |

### 14.3 Dependency Risks

- **`app/core/normalize.py::client_ip_from_request()`** (line 9): Must be enhanced to correctly extract client IP behind proxies with CIDR validation. Currently it simply returns the first X-Forwarded-For entry or `request.client.host` without any `TRUSTED_PROXY_CIDRS` check. Misconfigured implementation could cause all traffic to appear as a single IP (the load balancer), triggering false rate limits. <!-- CORRECTED: Function exists but does not implement the TRUSTED_PROXY_CIDRS logic the ticket assumes. -->
- **DDB table creation**: `rate_limits` and `rate_limit_events` tables must be created in `scripts/local-ddb-init.py` before the middleware starts.

---

## 15. Implementation Timeline

### Phase 1: Infrastructure + Store (Days 1-3)

| Day | Task |
|-----|------|
| 1 | Add `rate_limits` and `rate_limit_events` tables to `scripts/local-ddb-init.py`. Add settings + table handles. |
| 2 | Create `app/services/rate_limit_store.py` with `check_rate_limit()`, blocklist/allowlist helpers. |
| 3 | Create `app/services/rate_limit_config.py` with endpoint group definitions and DDB override loading. Unit tests. |

### Phase 2: Middleware (Days 4-6)

| Day | Task |
|-----|------|
| 4 | Create `app/middleware/rate_limit.py` with Layer 1 global IP middleware. Register in `app/main.py`. |
| 5 | Create `rate_limit_dependency(group)` factory for Layer 2. Wire into a test router group (messaging). |
| 6 | Wire Layer 2 into all router groups. Add response headers. Add async event logging. Unit tests. |

### Phase 3: Admin API (Days 7-8)

| Day | Task |
|-----|------|
| 7 | Create `app/routers/admin_rate_limits.py` with config, events, top-offenders endpoints. |
| 8 | Add allowlist/blocklist management endpoints. Create `app/services/rate_limit_dashboard.py`. |

### Phase 4: Frontend Dashboard (Days 9-11)

| Day | Task |
|-----|------|
| 9 | Create `RateLimitDashboard.tsx` with summary cards and time series chart. |
| 10 | Create `RateLimitConfigPanel.tsx` with inline edit and allowlist/blocklist management. |
| 11 | Add API client, TypeScript types, React Query hooks. Wire route. |

### Phase 5: E2E Tests + QA (Days 12-14)

| Day | Task |
|-----|------|
| 12 | Write E2E tests sections A-B (global IP, per-endpoint). |
| 13 | Write E2E tests sections C-E (headers, admin API, admin UI). |
| 14 | Full suite run, load testing with concurrent requests, fail-open testing, code review. |

---

## 16. Files to Create

| File | Purpose |
|------|---------|
| `app/middleware/rate_limit.py` | FastAPI middleware for Layer 1 + response header injection |
| `app/services/rate_limit_config.py` | Endpoint group definitions + DDB override loading |
| `app/services/rate_limit_store.py` | DDB read/write for rate limit counters |
| `app/services/rate_limit_dashboard.py` | Aggregates rate limit event data for admin UI |
| `app/routers/admin_rate_limits.py` | Admin endpoints for config/events/allowlist/blocklist |
| `frontend/src/pages/admin/RateLimitDashboard.tsx` | Admin monitoring page |
| `frontend/src/pages/admin/RateLimitConfigPanel.tsx` | Admin configuration UI |
| `frontend/src/api/endpoints/adminRateLimits.ts` | Axios wrappers |
| `frontend/e2e/rate-limiting.spec.ts` | E2E tests |

## 17. Files to Modify

| File | Change |
|------|--------|
| `app/main.py` | Register rate limit middleware + admin_rate_limits router |
| `app/core/settings.py` | Add `rate_limit_*` settings |
| `app/core/tables.py` | Add `rate_limits` and `rate_limit_events` table handles |
| `scripts/local-ddb-init.py` | Add `rate_limits` and `rate_limit_events` table definitions |
| `app/models.py` | Add Pydantic models for rate limit config/events |
| `frontend/src/api/types.ts` | Add TypeScript interfaces for rate limit data |
| `frontend/src/App.tsx` | Add `/admin/rate-limits` route |

---

## 18. Dependencies

| Dependency | Reason |
|------------|--------|
| `app/services/rate_limit.py` | Existing Layer 3 functions remain; new Layer 1+2 built alongside |
| `app/core/normalize.py::client_ip_from_request()` | IP extraction with proxy awareness |
| `app/core/settings.py::S` | Configuration via environment variables |
| `app/auth/deps.py` | Auth context needed for Layer 2 (user_sub, role) |
| `app/main.py` | Middleware registration |
| `T.sessions` | Existing rate limit data; Layer 3 continues to use it |

---

## 19. Acceptance Criteria

1. All API requests pass through Layer 1 global IP rate limiting.
2. Endpoint groups (auth, messaging, billing, etc.) have configurable per-user and per-IP limits.
3. 429 responses include `Retry-After`, `X-RateLimit-Limit`, `X-RateLimit-Remaining`, and `X-RateLimit-Reset` headers.
4. Root users bypass all rate limits.
5. Admin users bypass per-endpoint limits but not global IP limits (except allowlisted).
6. Admin dashboard shows 429 counts, top offenders, and endpoint group distribution.
7. Admin can update rate limits, add/remove allowlist and blocklist entries.
8. Existing Layer 3 business logic limits (MFA, login, admin actions) continue to function unchanged.
9. Middleware fails open if the `rate_limits` DDB table is unreachable.
10. Rate limit events auto-expire after 30 days via DynamoDB TTL.

---

## Appendix: Codebase Citations

| Reference | File | Line(s) | Status |
|-----------|------|---------|--------|
| `_bucket_limit()` | `app/services/rate_limit.py` | 60 | VERIFIED |
| `rate_limit_or_429()` | `app/services/rate_limit.py` | 17 | VERIFIED |
| `rate_limit_login_attempt()` | `app/services/rate_limit.py` | 163 | VERIFIED |
| `rate_limit_admin_action()` | `app/services/rate_limit.py` | 170 | VERIFIED |
| `rate_limit_mfa_verify()` | `app/services/rate_limit.py` | 175 | VERIFIED |
| `rate_limit_password_recovery()` | `app/services/rate_limit.py` | 182 | VERIFIED |
| `rate_limit_profile_lookup()` | `app/services/rate_limit.py` | 198 | VERIFIED (includes Retry-After header) |
| `rate_limit_feed_query()` | `app/services/rate_limit.py` | 227 | VERIFIED (also includes Retry-After header -- ticket originally omitted this) |
| `rate_limit_filemgr_mount_onboarding()` | `app/services/rate_limit.py` | 340 | VERIFIED |
| `rate_limit_filemgr_mount_verify()` | `app/services/rate_limit.py` | 350 | VERIFIED |
| `rate_limit_filemgr_mount_rotate()` | `app/services/rate_limit.py` | 360 | VERIFIED |
| `rate_limit_filemgr_mount_revoke()` | `app/services/rate_limit.py` | 370 | VERIFIED |
| `enforce_lockout()` | `app/services/rate_limit.py` | 247 | VERIFIED |
| `can_send_alert_channel()` | `app/services/rate_limit.py` | 321 | VERIFIED |
| `can_send_verification()` | `app/services/rate_limit.py` | 314 | VERIFIED |
| `client_ip_from_request()` | `app/core/normalize.py` | 9 | CORRECTED: does NOT respect TRUSTED_PROXY_CIDRS; simply returns first X-Forwarded-For or client.host |
| `T.sessions` (rate limit storage) | `app/core/tables.py` | exists | VERIFIED |
| Middleware registration pattern `app.middleware("http")` | `app/main.py` | 289-291 | VERIFIED |
| `require_ui_session` | `app/services/sessions.py` | 283 | VERIFIED |
| `get_authenticated_user` → `AuthenticatedUser(sub, role, admin_profile)` | `app/auth/deps.py` | 184, 126 | VERIFIED |
| `require_root_session` | N/A | N/A | CORRECTED: does not exist; use `require_ui_session` + role check |
| `now_ts()` | `app/core/time.py` | 2 | VERIFIED |
| `TableDef` dataclass | `scripts/local-ddb-init.py` | 29 | VERIFIED |
| `_resolve_table_name()` | `scripts/local-ddb-init.py` | 38 | VERIFIED |
| Settings dataclass | `app/core/settings.py` | entire file | VERIFIED (proposed new settings do not exist yet) |
| Tables dataclass | `app/core/tables.py` | entire file | VERIFIED (proposed new table handles do not exist yet) |


---

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_rate_limit_store.py`

| # | Test Function | Description |
|---|--------------|-------------|
| 1 | `test_check_allows_below_limit` | Requests below limit succeed |
| 2 | `test_check_rejects_above_limit` | Requests above limit rejected |
| 3 | `test_counter_resets_after_window` | Counter resets after window expires |
| 4 | `test_extract_ip_x_forwarded` | X-Forwarded-For with trusted proxy extracted |
| 5 | `test_layer1_returns_429_headers` | 429 with Retry-After, X-RateLimit-* headers |
| 6 | `test_layer2_bypasses_admin` | Admin role bypasses per-endpoint limit |
| 7 | `test_blocklisted_ip_403` | Blocklisted IP gets 403 |
| 8 | `test_allowlisted_ip_bypasses` | Allowlisted IP bypasses Layer 1 |
| 9 | `test_fail_open_on_ddb_error` | DDB unreachable; request allowed |
| 10 | `test_config_override_precedence` | DDB override takes precedence over defaults |

All tests use moto-mocked DynamoDB.

### Integration Tests

| # | Scenario | Services Involved |
|---|----------|-------------------|
| 1 | Layer 1 + Layer 2 combined enforcement | middleware + dependency + DDB rate_limits table |
| 2 | Admin config update changes live limits | admin router + rate_limit_config + DDB |
| 3 | Event logging writes to rate_limit_events | middleware + events table |

### E2E Tests (Playwright)

**File**: `frontend/e2e/rate-limiting.spec.ts` -- 19 tests

**Auth**: `injectAuth(page, identity)` for cookie auth; CSRF header for mutations.

Sections: A (global IP limit, 4), B (per-endpoint group, 5), C (headers, 3), D (admin API, 4), E (admin UI, 3)

**Negative/edge tests**: 429 with Retry-After header, admin 403 for non-root, rate limit resets after window

### Test Data Requirements

- DDB seeds: rate_limits, rate_limit_events tables
- Test users: Alice (USER), Charlie (ADMIN), Root
- Sessions via `e2e_admin_session_setup.py`

### CI/Pipeline

- Feature flags: RATE_LIMIT_GLOBAL_ENABLED, RATE_LIMIT_PER_ENDPOINT_ENABLED, RATE_LIMIT_DASHBOARD_ENABLED
- Serial execution (1 worker), 1 retry per playwright.config.ts
- Retry-safe: unique timestamps in test data


---

## Dependencies & Merge Safety

### Depends On

| Ticket | Type | Detail |
|--------|------|--------|
| (none) | -- | Standalone infrastructure feature |

### Depended On By

| Ticket | Type | Detail |
|--------|------|--------|
| PLATFORM-002 | Uses | Webhooks can use per-endpoint rate limit groups |
| PLATFORM-006 | Uses | Email delivery benefits from rate limit middleware |

### Merge Strategy

**Independent** -- Foundation infrastructure. Should be merged early as other features benefit from rate limiting.

### Merge Checklist

- [ ] rate_limits + rate_limit_events DDB tables in local-ddb-init.py
- [ ] Layer 1 global IP middleware in app/middleware/rate_limit.py
- [ ] Layer 2 per-endpoint dependency in rate_limit_dependency()
- [ ] X-RateLimit-* response headers on all responses
- [ ] Admin dashboard at /admin/rate-limits
- [ ] E2E pass: `npx playwright test e2e/rate-limiting.spec.ts`
