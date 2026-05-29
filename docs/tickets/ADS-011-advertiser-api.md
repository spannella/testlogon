# ADS-011: Advertiser API — Programmatic Campaign & Analytics Access

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-29  
**Priority**: High  
**Estimated effort**: 8-10 days  
**Dependencies**: ADS-001 (advertiser accounts & campaign manager), ADS-002 (ad creative management), ADS-008 (ad analytics dashboard) — all sibling tickets, not yet implemented
<!-- NOTE: All ADS dependencies are sibling tickets. Existing: API key infrastructure (app/services/api_keys.py, app/services/api_key_capabilities.py). The CANONICAL_API_KEY_CAPABILITIES tuple at api_key_capabilities.py:5 has no ads:* scopes — these must be added. -->

---

## 1. Overview & Motivation

### The Gap

The advertising platform (ADS-001 through ADS-010) provides a full-featured web UI for campaign management, but lacks a programmatic interface. Advertisers who manage dozens or hundreds of campaigns need automation: scheduled budget adjustments, bulk creative uploads, automated reporting pipelines, and integration with external marketing platforms. Without an API, every operation requires manual UI interaction.

The platform already has a mature API key infrastructure (`app/services/api_keys.py`) that handles key generation, hashing with `API_KEY_PEPPER`, scope-based capability checks, and rate limiting. The existing `CANONICAL_API_KEY_CAPABILITIES` tuple in `app/services/api_key_capabilities.py` defines scopes like `filemanager:read`, `messager:manage`, etc. — but there are no `ads:*` scopes. Adding advertising API scopes and a dedicated router enables programmatic access to the full campaign lifecycle.

### Why This Is Needed

1. **Automation**: Advertisers managing >10 campaigns cannot efficiently use the web UI for daily budget adjustments, creative rotation, and reporting. An API enables cron jobs, scripts, and third-party tool integrations.

2. **Analytics pipelines**: Marketing teams need to pull impression/click/conversion data into their own BI tools (Tableau, Looker, custom dashboards). A read-only analytics API with date-range queries and CSV export makes this possible.

3. **Bulk operations**: Pausing 50 campaigns for a holiday, adjusting budgets across all campaigns by 20%, or uploading 100 creative variants are impractical via the UI. Bulk API endpoints reduce these to single requests.

4. **Webhook integration**: External systems need real-time notifications when campaigns exhaust their budgets, creatives pass review, or spending exceeds thresholds. Webhook delivery decouples the ad platform from downstream systems.

5. **Sandbox testing**: Advertisers building API integrations need a safe environment to test requests without incurring real charges or serving real ads. A sandbox mode with deterministic responses enables integration testing.

### Architecture After This Change

```
External Client (curl / SDK / cron)
        │
        │  Authorization: Bearer ak_xxxx.yyyyyyyy
        │
        ▼
┌──────────────────────────────────────────┐
│   FastAPI Router: /api/v1/ads/           │
│   app/routers/ads_api.py                 │
│                                          │
│   Auth: require_api_key_auth             │
│   Rate limit: 1000 req/min per key       │
│   Scopes: ads:manage / ads:read /        │
│           ads:serve                      │
│                                          │
│   ┌────────────────────────────────────┐ │
│   │ Campaign CRUD                      │ │
│   │ POST   /campaigns                  │ │
│   │ GET    /campaigns                  │ │
│   │ GET    /campaigns/{id}             │ │
│   │ PATCH  /campaigns/{id}             │ │
│   │ DELETE /campaigns/{id}             │ │
│   │ POST   /campaigns/bulk-action      │ │
│   └────────────────────────────────────┘ │
│   ┌────────────────────────────────────┐ │
│   │ Creative Management                │ │
│   │ POST   /creatives                  │ │
│   │ GET    /creatives                  │ │
│   │ GET    /creatives/{id}             │ │
│   │ PATCH  /creatives/{id}             │ │
│   │ DELETE /creatives/{id}             │ │
│   └────────────────────────────────────┘ │
│   ┌────────────────────────────────────┐ │
│   │ Analytics                          │ │
│   │ GET    /analytics/summary          │ │
│   │ GET    /analytics/by-campaign      │ │
│   │ GET    /analytics/by-creative      │ │
│   │ GET    /analytics/by-date          │ │
│   └────────────────────────────────────┘ │
│   ┌────────────────────────────────────┐ │
│   │ Webhooks                           │ │
│   │ POST   /webhooks                   │ │
│   │ GET    /webhooks                   │ │
│   │ DELETE /webhooks/{id}              │ │
│   │ POST   /webhooks/{id}/test         │ │
│   └────────────────────────────────────┘ │
│   ┌────────────────────────────────────┐ │
│   │ Budget                             │ │
│   │ PATCH  /campaigns/{id}/budget      │ │
│   │ POST   /campaigns/bulk-budget      │ │
│   └────────────────────────────────────┘ │
│   ┌────────────────────────────────────┐ │
│   │ Sandbox                            │ │
│   │ POST   /sandbox/serve              │ │
│   │ POST   /sandbox/impression         │ │
│   └────────────────────────────────────┘ │
└──────────────────────────────────────────┘
        │
        ▼
┌──────────────────────────────────────────┐
│   Existing Services                      │
│   app/services/ad_placement.py           │
│   app/services/api_keys.py               │
│   app/services/billing_shared.py         │
│   (+ new) app/services/ad_webhooks.py    │
└──────────────────────────────────────────┘
```

### Data Flow — API Request Lifecycle

```
Client                          FastAPI                           DynamoDB
  │                                │                                 │
  │── GET /api/v1/ads/campaigns ──>│                                 │
  │   Authorization: Bearer ak_... │                                 │
  │                                │                                 │
  │                                │── parse_api_key(token) ────────>│
  │                                │   api_keys table: lookup key_id │
  │                                │<── key record (scopes, user_id) │
  │                                │                                 │
  │                                │── check rate limit ────────────>│
  │                                │   api_keys table: rate_limit SK │
  │                                │<── within limit ───────────────│
  │                                │                                 │
  │                                │── verify scope: "ads:read" ─────│
  │                                │   key.capabilities includes     │
  │                                │   "ads:read" or "ads:manage"    │
  │                                │                                 │
  │                                │── list_campaigns(user_id) ─────>│
  │                                │   ad_campaigns table query      │
  │                                │<── campaign items ─────────────│
  │                                │                                 │
  │<── 200 { campaigns: [...],    │                                 │
  │     pagination: {...} }        │                                 │
```

---

## 2. Current State Analysis

### 2.1 API Key Infrastructure (`app/services/api_keys.py`)

The existing API key system provides:

- **Key generation**: `new_api_key_secret()` generates `secrets.token_urlsafe(32)` tokens. Keys follow the format `ak_{key_id}.{secret}`.
- **Key parsing**: `parse_api_key()` splits key into `key_id` and `secret`, validates format.
- **Hash verification**: `api_key_hash(secret)` uses `sha256_str(secret + "|" + S.api_key_pepper)` for secure storage.
- **Capability scoping**: Keys are created with a list of capabilities from `CANONICAL_API_KEY_CAPABILITIES`. The `normalize_api_key_capabilities()` function validates and normalizes scope strings.
- **Entitlement checking**: `_allowed_capabilities_for_user_plan()` queries the `entitlements` table to determine which capabilities a user's plan allows.

Missing for ADS-011:
- No `ads:*` scopes in `CANONICAL_API_KEY_CAPABILITIES`
- No API key auth dependency for FastAPI routes (existing routes use `require_ui_session`)
- No rate limiting middleware per API key

### 2.2 API Key Capabilities (`app/services/api_key_capabilities.py`)

```python
CANONICAL_API_KEY_CAPABILITIES: tuple[str, ...] = (
    "filemanager:admin", "filemanager:read", "filemanager:share", "filemanager:write",
    "messager:manage", "messager:read", "messager:write",
    "newsfeed:moderate", "newsfeed:read", "newsfeed:write",
    "shopping:cart:write", "shopping:catalog:read", "shopping:checkout:write", "shopping:orders:read",
    "tickets:admin", "tickets:read", "tickets:write",
)
```

The `CAPABILITY_IMPLICATIONS` dict defines inheritance: `"ads:manage"` should imply `"ads:read"` and `"ads:serve"`.

### 2.3 API Key Router (`app/routers/api_keys.py`)

Existing router handles CRUD for API keys (create, list, revoke). Registration in `app/main.py`. Keys are stored in `T.api_keys` (DynamoDB table `api_keys`, setting `S.api_keys_table_name`).

### 2.4 Ad Campaign Data (ADS-001)

ADS-001 defines the campaign data model stored in the `ad_campaigns` DynamoDB table. Campaign records include: `campaign_id`, `advertiser_account_id`, `name`, `status`, `budget_cents`, `spent_cents`, `daily_budget_cents`, `targeting`, `schedule`, `created_at`, `updated_at`. GSIs by advertiser and by status.

### 2.5 Ad Impressions Table

The existing `AdImpressions` table (`T.ad_impressions`, `S.ad_impressions_table_name`) stores impression events with PK `AD_IMP#{date}` and SK `VIDEO#{video_id}#{user_id}#{ts}`. This data feeds the analytics API.

### 2.6 Gaps

1. No `ads:manage`, `ads:read`, or `ads:serve` API key scopes
2. No `require_api_key_auth` FastAPI dependency for route-level auth
3. No rate limiting per API key (existing rate limiting is per-user session)
4. No webhook delivery system for ad events
5. No sandbox mode for testing API integrations
6. No bulk operation endpoints

---

## 3. Technical Design

### 3.1 New API Key Scopes

**File**: `app/services/api_key_capabilities.py`

Add three new scopes to `CANONICAL_API_KEY_CAPABILITIES`:

```python
CANONICAL_API_KEY_CAPABILITIES: tuple[str, ...] = (
    "ads:manage",        # Full CRUD on campaigns, creatives, budgets, webhooks
    "ads:read",          # Read-only analytics, campaign status, creative details
    "ads:serve",         # Ad serving only (request ad, report impression)
    # ... existing scopes ...
)

CAPABILITY_IMPLICATIONS: Dict[str, tuple[str, ...]] = {
    "ads:manage": ("ads:read", "ads:serve"),
    # ... existing implications ...
}
```

### 3.2 API Key Auth Dependency

**File**: `app/auth/deps.py` — Add new dependency:

```python
async def require_api_key_auth(
    request: Request,
    required_scope: str = "",
) -> Dict[str, Any]:
    """Authenticate via API key (Authorization: Bearer ak_...).

    Returns dict with user_sub, key_id, scopes.
    Raises 401 if key is invalid/expired, 403 if scope is missing.
    """
    auth_header = request.headers.get("authorization", "")
    if not auth_header.startswith("Bearer ak_"):
        raise HTTPException(401, "API key required")

    token = auth_header[len("Bearer "):]
    parsed = parse_api_key(token)

    key_record = T.api_keys.get_item(
        Key={"pk": f"KEY#{parsed['key_id']}", "sk": "META"}
    ).get("Item")
    if not key_record:
        raise HTTPException(401, "Invalid API key")

    # Verify hash
    if api_key_hash(parsed["secret"]) != key_record.get("secret_hash"):
        raise HTTPException(401, "Invalid API key")

    # Check expiry
    if key_record.get("expires_at") and key_record["expires_at"] < now_ts():
        raise HTTPException(401, "API key expired")

    # Check scope
    capabilities = expand_api_key_capabilities(key_record.get("capabilities", []))
    if required_scope and required_scope not in capabilities:
        raise HTTPException(403, f"API key missing required scope: {required_scope}")

    return {
        "user_sub": key_record["user_id"],
        "key_id": parsed["key_id"],
        "scopes": capabilities,
        "advertiser_account_id": key_record.get("advertiser_account_id"),
    }
```

### 3.3 Rate Limiting

**File**: `app/services/ads_api_rate_limit.py`

```python
"""Per-API-key rate limiting for the advertiser API.

Uses a sliding window counter stored in DynamoDB. Each key gets a
rate limit record with PK=RATE#{key_id}, SK=WINDOW#{minute_bucket}.
"""

DEFAULT_RATE_LIMIT = 1000  # requests per minute

def check_rate_limit(key_id: str, limit: int = DEFAULT_RATE_LIMIT) -> bool:
    """Check and increment rate limit counter.

    Returns True if within limit, raises 429 if exceeded.
    """
    ts = now_ts()
    minute_bucket = ts // 60

    try:
        resp = T.api_keys.update_item(
            Key={"pk": f"RATE#{key_id}", "sk": f"WINDOW#{minute_bucket}"},
            UpdateExpression="SET #cnt = if_not_exists(#cnt, :z) + :one, #ttl = :ttl",
            ExpressionAttributeNames={"#cnt": "count", "#ttl": "ttl"},
            ExpressionAttributeValues={
                ":z": 0, ":one": 1,
                ":ttl": ts + 120,  # TTL: 2 minutes after bucket
            },
            ReturnValues="UPDATED_NEW",
        )
        count = int(resp["Attributes"]["count"])
        if count > limit:
            raise HTTPException(429, {
                "code": "rate_limit_exceeded",
                "limit": limit,
                "window": "1 minute",
                "retry_after_seconds": 60 - (ts % 60),
            })
        return True
    except ClientError:
        # On DDB error, allow the request (fail open)
        return True
```

### 3.4 Router: `app/routers/ads_api.py`

New router registered at `/api/v1/ads` in `app/main.py`. All endpoints use `require_api_key_auth` for authentication and `check_rate_limit` for throttling.

#### Campaign Endpoints

| Method | Path | Scope | Description |
|--------|------|-------|-------------|
| POST | `/campaigns` | `ads:manage` | Create a new campaign |
| GET | `/campaigns` | `ads:read` | List campaigns (paginated, filterable by status) |
| GET | `/campaigns/{id}` | `ads:read` | Get campaign details |
| PATCH | `/campaigns/{id}` | `ads:manage` | Update campaign (name, targeting, schedule) |
| DELETE | `/campaigns/{id}` | `ads:manage` | Archive campaign (soft delete) |
| POST | `/campaigns/bulk-action` | `ads:manage` | Bulk pause/resume/archive campaigns |

#### Creative Endpoints

| Method | Path | Scope | Description |
|--------|------|-------|-------------|
| POST | `/creatives` | `ads:manage` | Upload new creative |
| GET | `/creatives` | `ads:read` | List creatives (paginated) |
| GET | `/creatives/{id}` | `ads:read` | Get creative details |
| PATCH | `/creatives/{id}` | `ads:manage` | Update creative metadata |
| DELETE | `/creatives/{id}` | `ads:manage` | Archive creative |

#### Budget Endpoints

| Method | Path | Scope | Description |
|--------|------|-------|-------------|
| PATCH | `/campaigns/{id}/budget` | `ads:manage` | Update campaign budget |
| POST | `/campaigns/bulk-budget` | `ads:manage` | Update budgets for multiple campaigns |

#### Analytics Endpoints

| Method | Path | Scope | Description |
|--------|------|-------|-------------|
| GET | `/analytics/summary` | `ads:read` | Account-level summary (total spend, impressions, clicks) |
| GET | `/analytics/by-campaign` | `ads:read` | Per-campaign metrics with date range |
| GET | `/analytics/by-creative` | `ads:read` | Per-creative metrics with date range |
| GET | `/analytics/by-date` | `ads:read` | Daily time series for a campaign |

#### Webhook Endpoints

| Method | Path | Scope | Description |
|--------|------|-------|-------------|
| POST | `/webhooks` | `ads:manage` | Register a webhook endpoint |
| GET | `/webhooks` | `ads:read` | List registered webhooks |
| DELETE | `/webhooks/{id}` | `ads:manage` | Remove webhook |
| POST | `/webhooks/{id}/test` | `ads:manage` | Send test event to webhook |

#### Sandbox Endpoints

| Method | Path | Scope | Description |
|--------|------|-------|-------------|
| POST | `/sandbox/serve` | `ads:serve` | Simulate ad serving request |
| POST | `/sandbox/impression` | `ads:serve` | Simulate impression recording |

### 3.5 Webhook Service: `app/services/ad_webhooks.py`

```python
"""Webhook delivery for ad platform events.

Events:
- campaign_approved: campaign passes moderation review
- campaign_exhausted: campaign budget fully spent
- creative_reviewed: creative approved or rejected
- budget_alert: spending hits 80% or 90% of budget

Webhooks are stored in DDB and delivered via fire-and-forget HTTP POST.
In dev mode, delivery logs to a DDB table instead of making HTTP calls.
"""

WEBHOOK_EVENTS = [
    "campaign_approved",
    "campaign_exhausted",
    "creative_reviewed",
    "budget_alert",
]

def register_webhook(
    *, advertiser_id: str, url: str, events: List[str], secret: str = ""
) -> Dict[str, Any]:
    """Register a new webhook endpoint."""
    webhook_id = f"wh_{uuid.uuid4().hex[:12]}"
    signing_secret = secret or secrets.token_urlsafe(32)
    # Validate URL format
    # Validate events are in WEBHOOK_EVENTS
    # Store in DDB
    ...

def deliver_webhook(
    *, advertiser_id: str, event_type: str, payload: Dict[str, Any]
) -> None:
    """Deliver webhook to all registered endpoints for the event type.

    Signs payload with HMAC-SHA256 using the webhook's signing secret.
    In dev mode: logs delivery to DDB instead of making HTTP calls.
    """
    ...
```

### 3.6 Webhook DDB Schema

Webhooks stored in the `ad_webhooks` table:

| Field | Type | Description |
|-------|------|-------------|
| `pk` | S | `ADV#{advertiser_id}` |
| `sk` | S | `WEBHOOK#{webhook_id}` |
| `webhook_id` | S | Unique ID (`wh_xxxx`) |
| `url` | S | HTTPS endpoint URL |
| `events` | L | List of subscribed event types |
| `signing_secret` | S | HMAC-SHA256 signing secret |
| `active` | BOOL | Whether webhook is active |
| `created_at` | N | Unix timestamp |
| `last_delivery_at` | N | Last successful delivery timestamp |
| `failure_count` | N | Consecutive delivery failures |

**DDB table definition** in `scripts/local-ddb-init.py`:

```python
TableDef(
    name="ad_webhooks",
    pk="pk", sk="sk",
    gsis=[],  # No GSIs needed; all queries by advertiser_id
)
```

**Settings** in `app/core/settings.py`:
```python
ad_webhooks_table_name: str = os.environ.get("DDB_AD_WEBHOOKS", "ad_webhooks")
```

**Table handle** in `app/core/tables.py`:
```python
ad_webhooks=ddb.Table(S.ad_webhooks_table_name),
```

### 3.7 Webhook Delivery Log DDB Schema

| Field | Type | Description |
|-------|------|-------------|
| `pk` | S | `WHLOG#{advertiser_id}` |
| `sk` | S | `DELIVERY#{ts}#{delivery_id}` |
| `webhook_id` | S | Which webhook received it |
| `event_type` | S | Event name |
| `payload` | M | Event payload (map) |
| `status_code` | N | HTTP response status (0 = dev mode skip) |
| `success` | BOOL | Whether delivery succeeded |
| `error` | S | Error message if failed |
| `created_at` | N | Unix timestamp |

Stored in the same `ad_webhooks` table (single-table pattern).

### 3.8 Sandbox Mode

Sandbox mode is activated by passing `X-Sandbox: true` header or by using API keys created with `sandbox: true` flag. In sandbox mode:

- Campaign creation/updates are stored with `sandbox: true` flag
- Ad serving returns deterministic placeholder ads
- Impression recording writes to a separate partition (`SANDBOX_IMP#...`)
- No billing charges are incurred
- Webhook deliveries are logged but not sent over HTTP

### 3.9 Analytics Query Design

Analytics queries aggregate data from the `AdImpressions` table. For large date ranges, the service queries day-by-day partitions (`AD_IMP#{date}`) and aggregates in code.

```python
def get_analytics_summary(
    *, advertiser_id: str, start_date: str, end_date: str
) -> Dict[str, Any]:
    """Aggregate impressions, clicks, spend across all campaigns for date range."""
    # Query ad_impressions by date range
    # Filter by campaign IDs belonging to advertiser
    # Aggregate: impressions, clicks, completions, spend
    return {
        "impressions": total_impressions,
        "clicks": total_clicks,
        "completions": total_completions,
        "spend_cents": total_spend,
        "ctr": clicks / impressions if impressions else 0,
        "cpm_cents": (spend * 1000) / impressions if impressions else 0,
    }
```

### 3.10 Pydantic Models

**File**: `app/models.py` — Add new models:

```python
class AdsApiCampaignCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    daily_budget_cents: int = Field(ge=100)  # minimum $1/day
    total_budget_cents: int = Field(ge=500)  # minimum $5 total
    targeting: Optional[Dict[str, Any]] = None
    schedule: Optional[Dict[str, Any]] = None
    creative_ids: List[str] = Field(default_factory=list)

class AdsApiCampaignUpdate(BaseModel):
    name: Optional[str] = Field(default=None, max_length=200)
    targeting: Optional[Dict[str, Any]] = None
    schedule: Optional[Dict[str, Any]] = None

class AdsApiBulkAction(BaseModel):
    campaign_ids: List[str] = Field(min_length=1, max_length=100)
    action: str = Field(pattern=r"^(pause|resume|archive)$")

class AdsApiBulkBudget(BaseModel):
    updates: List[Dict[str, Any]] = Field(min_length=1, max_length=100)
    # Each dict: {"campaign_id": str, "daily_budget_cents": int, "total_budget_cents": int}

class AdsApiWebhookCreate(BaseModel):
    url: str = Field(pattern=r"^https://")
    events: List[str] = Field(min_length=1)

class AdsApiAnalyticsQuery(BaseModel):
    start_date: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    end_date: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    campaign_id: Optional[str] = None
    creative_id: Optional[str] = None
```

---

## 4. Implementation Plan

### 4.1 Backend — Phase 1: API Key Scopes & Auth (Day 1-2)

1. **`app/services/api_key_capabilities.py`**: Add `"ads:manage"`, `"ads:read"`, `"ads:serve"` to `CANONICAL_API_KEY_CAPABILITIES`. Add implication `"ads:manage" -> ("ads:read", "ads:serve")`.

2. **`app/auth/deps.py`**: Add `require_api_key_auth` dependency that validates API key from `Authorization: Bearer ak_...` header, checks hash, expiry, and scope.

3. **`app/services/ads_api_rate_limit.py`**: New file. Sliding-window rate limiter using DDB atomic counters on the `api_keys` table.

4. **`app/models.py`**: Add Pydantic models for API request/response bodies.

### 4.2 Backend — Phase 2: Campaign & Creative API (Day 3-4)

5. **`app/routers/ads_api.py`**: New router. Register in `app/main.py` with prefix `/api/v1/ads`. Implement campaign CRUD endpoints, creative CRUD endpoints, and budget update endpoints. Each endpoint:
   - Calls `require_api_key_auth` with the appropriate scope
   - Calls `check_rate_limit` with the key_id
   - Delegates to existing campaign/creative service functions
   - Returns JSON with consistent pagination format

6. **`app/main.py`**: Register the new router:
   ```python
   from app.routers.ads_api import ads_api_router
   app.include_router(ads_api_router, prefix="/api/v1/ads", tags=["Advertiser API"])
   ```

### 4.3 Backend — Phase 3: Analytics API (Day 5-6)

7. **`app/services/ads_api_analytics.py`**: New file. Analytics aggregation functions that query `AdImpressions` by date partitions, filter by campaign/creative, and aggregate metrics. Functions: `get_analytics_summary()`, `get_analytics_by_campaign()`, `get_analytics_by_creative()`, `get_analytics_by_date()`.

8. **`app/routers/ads_api.py`**: Add analytics endpoints.

### 4.4 Backend — Phase 4: Webhooks (Day 6-7)

9. **`app/services/ad_webhooks.py`**: New file. Webhook registration, delivery, and logging. HMAC-SHA256 payload signing. Dev-mode DDB logging instead of HTTP delivery.

10. **`scripts/local-ddb-init.py`**: Add `ad_webhooks` table definition.

11. **`app/core/settings.py`**: Add `ad_webhooks_table_name`.

12. **`app/core/tables.py`**: Add `ad_webhooks` table handle.

13. **`app/routers/ads_api.py`**: Add webhook CRUD and test endpoints.

### 4.5 Backend — Phase 5: Sandbox & Bulk Operations (Day 7-8)

14. **`app/routers/ads_api.py`**: Add sandbox endpoints (`/sandbox/serve`, `/sandbox/impression`). Add bulk action endpoint (`/campaigns/bulk-action`), bulk budget endpoint (`/campaigns/bulk-budget`).

15. **Sandbox isolation**: Sandbox requests write to `SANDBOX_*` PK prefixes to avoid polluting production data.

### 4.6 Frontend (Day 8-9)

The Advertiser API is primarily a machine-to-machine interface, but the frontend needs:

16. **`frontend/src/pages/settings/ApiKeysPage.tsx`**: Update existing API key management page to show `ads:*` scopes in the scope selector when creating new keys.

17. **`frontend/src/api/types.ts`**: Add TypeScript types for API key scopes including `ads:manage`, `ads:read`, `ads:serve`.

18. **`frontend/src/pages/ads/ApiDocsPage.tsx`**: New page. Auto-generated API documentation rendered from the OpenAPI spec at `/openapi.json`, filtered to `/api/v1/ads/` endpoints.

### 4.7 DynamoDB Tables

No new tables required for the core API (campaigns, creatives, impressions use existing tables from ADS-001/ADS-002/ADS-008). One new table for webhooks:

**Table**: `ad_webhooks`

| Attribute | Type | Role |
|-----------|------|------|
| `pk` | S | Partition key: `ADV#{advertiser_id}` or `WHLOG#{advertiser_id}` |
| `sk` | S | Sort key: `WEBHOOK#{webhook_id}` or `DELIVERY#{ts}#{delivery_id}` |

**Table definition** in `scripts/local-ddb-init.py`:
```python
TableDef(
    name="ad_webhooks",
    pk="pk", sk="sk",
    gsis=[],
)
```

---

## 5. API Contract Details

### 5.1 Authentication

All endpoints require `Authorization: Bearer ak_{key_id}.{secret}` header. The key must have the appropriate scope for the endpoint.

**Error responses:**
- `401`: Invalid or expired API key
- `403`: API key missing required scope
- `429`: Rate limit exceeded (includes `Retry-After` header)

### 5.2 Pagination

All list endpoints support cursor-based pagination:

```json
{
  "data": [...],
  "pagination": {
    "next_cursor": "eyJsYXN0X2tleS...",
    "has_more": true,
    "total_count": 42
  }
}
```

Query parameters: `limit` (default 20, max 100), `cursor` (opaque string).

### 5.3 Campaign Create — POST `/api/v1/ads/campaigns`

**Scope**: `ads:manage`

**Request:**
```json
{
  "name": "Summer Sale Campaign",
  "daily_budget_cents": 5000,
  "total_budget_cents": 100000,
  "targeting": {
    "age_range": [18, 45],
    "interests": ["shopping", "fashion"],
    "geo": ["US", "CA"]
  },
  "schedule": {
    "start_date": "2026-06-01",
    "end_date": "2026-06-30"
  },
  "creative_ids": ["cr_abc123", "cr_def456"]
}
```

**Response (201):**
```json
{
  "campaign_id": "camp_xyz789",
  "name": "Summer Sale Campaign",
  "status": "draft",
  "daily_budget_cents": 5000,
  "total_budget_cents": 100000,
  "spent_cents": 0,
  "targeting": { ... },
  "schedule": { ... },
  "creative_ids": ["cr_abc123", "cr_def456"],
  "created_at": 1748534400,
  "updated_at": 1748534400
}
```

### 5.4 Bulk Action — POST `/api/v1/ads/campaigns/bulk-action`

**Scope**: `ads:manage`

**Request:**
```json
{
  "campaign_ids": ["camp_abc", "camp_def", "camp_ghi"],
  "action": "pause"
}
```

**Response (200):**
```json
{
  "results": [
    {"campaign_id": "camp_abc", "status": "paused", "ok": true},
    {"campaign_id": "camp_def", "status": "paused", "ok": true},
    {"campaign_id": "camp_ghi", "error": "campaign not found", "ok": false}
  ],
  "success_count": 2,
  "error_count": 1
}
```

### 5.5 Analytics Summary — GET `/api/v1/ads/analytics/summary`

**Scope**: `ads:read`

**Query parameters**: `start_date`, `end_date`

**Response (200):**
```json
{
  "period": {"start_date": "2026-06-01", "end_date": "2026-06-15"},
  "impressions": 125000,
  "clicks": 3750,
  "completions": 87500,
  "conversions": 125,
  "spend_cents": 62500,
  "ctr": 0.03,
  "completion_rate": 0.70,
  "conversion_rate": 0.001,
  "cpm_cents": 500
}
```

### 5.6 Webhook Registration — POST `/api/v1/ads/webhooks`

**Scope**: `ads:manage`

**Request:**
```json
{
  "url": "https://myserver.com/hooks/ads",
  "events": ["campaign_exhausted", "budget_alert"]
}
```

**Response (201):**
```json
{
  "webhook_id": "wh_abc123",
  "url": "https://myserver.com/hooks/ads",
  "events": ["campaign_exhausted", "budget_alert"],
  "signing_secret": "whsec_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  "active": true,
  "created_at": 1748534400
}
```

### 5.7 Webhook Payload Format

```json
{
  "event_id": "evt_xyz789",
  "event_type": "campaign_exhausted",
  "timestamp": 1748534400,
  "data": {
    "campaign_id": "camp_abc",
    "campaign_name": "Summer Sale Campaign",
    "total_budget_cents": 100000,
    "spent_cents": 100000
  }
}
```

Headers on delivery:
```
Content-Type: application/json
X-Ads-Signature: sha256=<hmac_hex_digest>
X-Ads-Event: campaign_exhausted
X-Ads-Delivery: del_xxx
```

---

## 6. Security Considerations

### 6.1 API Key Security

- Keys are never stored in plaintext. Only `api_key_hash(secret)` is persisted.
- `API_KEY_PEPPER` environment variable is required for hash computation. Missing pepper causes `RuntimeError` at startup.
- Keys can be scoped to minimum required permissions (`ads:read` for analytics-only access).
- Keys have configurable expiration (`expires_at` field).

### 6.2 Rate Limiting

- Default 1000 requests/minute per API key. Configurable per key via `rate_limit` field.
- Rate limit uses sliding-window DDB counters with TTL cleanup.
- `429 Too Many Requests` response includes `Retry-After` header.
- Rate limiting fails open (DDB errors allow the request through) to avoid blocking legitimate traffic.

### 6.3 Webhook Security

- Webhook URLs must use HTTPS (enforced by Pydantic regex validation).
- Payloads signed with HMAC-SHA256 using per-webhook signing secret.
- Signing secret returned only once at webhook creation (not retrievable later).
- Auto-disable webhooks after 10 consecutive delivery failures.

### 6.4 Sandbox Isolation

- Sandbox data stored in separate DDB partitions (`SANDBOX_*` prefixes).
- Sandbox API calls do not incur billing charges.
- Sandbox ad serving returns static placeholder creatives only.

---

## 7. Testing Strategy

### 7.1 Unit Tests (`tests/test_ads_api.py`)

| # | Test | Description |
|---|------|-------------|
| 1 | API key with ads:manage scope can create campaign | Verify scope check passes |
| 2 | API key with ads:read scope cannot create campaign | Verify 403 on write |
| 3 | API key with ads:serve scope can use sandbox | Verify serve-only access |
| 4 | Rate limit blocks after 1000 requests | Verify 429 response |
| 5 | Webhook HMAC signature is valid | Verify HMAC-SHA256 computation |
| 6 | Bulk action processes partial failures | Verify mixed success/error response |
| 7 | Analytics aggregation sums correctly | Verify date-range aggregation |
| 8 | Sandbox requests isolated from production | Verify separate partitions |

### 7.2 E2E Tests (`frontend/e2e/ads-api.spec.ts`)

**Test File**: `frontend/e2e/ads-api.spec.ts`

**Test setup (beforeAll):**
- Seed sessions for Alice (advertiser) and Root (admin)
- Create an API key for Alice with `ads:manage` scope
- Create a read-only API key with `ads:read` scope
- Create a serve-only API key with `ads:serve` scope

**Section 388: API Key Scope Enforcement (5 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 1 | `ads:manage key can create campaign` | POST /campaigns with manage key → 201, campaign returned |
| 2 | `ads:read key cannot create campaign` | POST /campaigns with read key → 403 |
| 3 | `ads:read key can list campaigns` | GET /campaigns with read key → 200, array returned |
| 4 | `ads:serve key cannot list campaigns` | GET /campaigns with serve key → 403 |
| 5 | `Expired API key returns 401` | Set key expiry in past, any request → 401 |

**Section 389: Campaign CRUD via API (5 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 6 | `Create campaign with valid payload` | POST /campaigns → 201, campaign_id present, status="draft" |
| 7 | `Get campaign by ID` | GET /campaigns/{id} → 200, all fields match creation payload |
| 8 | `Update campaign name and targeting` | PATCH /campaigns/{id} → 200, name updated |
| 9 | `Bulk pause multiple campaigns` | POST /campaigns/bulk-action {action:"pause", ids:[...]} → 200, all paused |
| 10 | `Delete (archive) campaign` | DELETE /campaigns/{id} → 200, re-GET returns status="archived" |

**Section 390: Analytics API (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 11 | `Summary analytics for date range` | GET /analytics/summary?start_date=...&end_date=... → 200, has impressions, clicks, spend fields |
| 12 | `Analytics by campaign` | GET /analytics/by-campaign → 200, array with campaign_id + metrics |
| 13 | `Analytics by date` | GET /analytics/by-date?campaign_id=... → 200, daily time series array |
| 14 | `Analytics with no data returns zeros` | Query future date range → 200, all metrics = 0 |

**Section 391: Webhooks & Rate Limiting (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 15 | `Register webhook endpoint` | POST /webhooks → 201, webhook_id + signing_secret returned |
| 16 | `List registered webhooks` | GET /webhooks → 200, array includes the registered webhook |
| 17 | `Test webhook delivery` | POST /webhooks/{id}/test → 200, delivery log entry created |
| 18 | `Rate limit enforced` | Send 1001 requests in rapid succession → 429 on the 1001st |

---

## 8. Files to Create

| File | Purpose |
|------|---------|
| `app/routers/ads_api.py` | Advertiser API router (all endpoints) |
| `app/services/ads_api_rate_limit.py` | Per-key rate limiting |
| `app/services/ads_api_analytics.py` | Analytics aggregation |
| `app/services/ad_webhooks.py` | Webhook registration + delivery |
| `frontend/src/pages/ads/ApiDocsPage.tsx` | API documentation page |
| `frontend/e2e/ads-api.spec.ts` | E2E tests (18 tests, sections 388-391) |
| `tests/test_ads_api.py` | Unit tests |

## 9. Files to Modify

| File | Change |
|------|--------|
| `app/services/api_key_capabilities.py` | Add `ads:manage`, `ads:read`, `ads:serve` scopes + implications |
| `app/auth/deps.py` | Add `require_api_key_auth` dependency |
| `app/models.py` | Add Pydantic models for API request/response |
| `app/main.py` | Register `ads_api_router` |
| `app/core/settings.py` | Add `ad_webhooks_table_name` |
| `app/core/tables.py` | Add `ad_webhooks` table handle |
| `scripts/local-ddb-init.py` | Add `ad_webhooks` table definition |
| `frontend/src/api/types.ts` | Add `ads:*` scope types |
| `frontend/src/pages/settings/ApiKeysPage.tsx` | Show `ads:*` scopes in key creation UI |

## 10. Acceptance Criteria

1. API keys with `ads:manage` scope can perform full CRUD on campaigns, creatives, budgets, and webhooks via `/api/v1/ads/` endpoints
2. API keys with `ads:read` scope can query analytics and list resources but cannot create/modify
3. API keys with `ads:serve` scope can only use sandbox endpoints
4. Rate limiting enforces 1000 requests/minute per key with 429 response on breach
5. Webhook endpoints register, list, delete, and test-deliver with HMAC-SHA256 signing
6. Analytics endpoints return correct aggregated metrics for date ranges
7. Sandbox mode isolates test data from production data
8. Bulk operations process up to 100 items per request with partial-failure handling
9. All 18 E2E tests pass in `frontend/e2e/ads-api.spec.ts`
10. OpenAPI documentation auto-generated at `/openapi.json` includes all `/api/v1/ads/` endpoints

---

## Codebase References

| File | Line(s) | What |
|------|---------|------|
| `app/services/api_keys.py` | — | Existing API key service (generation, hashing, validation) |
| `app/services/api_key_capabilities.py` | 5, 45, 57 | `CANONICAL_API_KEY_CAPABILITIES` (line 5 — no `ads:*` scopes), `normalize_api_key_capabilities` (line 45), `expand_api_key_capabilities` (line 57) |
| `app/core/tables.py` | 18, 142 | Existing `api_keys` table handle |
| `app/services/ad_placement.py` | 25, 222 | Existing ad placement (dev creatives, impression recording) |
| `app/routers/ads_api.py` | — | Does not exist yet — new implementation required |

---

## Testing Strategy


### Unit Tests (pytest)


**Test file**: `tests/test_ads_api.py`


**Mock setup**: moto for DynamoDB tables, `unittest.mock.patch` for external services (S3, Cognito, Stripe mock). All DDB tables created in-memory via moto `@mock_dynamodb` decorator.


| Test Function | Verifies |
|---|---|
| `test_create_ads_api` | Creates record with correct fields and generated ID |
| `test_create_ads_api_validation` | Rejects invalid input (missing required fields, out-of-range values) |
| `test_get_ads_api_found` | Returns correct record by ID |
| `test_get_ads_api_not_found` | Returns None for non-existent ID |
| `test_list_ads_api` | Returns all records for the given scope/owner |
| `test_update_ads_api` | Updates mutable fields and sets updated_at |
| `test_delete_ads_api` | Removes record; subsequent get returns None |
| `test_ads_api_owner_check` | Rejects operations from non-owner users |
| `test_ads_api_admin_only` | Admin/root endpoints reject USER role with 403 |
| `test_ads_api_concurrent_write` | Conditional update prevents stale overwrites |

### Integration Tests


Cross-service tests with real DDB (moto), verifying end-to-end flows:


1. Full CRUD lifecycle: create -> read -> update -> delete with real DDB (moto)
2. Authorization enforcement: non-owner access returns 403/404
3. Admin review/approval workflow with role-gated endpoints
4. Concurrent write safety: conditional updates prevent stale overwrites
5. Edge case: empty list returns `[]` not error; missing optional fields use defaults

### E2E Tests (Playwright)


**Test file**: `frontend/e2e/ads-api.spec.ts`


**Auth setup**:
- Cookie auth: `injectAuth(page, "alice")` for UI session tests
- CSRF header: `headers: { "x-csrf-token": sessions[identity].csrf_token }`
- Bearer auth: global `request` fixture for API-only tests (bypasses CSRF)
- Admin auth: `injectAuth(page, "root")` for admin endpoints

| # | Test | Key Assertion |
|---|------|--------------|
| 1 | Create resource via API | `expect(response.status()).toBe(201)` with correct fields |
| 2 | List resources returns array | `expect(response.status()).toBe(200)`; array length > 0 |
| 3 | Get single resource by ID | `expect(response.status()).toBe(200)`; fields match |
| 4 | Update resource | `expect(response.status()).toBe(200)`; GET confirms change |
| 5 | Delete resource | `expect(response.status()).toBe(200)`; subsequent GET 404 |
| 6 | Non-owner access blocked | `expect(response.status()).toBe(403)` or `toBe(404)` |
| 7 | Admin endpoint blocked for USER | `expect(response.status()).toBe(403)` |
| 8 | Unauthenticated request | `expect(response.status()).toBe(401)` |
| 9 | Invalid input rejected | `expect(response.status()).toBe(422)` |
| 10 | Duplicate/conflict handled | `expect(response.status()).toBe(409)` or idempotent 200 |
| 11 | UI page loads correctly | `page.getByRole("heading", { name: expectedTitle })` visible |
| 12 | UI create flow works | Click create -> fill form -> submit -> new item in list |
| 13 | UI status badges display | `page.getByText("Active")` or `page.getByText("Pending")` |
| 14 | Concurrent operations safe | Parallel requests both succeed or one gets 409 |
| 15 | Edge case: empty state | Empty list shows placeholder text, not error |

### Test Data Requirements


**Test users**: Alice = USER (primary actor), Bob = USER (secondary/viewer), Root = ROOT (admin reviewer), Charlie = ADMIN (scoped admin)


**DDB seed data**: Uses existing tables; no new tables required. See DDB access patterns in technical design section.


### CI/Pipeline


- **Feature flags**: `ADS_API_ENABLED` must be `true` in `.env.local`
- **Execution**: E2E tests run serially (1 worker, Chromium only) per `playwright.config.ts`; pytest can run in parallel
- **Retry safety**: All tests are idempotent; unique `TS = Date.now()` suffixed identifiers prevent cross-run collisions
- **Prerequisite**: `just restart` to create DDB tables and seed E2E sessions before running

## Dependencies & Merge Safety


### Depends On


| Ticket | What's Needed | Status | Can Overlap? |
|--------|--------------|--------|-------------|
| ADS-001 | Advertiser accounts + campaigns | Pending | No |
| ADS-002 | Creative management | Pending | No |
| ADS-008 | Analytics data for reporting | Pending | No |
| API key infra | `app/services/api_keys.py` | Implemented | N/A |

### Depended On By


| Ticket | What It Needs From This |
|--------|------------------------|
| (none currently identified) | -- |

### Merge Strategy


**Sequential (after ADS-008)**


- Must merge after: ADS-001, ADS-002, ADS-008
- Branch from `main` after dependencies are merged
- Can begin development in parallel but must rebase before merge
- DDB table creation is additive (no migration needed for new tables)

### Merge Checklist


- [ ] DDB tables verified (uses existing tables only)
- [ ] `.env.local` updated with any new environment variables
- [ ] Router registered in `app/main.py` (from `app/routers/ads_api.py`)
- [ ] All E2E tests passing (`just e2e` or targeted spec file)
- [ ] No breaking changes to existing endpoints or UI components
- [ ] `just restart` succeeds with new table definitions
