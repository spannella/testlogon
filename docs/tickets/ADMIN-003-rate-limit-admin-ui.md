# ADMIN-003: Rate Limit Admin UI

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-29  
**Priority**: Medium  
**Estimated effort**: 7-9 days  
**Dependencies**: Rate limiting (`rate_limit.py` — see `app/services/rate_limit.py`, `rate_limit_config.py` — see `app/services/rate_limit_config.py`, `rate_limit_store.py` — see `app/services/rate_limit_store.py`, `rate_limit_dashboard.py` — see `app/services/rate_limit_dashboard.py`), admin rate limits router (`admin_rate_limits.py` — see `app/routers/admin_rate_limits.py`, prefix `/ui/admin/rate-limits`, registered in `app/main.py:113,436`), admin auth (`auth/policy.py` — `require_root` at line 63)
<!-- NOTE: auth/deps.py does not have require_admin_session. The admin_rate_limits.py router uses require_root from app/auth/policy.py:63. -->

---

## 1. Overview & Motivation

### The Gap

The platform has a comprehensive rate limiting system:

- **`rate_limit.py`**: Core rate limiter with `check_rate_limit`, blocklist/allowlist management
- **`rate_limit_config.py`**: Per-endpoint group configuration with `get_group_config`, `save_group_override`, `get_all_configs`, `match_path_to_group`
- **`rate_limit_store.py`**: Blocklist/allowlist persistence (`add_to_blocklist`, `remove_from_blocklist`, `add_to_allowlist`, `remove_from_allowlist`, `list_blocklist`, `list_allowlist`)
- **`rate_limit_dashboard.py`**: Event logging and analytics (`log_rate_limit_event`, `query_events`, `get_top_offenders`)
- **`admin_rate_limits.py` router**: Config CRUD, events, top offenders, blocklist/allowlist management

All the backend pieces exist, but there is no admin UI. The router exposes 10 endpoints that are not consumed by any frontend page. Admins manage rate limiting through raw API calls, which is impractical for:

- Viewing current rate limit rules per endpoint group
- Editing rules (requests per window, window duration, burst allowance)
- Managing blocklists (viewing blocked IPs/users, adding/removing entries)
- Managing allowlists (viewing exempt IPs/users, adding/removing entries)
- Monitoring real-time rate limit hits
- Searching rate limit event logs

### Why This Is Needed

1. **Operational visibility**: When users report "429 Too Many Requests" errors, admins need to quickly check if the rate limit is too aggressive or if the user is genuinely abusing the API. Without a dashboard, debugging requires DynamoDB queries.

2. **Adaptive tuning**: As the platform grows, default rate limits may need adjustment. Some endpoints (e.g., search) may need higher limits; others (e.g., registration) may need lower limits. A UI enables non-engineer admins to tune limits.

3. **Blocklist response time**: When a bot attack hits the platform, admins need to block offending IPs within seconds. A UI with one-click blocking is faster than crafting API calls.

4. **Allowlist management**: VIP users, internal monitoring systems, and partner integrations may need rate limit exemptions. A UI makes exemption management self-service for operations teams.

5. **Compliance**: Some rate limit events may indicate attack attempts that must be reported. An event log with search enables security incident investigation.

### User Stories

- As a **platform admin**, I want to view all rate limit rules per endpoint group so I can understand current limits.
- As a **platform admin**, I want to edit rate limit rules so I can adjust limits when they are too aggressive or too lenient.
- As a **platform admin**, I want to view and manage the IP blocklist so I can block attackers and unblock false positives.
- As a **platform admin**, I want to view real-time rate limit hits so I can see which endpoints and users are hitting limits.
- As a **platform admin**, I want to search the rate limit event log so I can investigate incidents.
- As a **platform admin**, I want to see top offenders so I can identify and block persistent abusers.

### Architecture After This Change

```
Rate Limit Admin UI (/admin/rate-limits)
│
├── Rules Tab
│   ├── Endpoint group list
│   │   ├── Group name (e.g., "messaging", "auth", "search")
│   │   ├── Current rule: X requests / Y seconds
│   │   ├── Burst allowance
│   │   └── Status: default / overridden
│   │
│   ├── Edit Rule Dialog
│   │   ├── Requests per window (number input)
│   │   ├── Window duration (seconds)
│   │   ├── Burst allowance (number input)
│   │   └── Save / Reset to default
│   │
│   └── Rule diff badge (shows if override differs from default)
│
├── Blocklist Tab
│   ├── Blocked entries table (IP, user, API key, added_at, reason)
│   ├── Add block button (IP, user ID, or API key + reason)
│   ├── Remove block button (per entry)
│   └── Search/filter
│
├── Allowlist Tab
│   ├── Exempt entries table (IP/CIDR, added_at, reason)
│   ├── Add exemption button
│   ├── Remove exemption button
│   └── Search/filter
│
├── Live Dashboard Tab
│   ├── Real-time rate limit hits (auto-refreshing)
│   ├── Hits by endpoint group (bar chart)
│   ├── Hits by source (IP/user, top N)
│   └── Hit rate over time (line chart, last hour)
│
└── Event Log Tab
    ├── Searchable event log
    ├── Filters: date range, endpoint group, source IP/user, action
    ├── Event detail (timestamp, path, IP, user, action, remaining)
    └── Export as CSV
```

### Architecture & Data Flow

```
┌─────────────────┐    ┌──────────────────────┐    ┌──────────────────┐
│   Admin UI       │───▶│  FastAPI Router       │───▶│  DynamoDB Tables  │
│  (React + Tabs)  │    │  admin_rate_limits.py │    │  rate_limit_conf  │
│                  │    │                       │    │  rate_limit_store │
│  Rules | Block   │    │  GET  /config         │    │  rate_limit_dash  │
│  Allow | Live    │    │  PUT  /config         │    │                  │
│  Events          │    │  GET  /events         │    └──────────────────┘
└──────┬───────────┘    │  GET  /live-summary   │
       │                │  POST /blocklist      │
       │ React Query    │  POST /allowlist      │
       │ refetchInterval│  GET  /events/export  │
       │ =15s (live)    └───────────┬───────────┘
       │                            │
       ▼                            ▼
┌─────────────────┐    ┌──────────────────────┐
│  Auto-refresh    │    │  Service Layer        │
│  useQuery({     │    │  rate_limit_config    │
│   refetchInterval│    │  rate_limit_store     │
│   : 15000       │    │  rate_limit_dashboard │
│  })             │    └──────────────────────┘
└─────────────────┘

Request Flow — Config Update:
  Browser → PUT /v1/admin/rate-limits/config
         → require_root (cookie auth + CSRF check)
         → save_group_override(group, requests_per_window, window_seconds, burst)
         → DDB PutItem: PK=RATE_CONFIG, SK=GROUP#{group_name}
         → return updated config with is_override=true

Request Flow — Live Summary:
  Browser → GET /v1/admin/rate-limits/live-summary?hours=1
         → require_root
         → query_events(start=now-3600, end=now, limit=1000)
         → _group_by(events, "group") → by_group counts
         → _top_n(events, "source_ip", 20) → top sources
         → _bucket_by_time(events, 300) → 5-min time series
         → return LiveSummary JSON

Request Flow — CSV Export:
  Browser → GET /v1/admin/rate-limits/events/export?start=X&end=Y
         → require_root
         → query_events(start, end, limit=10000)
         → _events_to_csv(events)
         → return Response(media_type="text/csv")
```

---

## 2. Current State Analysis

### 2.1 Rate Limit Config (`app/services/rate_limit_config.py`)

Existing functions (verified):
- `get_group_config(group)` (line 126): Get rate limit config for an endpoint group (with defaults)
- `save_group_override(group, *, admin_sub, ...)` (line 164): Save custom config for a group
- `get_all_configs()` (line 199): Get all configs (default + overrides)
- `match_path_to_group(path)` (line 212): Map request path to rate limit group

Config fields per group: `requests_per_window`, `window_seconds`, `burst`.

### 2.2 Rate Limit Store (`app/services/rate_limit_store.py`)

Existing functions (verified):
- `check_rate_limit(key, group)` (line 26): Check if request is within limits
- `is_blocked(ip)` (line 86): Check if IP is blocked
- `is_allowlisted(ip)` (line 99): Check if IP is allowlisted
- `add_to_blocklist(ip, *, reason, admin_sub)` (line 129) / `remove_from_blocklist(ip)` (line 150)
- `add_to_allowlist(cidr, *, reason, admin_sub)` (line 154) / `remove_from_allowlist(cidr)` (line 172)
- `list_blocklist()` (line 176) / `list_allowlist()` (line 188)

### 2.3 Rate Limit Dashboard (`app/services/rate_limit_dashboard.py`)

Existing functions (verified):
- `log_rate_limit_event(...)` (line 23): Log a rate limit event
- `query_events(*, start, end, group, source, limit)` (line 66): Search events
- `get_top_offenders(*, hours, limit)` (line 116): Top rate limit violators

### 2.4 Admin Rate Limits Router (`app/routers/admin_rate_limits.py`)

Existing endpoints (prefix `/ui/admin/rate-limits` — see line 32, auth: `require_root` from `app/auth/policy.py:63`, registered in `app/main.py:113,436`):
- `GET /config` (line 63): Get all rate limit configs — `get_config()`
- `PUT /config` (line 93): Update config for a group — `update_config()`
- `GET /events` (line 132): Query rate limit events — `get_events()`
- `GET /top-offenders` (line 147): Top offenders — `top_offenders()`
- `POST /blocklist` (line 160): Add to blocklist — `add_blocklist()`
- `DELETE /blocklist/{entry_id}` (line 179): Remove from blocklist — `delete_blocklist()`
- `POST /allowlist` (line 189): Add to allowlist — `add_allowlist_entry()`
- `DELETE /allowlist/{entry_id}` (line 206): Remove from allowlist — `delete_allowlist_entry()`
- `GET /blocklist` (line 216): List blocklist — `get_blocklist()`
- `GET /allowlist` (line 222): List allowlist — `get_allowlist()`

### 2.5 Existing Frontend

A `RateLimitDashboard.tsx` (544 lines) already exists at `frontend/src/pages/admin/RateLimitDashboard.tsx`, registered in `App.tsx` at line 202 (`/admin/rate-limits`). It has blocklist/allowlist management, event log, top offenders, and a `RateLimitConfigPanel` (see `frontend/src/pages/admin/RateLimitConfigPanel.tsx`). An `adminRateLimits.ts` API endpoints file (122 lines) also exists at `frontend/src/api/endpoints/adminRateLimits.ts`.

### 2.6 Gaps
<!-- NOTE: Several "gaps" are already partially addressed by the existing RateLimitDashboard.tsx. -->

1. ~~No frontend UI for any of the above~~ — **CORRECTED**: A 544-line `RateLimitDashboard.tsx` already exists with blocklist/allowlist CRUD, event log, top offenders, and config panel
2. No real-time rate limit hit visualization (auto-refreshing live summary)
3. No rule diff display (default vs override badge)
4. ~~No event log search UI~~ — partially exists in current dashboard
5. No event export functionality (CSV export)
6. No live auto-refreshing dashboard with time series charts

---

## 3. Technical Design

### 3.1 Backend Enhancements

The backend already has all necessary endpoints. Minor additions needed:

**New endpoint: Real-time hit summary**

```python
@router.get("/live-summary")
async def live_summary(
    user: AuthenticatedUser = Depends(require_root),
    hours: int = Query(default=1, ge=1, le=24),
):
    """Get rate limit hit summary for the last N hours.

    Returns hits grouped by endpoint group and source,
    plus a time series (5-minute buckets).
    """
    events = query_events(
        start=now_ts() - hours * 3600,
        end=now_ts(),
        limit=1000,
    )
    return {
        "by_group": _group_by(events, "group"),
        "by_source": _top_n(events, "source_ip", 20),
        "time_series": _bucket_by_time(events, 300),  # 5-min buckets
        "total_hits": len(events),
        "window_hours": hours,
    }
```

**New endpoint: Event export**

```python
@router.get("/events/export")
async def export_events(
    user: AuthenticatedUser = Depends(require_root),
    start: int = Query(...),
    end: int = Query(...),
    group: str = Query(default=None),
):
    """Export rate limit events as CSV."""
    events = query_events(start=start, end=end, group=group, limit=10000)
    csv_content = _events_to_csv(events)
    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=rate-limit-events.csv"},
    )
```

### 3.2 DynamoDB Access Patterns

| Access Pattern | Table | PK | SK / GSI | Query Type | Example |
|---------------|-------|-----|----------|------------|---------|
| Get all rate limit configs | `rate_limit_config` | `RATE_CONFIG` | SK begins_with `GROUP#` | Query | All endpoint group configs |
| Get single group config | `rate_limit_config` | `RATE_CONFIG` | SK = `GROUP#{group_name}` | GetItem | Config for "messaging" group |
| Save group override | `rate_limit_config` | `RATE_CONFIG` | SK = `GROUP#{group_name}` | PutItem | Update messaging limits |
| Delete group override (reset) | `rate_limit_config` | `RATE_CONFIG` | SK = `GROUP#{group_name}` | DeleteItem | Reset messaging to defaults |
| List blocklist entries | `rate_limit_store` | `BLOCKLIST` | SK begins_with `IP#` | Query | All blocked IPs |
| Add to blocklist | `rate_limit_store` | `BLOCKLIST` | SK = `IP#{ip_address}` | PutItem | Block 192.168.1.100 |
| Remove from blocklist | `rate_limit_store` | `BLOCKLIST` | SK = `IP#{ip_address}` | DeleteItem | Unblock IP |
| List allowlist entries | `rate_limit_store` | `ALLOWLIST` | SK begins_with `CIDR#` | Query | All allowed CIDRs |
| Add to allowlist | `rate_limit_store` | `ALLOWLIST` | SK = `CIDR#{cidr}` | PutItem | Allow 10.0.0.0/8 |
| Remove from allowlist | `rate_limit_store` | `ALLOWLIST` | SK = `CIDR#{cidr}` | DeleteItem | Remove exemption |
| Query events by time range | `rate_limit_dashboard` | `EVENTS#{date}` | SK between start and end timestamps | Query (range) | Events in last hour |
| Query events by group | `rate_limit_dashboard` | `EVENTS#{date}` | FilterExpression on `group` | Query + Filter | Events for "auth" group |
| Get top offenders | `rate_limit_dashboard` | `OFFENDERS` | SK descending, Limit=N | Query | Top 20 offenders by count |

### 3.3 Updated Router: `app/routers/admin_rate_limits.py`

Add 2 new endpoints to existing router:
<!-- NOTE: Actual router prefix is /ui/admin/rate-limits (line 32 of admin_rate_limits.py), not /v1/admin/rate-limits -->

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/ui/admin/rate-limits/live-summary` | `require_root` | Real-time hit summary |
| GET | `/ui/admin/rate-limits/events/export` | `require_root` | Event CSV export |

Full endpoint list (existing + new):

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/config` | `require_root` | All rate limit configs |
| PUT | `/config` | `require_root` | Update group config |
| GET | `/events` | `require_root` | Query events |
| GET | `/events/export` | `require_root` | Export events CSV |
| GET | `/top-offenders` | `require_root` | Top offenders |
| GET | `/live-summary` | `require_root` | Real-time hit summary |
| GET | `/blocklist` | `require_root` | List blocklist |
| POST | `/blocklist` | `require_root` | Add to blocklist |
| DELETE | `/blocklist/{entry_id}` | `require_root` | Remove from blocklist |
| GET | `/allowlist` | `require_root` | List allowlist |
| POST | `/allowlist` | `require_root` | Add to allowlist |
| DELETE | `/allowlist/{entry_id}` | `require_root` | Remove from allowlist |

### 3.4 API Request/Response Examples

**GET /v1/admin/rate-limits/config**

```json
// Response 200
{
  "groups": [
    {
      "group": "messaging",
      "requests_per_window": 100,
      "window_seconds": 60,
      "burst": 20,
      "is_override": false
    },
    {
      "group": "auth",
      "requests_per_window": 10,
      "window_seconds": 60,
      "burst": 5,
      "is_override": false
    },
    {
      "group": "search",
      "requests_per_window": 200,
      "window_seconds": 60,
      "burst": 50,
      "is_override": true
    }
  ]
}
```

**PUT /v1/admin/rate-limits/config**

```json
// Request
{
  "group": "messaging",
  "requests_per_window": 200,
  "window_seconds": 60,
  "burst": 40
}

// Response 200
{
  "ok": true,
  "group": "messaging",
  "requests_per_window": 200,
  "window_seconds": 60,
  "burst": 40,
  "is_override": true,
  "updated_by": "root.admin@testdev.local",
  "updated_at": 1748500000
}
```

**GET /v1/admin/rate-limits/events?limit=5&group=auth**

```json
// Response 200
{
  "events": [
    {
      "timestamp": 1748499900,
      "path": "/ui/auth/login",
      "group": "auth",
      "source_ip": "203.0.113.42",
      "user_id": null,
      "action": "limited",
      "remaining": 0
    },
    {
      "timestamp": 1748499850,
      "path": "/ui/auth/register",
      "group": "auth",
      "source_ip": "198.51.100.17",
      "user_id": null,
      "action": "allowed",
      "remaining": 3
    }
  ],
  "next_cursor": "eyJsYXN0..."
}
```

**GET /v1/admin/rate-limits/live-summary?hours=1**

```json
// Response 200
{
  "by_group": {
    "auth": 45,
    "messaging": 12,
    "search": 8,
    "billing": 3
  },
  "by_source": [
    {"source_ip": "203.0.113.42", "count": 28},
    {"source_ip": "198.51.100.17", "count": 15},
    {"source_ip": "192.0.2.99", "count": 7}
  ],
  "time_series": [
    {"bucket": "2026-05-29T14:00", "count": 12},
    {"bucket": "2026-05-29T14:05", "count": 8},
    {"bucket": "2026-05-29T14:10", "count": 15},
    {"bucket": "2026-05-29T14:15", "count": 22}
  ],
  "total_hits": 68,
  "window_hours": 1
}
```

**POST /v1/admin/rate-limits/blocklist**

```json
// Request
{
  "ip": "192.168.1.100",
  "reason": "Automated bot attack detected"
}

// Response 201
{
  "entry_id": "blk_a1b2c3d4",
  "ip": "192.168.1.100",
  "reason": "Automated bot attack detected",
  "admin_sub": "root.admin@testdev.local",
  "added_at": 1748500100
}
```

**POST /v1/admin/rate-limits/allowlist**

```json
// Request
{
  "cidr": "10.0.0.0/8",
  "reason": "Internal monitoring infrastructure"
}

// Response 201
{
  "entry_id": "alw_e5f6g7h8",
  "cidr": "10.0.0.0/8",
  "reason": "Internal monitoring infrastructure",
  "admin_sub": "root.admin@testdev.local",
  "added_at": 1748500200
}
```

**GET /v1/admin/rate-limits/top-offenders?hours=24&limit=5**

```json
// Response 200
[
  {"source_ip": "203.0.113.42", "hit_count": 1247, "last_hit_at": 1748499900},
  {"source_ip": "198.51.100.17", "hit_count": 856, "last_hit_at": 1748499800},
  {"source_ip": "192.0.2.99", "hit_count": 342, "last_hit_at": 1748499700}
]
```

**GET /v1/admin/rate-limits/events/export?start=1748400000&end=1748500000**

```
// Response 200 (text/csv)
timestamp,path,group,source_ip,user_id,action,remaining
1748499900,/ui/auth/login,auth,203.0.113.42,,limited,0
1748499850,/ui/auth/register,auth,198.51.100.17,,allowed,3
...
```

### 3.5 Pydantic Models (`app/models.py`)

```python
class RateLimitGroupConfig(BaseModel):
    group: str
    requests_per_window: int = Field(ge=1, le=100000)
    window_seconds: int = Field(ge=1, le=86400)
    burst: int = Field(ge=0, le=10000)
    is_override: bool  # True if custom, False if default

class RateLimitConfigUpdate(BaseModel):
    group: str = Field(min_length=1, max_length=100)
    requests_per_window: Optional[int] = Field(default=None, ge=1, le=100000)
    window_seconds: Optional[int] = Field(default=None, ge=1, le=86400)
    burst: Optional[int] = Field(default=None, ge=0, le=10000)

    @field_validator("group", mode="before")
    @classmethod
    def normalize_group(cls, v):
        if isinstance(v, str):
            return v.strip().lower().replace(" ", "_")
        return v

class RateLimitEvent(BaseModel):
    timestamp: int
    path: str
    group: str
    source_ip: str
    user_id: Optional[str] = None
    action: str  # "allowed", "limited", "blocked"
    remaining: int

class LiveSummary(BaseModel):
    by_group: Dict[str, int]
    by_source: List[Dict[str, Any]]
    time_series: List[Dict[str, Any]]
    total_hits: int
    window_hours: int

class BlocklistEntry(BaseModel):
    entry_id: str
    ip: str
    reason: str
    admin_sub: str
    added_at: int

class AllowlistEntry(BaseModel):
    entry_id: str
    cidr: str
    reason: str
    admin_sub: str
    added_at: int

class BlocklistAdd(BaseModel):
    ip: str = Field(min_length=1, max_length=45)
    reason: str = Field(default="", max_length=500)

    @field_validator("ip", mode="before")
    @classmethod
    def validate_ip_format(cls, v):
        """Basic IP format validation."""
        if isinstance(v, str):
            v = v.strip()
            parts = v.split(".")
            if len(parts) != 4:
                raise ValueError("IP must be IPv4 format (x.x.x.x)")
        return v

class AllowlistAdd(BaseModel):
    cidr: str = Field(min_length=1, max_length=49)
    reason: str = Field(default="", max_length=500)

    @field_validator("cidr", mode="before")
    @classmethod
    def validate_cidr_format(cls, v):
        """Basic CIDR format validation."""
        if isinstance(v, str):
            v = v.strip()
            if "/" not in v:
                raise ValueError("CIDR must include prefix length (e.g., 10.0.0.0/8)")
        return v
```

### 3.6 Error Handling Matrix

| Scenario | HTTP Status | Error Message | Recovery Action |
|----------|-------------|---------------|-----------------|
| Non-root user accesses any endpoint | 403 | "Forbidden: root role required" | Escalate to root role |
| Invalid group name (empty) | 422 | "group must have at least 1 character" | Provide valid group name |
| requests_per_window out of range | 422 | "requests_per_window must be >= 1 and <= 100000" | Adjust value within range |
| window_seconds out of range | 422 | "window_seconds must be >= 1 and <= 86400" | Use 1-86400 range |
| burst exceeds maximum | 422 | "burst must be >= 0 and <= 10000" | Lower burst value |
| Invalid IP format for blocklist | 422 | "IP must be IPv4 format (x.x.x.x)" | Provide valid IPv4 |
| Invalid CIDR format for allowlist | 422 | "CIDR must include prefix length (e.g., 10.0.0.0/8)" | Include /prefix |
| Self-block (admin's own IP) | 400 | "Cannot block your own IP address" | Use a different IP |
| Blocklist entry not found | 404 | "Blocklist entry not found" | Verify entry_id |
| Allowlist entry not found | 404 | "Allowlist entry not found" | Verify entry_id |
| Blocklist capacity exceeded (>10000) | 400 | "Maximum 10000 blocklist entries" | Remove old entries first |
| Event query range too large (>30 days) | 400 | "Event query range must not exceed 30 days" | Narrow the time range |
| Export query returns too many events | 200 | Returns first 10000 events (truncated) | Narrow the date range |
| Live summary with invalid hours | 422 | "hours must be >= 1 and <= 24" | Use 1-24 range |
| DynamoDB query timeout | 500 | "Internal server error" | Retry; check DDB health |

### 3.7 Frontend: Rate Limit Admin Page

**Route**: `/admin/rate-limits` in `frontend/src/App.tsx` (see line 202 — route already exists)  
**Page**: `frontend/src/pages/admin/RateLimitDashboard.tsx` (see existing 544-line file — already registered via lazy import at App.tsx line 62)
<!-- NOTE: The page is at frontend/src/pages/admin/RateLimitDashboard.tsx (not in a rateLimits/ subdirectory). It already has blocklist/allowlist CRUD, event log, top offenders, and a RateLimitConfigPanel. This ticket should extend the existing page rather than creating a new one. -->

#### Frontend Component Tree

```
RateLimitDashboard
├── Tabs (shadcn/ui)
│   ├── TabsTrigger "Rules"
│   ├── TabsTrigger "Blocklist"
│   ├── TabsTrigger "Allowlist"
│   ├── TabsTrigger "Live Dashboard"
│   └── TabsTrigger "Event Log"
│
├── TabsContent "rules"
│   └── Card
│       ├── CardHeader → "Rate Limit Rules by Endpoint Group"
│       └── CardContent
│           ├── Table
│           │   ├── TableHeader (Group | Requests/Window | Window(s) | Burst | Status | Actions)
│           │   └── TableBody
│           │       └── TableRow (per config)
│           │           ├── TableCell → group name
│           │           ├── TableCell → requests_per_window
│           │           ├── TableCell → window_seconds
│           │           ├── TableCell → burst
│           │           ├── TableCell → Badge (Custom | Default)
│           │           └── TableCell → Button("Edit") + Button("Reset", conditional)
│           └── EditRuleDialog (open, config, onSave, onCancel)
│
├── TabsContent "blocklist"
│   └── Card
│       ├── CardHeader → "IP Blocklist" + Button("Block IP")
│       └── CardContent
│           ├── SearchInput (filter blocklist entries)
│           ├── BlocklistTable (entries, onRemove)
│           └── AddBlockDialog (open, onAdd)
│
├── TabsContent "allowlist"
│   └── Card
│       ├── CardHeader → "IP/CIDR Allowlist" + Button("Add Exemption")
│       └── CardContent
│           ├── AllowlistTable (entries, onRemove)
│           └── AddAllowDialog (open, onAdd)
│
├── TabsContent "live"
│   ├── KpiCardRow
│   │   ├── KpiCard (title="Total Hits (1h)", value)
│   │   ├── KpiCard (title="Top Group", value)
│   │   └── KpiCard (title="Top Source", value)
│   ├── HitTimelineChart (data={time_series})
│   └── div.grid
│       ├── GroupHitsChart (data={by_group})
│       └── TopSourcesTable (data={by_source})
│
└── TabsContent "events"
    └── Card
        ├── CardHeader → "Event Log" + Button("Export CSV")
        └── CardContent
            ├── EventSearchForm (onSearch)
            │   ├── DateRangePicker (start, end)
            │   ├── Select (group filter)
            │   └── Input (source IP/user filter)
            └── EventTable (events, onLoadMore)
```

#### TypeScript Props Interfaces

```typescript
interface EditRuleDialogProps {
  open: boolean;
  config: RateLimitGroupConfig | null;
  onSave: (group: string, updates: RateLimitConfigUpdate) => void;
  onCancel: () => void;
}

interface BlocklistTableProps {
  entries: BlocklistEntry[];
  onRemove: (entryId: string) => void;
  loading?: boolean;
}

interface AllowlistTableProps {
  entries: AllowlistEntry[];
  onRemove: (entryId: string) => void;
  loading?: boolean;
}

interface AddBlockDialogProps {
  open: boolean;
  onAdd: (data: { ip: string; reason?: string }) => void;
  onOpenChange: (open: boolean) => void;
}

interface HitTimelineChartProps {
  data: Array<{ bucket: string; count: number }>;
  loading?: boolean;
}

interface GroupHitsChartProps {
  data: Record<string, number>;
}

interface TopSourcesTableProps {
  data: Array<{ source_ip: string; count: number }>;
}

interface EventSearchFormProps {
  onSearch: (params: {
    start?: number;
    end?: number;
    group?: string;
    source?: string;
  }) => void;
}

interface EventTableProps {
  events: RateLimitEvent[];
  onLoadMore?: () => void;
  hasMore?: boolean;
}
```

```tsx
<Tabs defaultValue="rules">
  <TabsList>
    <TabsTrigger value="rules">Rules</TabsTrigger>
    <TabsTrigger value="blocklist">Blocklist</TabsTrigger>
    <TabsTrigger value="allowlist">Allowlist</TabsTrigger>
    <TabsTrigger value="live">Live Dashboard</TabsTrigger>
    <TabsTrigger value="events">Event Log</TabsTrigger>
  </TabsList>

  <TabsContent value="rules">
    <Card>
      <CardHeader><CardTitle>Rate Limit Rules by Endpoint Group</CardTitle></CardHeader>
      <CardContent>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Group</TableHead>
              <TableHead>Requests / Window</TableHead>
              <TableHead>Window (seconds)</TableHead>
              <TableHead>Burst</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {configs.map(c => (
              <TableRow key={c.group}>
                <TableCell>{c.group}</TableCell>
                <TableCell>{c.requests_per_window}</TableCell>
                <TableCell>{c.window_seconds}</TableCell>
                <TableCell>{c.burst}</TableCell>
                <TableCell>
                  <Badge variant={c.is_override ? "default" : "secondary"}>
                    {c.is_override ? "Custom" : "Default"}
                  </Badge>
                </TableCell>
                <TableCell>
                  <Button size="sm" onClick={() => setEditGroup(c)}>Edit</Button>
                  {c.is_override && (
                    <Button size="sm" variant="ghost" onClick={() => resetGroup(c.group)}>Reset</Button>
                  )}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </CardContent>
    </Card>

    <EditRuleDialog
      open={!!editGroup}
      config={editGroup}
      onSave={handleSaveRule}
      onCancel={() => setEditGroup(null)}
    />
  </TabsContent>

  <TabsContent value="blocklist">
    <Card>
      <CardHeader>
        <CardTitle>IP Blocklist</CardTitle>
        <Button size="sm" onClick={() => setShowAddBlock(true)}>
          <ShieldBan className="mr-2 h-4 w-4" /> Block IP
        </Button>
      </CardHeader>
      <CardContent>
        <BlocklistTable entries={blocklist} onRemove={handleRemoveBlock} />
      </CardContent>
    </Card>
    <AddBlockDialog open={showAddBlock} onAdd={handleAddBlock} />
  </TabsContent>

  <TabsContent value="allowlist">
    <Card>
      <CardHeader>
        <CardTitle>IP/CIDR Allowlist</CardTitle>
        <Button size="sm" onClick={() => setShowAddAllow(true)}>
          <ShieldCheck className="mr-2 h-4 w-4" /> Add Exemption
        </Button>
      </CardHeader>
      <CardContent>
        <AllowlistTable entries={allowlist} onRemove={handleRemoveAllow} />
      </CardContent>
    </Card>
    <AddAllowDialog open={showAddAllow} onAdd={handleAddAllow} />
  </TabsContent>

  <TabsContent value="live">
    <div className="space-y-4">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <KpiCard title="Total Hits (1h)" value={liveSummary.total_hits} />
        <KpiCard title="Top Group" value={topGroup} />
      </div>
      <Card>
        <CardHeader><CardTitle>Hits Over Time</CardTitle></CardHeader>
        <CardContent><HitTimelineChart data={liveSummary.time_series} /></CardContent>
      </Card>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Card>
          <CardHeader><CardTitle>Hits by Group</CardTitle></CardHeader>
          <CardContent><GroupHitsChart data={liveSummary.by_group} /></CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle>Top Sources</CardTitle></CardHeader>
          <CardContent><TopSourcesTable data={liveSummary.by_source} /></CardContent>
        </Card>
      </div>
    </div>
  </TabsContent>

  <TabsContent value="events">
    <Card>
      <CardHeader>
        <CardTitle>Rate Limit Event Log</CardTitle>
        <Button size="sm" variant="outline" onClick={handleExport}>
          <Download className="mr-2 h-4 w-4" /> Export CSV
        </Button>
      </CardHeader>
      <CardContent>
        <EventSearchForm onSearch={handleSearch} />
        <EventTable events={events} />
      </CardContent>
    </Card>
  </TabsContent>
</Tabs>
```

### 3.8 Frontend API (`frontend/src/api/endpoints/adminRateLimits.ts`)
<!-- NOTE: This file already exists (122 lines) with types and API wrappers for rate limit config, events, blocklist, and allowlist. New endpoints (live-summary, events/export) should be added to the existing file. -->

```typescript
// Config
export const getRateLimitConfigs = () =>
  client.get("/ui/admin/rate-limits/config");

export const updateRateLimitConfig = (data: RateLimitConfigUpdate) =>
  client.put("/ui/admin/rate-limits/config", data);

// Events
export const queryRateLimitEvents = (params: {
  start?: number; end?: number; group?: string; source?: string; limit?: number;
}) =>
  client.get("/ui/admin/rate-limits/events", { params });

export const exportRateLimitEvents = (params: { start: number; end: number; group?: string }) =>
  client.get("/ui/admin/rate-limits/events/export", { params, responseType: "blob" });

export const getTopOffenders = (params?: { hours?: number; limit?: number }) =>
  client.get("/ui/admin/rate-limits/top-offenders", { params });

export const getLiveSummary = (params?: { hours?: number }) =>
  client.get("/ui/admin/rate-limits/live-summary", { params });

// Blocklist
export const getBlocklist = () =>
  client.get("/ui/admin/rate-limits/blocklist");

export const addToBlocklist = (data: { ip: string; reason?: string }) =>
  client.post("/ui/admin/rate-limits/blocklist", data);

export const removeFromBlocklist = (entryId: string) =>
  client.delete(`/v1/admin/rate-limits/blocklist/${entryId}`);

// Allowlist
export const getAllowlist = () =>
  client.get("/ui/admin/rate-limits/allowlist");

export const addToAllowlist = (data: { cidr: string; reason?: string }) =>
  client.post("/ui/admin/rate-limits/allowlist", data);

export const removeFromAllowlist = (entryId: string) =>
  client.delete(`/v1/admin/rate-limits/allowlist/${encodeURIComponent(entryId)}`);
```

---

## 4. Implementation Plan

### Phase 1: Backend Enhancements (Days 1-2)

1. **`app/routers/admin_rate_limits.py`**: Add `live-summary` and `events/export` endpoints.
2. **`app/models.py`**: Add rate limit admin Pydantic models.

### Phase 2: Frontend (Days 2-6)

3. **`frontend/src/api/types.ts`**: Add rate limit admin TypeScript types.
4. **`frontend/src/api/endpoints/adminRateLimits.ts`**: New file. API wrappers.
5. **`frontend/src/pages/admin/rateLimits/RateLimitDashboard.tsx`**: New page with 5 tabs (rules, blocklist, allowlist, live dashboard, event log).
6. **`frontend/src/App.tsx`**: Add `/admin/rate-limits` route.
7. **`frontend/src/components/layout/Sidebar.tsx`**: Add "Rate Limits" admin nav link.

### Phase 3: E2E Tests (Days 7-9)

8. **`frontend/e2e/admin-rate-limits.spec.ts`**: 30 tests across 8 sections.

---

## 5. Observability

### 5.1 Metrics

| Metric Name | Type | Labels | Description |
|------------|------|--------|-------------|
| `admin_rate_limit_config_update_total` | counter | `group`, `admin_sub` | Config overrides applied |
| `admin_rate_limit_config_reset_total` | counter | `group`, `admin_sub` | Config reset to defaults |
| `admin_blocklist_add_total` | counter | `admin_sub` | IPs added to blocklist |
| `admin_blocklist_remove_total` | counter | `admin_sub` | IPs removed from blocklist |
| `admin_allowlist_add_total` | counter | `admin_sub` | CIDRs added to allowlist |
| `admin_allowlist_remove_total` | counter | `admin_sub` | CIDRs removed from allowlist |
| `admin_live_summary_requests_total` | counter | `admin_sub` | Live dashboard queries |
| `admin_events_export_total` | counter | `admin_sub` | CSV exports triggered |

### 5.2 Logging Events

| Event | Level | Fields | Trigger |
|-------|-------|--------|---------|
| `admin_rate_config_updated` | INFO | `group`, `old_values`, `new_values`, `admin_sub` | Config override saved |
| `admin_rate_config_reset` | INFO | `group`, `admin_sub` | Config reset to default |
| `admin_blocklist_ip_added` | WARN | `ip`, `reason`, `admin_sub` | IP blocked |
| `admin_blocklist_ip_removed` | INFO | `ip`, `admin_sub` | IP unblocked |
| `admin_allowlist_cidr_added` | INFO | `cidr`, `reason`, `admin_sub` | CIDR exempted |
| `admin_allowlist_cidr_removed` | INFO | `cidr`, `admin_sub` | CIDR exemption removed |
| `admin_self_block_attempt` | WARN | `ip`, `admin_sub` | Admin tried to block own IP |
| `admin_events_export` | INFO | `start`, `end`, `event_count`, `admin_sub` | CSV export generated |

### 5.3 Alerting Rules

| Alert | Condition | Severity | Action |
|-------|-----------|----------|--------|
| Blocklist size critical | `blocklist_count > 8000` (80% of 10K limit) | MEDIUM | Notify admin to clean up stale entries |
| Rate limit hits spike | `total_hits > 500` in 5-minute window | HIGH | Possible DDoS; auto-suggest top offenders for blocking |
| Config override divergence | Any group override > 10x default value | LOW | Review for potential misconfiguration |

---

## 6. Rollout Plan

### Phase 1: Backend (Feature Flag: `ADMIN_RATE_LIMITS_UI_ENABLED=false`)

| Step | Action | Validation |
|------|--------|------------|
| 1 | Deploy `live-summary` and `events/export` endpoints | API tests pass; Swagger shows new endpoints |
| 2 | Validate existing 10 endpoints work with new models | No regressions |

### Phase 2: Frontend (Feature Flag: `ADMIN_RATE_LIMITS_UI_ENABLED=true`)

| Step | Action | Validation |
|------|--------|------------|
| 3 | Deploy RateLimitDashboard with Rules tab only | Config table renders; edit dialog works |
| 4 | Enable Blocklist and Allowlist tabs | CRUD operations work end-to-end |
| 5 | Enable Live Dashboard tab | Auto-refresh shows real-time data |
| 6 | Enable Event Log tab with export | Search and CSV export functional |

### Phase 3: GA (Remove Feature Flag)

| Step | Action | Validation |
|------|--------|------------|
| 7 | Enable for all root users | All 30 E2E tests pass |
| 8 | Monitor live dashboard performance | No latency regression |
| 9 | Remove feature flag | Clean deploy |

### Feature Flags Table

| Flag | Default | Purpose |
|------|---------|---------|
| `ADMIN_RATE_LIMITS_UI_ENABLED` | `false` | Gates `/admin/rate-limits` route visibility |
| `RATE_LIMIT_LIVE_REFRESH_INTERVAL` | `15000` (ms) | Auto-refresh interval for live dashboard tab |

---

## 7. Performance Considerations

### 7.1 Latency Targets

| Endpoint | Target P50 | Target P99 | Notes |
|----------|-----------|-----------|-------|
| GET /config | < 100ms | < 300ms | Query all configs; small result set |
| PUT /config | < 100ms | < 250ms | Single PutItem |
| GET /events | < 200ms | < 600ms | Range query with limit; may require pagination |
| GET /events/export | < 2000ms | < 5000ms | Up to 10K events; CSV generation |
| GET /top-offenders | < 150ms | < 400ms | Pre-aggregated query |
| GET /live-summary | < 300ms | < 800ms | 1-hour event scan + aggregation |
| GET /blocklist | < 100ms | < 300ms | Query with begins_with |
| POST /blocklist | < 100ms | < 250ms | Single PutItem |
| DELETE /blocklist | < 100ms | < 250ms | Single DeleteItem |
| GET /allowlist | < 100ms | < 300ms | Query with begins_with |

### 7.2 Caching Strategy

- **Configs**: React Query `staleTime: 30_000` (30s). Configs rarely change; stale data is acceptable for display.
- **Blocklist/Allowlist**: React Query `staleTime: 15_000` (15s). Mutations invalidate the cache immediately.
- **Live Summary**: React Query `refetchInterval: 15_000` (15s auto-refresh). Stale time 0 for always-fresh data.
- **Events**: React Query `staleTime: 10_000` (10s). Search results cached until new search submitted.
- **Top Offenders**: React Query `staleTime: 60_000` (60s). Updated less frequently.
- **No backend caching**: All queries hit DDB directly. Live summary aggregation is computed on each request.

### 7.3 Pagination

- **Event log**: Cursor-based pagination using `LastEvaluatedKey` from DDB. Default `limit=50`, max `limit=200`.
- **Blocklist/Allowlist**: Non-paginated (expected < 10K entries). Full scan with `Limit=10000`.
- **CSV export**: Single large query with `limit=10000`. Exported as streaming response.
- **Live summary**: Non-paginated. Capped at 1000 recent events for aggregation.

---

## 8. Security Considerations

### 8.1 Role-Based Access
- All rate limit admin endpoints require ROOT role (not just ADMIN)
- Rate limit configuration is a security-critical function — misconfiguration can enable DDoS or lock out legitimate users

### 8.2 Blocklist Safety
- Blocklist additions take effect immediately (next request from that IP is rejected)
- Self-blocking prevention: the admin's own IP cannot be added to the blocklist
- Blocklist entries logged with admin identity and reason
- Maximum 10,000 blocklist entries to prevent memory exhaustion

### 8.3 Config Safety
- Minimum values enforced: `requests_per_window >= 1`, `window_seconds >= 1`
- Maximum values enforced to prevent effectively disabling rate limits
- Config changes take effect immediately (no restart required)
- Reset-to-default option removes overrides without breaking the system

### 8.4 Event Log Privacy
- Event logs contain IP addresses (PII in some jurisdictions)
- Event logs should not be cached (Cache-Control: no-store)
- CSV exports should be transmitted over HTTPS only

---

## 9. E2E Test Plan

**Test file**: `frontend/e2e/admin-rate-limits.spec.ts`

**Setup (beforeAll)**:
- Inject auth for Root, Alice
- Seed rate limit events via `log_rate_limit_event` (5 events for different groups)
- Seed 1 blocklist entry and 1 allowlist entry

**Section 555: Rate Limit Config API (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 1 | `Root retrieves all rate limit configs` | GET `/v1/admin/rate-limits/config` as Root -> 200; object with group names as keys, each has `requests_per_window`, `window_seconds`, `burst` |
| 2 | `Root updates group config` | PUT `/v1/admin/rate-limits/config` with `{group: "messaging", requests_per_window: 200}` -> 200; re-GET shows updated value |
| 3 | `Updated config marked as override` | re-GET config for "messaging" has `is_override: true` (or equivalent indicator) |
| 4 | `Non-root cannot access config` | GET as Alice -> 403 |

**Section 556: Blocklist & Allowlist API (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 5 | `Root views blocklist` | GET `/v1/admin/rate-limits/blocklist` as Root -> 200; array includes seeded entry |
| 6 | `Root adds IP to blocklist` | POST `/v1/admin/rate-limits/blocklist` with `{ip: "192.168.1.100", reason: "bot"}` -> 201; re-GET includes new entry |
| 7 | `Root removes IP from blocklist` | DELETE `/v1/admin/rate-limits/blocklist/{entry_id}` -> 200; re-GET excludes it |
| 8 | `Root adds CIDR to allowlist` | POST `/v1/admin/rate-limits/allowlist` with `{cidr: "10.0.0.0/8", reason: "internal"}` -> 201; re-GET includes entry |

**Section 557: Events & Top Offenders API (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 9 | `Root queries rate limit events` | GET `/v1/admin/rate-limits/events?limit=10` as Root -> 200; array with seeded events |
| 10 | `Events filterable by group` | GET with `?group=messaging` -> 200; all events have matching group |
| 11 | `Top offenders returns ranked list` | GET `/v1/admin/rate-limits/top-offenders?hours=24` -> 200; array sorted by hit count descending |
| 12 | `Event export returns CSV` | GET `/v1/admin/rate-limits/events/export?start=0&end=9999999999` -> 200; content-type contains `text/csv` |

**Section 558: Live Summary API (3 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 13 | `Root retrieves live summary` | GET `/v1/admin/rate-limits/live-summary?hours=1` as Root -> 200; `total_hits >= 0`, `by_group` is object, `time_series` is array |
| 14 | `Live summary includes top sources` | Response `by_source` is array of `{source_ip, count}` objects |
| 15 | `Non-root cannot access live summary` | GET as Alice -> 403 |

**Section 559: Input Validation Edge Cases (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 16 | `Invalid IP format rejected for blocklist` | POST with `{ip: "not-an-ip"}` -> 422; validation error |
| 17 | `Invalid CIDR format rejected for allowlist` | POST with `{cidr: "10.0.0.0"}` (no prefix) -> 422 |
| 18 | `Config update with zero requests_per_window rejected` | PUT with `requests_per_window: 0` -> 422 |
| 19 | `Config update with negative burst rejected` | PUT with `burst: -1` -> 422 |

**Section 560: Concurrent Operations (3 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 20 | `Duplicate blocklist add is idempotent` | POST same IP twice; both return success; list has one entry for that IP |
| 21 | `Config update during event query does not fail` | PUT config + GET events concurrently; both succeed |
| 22 | `Blocklist remove of non-existent entry returns 404` | DELETE random entry_id -> 404 |

**Section 561: Authorization Boundary Tests (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 23 | `Regular user cannot add to blocklist` | Alice POST blocklist -> 403 |
| 24 | `Regular user cannot remove from allowlist` | Alice DELETE allowlist -> 403 |
| 25 | `Regular user cannot export events` | Alice GET events/export -> 403 |
| 26 | `Regular user cannot update config` | Alice PUT config -> 403 |

**Section 562: Rate Limit Dashboard UI (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 27 | `Dashboard loads with Rules tab` | Root navigates to `/admin/rate-limits`; "Rules" tab active; config table visible with endpoint groups |
| 28 | `Blocklist tab shows entries` | Click "Blocklist" tab; blocklist table visible; seeded entry present |
| 29 | `Live dashboard shows summary` | Click "Live Dashboard" tab; KPI cards visible; "Total Hits" card present |
| 30 | `Event log tab with search` | Click "Event Log" tab; search form visible; event table visible |

---

## 10. Files to Create

| File | Purpose |
|------|---------|
| `frontend/e2e/admin-rate-limits.spec.ts` | E2E tests (30 tests, sections 555-562) |

## 11. Files to Modify

| File | Change |
|------|--------|
| `app/routers/admin_rate_limits.py` | Add `live-summary` and `events/export` endpoints (see existing router at line 32, prefix `/ui/admin/rate-limits`) |
| `app/models.py` | Add rate limit admin Pydantic models |
| `frontend/src/api/endpoints/adminRateLimits.ts` | Add `getLiveSummary` and `exportRateLimitEvents` wrappers to existing 122-line file <!-- NOTE: file already exists --> |
| `frontend/src/pages/admin/RateLimitDashboard.tsx` | Add Live Dashboard tab and Event Log enhancements to existing 544-line file <!-- NOTE: file already exists at this path, not in a rateLimits/ subdirectory --> |
| `frontend/src/api/types.ts` | Add rate limit admin TypeScript types |
| `frontend/src/App.tsx` | Route already exists at line 202 — no change needed <!-- NOTE: /admin/rate-limits route already registered --> |
| `frontend/src/components/layout/Sidebar.tsx` | Add "Rate Limits" admin nav link (if not already present) |

## 12. Acceptance Criteria

1. Rate limit rules displayed per endpoint group with current values and override status
2. Root can edit rules (requests per window, window duration, burst) with immediate effect
3. Blocklist manageable: view, add IP with reason, remove entry
4. Allowlist manageable: view, add CIDR with reason, remove entry
5. Live summary shows rate limit hits by group, by source, and over time
6. Event log searchable by date range, group, and source
7. Event export generates valid CSV
8. Top offenders ranked by hit count for configurable time window
9. All endpoints require ROOT role (403 for non-root)
10. All 30 E2E tests pass in `frontend/e2e/admin-rate-limits.spec.ts`

---

## Testing Strategy

### Unit Tests (pytest)

**Test file**: `tests/test_rate_limit_admin.py`

**Mock setup**: DynamoDB mocked via `moto`. Rate limit event logging mocked with `unittest.mock.patch("app.services.rate_limit_dashboard.log_rate_limit_event")` where needed. IP validation uses real logic (no mocking).

**Fixtures**:
- `rate_limit_tables`: moto-backed `rate_limit_config`, `rate_limit_store`, and `rate_limit_events` DDB tables
- `root_session`: Fake session dict `{"user_sub": "root.admin@testdev.local", "role": "ROOT"}`
- `sample_events`: Pre-seeded rate limit events across multiple groups and source IPs
- `sample_blocklist`: Pre-seeded blocklist entries for testing removal

**Test functions**:

| Function | What it tests |
|----------|---------------|
| `test_get_all_configs_returns_defaults` | `get_all_configs()` returns all endpoint groups with default values |
| `test_save_group_override_persists` | `save_group_override("messaging", requests_per_window=200)` persists and `get_group_config("messaging")` reflects change |
| `test_save_group_override_marks_is_override` | After override, config has `is_override=True` |
| `test_config_update_validates_min_requests` | `requests_per_window=0` raises validation error |
| `test_config_update_validates_max_burst` | `burst=10001` raises validation error |
| `test_config_update_validates_group_name` | Empty group name raises validation error |
| `test_add_to_blocklist_persists` | `add_to_blocklist("192.168.1.100", reason="bot")` and `is_blocked("192.168.1.100")` returns True |
| `test_remove_from_blocklist` | After `remove_from_blocklist`, `is_blocked` returns False |
| `test_blocklist_entry_not_found_returns_404` | Removing nonexistent entry returns 404 |
| `test_add_to_allowlist_with_cidr` | `add_to_allowlist("10.0.0.0/8")` and `is_allowlisted("10.0.0.1")` returns True |
| `test_invalid_ip_format_rejected` | `add_to_blocklist("not-an-ip")` raises validation error |
| `test_invalid_cidr_format_rejected` | `add_to_allowlist("10.0.0.0")` (no prefix) raises validation error |
| `test_query_events_by_time_range` | `query_events(start=T-3600, end=T)` returns only events within range |
| `test_query_events_by_group_filter` | `query_events(group="auth")` returns only auth group events |
| `test_get_top_offenders_sorted_by_count` | `get_top_offenders()` returns list sorted by `hit_count` descending |
| `test_live_summary_aggregates_by_group` | Live summary endpoint returns `by_group` dict with correct counts per group |
| `test_live_summary_buckets_time_series` | `time_series` has 5-minute buckets with correct counts |
| `test_live_summary_top_sources` | `by_source` returns top N source IPs by count |
| `test_events_export_csv_format` | Export returns valid CSV with header row and correct columns |
| `test_events_export_caps_at_10000` | Export with >10000 events returns exactly 10000 rows |
| `test_non_root_gets_403` | USER role on any endpoint returns 403 |
| `test_admin_role_gets_403` | ADMIN (non-root) role on any endpoint returns 403 (these endpoints require ROOT) |

### Integration Tests

**Test file**: `tests/test_rate_limit_admin_integration.py`

Tests with real moto DynamoDB (no patching of DDB calls):

| Test | What it validates |
|------|-------------------|
| `test_config_override_then_reset_roundtrip` | Override config, verify `is_override=True`, delete override row, verify config returns to default |
| `test_blocklist_add_remove_roundtrip` | Add IP, verify `is_blocked`, remove, verify no longer blocked |
| `test_allowlist_cidr_matching` | Add `10.0.0.0/8`, verify `10.1.2.3` is allowlisted, verify `192.168.1.1` is not |
| `test_event_query_pagination` | Seed 100 events, query with `limit=20`, use cursor for next page, verify all 100 retrieved |
| `test_live_summary_with_fresh_events` | Log events, immediately query live summary, verify counts match |
| `test_concurrent_blocklist_operations` | Add and remove different IPs concurrently, verify final state is correct |

### E2E Tests (Playwright)

**Test file**: `frontend/e2e/admin-rate-limits.spec.ts`
**Sections**: 555-562 (30 tests) as detailed in section 9 above.

**Auth pattern**: `injectAuth(page, "root")` for root operations; `injectAuth(page, "alice")` for authorization boundary tests.

**CSRF handling**: All POST/PUT/DELETE requests via `page.request` include `headers: { "x-csrf-token": sessions["root"].csrf_token }`.

**Setup/teardown**:
- `beforeAll`: Inject auth for Root and Alice. Seed 5 rate limit events via direct DDB writes to `rate_limit_events` table. Seed 1 blocklist entry and 1 allowlist entry via POST endpoints.
- `afterAll`: Remove seeded blocklist/allowlist entries. Reset any config overrides via DELETE or reset endpoint.

**Negative tests**: 403 (non-root on all endpoints including Alice as USER and Charlie as ADMIN), 404 (nonexistent blocklist entry removal), 422 (invalid IP, invalid CIDR, zero requests_per_window, negative burst)

**Key selectors**:
- Rules tab: `page.getByRole("tab", { name: /rules/i })`
- Blocklist tab: `page.getByRole("tab", { name: /blocklist/i })`
- Live dashboard tab: `page.getByRole("tab", { name: /live/i })`
- Config table row: `page.getByRole("row").filter({ hasText: "messaging" })`
- Block IP button: `page.getByRole("button", { name: /block ip/i })`
- Override badge: `page.getByText("Custom")` scoped within config row
- Export CSV button: `page.getByRole("button", { name: /export csv/i })`

### Test Data Requirements

**DDB seed data**:
- `rate_limit_events` table: 5 events with varying `group` (auth, messaging, search), `source_ip`, `action` (limited, allowed), `timestamp` within last hour
- `rate_limit_store` table (blocklist): PK=`BLOCKLIST`, SK=`IP#192.168.1.50` with `reason` and `added_at`
- `rate_limit_store` table (allowlist): PK=`ALLOWLIST`, SK=`CIDR#172.16.0.0/12` with `reason` and `added_at`

**Test user roles**:
- Root (ROOT): Full access to all rate limit admin endpoints
- Alice (USER): Non-root for 403 boundary tests

**Cleanup strategy**: `afterAll` removes blocklist/allowlist entries created during tests via DELETE endpoints. Config overrides are reset. Events are not cleaned (they accumulate harmlessly and are filtered by timestamp).

### CI/Pipeline Considerations

- **Feature flag**: `ADMIN_RATE_LIMITS_UI_ENABLED=true` in `.env.local` for E2E tests
- **No new DDB tables**: All required tables (`rate_limits`, `rate_limit_events`) already exist in `scripts/local-ddb-init.py`
- **Serial execution**: Blocklist tests depend on `beforeAll` seeding; config tests modify shared state — run in declared order
- **Retry safety**: Each test uses unique IPs/CIDRs with timestamp suffix (e.g., `192.168.${Math.floor(Date.now() % 255)}.100`) to avoid cross-retry collisions
- **Live summary timing**: Tests that validate live summary counts may see events from other tests in the same run; assert `total_hits >= expected` (not exact equality)

---

## Dependencies & Merge Safety

### Depends On (upstream)

| Ticket / Component | What's needed | Status | Can work start before dependency merges? |
|-------------------|---------------|--------|------------------------------------------|
| `app/services/rate_limit_config.py` | `get_all_configs`, `save_group_override`, `get_group_config` | **Implemented** (exists in codebase) | Yes — already merged |
| `app/services/rate_limit_store.py` | Blocklist/allowlist CRUD, `is_blocked`, `is_allowlisted` | **Implemented** (exists in codebase) | Yes — already merged |
| `app/services/rate_limit_dashboard.py` | `log_rate_limit_event`, `query_events`, `get_top_offenders` | **Implemented** (exists in codebase) | Yes — already merged |
| `app/routers/admin_rate_limits.py` | Existing 10-endpoint router (prefix `/ui/admin/rate-limits`) | **Implemented** (registered in `main.py:113,436`) | Yes — already merged |
| `app/auth/policy.py` | `require_root` auth dependency | **Implemented** (exists in codebase) | Yes — already merged |
| `frontend/src/pages/admin/RateLimitDashboard.tsx` | Existing 544-line dashboard page to extend | **Implemented** (exists in codebase) | Yes — already merged |
| `frontend/src/api/endpoints/adminRateLimits.ts` | Existing 122-line API wrappers | **Implemented** (exists in codebase) | Yes — already merged |

All upstream dependencies are already implemented and merged. This ticket has no blocking dependencies.

### Depended On By (downstream)

| Ticket | What it needs from ADMIN-003 |
|--------|------------------------------|
| None identified | No other tickets reference ADMIN-003 as a dependency |

### Merge Strategy

**Classification**: **Independent**

This ticket modifies existing files only (no new tables, no new services). It adds 2 endpoints to an existing router and enhances an existing frontend page.

- **No cross-ticket conflicts**: The `admin_rate_limits.py` router and `RateLimitDashboard.tsx` page are not modified by any other in-flight ticket
- **No new DDB tables**: Uses existing `rate_limits` and `rate_limit_events` tables
- **Feature flag gated**: `ADMIN_RATE_LIMITS_UI_ENABLED` defaults to `false`
- **Safe to merge to main independently** at any time

### Merge Checklist

- [ ] **DDB tables**: No new tables required. Existing `rate_limits` (line 842) and `rate_limit_events` (line 848) in `local-ddb-init.py` are sufficient
- [ ] **Settings**: Add `ADMIN_RATE_LIMITS_UI_ENABLED` and `RATE_LIMIT_LIVE_REFRESH_INTERVAL` to `app/core/settings.py` and `.env.local.example`
- [ ] **Router registration**: No new router registration needed — adding endpoints to existing `admin_rate_limits.py`
- [ ] **Frontend route**: Route `/admin/rate-limits` already exists in `App.tsx` line 202 — no change needed
- [ ] **Frontend sidebar**: Verify "Rate Limits" link already present in admin section of `Sidebar.tsx` (may already exist)
- [ ] **E2E tests**: All 30 tests in `frontend/e2e/admin-rate-limits.spec.ts` pass
- [ ] **Unit tests**: All tests in `tests/test_rate_limit_admin.py` pass
- [ ] **No breaking changes**: Existing 10 endpoints in `admin_rate_limits.py` unchanged; existing `RateLimitDashboard.tsx` UI extended (not replaced)
- [ ] **Feature flag default**: Verify `ADMIN_RATE_LIMITS_UI_ENABLED` defaults to `false` in production

---

## Codebase References

| File | Line(s) | What |
|------|---------|------|
| `app/services/rate_limit_config.py` | 126, 164, 199, 212 | Existing: `get_group_config`, `save_group_override`, `get_all_configs`, `match_path_to_group` |
| `app/services/rate_limit_store.py` | 26, 86, 99, 129, 150, 154, 172, 176, 188 | Existing: `check_rate_limit`, `is_blocked`, `is_allowlisted`, blocklist/allowlist CRUD |
| `app/services/rate_limit_dashboard.py` | 23, 66, 116 | Existing: `log_rate_limit_event`, `query_events`, `get_top_offenders` |
| `app/routers/admin_rate_limits.py` | 32, 63-222 | Existing router, prefix `/ui/admin/rate-limits`, 10 endpoints, auth: `require_root` |
| `app/auth/policy.py` | 63 | `require_root` — used by all admin_rate_limits endpoints |
| `app/main.py` | 113, 436 | Registration of `admin_rate_limits_router` |
| `frontend/src/pages/admin/RateLimitDashboard.tsx` | 1-544 | Existing 544-line dashboard with blocklist/allowlist, events, top offenders, config panel |
| `frontend/src/pages/admin/RateLimitConfigPanel.tsx` | — | Existing config panel component (imported by RateLimitDashboard) |
| `frontend/src/api/endpoints/adminRateLimits.ts` | 1-122 | Existing 122-line API wrappers with types |
| `frontend/src/App.tsx` | 62, 202 | Lazy import of RateLimitDashboard (line 62), route `/admin/rate-limits` (line 202) |
| `scripts/local-ddb-init.py` | 842, 848 | DDB table definitions: `rate_limits` (line 842), `rate_limit_events` (line 848) |
