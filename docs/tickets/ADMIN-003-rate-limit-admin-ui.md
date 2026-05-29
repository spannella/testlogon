# ADMIN-003: Rate Limit Admin UI

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-29  
**Priority**: Medium  
**Estimated effort**: 7-9 days  
**Dependencies**: Rate limiting (`rate_limit.py`, `rate_limit_config.py`, `rate_limit_store.py`, `rate_limit_dashboard.py`), admin rate limits router (`admin_rate_limits.py`), admin auth (`auth/deps.py`)

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

---

## 2. Current State Analysis

### 2.1 Rate Limit Config (`app/services/rate_limit_config.py`)

Existing functions:
- `get_group_config(group)`: Get rate limit config for an endpoint group (with defaults)
- `save_group_override(group, *, admin_sub, ...)`: Save custom config for a group
- `get_all_configs()`: Get all configs (default + overrides)
- `match_path_to_group(path)`: Map request path to rate limit group

Config fields per group: `requests_per_window`, `window_seconds`, `burst`.

### 2.2 Rate Limit Store (`app/services/rate_limit_store.py`)

Existing functions:
- `check_rate_limit(key, group)`: Check if request is within limits
- `is_blocked(ip)`: Check if IP is blocked
- `is_allowlisted(ip)`: Check if IP is allowlisted
- `add_to_blocklist(ip, *, reason, admin_sub)` / `remove_from_blocklist(ip)`
- `add_to_allowlist(cidr, *, reason, admin_sub)` / `remove_from_allowlist(cidr)`
- `list_blocklist()` / `list_allowlist()`

### 2.3 Rate Limit Dashboard (`app/services/rate_limit_dashboard.py`)

Existing functions:
- `log_rate_limit_event(...)`: Log a rate limit event
- `query_events(*, start, end, group, source, limit)`: Search events
- `get_top_offenders(*, hours, limit)`: Top rate limit violators

### 2.4 Admin Rate Limits Router (`app/routers/admin_rate_limits.py`)

Existing endpoints (requires ROOT role):
- `GET /config`: Get all rate limit configs
- `PUT /config`: Update config for a group
- `GET /events`: Query rate limit events
- `GET /top-offenders`: Top offenders
- `POST /blocklist`: Add to blocklist
- `DELETE /blocklist/{entry_id}`: Remove from blocklist
- `POST /allowlist`: Add to allowlist
- `DELETE /allowlist/{entry_id}`: Remove from allowlist
- `GET /blocklist`: List blocklist
- `GET /allowlist`: List allowlist

### 2.5 Gaps

1. No frontend UI for any of the above (all 10 endpoints are API-only)
2. No real-time rate limit hit visualization
3. No rule diff display (default vs override)
4. No event log search UI
5. No event export functionality
6. No live auto-refreshing dashboard

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

### 3.2 Updated Router: `app/routers/admin_rate_limits.py`

Add 2 new endpoints to existing router:

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/v1/admin/rate-limits/live-summary` | `require_root` | Real-time hit summary |
| GET | `/v1/admin/rate-limits/events/export` | `require_root` | Event CSV export |

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

### 3.3 Pydantic Models (`app/models.py`)

```python
class RateLimitGroupConfig(BaseModel):
    group: str
    requests_per_window: int
    window_seconds: int
    burst: int
    is_override: bool  # True if custom, False if default

class RateLimitConfigUpdate(BaseModel):
    group: str
    requests_per_window: Optional[int] = Field(default=None, ge=1, le=100000)
    window_seconds: Optional[int] = Field(default=None, ge=1, le=86400)
    burst: Optional[int] = Field(default=None, ge=0, le=10000)

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
    ip: str = Field(min_length=1)
    reason: str = Field(default="", max_length=500)

class AllowlistAdd(BaseModel):
    cidr: str = Field(min_length=1)
    reason: str = Field(default="", max_length=500)
```

### 3.4 Frontend: Rate Limit Admin Page

**Route**: `/admin/rate-limits` in `frontend/src/App.tsx`  
**Page**: `frontend/src/pages/admin/rateLimits/RateLimitDashboard.tsx`

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

### 3.5 Frontend API (`frontend/src/api/endpoints/adminRateLimits.ts`)

```typescript
// Config
export const getRateLimitConfigs = () =>
  client.get("/v1/admin/rate-limits/config");

export const updateRateLimitConfig = (data: RateLimitConfigUpdate) =>
  client.put("/v1/admin/rate-limits/config", data);

// Events
export const queryRateLimitEvents = (params: {
  start?: number; end?: number; group?: string; source?: string; limit?: number;
}) =>
  client.get("/v1/admin/rate-limits/events", { params });

export const exportRateLimitEvents = (params: { start: number; end: number; group?: string }) =>
  client.get("/v1/admin/rate-limits/events/export", { params, responseType: "blob" });

export const getTopOffenders = (params?: { hours?: number; limit?: number }) =>
  client.get("/v1/admin/rate-limits/top-offenders", { params });

export const getLiveSummary = (params?: { hours?: number }) =>
  client.get("/v1/admin/rate-limits/live-summary", { params });

// Blocklist
export const getBlocklist = () =>
  client.get("/v1/admin/rate-limits/blocklist");

export const addToBlocklist = (data: { ip: string; reason?: string }) =>
  client.post("/v1/admin/rate-limits/blocklist", data);

export const removeFromBlocklist = (entryId: string) =>
  client.delete(`/v1/admin/rate-limits/blocklist/${entryId}`);

// Allowlist
export const getAllowlist = () =>
  client.get("/v1/admin/rate-limits/allowlist");

export const addToAllowlist = (data: { cidr: string; reason?: string }) =>
  client.post("/v1/admin/rate-limits/allowlist", data);

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

8. **`frontend/e2e/admin-rate-limits.spec.ts`**: 15 tests across 4 sections.

---

## 5. E2E Test Plan

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

---

## 6. Security Considerations

### 6.1 Role-Based Access
- All rate limit admin endpoints require ROOT role (not just ADMIN)
- Rate limit configuration is a security-critical function — misconfiguration can enable DDoS or lock out legitimate users

### 6.2 Blocklist Safety
- Blocklist additions take effect immediately (next request from that IP is rejected)
- Self-blocking prevention: the admin's own IP cannot be added to the blocklist
- Blocklist entries logged with admin identity and reason
- Maximum 10,000 blocklist entries to prevent memory exhaustion

### 6.3 Config Safety
- Minimum values enforced: `requests_per_window >= 1`, `window_seconds >= 1`
- Maximum values enforced to prevent effectively disabling rate limits
- Config changes take effect immediately (no restart required)
- Reset-to-default option removes overrides without breaking the system

### 6.4 Event Log Privacy
- Event logs contain IP addresses (PII in some jurisdictions)
- Event logs should not be cached (Cache-Control: no-store)
- CSV exports should be transmitted over HTTPS only

---

## 7. Files to Create

| File | Purpose |
|------|---------|
| `frontend/src/api/endpoints/adminRateLimits.ts` | API wrappers |
| `frontend/src/pages/admin/rateLimits/RateLimitDashboard.tsx` | Rate limit admin page |
| `frontend/e2e/admin-rate-limits.spec.ts` | E2E tests (15 tests, sections 555-558) |

## 8. Files to Modify

| File | Change |
|------|--------|
| `app/routers/admin_rate_limits.py` | Add `live-summary` and `events/export` endpoints |
| `app/models.py` | Add rate limit admin Pydantic models |
| `frontend/src/api/types.ts` | Add rate limit admin TypeScript types |
| `frontend/src/App.tsx` | Add `/admin/rate-limits` route |
| `frontend/src/components/layout/Sidebar.tsx` | Add "Rate Limits" admin nav link |

## 9. Acceptance Criteria

1. Rate limit rules displayed per endpoint group with current values and override status
2. Root can edit rules (requests per window, window duration, burst) with immediate effect
3. Blocklist manageable: view, add IP with reason, remove entry
4. Allowlist manageable: view, add CIDR with reason, remove entry
5. Live summary shows rate limit hits by group, by source, and over time
6. Event log searchable by date range, group, and source
7. Event export generates valid CSV
8. Top offenders ranked by hit count for configurable time window
9. All endpoints require ROOT role (403 for non-root)
10. All 15 E2E tests pass in `frontend/e2e/admin-rate-limits.spec.ts`
