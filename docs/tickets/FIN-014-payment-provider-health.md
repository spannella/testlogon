# FIN-014: Payment Provider Health Monitoring

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-29  
**Priority**: High  
**Estimated effort**: 8-10 days  
**Dependencies**: Webhook infrastructure (`webhook_stats.py`, `webhook_circuit_breaker.py`), billing routers (`billing.py`, `billing_ccbill.py`), admin auth (`auth/deps.py`)

---

## 1. Overview & Motivation

### The Gap

The platform integrates three payment providers (Stripe, PayPal, CCBill) and processes their webhook events for payment confirmations, refunds, disputes, and subscription lifecycle events. The webhook infrastructure includes delivery stats (`webhook_stats.py`), circuit breaker logic (`webhook_circuit_breaker.py`), retry queues (`webhook_retry.py`), and dead-letter queues (`webhook_dlq.py`). However, there is no admin-facing dashboard that shows the health status of each payment provider. Admins cannot:

- See webhook delivery success/failure rates per provider
- View average webhook processing latency
- Identify which error types are occurring most frequently
- Set alert thresholds for error rates or latency spikes
- Track historical uptime/downtime for each provider
- Manually disable a provider if it becomes unhealthy
- View a consolidated health timeline across all providers

Without provider health visibility, outages go unnoticed until users report payment failures. By the time an admin investigates, the damage is done — failed payments, lost revenue, and unhappy users.

### Why This Is Needed

1. **Early outage detection**: A provider's webhook error rate spiking from 1% to 15% signals an emerging outage. Automated alerts give admins a 5-10 minute head start versus waiting for user complaints.

2. **Incident response**: When a provider is unhealthy, admins need a one-click toggle to disable it and route payments through an alternative provider, preventing further failures.

3. **SLA tracking**: Knowing each provider's historical uptime helps evaluate whether they meet their SLA commitments and informs contract renewal decisions.

4. **Debugging**: When a specific webhook type fails repeatedly (e.g., `payment_intent.succeeded` from Stripe), the error type drilldown helps engineers pinpoint the cause without searching logs.

5. **Business continuity**: If one provider goes down, the platform should gracefully degrade — disabling the unhealthy provider and redirecting users to alternatives.

### User Stories

- As a **platform admin**, I want to see a health status indicator for each payment provider so I can quickly identify outages.
- As a **platform admin**, I want to view webhook success/failure rates over time so I can detect degradation trends.
- As a **platform admin**, I want to receive alerts when a provider's error rate exceeds a threshold so I can respond before users are impacted.
- As a **platform admin**, I want to manually disable a provider so I can prevent further failures during an outage.
- As a **platform admin**, I want to see a historical uptime timeline so I can evaluate provider reliability.

### Architecture After This Change

```
Admin Dashboard (/admin/provider-health)
│
├── Provider Status Cards (one per provider)
│   ├── Stripe  [Healthy ●]  99.7% success  12ms avg latency
│   ├── PayPal  [Degraded ●]  94.2% success  85ms avg latency
│   └── CCBill  [Healthy ●]  99.9% success  8ms avg latency
│
├── Health Timeline
│   ├── Stacked bar chart (hourly buckets)
│   ├── Green = success, Yellow = retried, Red = failed
│   └── Last 24h / 7d / 30d toggle
│
├── Error Drilldown
│   ├── Error type distribution (pie chart)
│   ├── Recent failures table (timestamp, provider, event_type, error)
│   └── Click to view full webhook payload
│
├── Alert Configuration
│   ├── Error rate threshold (e.g., >5% triggers alert)
│   ├── Latency threshold (e.g., >500ms triggers alert)
│   ├── Alert channels (email, in-app notification)
│   └── Current alert status
│
├── Provider Toggle
│   ├── Enable/Disable each provider
│   ├── Confirmation dialog with impact summary
│   └── Audit log of toggle events
│
└── Uptime History
    ├── Daily uptime percentage per provider
    ├── Incident log (start, end, duration, impact)
    └── Monthly availability report
```

---

## 2. Current State Analysis

### 2.1 Webhook Stats (`app/services/webhook_stats.py`)

Existing functions:
- `record_delivery_stat(...)`: Records success/failure for a webhook delivery
- `get_endpoint_stats(...)`: Stats for a specific endpoint
- `get_global_stats(hours=24)`: Global webhook stats for a time window

Stats are bucketed by hour (`_hour_bucket(ts)`) and stored in DynamoDB.

### 2.2 Circuit Breaker (`app/services/webhook_circuit_breaker.py`)

Existing functions:
- `get_circuit_state(endpoint)`: Returns `"closed"`, `"open"`, or `"half_open"`
- `should_attempt_delivery(endpoint, now)`: Whether delivery should be attempted
- `record_delivery_result(...)`: Updates circuit state based on result
- `reset_circuit(endpoint_id, user_sub)`: Manually resets circuit

### 2.3 Webhook Infrastructure

- `webhook_retry.py`: Retry queue for failed deliveries
- `webhook_dlq.py`: Dead-letter queue for permanently failed webhooks
- `webhook_dispatcher.py`: Core webhook dispatch logic
- `webhook_service.py`: Webhook registration and management

### 2.4 Payment Provider Adapters

- `payment_incident_stripe_adapter.py`: Stripe-specific incident handling
- `payment_incident_paypal_adapter.py`: PayPal-specific incident handling
- `payment_incident_ccbill_adapter.py`: CCBill-specific incident handling

### 2.5 Gaps

1. No per-provider health status aggregation
2. No health status indicators (healthy/degraded/down)
3. No alert threshold configuration for error rates or latency
4. No provider enable/disable toggle
5. No historical uptime tracking
6. No admin UI for provider health monitoring
7. No incident timeline or log

---

## 3. Technical Design

### 3.1 Provider Health Table: `provider_health`

**Table definition** in `scripts/local-ddb-init.py`:

```python
TableDef(
    name="provider_health",
    pk="pk", sk="sk",
    gsis=[
        GsiDef("GSI1", "GSI1PK", "GSI1SK"),
    ],
    attr_types={"sk": "S"},
)
```

**Health snapshot rows** (written every 5 minutes by background task):

| Field | Type | Description |
|-------|------|-------------|
| `pk` | S | `PROVIDER#{provider_name}` (e.g., `PROVIDER#stripe`) |
| `sk` | S | `SNAP#{timestamp}` |
| `success_count` | N | Successful webhook deliveries in window |
| `failure_count` | N | Failed webhook deliveries in window |
| `avg_latency_ms` | N | Average processing latency |
| `error_types` | M | Map of error_type -> count |
| `status` | S | `"healthy"`, `"degraded"`, `"down"` |

**Provider configuration row**:

| Field | Type | Description |
|-------|------|-------------|
| `pk` | S | `PROVIDER#{provider_name}` |
| `sk` | S | `CONFIG` |
| `enabled` | BOOL | Whether provider is accepting payments |
| `alert_error_rate_threshold` | N | Error rate % to trigger alert (default 5) |
| `alert_latency_threshold_ms` | N | Latency ms to trigger alert (default 500) |
| `alert_email` | S | Admin email for alerts |
| `disabled_at` | N | When provider was disabled (null if enabled) |
| `disabled_by` | S | Admin who disabled |
| `disable_reason` | S | Why disabled |

**Incident log rows**:

| Field | Type | Description |
|-------|------|-------------|
| `pk` | S | `PROVIDER#{provider_name}` |
| `sk` | S | `INCIDENT#{incident_id}` |
| `GSI1PK` | S | `INCIDENTS#ALL` |
| `GSI1SK` | S | `{started_at}#{incident_id}` |
| `started_at` | N | When incident started |
| `ended_at` | N | When incident resolved (null if ongoing) |
| `status` | S | `"degraded"` or `"down"` |
| `peak_error_rate` | N | Highest error rate during incident |
| `affected_webhooks` | N | Count of affected webhook deliveries |

### 3.2 Provider Health Service: `app/services/provider_health.py`

```python
"""Payment provider health monitoring (FIN-014).

Aggregates webhook delivery stats per payment provider,
computes health status, manages alert thresholds, and
tracks uptime/downtime incidents.
"""

PROVIDERS = ["stripe", "paypal", "ccbill"]
STATUS_HEALTHY = "healthy"
STATUS_DEGRADED = "degraded"
STATUS_DOWN = "down"

# Thresholds for auto-detection
DEFAULT_DEGRADED_ERROR_RATE = 5.0   # 5% errors → degraded
DEFAULT_DOWN_ERROR_RATE = 25.0      # 25% errors → down
DEFAULT_LATENCY_WARN_MS = 500

def get_provider_status(provider: str) -> Dict[str, Any]:
    """Get current health status for a provider.

    Returns status (healthy/degraded/down), success rate,
    avg latency, error count, and last check timestamp.
    """
    ...

def get_all_providers_status() -> List[Dict[str, Any]]:
    """Get health status for all providers."""
    ...

def get_health_timeline(
    provider: str, *, hours: int = 24
) -> List[Dict[str, Any]]:
    """Get hourly health snapshots for timeline chart."""
    ...

def get_error_drilldown(
    provider: str, *, hours: int = 24
) -> Dict[str, Any]:
    """Get error type breakdown and recent failures."""
    ...

def get_provider_config(provider: str) -> Dict[str, Any]:
    """Get provider configuration (enabled, thresholds)."""
    ...

def update_provider_config(
    provider: str, *, admin_sub: str, **updates
) -> Dict[str, Any]:
    """Update provider configuration."""
    ...

def toggle_provider(
    provider: str, *, enabled: bool, admin_sub: str, reason: str = ""
) -> Dict[str, Any]:
    """Enable or disable a payment provider."""
    ...

def get_incidents(
    *, provider: str = None, limit: int = 50
) -> List[Dict[str, Any]]:
    """List incidents (optionally filtered by provider)."""
    ...

def get_uptime_report(
    provider: str, *, days: int = 30
) -> Dict[str, Any]:
    """Calculate uptime percentage for a provider over N days."""
    ...

def check_and_alert(provider: str) -> Optional[Dict[str, Any]]:
    """Check if provider exceeds alert thresholds and send alert.

    Called by background health check task.
    Returns alert details if threshold exceeded, None otherwise.
    """
    ...
```

### 3.3 Router: `app/routers/admin_provider_health.py`

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/v1/admin/provider-health` | `require_admin_session` | All providers status |
| GET | `/v1/admin/provider-health/{provider}` | `require_admin_session` | Single provider status |
| GET | `/v1/admin/provider-health/{provider}/timeline` | `require_admin_session` | Health timeline |
| GET | `/v1/admin/provider-health/{provider}/errors` | `require_admin_session` | Error drilldown |
| GET | `/v1/admin/provider-health/{provider}/config` | `require_admin_session` | Provider config |
| PATCH | `/v1/admin/provider-health/{provider}/config` | `require_root_session` | Update config |
| POST | `/v1/admin/provider-health/{provider}/toggle` | `require_root_session` | Enable/disable |
| GET | `/v1/admin/provider-health/incidents` | `require_admin_session` | Incident log |
| GET | `/v1/admin/provider-health/{provider}/uptime` | `require_admin_session` | Uptime report |

### 3.4 Pydantic Models (`app/models.py`)

```python
class ProviderHealthStatus(BaseModel):
    provider: str
    status: str  # "healthy", "degraded", "down"
    enabled: bool
    success_rate: float
    avg_latency_ms: int
    total_success: int
    total_failure: int
    last_check_at: int

class ProviderHealthTimeline(BaseModel):
    provider: str
    hours: int
    data: List[Dict[str, Any]]  # [{hour, success, failure, avg_latency_ms, status}]

class ProviderErrorDrilldown(BaseModel):
    provider: str
    error_types: Dict[str, int]
    recent_failures: List[Dict[str, Any]]

class ProviderConfigUpdate(BaseModel):
    alert_error_rate_threshold: Optional[float] = Field(default=None, ge=1.0, le=100.0)
    alert_latency_threshold_ms: Optional[int] = Field(default=None, ge=50, le=10000)
    alert_email: Optional[str] = None

class ProviderToggle(BaseModel):
    enabled: bool
    reason: str = Field(default="", max_length=500)

class ProviderIncident(BaseModel):
    incident_id: str
    provider: str
    started_at: int
    ended_at: Optional[int]
    status: str
    peak_error_rate: float
    affected_webhooks: int

class ProviderUptimeReport(BaseModel):
    provider: str
    days: int
    uptime_pct: float
    total_incidents: int
    total_downtime_minutes: int
```

### 3.5 Frontend: Provider Health Dashboard

**Route**: `/admin/provider-health` in `frontend/src/App.tsx`  
**Page**: `frontend/src/pages/admin/providerHealth/ProviderHealthDashboard.tsx`

```tsx
<div className="space-y-6">
  {/* Status cards row */}
  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
    {providers.map(p => (
      <ProviderStatusCard
        key={p.provider}
        provider={p}
        onToggle={() => setToggleTarget(p)}
      />
    ))}
  </div>

  {/* Timeline chart */}
  <Card>
    <CardHeader>
      <CardTitle>Health Timeline</CardTitle>
      <Select value={selectedProvider} onValueChange={setSelectedProvider}>...</Select>
    </CardHeader>
    <CardContent>
      <HealthTimelineChart data={timeline} />
    </CardContent>
  </Card>

  {/* Error drilldown + Incidents */}
  <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
    <Card>
      <CardHeader><CardTitle>Error Breakdown</CardTitle></CardHeader>
      <CardContent><ErrorPieChart data={errors.error_types} /></CardContent>
    </Card>
    <Card>
      <CardHeader><CardTitle>Recent Incidents</CardTitle></CardHeader>
      <CardContent><IncidentTable data={incidents} /></CardContent>
    </Card>
  </div>

  {/* Alert config */}
  <Card>
    <CardHeader><CardTitle>Alert Configuration</CardTitle></CardHeader>
    <CardContent><AlertConfigForm config={config} onSave={saveConfig} /></CardContent>
  </Card>

  {/* Provider toggle dialog */}
  <ProviderToggleDialog
    provider={toggleTarget}
    open={!!toggleTarget}
    onConfirm={handleToggle}
    onCancel={() => setToggleTarget(null)}
  />
</div>
```

### 3.6 Frontend API (`frontend/src/api/endpoints/adminProviderHealth.ts`)

```typescript
export const getAllProviderStatus = () =>
  client.get("/v1/admin/provider-health");

export const getProviderStatus = (provider: string) =>
  client.get(`/v1/admin/provider-health/${provider}`);

export const getProviderTimeline = (provider: string, params?: { hours?: number }) =>
  client.get(`/v1/admin/provider-health/${provider}/timeline`, { params });

export const getProviderErrors = (provider: string, params?: { hours?: number }) =>
  client.get(`/v1/admin/provider-health/${provider}/errors`, { params });

export const getProviderConfig = (provider: string) =>
  client.get(`/v1/admin/provider-health/${provider}/config`);

export const updateProviderConfig = (provider: string, data: ProviderConfigUpdate) =>
  client.patch(`/v1/admin/provider-health/${provider}/config`, data);

export const toggleProvider = (provider: string, data: { enabled: boolean; reason?: string }) =>
  client.post(`/v1/admin/provider-health/${provider}/toggle`, data);

export const getIncidents = (params?: { provider?: string; limit?: number }) =>
  client.get("/v1/admin/provider-health/incidents", { params });

export const getProviderUptime = (provider: string, params?: { days?: number }) =>
  client.get(`/v1/admin/provider-health/${provider}/uptime`, { params });
```

---

## 4. Implementation Plan

### Phase 1: Backend Data Layer (Days 1-3)

1. **`scripts/local-ddb-init.py`**: Add `provider_health` table with GSI.
2. **`app/core/settings.py`**: Add `provider_health_table_name`.
3. **`app/core/tables.py`**: Add `provider_health` table handle.
4. **`app/services/provider_health.py`**: New file. Health status computation, timeline, error drilldown, config management, provider toggle, incident tracking, uptime report.

### Phase 2: Backend Router (Days 3-5)

5. **`app/models.py`**: Add provider health Pydantic models.
6. **`app/routers/admin_provider_health.py`**: New router with 9 endpoints.
7. **`app/main.py`**: Register router with prefix `/v1/admin/provider-health`.
8. **Integrate with webhook pipeline**: Update `webhook_stats.py` to also write to `provider_health` table for per-provider aggregation.

### Phase 3: Frontend (Days 5-8)

9. **`frontend/src/api/types.ts`**: Add TypeScript types.
10. **`frontend/src/api/endpoints/adminProviderHealth.ts`**: New file.
11. **`frontend/src/pages/admin/providerHealth/ProviderHealthDashboard.tsx`**: New page.
12. **`frontend/src/App.tsx`**: Add `/admin/provider-health` route.
13. **`frontend/src/components/layout/Sidebar.tsx`**: Add "Provider Health" admin nav link.

### Phase 4: E2E Tests (Days 9-10)

14. **`frontend/e2e/admin-provider-health.spec.ts`**: 14 tests across 4 sections.

---

## 5. E2E Test Plan

**Test file**: `frontend/e2e/admin-provider-health.spec.ts`

**Setup (beforeAll)**:
- Inject auth for Root, Alice, Charlie (admin)
- Seed provider_health table with health snapshots for stripe, paypal, ccbill
- Seed 3 incidents (1 ongoing, 2 resolved) for stripe

**Section 527: Provider Status API (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 1 | `Admin retrieves all provider statuses` | GET `/v1/admin/provider-health` as Root -> 200; array of 3 providers, each has `provider`, `status`, `enabled`, `success_rate`, `avg_latency_ms` |
| 2 | `Single provider status returns details` | GET `/v1/admin/provider-health/stripe` -> 200; has `total_success`, `total_failure`, `last_check_at` |
| 3 | `Unknown provider returns 404` | GET `/v1/admin/provider-health/unknown` -> 404 |
| 4 | `Non-admin cannot access provider health` | GET as Alice -> 403 |

**Section 528: Timeline & Error Drilldown API (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 5 | `Timeline returns hourly health data` | GET `/v1/admin/provider-health/stripe/timeline?hours=24` -> 200; `data` array with entries having `hour`, `success`, `failure` |
| 6 | `Error drilldown shows error types` | GET `/v1/admin/provider-health/stripe/errors` -> 200; `error_types` is object, `recent_failures` is array |
| 7 | `Uptime report returns percentage` | GET `/v1/admin/provider-health/stripe/uptime?days=30` -> 200; `uptime_pct` between 0 and 100, `total_incidents >= 0` |
| 8 | `Incident list returns provider incidents` | GET `/v1/admin/provider-health/incidents?provider=stripe` -> 200; array with seeded incidents |

**Section 529: Provider Configuration API (3 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 9 | `Admin retrieves provider config` | GET `/v1/admin/provider-health/stripe/config` as Root -> 200; has `alert_error_rate_threshold`, `alert_latency_threshold_ms` |
| 10 | `Root updates alert thresholds` | PATCH `/v1/admin/provider-health/stripe/config` with `{alert_error_rate_threshold: 10}` -> 200; re-GET confirms value changed |
| 11 | `Non-root cannot update config` | PATCH as Charlie -> 403 |

**Section 530: Provider Toggle API (3 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 12 | `Root disables a provider` | POST `/v1/admin/provider-health/paypal/toggle` with `{enabled: false, reason: "maintenance"}` as Root -> 200; `enabled: false` |
| 13 | `Root re-enables a provider` | POST toggle with `{enabled: true}` -> 200; `enabled: true` |
| 14 | `Non-root cannot toggle provider` | POST toggle as Charlie -> 403 |

**Section 531: Provider Health Edge Cases (5 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 15 | `Timeline with no data returns empty` | GET timeline for provider with no snapshots; 200; empty data array |
| 16 | `Uptime for new provider is 100%` | New provider with no incidents; uptime_pct = 100.0 |
| 17 | `Error drilldown empty when no errors` | GET errors for healthy provider; error_types empty; recent_failures empty |
| 18 | `Disable already-disabled provider` | Toggle enabled=false twice; second returns 200; still disabled (idempotent) |
| 19 | `Incident create and resolve` | POST new incident; POST resolve; incident has end_time |

**Total E2E tests: 19**

---

## 6. API Request/Response Examples

**Get all provider statuses** (curl):

```bash
curl -X GET http://localhost:8000/v1/admin/provider-health \
  -H "Cookie: ui_session=sess_root; ui_csrf=csrf_r; ui_access_token=eyJ..."
```

**Response (200)**:
```json
[
  {
    "provider": "stripe",
    "status": "healthy",
    "enabled": true,
    "success_rate": 99.7,
    "avg_latency_ms": 234,
    "total_success": 4521,
    "total_failure": 14,
    "last_check_at": 1748520100
  },
  {
    "provider": "paypal",
    "status": "degraded",
    "enabled": true,
    "success_rate": 95.2,
    "avg_latency_ms": 890,
    "total_success": 1230,
    "total_failure": 62,
    "last_check_at": 1748520100
  }
]
```

**Get provider timeline** (curl):

```bash
curl -X GET "http://localhost:8000/v1/admin/provider-health/stripe/timeline?hours=24" \
  -H "Cookie: ui_session=sess_root; ui_csrf=csrf_r; ui_access_token=eyJ..."
```

**Response (200)**:
```json
{
  "data": [
    {"hour": "2026-05-29T00:00:00Z", "success": 189, "failure": 1, "avg_latency_ms": 220},
    {"hour": "2026-05-29T01:00:00Z", "success": 195, "failure": 0, "avg_latency_ms": 210}
  ]
}
```

**Toggle provider** (curl):

```bash
curl -X POST http://localhost:8000/v1/admin/provider-health/paypal/toggle \
  -H "Content-Type: application/json" \
  -H "Cookie: ui_session=sess_root; ui_csrf=csrf_r; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_r" \
  -d '{"enabled": false, "reason": "Scheduled maintenance window"}'
```

**Response (200)**:
```json
{"provider": "paypal", "enabled": false, "toggled_at": 1748520500, "reason": "Scheduled maintenance window"}
```

---

## 7. Error Handling Matrix

| Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|----------|-------------|------------|---------------------|-----------------|
| Unknown provider | 404 | `provider_not_found` | "Provider not found" | Check provider name |
| Non-admin access | 403 | `forbidden` | "Admin access required" | Use admin account |
| Non-root config update | 403 | `root_required` | "Root access required" | Use root account |
| Non-root toggle | 403 | `root_required` | "Root access required" | Use root account |
| Invalid threshold | 422 | `validation_error` | "Threshold must be > 0" | Fix value |
| Provider already disabled | 200 | — | Idempotent toggle | No action needed |

---

## 8. Observability

### 8.1 Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `provider_health_check_total` | Counter | `provider`, `status` | Health checks |
| `provider_success_rate` | Gauge | `provider` | Current success rate |
| `provider_latency_ms` | Histogram | `provider` | Payment latency |
| `provider_toggled_total` | Counter | `provider`, `enabled` | Toggle events |
| `provider_incident_total` | Counter | `provider` | Incidents created |

### 8.2 Alerts

| Alert | Condition | Severity | Action |
|-------|-----------|----------|--------|
| Provider degraded | Success rate < configured threshold | High | Auto-alert admins; investigate |
| Provider down | Success rate < 50% for > 5 min | Critical | Consider auto-disable; page oncall |
| High latency | avg_latency > configured threshold | Medium | Monitor; may indicate degradation |
| Incident unresolved > 4h | Open incident duration > 4 hours | High | Escalate |

---

## 9. Rollout Plan

### 9.1 Feature Flag

```python
provider_health_enabled: bool = os.environ.get("PROVIDER_HEALTH_ENABLED", "true").lower() == "true"
```

### 9.2 Phased Rollout

| Phase | Description | Duration | Criteria |
|-------|-------------|----------|----------|
| Phase 1: Backend | Deploy health check service + table | 2 days | Unit tests pass |
| Phase 2: Internal | Enable dashboard; verify real provider data | 3 days | All 19 E2E pass |
| Phase 3: GA | Visible to all admins | Permanent | Accurate health data |

### 9.3 Rollback

1. Set flag OFF — dashboard unavailable
2. Health check background job stops writing
3. Existing data preserved

---

## 10. Performance Considerations

| Concern | Target | Mitigation |
|---------|--------|-----------|
| Health check frequency | Every 5 min per provider | Background loop; lightweight DDB write |
| Timeline query | < 100ms | GSI on provider + hour |
| Error drilldown | < 200ms | Query last 100 failures from DDB |
| Uptime calculation | < 100ms | Count incidents in date range |
| Dashboard load | < 500ms | Parallel queries for all providers |

---

## 11. Frontend Component Tree

```
ProviderHealthDashboard
├── ProviderStatusGrid (row of status cards)
│   └── ProviderStatusCard (for each provider)
│       ├── StatusIndicator (green/yellow/red dot)
│       ├── ProviderName
│       ├── SuccessRate (percentage)
│       ├── AvgLatency (ms)
│       ├── EnabledBadge (on/off)
│       └── LastChecked (relative time)
├── Tabs
│   ├── TimelineTab
│   │   ├── ProviderSelector (dropdown)
│   │   ├── TimeRangeSelector (6h/12h/24h/48h/7d)
│   │   └── TimelineChart (stacked bar: success + failure per hour)
│   ├── ErrorsTab
│   │   ├── ErrorTypeDistribution (pie chart)
│   │   └── RecentFailuresTable (timestamp, error_type, details)
│   ├── IncidentsTab
│   │   └── IncidentTimeline (vertical timeline of incidents)
│   ├── UptimeTab
│   │   ├── UptimePercentage (large display)
│   │   └── UptimeCalendar (heatmap of daily availability)
│   └── ConfigTab (root only)
│       ├── AlertThresholdForm
│       │   ├── ErrorRateInput
│       │   └── LatencyInput
│       └── ProviderToggleSection
│           ├── EnableToggle
│           ├── ReasonInput
│           └── ConfirmationDialog
└── ExportButton (CSV download of health data)
```

---

## 12. Security Considerations

### 6.1 Role-Based Access
- Read-only endpoints (status, timeline, errors, incidents, uptime): ADMIN role
- Configuration updates and provider toggle: ROOT role (destructive operations)

### 6.2 Provider Toggle Safety
- Disabling a provider prevents new payment initiation through that provider
- In-flight payments are not affected (webhooks still processed)
- Toggle actions logged with admin identity, timestamp, and reason
- Confirmation dialog required in UI before disabling

### 6.3 Alert Security
- Alert emails sent only to configured admin addresses
- Alert threshold changes require ROOT role
- Alert history is immutable (cannot be deleted)

---

## 7. Files to Create

| File | Purpose |
|------|---------|
| `app/services/provider_health.py` | Provider health monitoring service |
| `app/routers/admin_provider_health.py` | Admin provider health API (9 endpoints) |
| `frontend/src/api/endpoints/adminProviderHealth.ts` | API wrappers |
| `frontend/src/pages/admin/providerHealth/ProviderHealthDashboard.tsx` | Dashboard page |
| `frontend/e2e/admin-provider-health.spec.ts` | E2E tests (14 tests, sections 527-530) |

## 8. Files to Modify

| File | Change |
|------|--------|
| `app/models.py` | Add provider health Pydantic models |
| `app/main.py` | Register `admin_provider_health_router` |
| `app/core/settings.py` | Add `provider_health_table_name` |
| `app/core/tables.py` | Add `provider_health` table handle |
| `scripts/local-ddb-init.py` | Add `provider_health` table |
| `app/services/webhook_stats.py` | Write per-provider stats to new table |
| `frontend/src/api/types.ts` | Add provider health TypeScript types |
| `frontend/src/App.tsx` | Add `/admin/provider-health` route |
| `frontend/src/components/layout/Sidebar.tsx` | Add "Provider Health" admin nav link |

## 9. Acceptance Criteria

1. All three payment providers shown with health status (healthy/degraded/down) and success rate
2. Timeline chart shows hourly health snapshots for configurable time windows
3. Error drilldown shows error type distribution and recent failure details
4. Alert thresholds configurable by ROOT (error rate %, latency ms)
5. Provider toggle enables/disables a provider with confirmation and audit logging
6. Incident log tracks historical outages with start/end times
7. Uptime report calculates availability percentage over configurable period
8. Non-admin users receive 403; non-root users cannot toggle or configure
9. All 14 E2E tests pass in `frontend/e2e/admin-provider-health.spec.ts`
