# INFRA-008: Instance Monitoring & Health

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-29  
**Priority**: Medium  
**Estimated effort**: 5-7 days  
**Dependencies**: INFRA-003 (EC2 Launcher), INFRA-004 (K8s Launcher)

---

## 1. Overview & Motivation

### The Gap

INFRA-003 and INFRA-004 track instance/pod lifecycle status (launching, running, stopped, terminated), but there is no health monitoring. Users cannot:

1. See whether a running instance is actually reachable (healthy vs. unreachable)
2. View resource utilization metrics (CPU, memory, disk, network)
3. See an instance's uptime or lifecycle timeline
4. Receive alerts when an instance becomes unreachable
5. Configure auto-restart on crash

The platform has an alerts system (`app/services/alerts.py`) with `write_alert()` (see `app/services/alerts.py:355`) for in-app notifications, but it is not wired to instance health events. The VNC system in `app/services/vnc_sessions.py` has timeout policies (see `app/services/vnc_sessions.py:143`) (idle timeout, max session duration) but no health probes.

### Why This Matters

1. **Status != health**: An instance can be in `running` status but completely unresponsive (kernel panic, OOM, network partition).
2. **Resource visibility**: Users need to know if their instance is at 95% CPU or 10% before deciding whether to scale up.
3. **Proactive alerts**: Getting notified when an instance goes down is faster than discovering it when you try to connect.
4. **Audit trail**: A timeline of lifecycle events (launch, health checks, restarts, stops) provides operational history.
5. **Auto-restart**: Crash-looping containers should be restarted automatically (up to a limit) without user intervention.

### Architecture After This Change

```
Health Monitoring System

  Background Health Checker (every 30s)
  +----------------------------+
  | For each running resource:  |
  |   1. TCP probe on SSH port  |  (mock: random healthy/degraded)
  |   2. Record health status   |
  |   3. Generate mock metrics  |
  |   4. Check restart policy   |
  |   5. Alert on status change |
  +----------------------------+
       |
       v
  ec2_instances / k8s_pods DDB tables
  +-- health_status: healthy | degraded | unreachable
  +-- last_health_check_at: timestamp
  +-- health_check_count: int
  +-- restart_count: int
  +-- consecutive_failures: int
       |
       v
  Instance timeline items (same table)
  SK = TIMELINE#{timestamp}#{event_id}
  Events: launched, health_check_passed, health_check_failed,
          status_changed, restarted, auto_terminated
       |
       v
  InstanceDetailPage (frontend)
  +-- Health badge (green/yellow/red)
  +-- Mock metrics charts (CPU, memory, disk, network)
  +-- Event timeline (scrollable)
  +-- Auto-restart configuration
```

---

## 2. Current State Analysis

### 2.1 Instance Status Tracking (INFRA-003/004)

EC2 instances and K8s pods have a `status` field tracking lifecycle state:
- EC2: `launching`, `running`, `stopping`, `stopped`, `terminating`, `terminated`
- K8s: `pending`, `running`, `succeeded`, `failed`, `terminated`

These statuses reflect intended state, not actual reachability. A `running` instance might be unreachable.

### 2.2 No Health Probes

Neither the EC2 launcher nor the K8s launcher performs health checks. The `_MockEc2Store` and `_MockK8sStore` in-memory stores track status but have no health probe simulation.

### 2.3 VNC Timeout Policy (`app/services/vnc_sessions.py`, line 143)

```python
def session_timeout_policy() -> dict[str, int]:
    return {
        "idle_timeout_seconds": ...,
        "max_session_duration_seconds": ...,
        "warning_seconds": ...,
    }
```

This is a timeout policy for VNC sessions (how long before an idle VNC session is disconnected), not a health check system. It provides a design precedent for timeout-based monitoring but serves a different purpose.

### 2.4 Alerts System (`app/services/alerts.py`)

`write_alert(user_sub, *, event, outcome, title, details)` (see `app/services/alerts.py:355`) creates in-app alerts. This is the integration point for health status change notifications.

---

## 3. Technical Design

### 3.1 Health Status Model

Add fields to `ec2_instances` and `k8s_pods` table items:

| Field | Type | Description |
|-------|------|-------------|
| `health_status` | S | `healthy`, `degraded`, `unreachable`, `unknown` |
| `last_health_check_at` | N | Unix timestamp of last health probe |
| `health_check_count` | N | Total health checks performed |
| `consecutive_failures` | N | Consecutive failed health checks |
| `restart_count` | N | Number of auto-restarts performed |
| `max_restarts` | N | Maximum auto-restarts allowed (default: 3) |
| `auto_restart_enabled` | BOOL | Whether auto-restart is enabled |
| `uptime_seconds` | N | Calculated uptime since last start |

### 3.2 Timeline Events

Timeline events are stored in the same DDB table as the resource (same PK) with a different SK pattern:

**EC2 timeline** (in `ec2_instances` table):

```
PK: user_sub
SK: TIMELINE#{instance_id}#{timestamp}#{event_id}
```

**K8s timeline** (in `k8s_pods` table):

```
PK: user_sub
SK: TIMELINE#{pod_id}#{timestamp}#{event_id}
```

**Timeline event schema**:

| Field | Type | Description |
|-------|------|-------------|
| `event_id` | S | UUID |
| `resource_id` | S | Instance/pod ID |
| `event_type` | S | `launched`, `health_ok`, `health_fail`, `status_changed`, `restarted`, `auto_terminated`, `user_stopped`, `user_terminated` |
| `timestamp` | N | Unix timestamp |
| `details` | M | Event-specific data |
| `health_status_before` | S | Health status before this event |
| `health_status_after` | S | Health status after this event |

### 3.3 Mock Health Probes

In dev mode, health probes are simulated:

```python
def _mock_health_probe(resource_id: str) -> str:
    """Simulate health probe results for dev mode.
    90% chance healthy, 8% degraded, 2% unreachable."""
    import random
    roll = random.random()
    if roll < 0.90:
        return "healthy"
    elif roll < 0.98:
        return "degraded"
    else:
        return "unreachable"
```

In production, health probes perform a TCP connect to the SSH port (22) with a 5-second timeout. A successful TCP handshake = healthy. Connection refused = degraded. Timeout = unreachable.

### 3.4 Mock Metrics

In dev mode, resource metrics are generated synthetically:

```python
def _mock_metrics(resource_id: str) -> Dict[str, Any]:
    """Generate mock resource metrics for dev mode."""
    import random
    return {
        "cpu_percent": round(random.uniform(5.0, 75.0), 1),
        "memory_percent": round(random.uniform(20.0, 60.0), 1),
        "memory_used_mb": random.randint(128, 2048),
        "memory_total_mb": 4096,
        "disk_percent": round(random.uniform(10.0, 50.0), 1),
        "disk_used_gb": round(random.uniform(2.0, 20.0), 1),
        "disk_total_gb": 50.0,
        "network_in_mbps": round(random.uniform(0.1, 10.0), 2),
        "network_out_mbps": round(random.uniform(0.1, 5.0), 2),
        "timestamp": now_ts(),
    }
```

In production, metrics would come from CloudWatch (EC2) or K8s metrics-server. This ticket only implements mock metrics.

### 3.5 Health Checker Service: `app/services/instance_health.py`

New file (~300 lines):

```python
"""Instance health monitoring — probes, metrics, timeline, auto-restart."""

from __future__ import annotations
import asyncio
import logging
import uuid
from typing import Any, Dict, List

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.alerts import write_alert, audit_event

logger = logging.getLogger(__name__)

HEALTH_CHECK_INTERVAL = 30  # seconds


async def run_health_checker(*, poll_interval: int = HEALTH_CHECK_INTERVAL):
    """Background task: probe all running instances/pods every poll_interval seconds."""
    while True:
        try:
            await _check_all_ec2_instances()
            await _check_all_k8s_pods()
        except Exception:
            logger.exception("Health checker error")
        await asyncio.sleep(poll_interval)


async def _check_all_ec2_instances():
    """Probe each running EC2 instance."""
    # Query all instances with status="running"
    # For each: probe, update health_status, record timeline, check restart policy

async def _check_all_k8s_pods():
    """Probe each running K8s pod."""

def _probe_instance(hostname: str, port: int) -> str:
    """TCP probe to host:port. Returns 'healthy', 'degraded', or 'unreachable'."""
    if S.dev_mode:
        return _mock_health_probe(hostname)
    # Real TCP probe with 5s timeout
    ...

def _handle_health_change(
    user_sub: str,
    resource_type: str,
    resource_id: str,
    *,
    old_status: str,
    new_status: str,
    resource_label: str,
):
    """Handle a health status transition. Write timeline event, send alert if needed."""
    # Record timeline event
    record_timeline_event(user_sub, resource_type, resource_id,
                          event_type="status_changed",
                          details={"from": old_status, "to": new_status})
    # Alert on degradation
    if new_status in ("degraded", "unreachable") and old_status == "healthy":
        write_alert(user_sub, event="compute.health_degraded", outcome="warning",
                    title=f"{resource_label} is {new_status}",
                    details={"resource_id": resource_id, "status": new_status})

def _check_restart_policy(user_sub: str, resource_type: str, resource_id: str):
    """If auto-restart enabled and consecutive_failures >= 3 and restart_count < max_restarts,
    restart the resource."""

def record_timeline_event(
    user_sub: str,
    resource_type: str,
    resource_id: str,
    *,
    event_type: str,
    details: dict | None = None,
) -> Dict[str, Any]:
    """Write a timeline event to the resource's DDB table."""

def get_timeline(
    user_sub: str,
    resource_type: str,
    resource_id: str,
    *,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """Get timeline events for a resource, most recent first."""

def get_metrics(
    user_sub: str,
    resource_type: str,
    resource_id: str,
) -> Dict[str, Any]:
    """Get current resource metrics (mock in dev mode)."""

def get_health_summary(
    user_sub: str,
    resource_type: str,
    resource_id: str,
) -> Dict[str, Any]:
    """Get health summary: status, uptime, check count, failure count, restarts."""
```

### 3.6 Auto-Restart Logic

```python
def _check_restart_policy(user_sub, resource_type, resource_id):
    resource = _get_resource(user_sub, resource_type, resource_id)
    if not resource:
        return
    if not resource.get("auto_restart_enabled", False):
        return
    if resource.get("consecutive_failures", 0) < 3:
        return  # Wait for 3 consecutive failures before restart
    if resource.get("restart_count", 0) >= resource.get("max_restarts", 3):
        # Max restarts exceeded — terminate instead
        write_alert(user_sub, event="compute.restart_exhausted", outcome="error",
                    title=f"{resource.get('label', resource_id)} exceeded max restarts",
                    details={"restart_count": resource["restart_count"]})
        return

    # Perform restart
    if resource_type == "ec2":
        from app.services.ec2_launcher import stop_instance, start_instance
        stop_instance(user_sub, resource_id)
        start_instance(user_sub, resource_id)
    elif resource_type == "k8s":
        from app.services.k8s_launcher import terminate_pod, launch_pod
        # Re-launch with same params
        terminate_pod(user_sub, resource_id)
        # ... re-launch logic ...

    record_timeline_event(user_sub, resource_type, resource_id,
                          event_type="restarted",
                          details={"restart_number": resource.get("restart_count", 0) + 1})
```

### 3.7 API Router: `app/routers/instance_health.py`

New file (~120 lines). Prefix: `/ui/remote/instances`.

| Method | Path | Request | Response | Description |
|--------|------|---------|----------|-------------|
| `GET` | `/ui/remote/instances/{type}/{id}/health` | — | `HealthSummaryOut` | Health summary |
| `GET` | `/ui/remote/instances/{type}/{id}/metrics` | — | `MetricsOut` | Current metrics |
| `GET` | `/ui/remote/instances/{type}/{id}/timeline` | `?limit=50` | `TimelineOut` | Event timeline |
| `PATCH` | `/ui/remote/instances/{type}/{id}/restart-policy` | `RestartPolicyIn` | `RestartPolicyOut` | Configure auto-restart |

Where `{type}` is `ec2` or `k8s`.

#### Pydantic Models

```python
class HealthSummaryOut(BaseModel):
    resource_id: str
    resource_type: str
    health_status: str
    last_health_check_at: int
    health_check_count: int
    consecutive_failures: int
    uptime_seconds: int
    restart_count: int
    max_restarts: int
    auto_restart_enabled: bool

class MetricsOut(BaseModel):
    resource_id: str
    cpu_percent: float
    memory_percent: float
    memory_used_mb: int
    memory_total_mb: int
    disk_percent: float
    disk_used_gb: float
    disk_total_gb: float
    network_in_mbps: float
    network_out_mbps: float
    timestamp: int

class TimelineEvent(BaseModel):
    event_id: str
    event_type: str
    timestamp: int
    details: Dict[str, Any] = {}
    health_status_before: str = ""
    health_status_after: str = ""

class TimelineOut(BaseModel):
    events: List[TimelineEvent]
    count: int

class RestartPolicyIn(BaseModel):
    auto_restart_enabled: bool
    max_restarts: int = Field(default=3, ge=0, le=10)

class RestartPolicyOut(BaseModel):
    resource_id: str
    auto_restart_enabled: bool
    max_restarts: int
    restart_count: int
```

### 3.8 Frontend Components

#### InstanceDetailPage (`frontend/src/pages/remote/InstanceDetailPage.tsx`)

New page (~450 lines):

- **Header**: Resource label with health status badge (green circle = healthy, yellow = degraded, red = unreachable)
- **Uptime counter**: "Up for 2h 34m" or "Last seen 5m ago"
- **Metrics cards row**: CPU gauge, Memory gauge, Disk gauge, Network I/O numbers
  - Gauges: circular progress indicators with percentage and color (green < 70%, yellow 70-90%, red > 90%)
  - Auto-refresh every 10 seconds via `useQuery` with `refetchInterval: 10_000`
- **Timeline section**: Scrollable list of events with icons, timestamps, and details
  - `launched` → rocket icon
  - `health_ok` → green check
  - `health_fail` → red X
  - `restarted` → refresh icon
  - `auto_terminated` → stop icon
- **Restart policy section**: Toggle switch for auto-restart, max restarts input
- **Actions**: Connect (SSH/VNC), Stop, Terminate

#### Route

```tsx
<Route path="/remote/instances/:type/:id" element={<InstanceDetailPage />} />
```

Accessed by clicking on an instance in the EC2 or K8s list pages.

---

## 4. Implementation Plan

### Phase 1: Health Check Service (2 days)

| File | Change |
|------|--------|
| `app/services/instance_health.py` | New file: health probes, mock metrics, timeline, auto-restart |
| `app/main.py` | Register health checker background task |

### Phase 2: DDB Schema + API (1-2 days)

| File | Change |
|------|--------|
| `app/services/ec2_launcher.py` | Add health fields to instance items, record launch timeline event |
| `app/services/k8s_launcher.py` | Add health fields to pod items, record launch timeline event |
| `app/routers/instance_health.py` | New file: 4 endpoints |
| `app/models.py` | Add health/metrics/timeline Pydantic models |
| `app/main.py` | Register instance_health router |

### Phase 3: Frontend (2-3 days)

| File | Change |
|------|--------|
| `frontend/src/api/types.ts` | Add health/metrics/timeline types |
| `frontend/src/api/endpoints/instance-health.ts` | New file: API wrappers |
| `frontend/src/pages/remote/InstanceDetailPage.tsx` | New file: detail page with metrics + timeline |
| `frontend/src/App.tsx` | Add `/remote/instances/:type/:id` route |
| `frontend/src/pages/remote/Ec2LauncherPage.tsx` | Add health badge to instance rows, link to detail page |
| `frontend/src/pages/remote/K8sLauncherPage.tsx` | Add health badge to pod rows, link to detail page |

### Phase 4: E2E Tests (1 day)

| File | Change |
|------|--------|
| `frontend/e2e/instance-monitoring.spec.ts` | New file: ~15 tests in 3 sections |

---

## 5. E2E Test Plan (`frontend/e2e/instance-monitoring.spec.ts`)

**Section 267: Health & Metrics API (5 tests)**

1. `Get health summary for running instance` — Launch EC2 instance, GET `/health`. Verify `health_status` is one of `healthy`, `degraded`, `unreachable`. Verify `health_check_count >= 0`, `uptime_seconds >= 0`.
2. `Get metrics for running instance` — Launch instance, GET `/metrics`. Verify `cpu_percent` >= 0, `memory_percent` >= 0, `timestamp` > 0.
3. `Health check of terminated instance returns 404` — Terminate instance, GET `/health` → 404 or `health_status: "unknown"`.
4. `Set restart policy` — PATCH `/restart-policy` with `auto_restart_enabled: true`, `max_restarts: 5`. GET health, verify settings.
5. `K8s pod health works same as EC2` — Launch K8s pod, GET `/health`. Verify same schema.

**Section 268: Timeline API (5 tests)**

6. `Launch creates timeline event` — Launch instance. GET `/timeline`. Verify at least 1 event with `event_type: "launched"`.
7. `Stop/start creates timeline events` — Stop, then start instance. GET timeline. Verify `user_stopped` and `status_changed` events.
8. `Timeline sorted newest first` — Create multiple events. Verify `events[0].timestamp >= events[1].timestamp`.
9. `Timeline limit works` — GET `/timeline?limit=2`. Verify `count <= 2`.
10. `Terminate creates timeline event` — Terminate instance. GET timeline before termination cleanup. Verify `auto_terminated` or `user_terminated` event.

**Section 269: Instance Detail UI (5 tests)**

11. `InstanceDetailPage renders health badge` — Navigate to `/remote/instances/ec2/{id}`. Verify health status badge visible.
12. `Metrics cards show CPU and memory` — Verify "CPU" and "Memory" labels with percentage values.
13. `Timeline shows lifecycle events` — Verify "Launched" event in timeline section.
14. `Restart policy toggle works` — Toggle auto-restart on. Verify toggle state persists after page reload.
15. `Navigate back to instance list` — Click back button. Verify return to EC2 instances page.

---

## 6. Security Considerations

### 6.1 Health Probe Network Access

In production, health probes run from the platform backend to instance SSH ports. The backend's egress IP must be allowed in the instance's security group (handled by INFRA-009).

### 6.2 Metrics Privacy

Metrics are per-user-scoped. No user can view another user's instance metrics. Admin access is covered by INFRA-012.

### 6.3 Auto-Restart Limits

`max_restarts` (default: 3, max: 10) prevents infinite restart loops. After exhausting restarts, the resource is left in its failed state and the user is alerted.

---

## 7. Acceptance Criteria

1. Health checker runs as a background task probing all running resources.
2. Health status is one of `healthy`, `degraded`, `unreachable`, `unknown`.
3. Mock metrics provide realistic CPU/memory/disk/network values.
4. Timeline records all lifecycle events with timestamps.
5. Alerts fire on health status degradation.
6. Auto-restart is configurable per resource with a max restart limit.
7. Instance detail page shows health badge, metric gauges, and event timeline.
8. Metrics auto-refresh every 10 seconds.
9. Health data is user-isolated.
10. All health and restart events produce audit log entries.

---

## 8. Architecture & Data Flow

```
  Background Health Checker (asyncio loop, every 30s)
       │
       ├── Query ec2_instances table: status="running"
       │     └── For each instance:
       │           │
       │           ├── _probe_instance(hostname, port=22)
       │           │     ├── dev_mode? → _mock_health_probe() → random(healthy/degraded/unreachable)
       │           │     └── prod? → TCP connect to SSH port, 5s timeout
       │           │
       │           ├── Compare old health_status vs new
       │           │     └── Changed? → _handle_health_change()
       │           │           ├── record_timeline_event(status_changed)
       │           │           └── write_alert() if degraded/unreachable
       │           │
       │           ├── Update DDB: health_status, last_health_check_at, health_check_count
       │           │     └── If unreachable: increment consecutive_failures
       │           │     └── If healthy: reset consecutive_failures to 0
       │           │
       │           ├── _check_restart_policy()
       │           │     └── consecutive_failures >= 3 AND auto_restart_enabled AND restart_count < max_restarts?
       │           │           ├── stop_instance() + start_instance()
       │           │           ├── record_timeline_event(restarted)
       │           │           └── increment restart_count
       │           │
       │           └── Generate mock metrics (_mock_metrics())
       │                 └── cpu_percent, memory_percent, disk_percent, network I/O
       │
       └── Query k8s_pods table: status="running"
             └── Same flow as EC2
```

---

## 9. Detailed DynamoDB Access Patterns

| # | Access Pattern | Table / GSI | PK | SK | Operation | Notes |
|---|---------------|-------------|----|----|-----------|-------|
| 1 | Get instance health fields | `ec2_instances` | `user_sub` | `INSTANCE#{instance_id}` | GetItem (projection: health_*) | Returns health status + counters |
| 2 | Update health status after probe | `ec2_instances` | `user_sub` | `INSTANCE#{instance_id}` | UpdateItem SET health_status, last_health_check_at, etc. | Conditional on attribute_exists |
| 3 | Write timeline event | `ec2_instances` | `user_sub` | `TIMELINE#{instance_id}#{timestamp}#{event_id}` | PutItem | Append-only timeline |
| 4 | List timeline events | `ec2_instances` | `user_sub` | begins_with `TIMELINE#{instance_id}#` | Query (ScanIndexForward=False, Limit) | Newest first |
| 5 | Find all running instances | `ec2_instances` GSI `ByStatus` | `status` = "running" | `user_sub` | Query | Used by health checker background task |
| 6 | Increment restart count | `ec2_instances` | `user_sub` | `INSTANCE#{instance_id}` | UpdateItem ADD restart_count :one | Atomic counter |
| 7 | Update restart policy | `ec2_instances` | `user_sub` | `INSTANCE#{instance_id}` | UpdateItem SET auto_restart_enabled, max_restarts | User-initiated |
| 8 | Get pod health (K8s) | `k8s_pods` | `user_sub` | `POD#{pod_id}` | GetItem | Same pattern as EC2 |

---

## 10. API Request/Response Examples

**GET /ui/remote/instances/ec2/{id}/health**

```bash
curl http://localhost:8000/ui/remote/instances/ec2/i-abc123/health \
  -H "Cookie: ui_session=sess_xxx; ui_access_token=jwt_xxx"
```

Response (200):
```json
{
  "resource_id": "i-abc123",
  "resource_type": "ec2",
  "health_status": "healthy",
  "last_health_check_at": 1748520030,
  "health_check_count": 142,
  "consecutive_failures": 0,
  "uptime_seconds": 7234,
  "restart_count": 0,
  "max_restarts": 3,
  "auto_restart_enabled": true
}
```

**GET /ui/remote/instances/ec2/{id}/metrics**

Response (200):
```json
{
  "resource_id": "i-abc123",
  "cpu_percent": 34.2,
  "memory_percent": 48.7,
  "memory_used_mb": 1996,
  "memory_total_mb": 4096,
  "disk_percent": 22.3,
  "disk_used_gb": 11.2,
  "disk_total_gb": 50.0,
  "network_in_mbps": 2.45,
  "network_out_mbps": 0.87,
  "timestamp": 1748520040
}
```

**GET /ui/remote/instances/ec2/{id}/timeline?limit=5**

Response (200):
```json
{
  "events": [
    {
      "event_id": "evt_a1b2c3",
      "event_type": "health_ok",
      "timestamp": 1748520030,
      "details": {"probe_target": "10.0.1.5:22"},
      "health_status_before": "healthy",
      "health_status_after": "healthy"
    },
    {
      "event_id": "evt_d4e5f6",
      "event_type": "launched",
      "timestamp": 1748512800,
      "details": {"instance_type": "t3.small", "ami_id": "ami-ubuntu-2204"},
      "health_status_before": "",
      "health_status_after": "unknown"
    }
  ],
  "count": 2
}
```

**PATCH /ui/remote/instances/ec2/{id}/restart-policy**

```json
// Request
{ "auto_restart_enabled": true, "max_restarts": 5 }

// Response (200)
{
  "resource_id": "i-abc123",
  "auto_restart_enabled": true,
  "max_restarts": 5,
  "restart_count": 0
}
```

---

## 11. Error Handling Matrix

| Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|----------|-------------|------------|---------------------|-----------------|
| Instance not found | 404 | `instance_not_found` | "Instance not found" | Verify instance ID |
| Instance belongs to another user | 403 | `forbidden` | "Access denied" | Use your own instances |
| Invalid resource type in path | 400 | `invalid_resource_type` | "Resource type must be 'ec2' or 'k8s'" | Fix URL path |
| max_restarts > 10 | 422 | `validation_error` | "Max restarts must be 0-10" | Reduce value |
| max_restarts < 0 | 422 | `validation_error` | "Max restarts must be 0-10" | Use non-negative value |
| Timeline limit exceeds 200 | 422 | `validation_error` | "Limit must be 1-200" | Reduce limit |
| Health check of terminated instance | 200 | N/A | Returns `health_status: "unknown"` | Instance is terminated |
| Metrics of stopped instance | 200 | N/A | Returns all zeros | Start instance first |
| Unauthenticated request | 401 | `unauthorized` | "Authentication required" | Log in |
| Background health checker DDB error | N/A (logged) | N/A | No user impact | Check DDB connectivity |

---

## 12. Frontend Component Tree

```
InstanceDetailPage
├── PageHeader
│   ├── BackButton → navigate to instance list
│   ├── ResourceLabel (instance name)
│   ├── HealthBadge (green/yellow/red circle)
│   │   └── Tooltip: "Healthy" / "Degraded" / "Unreachable"
│   └── UptimeCounter ("Up for 2h 34m" or "Last seen 5m ago")
├── MetricsRow (horizontal card layout, auto-refresh 10s)
│   ├── CpuGauge
│   │   ├── CircularProgress (color: green < 70%, yellow 70-90%, red > 90%)
│   │   └── Label ("CPU 34.2%")
│   ├── MemoryGauge
│   │   ├── CircularProgress
│   │   └── Label ("Memory 48.7% — 1.9GB / 4.0GB")
│   ├── DiskGauge
│   │   ├── CircularProgress
│   │   └── Label ("Disk 22.3%")
│   └── NetworkCard
│       ├── InRate ("↓ 2.45 Mbps")
│       └── OutRate ("↑ 0.87 Mbps")
├── TimelineSection
│   ├── SectionHeader ("Event Timeline")
│   └── TimelineList (scrollable, newest first)
│       └── TimelineItem[]
│           ├── EventIcon (rocket/check/x/refresh/stop per event_type)
│           ├── EventTitle (human-readable event_type)
│           ├── Timestamp (relative, e.g., "2 minutes ago")
│           └── ExpandableDetails (JSON detail view)
├── RestartPolicySection
│   ├── SectionHeader ("Auto-Restart Policy")
│   ├── AutoRestartToggle (Switch component)
│   ├── MaxRestartsInput (number input, 0-10)
│   ├── RestartCountDisplay ("Restarts used: 0 / 5")
│   └── SaveButton
└── ActionsRow
    ├── ConnectButton (SSH/VNC)
    ├── StopButton
    └── TerminateButton (with confirmation dialog)
```

**Props interfaces:**

```typescript
interface HealthBadgeProps {
  status: "healthy" | "degraded" | "unreachable" | "unknown";
}

interface MetricGaugeProps {
  label: string;
  value: number;       // percentage 0-100
  detail?: string;     // e.g. "1.9GB / 4.0GB"
}

interface TimelineItemProps {
  event: TimelineEvent;
}

interface RestartPolicySectionProps {
  resourceId: string;
  resourceType: "ec2" | "k8s";
  currentPolicy: RestartPolicyOut;
  onSave: (policy: RestartPolicyIn) => void;
}
```

---

## 13. Observability

### 13.1 Metrics

| Metric Name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `health_check_total` | Counter | `resource_type`, `result` (healthy/degraded/unreachable) | Health probe outcomes |
| `health_status_change_total` | Counter | `resource_type`, `from_status`, `to_status` | Status transitions |
| `auto_restart_total` | Counter | `resource_type` | Auto-restarts triggered |
| `auto_restart_exhausted_total` | Counter | `resource_type` | Resources that exceeded max restarts |
| `health_checker_duration_seconds` | Histogram | | Time to complete one full health check cycle |
| `timeline_events_written_total` | Counter | `event_type` | Timeline events recorded |

### 13.2 Structured Logging

| Log Event | Level | Fields | Trigger |
|-----------|-------|--------|---------|
| `health.probe_completed` | DEBUG | `resource_id`, `result`, `duration_ms` | Each probe |
| `health.status_changed` | INFO | `resource_id`, `from`, `to`, `user_sub` | Health transition |
| `health.auto_restart` | WARN | `resource_id`, `restart_number`, `max_restarts` | Auto-restart triggered |
| `health.restart_exhausted` | ERROR | `resource_id`, `user_sub`, `restart_count` | Max restarts exceeded |
| `health.checker_cycle` | DEBUG | `ec2_count`, `k8s_count`, `duration_ms` | Health checker loop |

### 13.3 Alerting

| Alert | Condition | Severity | Action |
|-------|-----------|----------|--------|
| Health checker not running | No `health.checker_cycle` log in 5 minutes | Critical | Restart backend |
| High unreachable rate | > 20% of probes return unreachable in 10 min | Warning | Check network / instance health |
| Auto-restart storm | > 5 auto-restarts in 10 minutes | Warning | Check underlying infrastructure |

---

## 14. Performance Considerations

### 14.1 Latency Targets

| Operation | Target P95 | Notes |
|-----------|-----------|-------|
| Health summary GET | < 50ms | Single DDB GetItem |
| Metrics GET | < 50ms | Single GetItem (or mock generation) |
| Timeline GET (50 events) | < 150ms | DDB Query with Limit |
| Restart policy PATCH | < 100ms | Single UpdateItem |
| Health checker full cycle | < 10s | Parallel probes for all running instances |

### 14.2 Health Checker Scalability

- The health checker queries all running instances per cycle. With 1000 running instances, this requires ~1000 DDB queries + 1000 TCP probes.
- TCP probes run concurrently via `asyncio.gather()` with a semaphore (max 50 concurrent probes) to avoid socket exhaustion.
- In dev mode, mock probes are instant (no network I/O), so the checker handles any instance count.

### 14.3 Metrics Refresh

- Frontend polls metrics every 10 seconds via `useQuery({ refetchInterval: 10_000 })`.
- Each poll is a single DDB GetItem (< 1ms at DDB level).
- 100 concurrent users viewing detail pages = 10 requests/second = negligible DDB load.

---

## 15. Rollout Plan

### 15.1 Feature Flags

| Flag | Environment Variable | Default | Description |
|------|---------------------|---------|-------------|
| `instance_health_enabled` | `INSTANCE_HEALTH_ENABLED` | `true` | Master switch for health monitoring |
| `auto_restart_enabled` | `INSTANCE_AUTO_RESTART_ENABLED` | `true` | Enable auto-restart on failure |
| `health_check_interval` | `HEALTH_CHECK_INTERVAL_SECONDS` | `30` | Seconds between health checker cycles |

### 15.2 Phased Rollout

**Phase 1 (Day 1-2)**: Health checker service + mock probes + mock metrics. Background task registered in `main.py`.

**Phase 2 (Day 3-4)**: API endpoints (4 routes). Timeline event recording on launch/stop/terminate.

**Phase 3 (Day 5-6)**: Frontend InstanceDetailPage with health badge, metrics, timeline, restart policy.

**Phase 4 (Day 7)**: E2E tests. Production rollout with auto-restart disabled initially.

### 15.3 Rollback

1. Set `INSTANCE_HEALTH_ENABLED=false` -- background checker stops, API returns 400.
2. Health fields on instance items remain but are stale.
3. Frontend hides health features when flag is off.

---

## 16. Expanded E2E Tests

### Section 267: Health & Metrics API (5 tests) -- existing

1-5. (As defined above in Section 5)

### Section 268: Timeline API (5 tests) -- existing

6-10. (As defined above in Section 5)

### Section 269: Instance Detail UI (5 tests) -- existing

11-15. (As defined above in Section 5)

### Section 270: Health Edge Cases & Auto-Restart (8 tests)

16. `Health check count increments on each probe` -- Launch instance, wait for at least 1 health check cycle. GET health. Verify `health_check_count >= 1`.
17. `Consecutive failures reset to 0 when healthy` -- Instance that was degraded becomes healthy. Verify `consecutive_failures: 0`.
18. `Auto-restart disabled by default on new instances` -- Launch instance. GET health. Verify `auto_restart_enabled: false` (default).
19. `Enable auto-restart, verify persists after reload` -- PATCH restart policy, reload page, GET health. Verify settings match.
20. `max_restarts=0 disables auto-restart even if enabled` -- Set `auto_restart_enabled: true, max_restarts: 0`. Instance failure does not trigger restart.
21. `K8s pod health returns same schema as EC2` -- Launch K8s pod. GET `/ui/remote/instances/k8s/{id}/health`. Verify same `HealthSummaryOut` fields.
22. `Metrics return non-negative values` -- GET metrics. Verify all numeric fields >= 0.
23. `Timeline events include resource_id in details` -- GET timeline after launch. Verify event details contain the instance/pod ID.

### Section 271: Multi-Instance Health Isolation (5 tests)

24. `Alice cannot view Bob's instance health` -- Bob launches instance. Alice tries GET health. Verify 403 or 404.
25. `Alice cannot modify Bob's restart policy` -- PATCH Bob's instance restart policy as Alice. Verify 403.
26. `Terminated instance health returns unknown` -- Terminate instance. GET health. Verify `health_status: "unknown"`.
27. `Stopped instance health returns unknown` -- Stop instance. GET health. Verify `health_status: "unknown"` or no health checks run.
28. `Timeline survives instance stop/start cycle` -- Launch, stop, start. GET timeline. Verify events for all transitions present.

---

## Codebase References

> **Verification performed**: 2026-05-29

### Verified (EXISTS in codebase)

| Reference | File | Line(s) | Status |
|-----------|------|---------|--------|
| `write_alert()` | `app/services/alerts.py` | 355 | VERIFIED |
| `audit_event()` | `app/services/alerts.py` | 695 | VERIFIED |
| `session_timeout_policy()` in VNC | `app/services/vnc_sessions.py` | 143 | VERIFIED |
| `browser_ssh_terminal_enabled` setting | `app/core/settings.py` | 114 | VERIFIED |

### Not Yet Implemented (requires new code)

<!-- NOTE: INFRA-003 (EC2 Launcher) and INFRA-004 (K8s Launcher) are dependencies but do not exist yet. All health monitoring infrastructure is new. -->

| Reference | Expected Location | Status |
|-----------|-------------------|--------|
| EC2 instance status tracking (INFRA-003) | `app/services/ec2_launcher.py` | NOT FOUND -- new implementation required |
| K8s pod status tracking (INFRA-004) | `app/services/k8s_launcher.py` | NOT FOUND -- new implementation required |
| `ec2_instances` DDB table | `scripts/local-ddb-init.py` | NOT FOUND -- new table required |
| `k8s_pods` DDB table | `scripts/local-ddb-init.py` | NOT FOUND -- new table required |
| Health check background worker | `app/services/instance_health.py` | NOT FOUND -- new service required |
| Health check router | `app/routers/instance_health.py` | NOT FOUND -- new router required |
| `HealthSummaryOut` model | `app/models.py` | NOT FOUND -- new model required |
| Health/timeline settings (feature flags) | `app/core/settings.py` | NOT FOUND -- new settings required |
| `frontend/src/pages/remote/InstanceDetailPage.tsx` | `frontend/src/pages/remote/` | NOT FOUND -- new page required |

---

## Testing Strategy

### Unit Tests (`tests/test_instance_health.py`)

**Mock setup**: Use `moto` to mock DynamoDB. Create `ec2_instances` and `k8s_pods` tables with health fields and TIMELINE SK pattern. Patch `app.core.tables.T` to point at moto tables. Patch `_mock_health_probe` to return deterministic results.

**Test functions**:

| Function | What it validates |
|----------|-------------------|
| `test_mock_health_probe_returns_valid_status` | `_mock_health_probe(id)` returns one of `healthy`, `degraded`, `unreachable`. |
| `test_mock_metrics_returns_all_fields` | `_mock_metrics(id)` returns dict with `cpu_percent`, `memory_percent`, `memory_used_mb`, `memory_total_mb`, `disk_percent`, `disk_used_gb`, `disk_total_gb`, `network_in_mbps`, `network_out_mbps`, `timestamp`. All numeric and non-negative. |
| `test_record_timeline_event_stores_item` | `record_timeline_event(user, "ec2", id, event_type="launched")` writes DDB item with SK starting with `TIMELINE#`. |
| `test_get_timeline_newest_first` | Write 3 events with different timestamps. `get_timeline(...)` returns events sorted newest first. |
| `test_get_timeline_respects_limit` | Write 5 events. `get_timeline(limit=2)` returns exactly 2 events. |
| `test_handle_health_change_writes_timeline` | Call `_handle_health_change(user, "ec2", id, old="healthy", new="degraded")`. Verify timeline event with `event_type="status_changed"`. |
| `test_handle_health_change_sends_alert_on_degradation` | Patch `write_alert`. Call `_handle_health_change(old="healthy", new="unreachable")`. Verify `write_alert` called with `event="compute.health_degraded"`. |
| `test_handle_health_change_no_alert_on_recovery` | Patch `write_alert`. Call `_handle_health_change(old="unreachable", new="healthy")`. Verify `write_alert` NOT called. |
| `test_check_restart_policy_restarts_on_3_failures` | Set instance with `auto_restart_enabled=True`, `consecutive_failures=3`, `restart_count=0`, `max_restarts=3`. Patch EC2 stop/start. Call `_check_restart_policy`. Verify stop+start called, timeline event "restarted" written. |
| `test_check_restart_policy_skips_when_disabled` | Set `auto_restart_enabled=False`, `consecutive_failures=5`. Call `_check_restart_policy`. Verify no restart triggered. |
| `test_check_restart_policy_skips_when_under_threshold` | Set `auto_restart_enabled=True`, `consecutive_failures=2`. Verify no restart (threshold is 3). |
| `test_check_restart_policy_exhausted` | Set `restart_count=3`, `max_restarts=3`. Verify no restart, alert with `event="compute.restart_exhausted"`. |
| `test_get_health_summary_returns_all_fields` | Populate health fields on instance. `get_health_summary(...)` returns `HealthSummaryOut`-compatible dict with all expected keys. |
| `test_consecutive_failures_reset_on_healthy` | After setting `consecutive_failures=5`, simulate healthy probe. Verify `consecutive_failures` reset to 0. |
| `test_health_check_count_increments` | Simulate 3 probe cycles. Verify `health_check_count == 3`. |

### Integration Tests (`tests/test_instance_health_integration.py`)

**Setup**: Full FastAPI test client with moto DDB. Pre-seed one running EC2 instance and one running K8s pod.

| Test | What it validates |
|------|-------------------|
| `test_get_health_api_returns_200` | GET `/ui/remote/instances/ec2/{id}/health` returns 200 with valid `HealthSummaryOut`. |
| `test_get_metrics_api_returns_200` | GET `/ui/remote/instances/ec2/{id}/metrics` returns 200 with valid `MetricsOut`. |
| `test_get_timeline_api_returns_200` | GET `/ui/remote/instances/ec2/{id}/timeline` returns 200 with `events` array. |
| `test_patch_restart_policy_api` | PATCH `/ui/remote/instances/ec2/{id}/restart-policy` with `{auto_restart_enabled: true, max_restarts: 5}`. Verify 200 and returned values. |
| `test_invalid_resource_type_returns_400` | GET `/ui/remote/instances/invalid/{id}/health` returns 400. |
| `test_nonexistent_instance_returns_404` | GET `/ui/remote/instances/ec2/nonexistent/health` returns 404. |
| `test_user_isolation_returns_403` | Alice requests Bob's instance health. Returns 403 or 404. |
| `test_max_restarts_validation` | PATCH with `max_restarts: 15` returns 422. PATCH with `max_restarts: -1` returns 422. |
| `test_k8s_pod_health_same_schema` | GET `/ui/remote/instances/k8s/{id}/health` returns same schema fields as EC2. |

### E2E Tests (`frontend/e2e/instance-monitoring.spec.ts`)

**Auth pattern**: `injectAuth(page, "alice")` for all operations. CSRF via `sessions["alice"].csrf_token` on PATCH.

**Section 267: Health & Metrics API (5 tests)**
- Setup: Launch EC2 instance via `page.request.post("/ui/remote/ec2/launch", ...)`.
- Test 1: `GET /ui/remote/instances/ec2/${id}/health` — assert 200, `body.health_status` is one of `["healthy", "degraded", "unreachable", "unknown"]`, `body.health_check_count >= 0`.
- Test 2: `GET /ui/remote/instances/ec2/${id}/metrics` — assert 200, `body.cpu_percent >= 0`, `body.memory_percent >= 0`, `body.timestamp > 0`.
- Test 3: Terminate instance. `GET /health` — assert 404 or `body.health_status === "unknown"`.
- Test 4: `PATCH /restart-policy` with `{ auto_restart_enabled: true, max_restarts: 5 }`, CSRF header. GET health, assert `auto_restart_enabled === true`, `max_restarts === 5`.
- Test 5: Launch K8s pod. `GET /ui/remote/instances/k8s/${podId}/health` — assert 200, same schema.

**Section 268: Timeline API (5 tests)**
- Test 6: After launch, GET `/timeline` — assert `body.events.length >= 1`, find event with `event_type === "launched"`.
- Test 7: Stop then start instance. GET `/timeline` — find events for transitions.
- Test 8: Verify `body.events[0].timestamp >= body.events[1].timestamp` (newest first).
- Test 9: GET `/timeline?limit=2` — assert `body.events.length <= 2`.
- Test 10: Terminate instance. GET `/timeline` — find termination event.

**Section 269: Instance Detail UI (5 tests)**
- Test 11: Navigate to `/remote/instances/ec2/${id}`. Assert health badge: `page.locator("[data-testid='health-badge']")` or `page.getByText(/healthy|degraded|unreachable/i)` visible.
- Test 12: Assert metrics labels: `page.getByText("CPU")`, `page.getByText("Memory")` visible with percentage values.
- Test 13: Assert timeline section: `page.getByText("Launched")` or equivalent event in timeline list.
- Test 14: Toggle auto-restart switch. Reload page. Verify toggle state persists.
- Test 15: Click back button. Assert URL matches `/remote/instances` or EC2 list.

**Section 270: Health Edge Cases & Auto-Restart (8 tests)**
- Tests 16-23: Health check count increments, consecutive failures reset, auto-restart default off, restart policy persistence, max_restarts=0, K8s schema parity, non-negative metrics, resource_id in timeline details.

**Section 271: Multi-Instance Health Isolation (5 tests)**
- Tests 24-28: Bob-to-Alice isolation (403/404), Alice can't PATCH Bob's policy, terminated health=unknown, stopped health=unknown, timeline survives stop/start cycle.

**Negative tests**: 401 (no auth), 403 (cross-user), 404 (nonexistent instance), 400 (invalid resource type), 422 (max_restarts out of range).

**Teardown**: Terminate launched instances in `afterAll`.

**Retry safety**: Each test run uses unique instance labels with `Date.now()` suffix. Health checks are non-deterministic but tests assert range-based values (>= 0, one of valid set) not exact values.

### Test Data Requirements

| Requirement | Details |
|-------------|---------|
| DynamoDB tables | `ec2_instances` and `k8s_pods` with health fields + TIMELINE SK pattern + `ByStatus` GSI |
| Running instances | Launched in `beforeAll` via EC2/K8s launch endpoints (INFRA-003/004 must exist) |
| Test users | Alice (USER) for primary tests, Bob (USER) for isolation tests |
| Session seeding | `e2e_session_setup.py` |
| Background health checker | Must be running (started via `app/main.py` startup event) |

### CI / Pipeline

| Concern | Approach |
|---------|----------|
| Feature flag | Set `INSTANCE_HEALTH_ENABLED=true` in CI `.env.local` |
| Health checker timing | Tests may need a brief wait (up to 35s) after launch for first health check cycle; use `page.waitForResponse` or retry loop |
| Serial execution | Single-worker; health checker modifies shared DDB state |
| Non-deterministic probes | Mock probes return random results; test assertions use `oneOf` / range checks, not exact values |
| Dependencies | INFRA-003 and INFRA-004 must be deployed for launch endpoints |

---

## Dependencies & Merge Safety

### Depends On

| Ticket | What's Needed | Status | Can Overlap? |
|--------|---------------|--------|--------------|
| INFRA-003 (EC2 Launcher) | `ec2_instances` DDB table, `launch_instance`, `stop_instance`, `start_instance` functions, instance status tracking | **Not yet implemented** | Partially — service layer can be written against interface, but integration tests require INFRA-003 |
| INFRA-004 (K8s Launcher) | `k8s_pods` DDB table, `launch_pod`, `terminate_pod` functions, pod status tracking | **Not yet implemented** | Same as above |

### Depended On By

| Ticket | What It Needs From INFRA-008 |
|--------|------------------------------|
| INFRA-012 (Admin Compute Dashboard) | Health status data for admin-level instance overview, timeline events for admin audit view |
| AGENT-010 (DevOps SRE Agent) | Health monitoring data for automated incident response |

### Merge Strategy

**Sequential after INFRA-003/004, feature-flag-gated**

- The health checker service must integrate with `ec2_instances` and `k8s_pods` DDB tables created by INFRA-003/004.
- The `instance_health.py` service imports from `ec2_launcher.py` and `k8s_launcher.py` for auto-restart. These files must exist.
- The router uses a new prefix (`/ui/remote/instances/{type}/{id}/...`) that does not conflict with existing routes.
- Feature flag `INSTANCE_HEALTH_ENABLED` gates both the background checker and API endpoints.
- Timeline events use the same DDB table as instances (single-table design), so no new table is needed.

### Merge Checklist

- [ ] INFRA-003 and INFRA-004 merged and functional
- [ ] `app/services/instance_health.py` — all functions implemented (probes, metrics, timeline, restart logic)
- [ ] `app/routers/instance_health.py` — 4 endpoints registered
- [ ] `app/main.py` — router registered + `run_health_checker()` background task started
- [ ] `app/models.py` — `HealthSummaryOut`, `MetricsOut`, `TimelineEvent`, `TimelineOut`, `RestartPolicyIn`, `RestartPolicyOut` added
- [ ] `app/core/settings.py` — `INSTANCE_HEALTH_ENABLED`, `INSTANCE_AUTO_RESTART_ENABLED`, `HEALTH_CHECK_INTERVAL_SECONDS` settings
- [ ] Health fields added to EC2 instance and K8s pod DDB items (in INFRA-003/004 service layers)
- [ ] `frontend/src/api/types.ts` — health/metrics/timeline TypeScript types
- [ ] `frontend/src/api/endpoints/instance-health.ts` — API wrappers
- [ ] `frontend/src/pages/remote/InstanceDetailPage.tsx` — detail page with metrics, timeline, restart policy
- [ ] `frontend/src/App.tsx` — `/remote/instances/:type/:id` route
- [ ] Feature flags in `.env.local.example`
- [ ] E2E tests pass: `npx playwright test e2e/instance-monitoring.spec.ts`
- [ ] Unit tests pass: `pytest tests/test_instance_health.py`
- [ ] Health checker does not crash the backend if DDB tables are missing (graceful degradation)
