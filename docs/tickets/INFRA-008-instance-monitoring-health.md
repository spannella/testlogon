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

The platform has an alerts system (`app/services/alerts.py`) with `write_alert()` for in-app notifications, but it is not wired to instance health events. The VNC system in `app/services/vnc_sessions.py` has timeout policies (idle timeout, max session duration) but no health probes.

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

`write_alert(user_sub, *, event, outcome, title, details)` creates in-app alerts. This is the integration point for health status change notifications.

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
