# AGENT-004: Worker Fleet Management UI

**Ticket**: AGENT-004
**Author**: Engineering
**Status**: Implemented
**Date**: 2026-05-29
**Priority**: Medium
**Estimated effort**: 8-10 days
**Dependencies**: AGENT-001 (LLM Keys), AGENT-002 (Worker Provisioning), AGENT-003 (Agent Framework)

---

## 1. Overview & Motivation

### 1.1 Purpose

AGENT-004 provides a comprehensive dashboard for managing a fleet of autonomous AI agent workers. Users can monitor all workers in one view, see which tickets each agent is working on, view live terminal output, manage worker lifecycle (start/stop/terminate), create new workers from templates, and track fleet-level metrics like throughput, queue depth, and cost. The dashboard uses SSE for real-time updates so state changes appear without polling.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| User | As a user, I want to see all my agent workers in one dashboard so that I can monitor my fleet at a glance. | Dashboard shows grid/table of all workers with status badges, current ticket, uptime. |
| User | As a user, I want to see live terminal output from a worker so that I can watch what the agent is doing. | Worker detail drawer shows streamed terminal output in a terminal emulator view. |
| User | As a user, I want to start all idle workers with one click so that I can spin up the fleet quickly. | "Start All" button sends start to all idle workers; status badges update in real-time. |
| User | As a user, I want to save a worker configuration as a template so that I can quickly create identical workers. | "Save as Template" button; templates appear in "Create from Template" dropdown. |
| User | As a user, I want to see queue depth vs. worker count so that I can decide if I need more workers. | Capacity bar shows tickets in queue per type vs. active workers per type. |
| User | As a user, I want cost tracking per worker so that I can identify expensive agents and optimize. | Worker detail shows uptime, estimated cost, tokens used, tickets completed. |
| User | As a user, I want real-time notifications when a worker changes state so that I can react to errors immediately. | SSE pushes state change events; badge count on nav item updates. |
| Admin | As an admin, I want to see fleet metrics across all users so that I can monitor platform-wide agent usage. | Admin dashboard shows total workers, aggregate throughput, cost distribution. |

### 1.3 Why This Is Needed

Managing individual workers through separate API calls (AGENT-002, AGENT-003) is workable for 1-2 agents but becomes unwieldy at scale. Users running 3-5 agents need a unified view to understand fleet health, identify bottlenecks (too many tickets, too few workers), and take bulk actions. The fleet dashboard is the primary user interface for the agent orchestration platform.

---

## 2. Current State Analysis

### 2.1 Existing Infrastructure

| Component | Location | Relevance |
|-----------|----------|-----------|
| Worker provisioner | `app/services/agent_worker_provisioner.py` (AGENT-002) | <!-- NOTE: does not exist yet — requires AGENT-002 --> Worker CRUD, lifecycle |
| Agent orchestrator | `app/services/agent_orchestrator.py` (AGENT-003) | <!-- NOTE: does not exist yet — requires AGENT-003 --> Agent state, ticket claims, heartbeat |
| LLM key store | `app/services/llm_provider_keys.py` (AGENT-001) | <!-- NOTE: does not exist yet — requires AGENT-001 --> Key usage stats |
| Ticket store | `app/services/tickets.py` | Ticket queue queries for capacity planning (verified — `TicketStore` at line 110) |
| SSE patterns | Various routers | `StreamingResponse` + `asyncio.Queue` for real-time push (verified) |
| DataTable component | `frontend/src/components/shared/DataTable.tsx` | <!-- NOTE: was `frontend/src/components/ui/data-table.tsx` which does not exist. The actual DataTable is at `frontend/src/components/shared/DataTable.tsx` --> Reusable table with sorting, filtering |
| Card/Sheet/Drawer | `frontend/src/components/ui/` | shadcn/ui layout primitives (verified — directory exists) |
| Cost tracking | `app/services/compute_cost.py` (INFRA-005) | <!-- NOTE: does not exist yet — requires INFRA-005 implementation --> Per-instance cost data |
| Alerts | `app/services/alerts.py` | Notification infrastructure (verified) |

### 2.2 Gaps

1. **No fleet-level API** -- no endpoints for bulk operations (start all, stop all) or aggregate metrics.
2. **No fleet dashboard page** -- no frontend page combining worker list, queue depth, and capacity view.
3. **No worker detail drawer** -- no in-page detail view with live terminal, logs, and metrics.
4. **No worker templates** -- no mechanism to save and reuse worker configurations.
5. **No SSE for agent state** -- worker state changes are not pushed to the frontend in real-time.
6. **No capacity planning view** -- no way to see ticket queue depth vs. available workers.
7. **No fleet-level cost view** -- no aggregation of per-worker costs into a fleet total.

---

## 3. Technical Design

### 3.1 DynamoDB Schema: Worker Templates

New item pattern in `agent_workers` table:

| PK Pattern | SK Pattern | Purpose | Key Fields |
|------------|------------|---------|------------|
| `USER#{user_id}` | `TEMPLATE#{template_id}` | Saved worker configuration | `template_id`, `label`, `agent_type`, `tool`, `compute_type`, `instance_type`, `llm_key_id`, `repo_url`, `branch_convention`, `idle_timeout_seconds`, `ticket_filter`, `created_at` |

### 3.2 Backend Service Extensions

**Extend**: `app/services/agent_worker_provisioner.py` (+150 lines)

```python
# --- Fleet operations ---

def fleet_status(user_id: str) -> Dict[str, Any]:
    """Get aggregate fleet metrics for a user.

    Returns:
    - total_workers: count by status (ready, running, stopped, error)
    - tickets_in_queue: count by type (eligible, unassigned)
    - throughput: tickets completed in last 24h / 7d
    - total_cost_cents: estimated cost for current billing period
    - workers: list of worker summaries (id, label, state, current_ticket)
    """
    workers = list_workers(user_id)
    
    status_counts = {"ready": 0, "running": 0, "stopped": 0, "error": 0, "provisioning": 0}
    for w in workers:
        s = w.get("worker_status", "unknown")
        if s in status_counts:
            status_counts[s] += 1
    
    # Query ticket queue depth
    from app.services.agent_orchestrator import find_eligible_ticket_count
    queue_depth = find_eligible_ticket_count(user_id)
    
    return {
        "total_workers": len(workers),
        "status_counts": status_counts,
        "queue_depth": queue_depth,
        "workers": [_worker_summary(w) for w in workers],
    }


def bulk_start(user_id: str) -> Dict[str, Any]:
    """Start all idle/stopped workers. Returns count started."""
    workers = list_workers(user_id, status="stopped")
    started = 0
    errors = []
    for w in workers:
        try:
            start_worker(user_id, w["worker_id"])
            started += 1
        except Exception as e:
            errors.append({"worker_id": w["worker_id"], "error": str(e)})
    return {"started": started, "errors": errors}


def bulk_stop(user_id: str) -> Dict[str, Any]:
    """Stop all running workers. Returns count stopped."""
    workers = list_workers(user_id, status="ready")
    stopped = 0
    errors = []
    for w in workers:
        try:
            stop_worker(user_id, w["worker_id"])
            stopped += 1
        except Exception as e:
            errors.append({"worker_id": w["worker_id"], "error": str(e)})
    return {"stopped": stopped, "errors": errors}


# --- Worker templates ---

def save_template(
    user_id: str,
    *,
    label: str,
    agent_type: str,
    tool: str,
    compute_type: str,
    instance_type: str,
    llm_key_id: str,
    repo_url: str = "",
    branch_convention: str = "",
    idle_timeout_seconds: int = 7200,
    ticket_filter: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    """Save a worker configuration as a reusable template."""
    template_id = uuid4().hex
    ts = now_ts()
    item = {
        "pk": f"USER#{user_id}",
        "sk": f"TEMPLATE#{template_id}",
        "template_id": template_id,
        "label": label,
        "agent_type": agent_type,
        "tool": tool,
        "compute_type": compute_type,
        "instance_type": instance_type,
        "llm_key_id": llm_key_id,
        "repo_url": repo_url,
        "branch_convention": branch_convention,
        "idle_timeout_seconds": idle_timeout_seconds,
        "ticket_filter": ticket_filter or {},
        "created_at": ts,
    }
    T.agent_workers.put_item(Item=item)
    return item


def list_templates(user_id: str) -> List[Dict[str, Any]]:
    """List saved worker templates."""
    resp = T.agent_workers.query(
        KeyConditionExpression="pk = :pk AND begins_with(sk, :prefix)",
        ExpressionAttributeValues={":pk": f"USER#{user_id}", ":prefix": "TEMPLATE#"},
    )
    return resp.get("Items", [])


def delete_template(user_id: str, template_id: str) -> None:
    """Delete a worker template."""
    T.agent_workers.delete_item(
        Key={"pk": f"USER#{user_id}", "sk": f"TEMPLATE#{template_id}"}
    )


def create_worker_from_template(user_id: str, template_id: str, label: str = "") -> Dict[str, Any]:
    """Create a new worker using a saved template's configuration."""
    template = T.agent_workers.get_item(
        Key={"pk": f"USER#{user_id}", "sk": f"TEMPLATE#{template_id}"}
    ).get("Item")
    if not template:
        raise ValueError("Template not found")
    
    return create_worker(
        user_id=user_id,
        label=label or f"{template['label']} (copy)",
        agent_type=template["agent_type"],
        tool=template["tool"],
        compute_type=template["compute_type"],
        instance_type=template["instance_type"],
        llm_key_id=template["llm_key_id"],
        repo_url=template.get("repo_url", ""),
        branch_convention=template.get("branch_convention", ""),
        idle_timeout_seconds=template.get("idle_timeout_seconds", 7200),
        template_id=template_id,
    )
```

### 3.3 SSE Endpoint for Fleet Events

```python
# In app/routers/agent_fleet.py

@router.get("/ui/agent/fleet/events")
async def fleet_events(
    request: Request,
    session: dict = Depends(require_ui_session),
):
    """SSE stream for fleet-level events.

    Events:
    - worker:state_change  — worker_id, old_state, new_state
    - worker:ticket_claimed — worker_id, ticket_id, ticket_title
    - worker:ticket_completed — worker_id, ticket_id, summary
    - worker:heartbeat_missed — worker_id, last_heartbeat
    - worker:error — worker_id, error_message
    - fleet:capacity_change — queue_depth, active_workers
    """
    user_id = session["user_sub"]
    queue = asyncio.Queue()
    
    # Register this SSE client in the user's event bus
    _fleet_event_buses[user_id].add(queue)
    
    async def event_generator():
        try:
            while True:
                event = await queue.get()
                yield f"event: {event['type']}\ndata: {json.dumps(event['data'])}\n\n"
        except asyncio.CancelledError:
            _fleet_event_buses[user_id].discard(queue)
    
    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
```

### 3.4 Backend Router

**New file**: `app/routers/agent_fleet.py` (~300 lines)

Prefix: `/ui/agent/fleet`

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/ui/agent/fleet/status` | `require_ui_session` | Get aggregate fleet metrics |
| `POST` | `/ui/agent/fleet/start-all` | `require_ui_session` | Start all stopped workers |
| `POST` | `/ui/agent/fleet/stop-all` | `require_ui_session` | Stop all running workers |
| `GET` | `/ui/agent/fleet/events` | `require_ui_session` | SSE stream for fleet events |
| `GET` | `/ui/agent/fleet/capacity` | `require_ui_session` | Queue depth vs. worker availability |
| `POST` | `/ui/agent/fleet/templates` | `require_ui_session` | Save a worker template |
| `GET` | `/ui/agent/fleet/templates` | `require_ui_session` | List worker templates |
| `DELETE` | `/ui/agent/fleet/templates/{template_id}` | `require_ui_session` | Delete a template |
| `POST` | `/ui/agent/fleet/templates/{template_id}/create` | `require_ui_session` | Create worker from template |
| `GET` | `/ui/admin/agent/fleet` | `require_admin_scope(AdminScope.AGENT_MANAGEMENT) <!-- NOTE: `require_admin_session` does not exist; use `require_admin_scope()` from `app/auth/policy.py:84` -->` | Admin: aggregate fleet metrics across users |

### 3.5 Pydantic Models

**Add to `app/models.py`**:

```python
# -- Agent Fleet Management (AGENT-004) --

class FleetStatusOut(BaseModel):
    total_workers: int
    status_counts: Dict[str, int]
    queue_depth: int
    workers: List[WorkerSummary]

class WorkerSummary(BaseModel):
    worker_id: str
    label: str
    agent_type: str
    tool: str
    worker_status: str
    agent_state: str = "idle"
    current_ticket_id: str = ""
    current_ticket_title: str = ""
    uptime_seconds: int = 0
    estimated_cost_cents: int = 0
    tickets_completed: int = 0

class BulkActionOut(BaseModel):
    count: int
    errors: List[Dict[str, str]] = Field(default_factory=list)

class CapacityOut(BaseModel):
    queue_by_type: Dict[str, int]            # e.g., {"bug": 5, "feature": 3}
    workers_by_type: Dict[str, int]          # e.g., {"coder": 2, "qa": 1}
    workers_by_state: Dict[str, int]         # e.g., {"idle": 1, "working": 2}
    recommended_action: str = ""             # e.g., "Add 1 more coder worker"

class WorkerTemplateIn(BaseModel):
    label: str = Field(..., min_length=1, max_length=200)
    agent_type: str
    tool: str
    compute_type: str
    instance_type: str
    llm_key_id: str
    repo_url: str = ""
    branch_convention: str = ""
    idle_timeout_seconds: int = Field(default=7200, ge=600, le=86400)
    ticket_filter: Optional[TicketFilterConfig] = None

class WorkerTemplateOut(BaseModel):
    template_id: str
    label: str
    agent_type: str
    tool: str
    compute_type: str
    instance_type: str
    llm_key_id: str
    repo_url: str = ""
    branch_convention: str = ""
    idle_timeout_seconds: int = 7200
    ticket_filter: Optional[TicketFilterConfig] = None
    created_at: int = 0

class WorkerTemplateListOut(BaseModel):
    templates: List[WorkerTemplateOut]
    count: int
```

### 3.6 Frontend Components

#### AgentsPage (`frontend/src/pages/agents/AgentsPage.tsx`)

Main dashboard page (~500 lines):

- **Header**: "Agent Fleet" with "Create Worker" button and fleet action buttons (Start All, Stop All)
- **Stats bar**: Cards showing Total Workers, Active, Queue Depth, Tickets/Day, Est. Cost Today
- **Capacity section**: Horizontal bar chart — tickets in queue per type vs. workers per type
- **Worker grid**: Card grid or table showing each worker:
  - Label, agent type icon, tool badge
  - Status badge (color-coded: green=working, blue=idle, yellow=paused, red=error, gray=stopped)
  - Current ticket title (if working)
  - Uptime, tickets completed count
  - Actions: Open Terminal, Pause/Resume, Stop, Details
- **Real-time updates**: `useEffect` with `EventSource` on `/ui/agent/fleet/events`
- **Auto-refresh**: `refetchInterval: 10_000` as fallback

#### WorkerDetailDrawer (`frontend/src/pages/agents/WorkerDetailDrawer.tsx`)

Sheet/Drawer (~400 lines):

- **Header**: Worker label, status badge, agent type
- **Tabs**:
  - **Terminal**: Embedded terminal view showing live agent output (read-only or interactive)
  - **Logs**: Provisioning log timeline, recent activity log
  - **Metrics**: Uptime, tokens used, cost estimate, tickets completed/failed
  - **Config**: Agent type, tool, compute, LLM key, ticket filter, idle timeout
- **Actions**: Start/Stop/Restart agent, Release current ticket, Open full terminal

#### CapacityChart (`frontend/src/pages/agents/CapacityChart.tsx`)

Component (~100 lines):

- Horizontal grouped bar chart showing queue depth vs. worker count per agent type
- Color coding: red if queue >> workers, green if balanced
- Recommendation text: "Consider adding 1 more coder worker"

#### TemplatesSection (`frontend/src/pages/agents/TemplatesSection.tsx`)

Component (~150 lines):

- Template cards with "Create from Template" button
- "Save Current Config" button on worker detail
- Delete template with confirmation

#### Route & Navigation

```tsx
<Route path="/agents" element={<AgentsPage />} />
```

Sidebar: "Fleet Dashboard" with `LayoutGrid` icon under "AI Agents" group (primary nav item).

---

## 4. Implementation Plan

### Phase 1: Fleet Service + Templates (2-3 days)

| File | Change |
|------|--------|
| `app/services/agent_worker_provisioner.py` | Add fleet_status, bulk_start/stop, template CRUD |
| `app/models.py` | Add fleet Pydantic models |

### Phase 2: SSE + Router (2-3 days)

| File | Change |
|------|--------|
| `app/routers/agent_fleet.py` | New file: 10 endpoints + SSE stream |
| `app/main.py` | Register `agent_fleet_router` |

### Phase 3: Frontend Dashboard (3-4 days)

| File | Change |
|------|--------|
| `frontend/src/api/types.ts` | Add fleet TypeScript types |
| `frontend/src/api/endpoints/agentFleet.ts` | New file: API wrappers |
| `frontend/src/pages/agents/AgentsPage.tsx` | New file: fleet dashboard |
| `frontend/src/pages/agents/WorkerDetailDrawer.tsx` | New file: worker detail |
| `frontend/src/pages/agents/CapacityChart.tsx` | New file: capacity visualization |
| `frontend/src/pages/agents/TemplatesSection.tsx` | New file: template management |
| `frontend/src/hooks/useFleetEvents.ts` | New file: SSE hook for fleet events |
| `frontend/src/App.tsx` | Add `/agents` route |
| `frontend/src/components/layout/Sidebar.tsx` | Add "Fleet Dashboard" nav item |
| `frontend/src/components/layout/MobileNav.tsx` | Add "Agents" to MORE_LINKS |

### Phase 4: E2E Tests (1-2 days)

| File | Change |
|------|--------|
| `frontend/e2e/agent-fleet.spec.ts` | New file: ~16 tests in 4 sections |

---

## 5. E2E Test Plan (`frontend/e2e/agent-fleet.spec.ts`)

**Test setup**: Uses `e2e_admin_session_setup.py` sessions. `beforeAll` creates an LLM key and 2 workers via AGENT-001/002 APIs.

**Section 635: Fleet Status API (4 tests)**

1. `Fleet status returns aggregate metrics` -- GET `/ui/agent/fleet/status`. Verify `total_workers >= 2`, `status_counts` has keys `ready`, `stopped`, etc., `workers` is an array with at least 2 entries.
2. `Worker summaries include current state` -- Verify each worker summary has `worker_id`, `label`, `agent_type`, `worker_status`, `agent_state`.
3. `Capacity endpoint shows queue vs. workers` -- GET `/ui/agent/fleet/capacity`. Verify response has `queue_by_type`, `workers_by_type`, `workers_by_state`.
4. `Queue depth reflects eligible tickets` -- Create 3 agent-eligible tickets. GET capacity. Verify `queue_by_type` total >= 3.

**Section 636: Bulk Operations API (4 tests)**

5. `Start all stopped workers` -- Stop both workers first. POST `/ui/agent/fleet/start-all`. Verify response `count: 2`, both workers transition to `ready`.
6. `Stop all running workers` -- POST `/ui/agent/fleet/stop-all`. Verify response `count: 2`, both workers transition to `stopped`.
7. `Start all with no stopped workers returns count 0` -- With all workers running, POST start-all. Verify `count: 0`.
8. `Bulk stop handles errors gracefully` -- Terminate one worker, stop the other. POST stop-all. Verify `errors` array contains the terminated worker (cannot stop terminated).

**Section 637: Worker Templates API (4 tests)**

9. `Save a worker template` -- POST `/ui/agent/fleet/templates` with worker config. Verify 201 with `template_id`, `label`, `agent_type`, `tool`.
10. `List templates` -- GET `/ui/agent/fleet/templates`. Verify `count >= 1`, template from step 9 is present.
11. `Create worker from template` -- POST `/ui/agent/fleet/templates/{template_id}/create` with optional label override. Verify 201 with new `worker_id`, config matching template.
12. `Delete template` -- DELETE `/ui/agent/fleet/templates/{template_id}`. Verify 200. GET templates, verify template removed.

**Section 638: Fleet Dashboard UI (6 tests)**

13. `Agents page renders fleet dashboard` -- Navigate to `/agents`. Verify heading "Agent Fleet" visible. Verify stats cards visible (Total Workers, Active, Queue).
14. `Worker grid shows all workers` -- Verify worker cards/rows for both test workers are visible with labels and status badges.
15. `Worker card shows current ticket` -- Assign a ticket to a worker (via agent orchestrator). Reload page. Verify ticket title appears on the worker card.
16. `Click worker opens detail drawer` -- Click on a worker card. Verify drawer opens with worker label, tabs (Terminal, Logs, Metrics, Config).
17. `Start All button starts workers` -- Click "Start All". Verify status badges transition to active state.
18. `Create from Template button in creation wizard` -- Click "Create Worker". Verify "From Template" option is visible. Select a template. Verify form pre-filled with template values.

---

## 6. Security Considerations

### 6.1 Fleet-Level Authorization

Fleet endpoints only return workers belonging to the authenticated user. Admin fleet endpoint requires `require_admin_scope(AdminScope.AGENT_MANAGEMENT) <!-- NOTE: `require_admin_session` does not exist; use `require_admin_scope()` from `app/auth/policy.py:84` -->`.

### 6.2 Bulk Action Safety

Bulk start/stop operations are rate-limited to prevent abuse. Each individual worker start/stop respects the same validation as single-worker operations.

### 6.3 SSE Authentication

The SSE endpoint validates the session cookie on connection. If the session expires, the SSE stream closes and the frontend reconnects with a fresh session.

### 6.4 Template Data

Templates store configuration references (key_id, instance_type) not actual secrets. The LLM key referenced by a template is still decrypted only at worker creation time.

---

## 7. Dependencies

| Dependency | Type | Description |
|------------|------|-------------|
| AGENT-001 | Upstream | LLM key references in templates and worker summaries |
| AGENT-002 | Upstream | Worker CRUD for fleet operations |
| AGENT-003 | Upstream | Agent state and ticket claims for status display |
| AGENT-005 | Related | Memory display in worker detail drawer |
| AGENT-006 | Related | Terminal output streaming in worker detail drawer |

---

## 8. Acceptance Criteria

1. Fleet dashboard displays all workers with real-time status badges.
2. Aggregate metrics (total workers, queue depth, throughput) are calculated and displayed.
3. Bulk start/stop operations work for all eligible workers.
4. Worker detail drawer shows terminal output, logs, metrics, and configuration.
5. Worker templates can be saved, listed, and used to create new workers.
6. Capacity planning view shows queue depth vs. worker count by type.
7. SSE events push state changes to the dashboard in real-time.
8. Admin endpoint provides cross-user fleet metrics.
9. Navigation includes the fleet dashboard in the sidebar under "AI Agents" group.
10. Empty states guide new users to create their first worker.

---

## 9. Architecture & Data Flow

### 9.1 Fleet Dashboard Request Flow

```
Browser (AgentsPage)
  │
  ├── GET /ui/agent/fleet/status ─────────────────────────────────┐
  │                                                                │
  │   ┌────────────────────────────────────────────────────────┐   │
  │   │  agent_fleet_router (require_ui_session)               │   │
  │   │    ↓                                                   │   │
  │   │  fleet_status(user_id)                                 │   │
  │   │    ├── list_workers(user_id)                           │   │
  │   │    │     └── DDB: query agent_workers PK=USER#{uid}    │   │
  │   │    ├── find_eligible_ticket_count(user_id)             │   │
  │   │    │     └── DDB: query tickets GSI by space_id        │   │
  │   │    └── aggregate status_counts, build worker summaries │   │
  │   └────────────────────────────────────────────────────────┘   │
  │                                                                │
  │   Response: FleetStatusOut {total_workers, status_counts,      │
  │             queue_depth, workers: WorkerSummary[]}             │
  │                                                                │
  ├── GET /ui/agent/fleet/events (SSE) ───────────────────────────┤
  │                                                                │
  │   ┌────────────────────────────────────────────────────────┐   │
  │   │  SSE EventSource opened                                │   │
  │   │    ↓                                                   │   │
  │   │  _fleet_event_buses[user_id].add(queue)                │   │
  │   │    ↓                                                   │   │
  │   │  Worker lifecycle hooks → push events:                 │   │
  │   │    worker:state_change, worker:ticket_claimed,         │   │
  │   │    worker:ticket_completed, worker:heartbeat_missed,   │   │
  │   │    worker:error, fleet:capacity_change                 │   │
  │   │    ↓                                                   │   │
  │   │  Frontend EventSource.onmessage → queryClient.setData  │   │
  │   └────────────────────────────────────────────────────────┘   │
  │                                                                │
  ├── POST /ui/agent/fleet/start-all ─────────────────────────────┤
  │     bulk_start(user_id) → iterate stopped workers → start     │
  │     each → return BulkActionOut {count, errors[]}             │
  │                                                                │
  └── POST /ui/agent/fleet/templates ─────────────────────────────┘
        save_template(user_id, config) → DDB put_item
        SK=TEMPLATE#{template_id}
```

### 9.2 SSE Event Bus Architecture

```
  Worker Agent Framework (AGENT-003)            Fleet Event Bus
  ┌───────────────────────────────┐      ┌──────────────────────┐
  │  Worker state machine:        │      │  _fleet_event_buses  │
  │  idle → running → error       │──────│  Dict[user_id, Set]  │
  │  heartbeat loop (30s)         │ push │                      │
  │  ticket claim/complete hooks  │──────│  queue.put(event)    │
  └───────────────────────────────┘      └────────┬─────────────┘
                                                  │
                     ┌────────────────────────────┼──────────────────┐
                     │                            │                  │
              SSE Client 1               SSE Client 2         SSE Client N
              (Browser Tab)              (Mobile)             (Admin)
```

---

## 10. Detailed DynamoDB Access Patterns

| # | Operation | Table | PK | SK / Key Condition | GSI | Notes |
|---|-----------|-------|----|--------------------|-----|-------|
| 1 | List all workers for user | `agent_workers` | `USER#{user_id}` | `begins_with(sk, "WORKER#")` | -- | Base table query |
| 2 | List stopped workers only | `agent_workers` | `USER#{user_id}` | `begins_with(sk, "WORKER#")` | -- | FilterExpression on `worker_status = stopped` |
| 3 | Get single worker | `agent_workers` | `USER#{user_id}` | `WORKER#{worker_id}` | -- | GetItem |
| 4 | Save template | `agent_workers` | `USER#{user_id}` | `TEMPLATE#{template_id}` | -- | PutItem |
| 5 | List templates | `agent_workers` | `USER#{user_id}` | `begins_with(sk, "TEMPLATE#")` | -- | Base table query |
| 6 | Delete template | `agent_workers` | `USER#{user_id}` | `TEMPLATE#{template_id}` | -- | DeleteItem |
| 7 | Get template by ID | `agent_workers` | `USER#{user_id}` | `TEMPLATE#{template_id}` | -- | GetItem |
| 8 | Count eligible tickets | `tickets` | varies | varies | `gsi_space` | Query by space_id, filter `status=open` |
| 9 | Admin: all workers globally | `agent_workers` | -- | -- | `gsi_status` | GSI PK=`STATUS#{status}`, used for admin fleet aggregation |
| 10 | Fleet event log | `agent_workers` | `USER#{user_id}` | `EVENT#{timestamp}#{event_id}` | -- | Append-only event log for audit |

---

## 11. API Request/Response Examples

### 11.1 Get Fleet Status

```bash
curl -s -X GET "http://localhost:8000/ui/agent/fleet/status" \
  -H "Cookie: ui_session=SESS_abc; ui_access_token=JWT_abc; ui_csrf=CSRF_abc"
```

```json
{
  "total_workers": 4,
  "status_counts": {
    "ready": 1,
    "running": 2,
    "stopped": 1,
    "error": 0,
    "provisioning": 0
  },
  "queue_depth": 7,
  "workers": [
    {
      "worker_id": "w_abc123",
      "label": "Backend Coder #1",
      "agent_type": "coder",
      "tool": "claude_code",
      "worker_status": "running",
      "agent_state": "working",
      "current_ticket_id": "tkt_xyz789",
      "current_ticket_title": "Add user search endpoint",
      "uptime_seconds": 3420,
      "estimated_cost_cents": 285,
      "tickets_completed": 3
    }
  ]
}
```

### 11.2 Bulk Start All

```bash
curl -s -X POST "http://localhost:8000/ui/agent/fleet/start-all" \
  -H "Cookie: ui_session=SESS_abc; ui_access_token=JWT_abc; ui_csrf=CSRF_abc" \
  -H "x-csrf-token: CSRF_abc"
```

```json
{
  "count": 2,
  "errors": []
}
```

### 11.3 Bulk Stop All (with partial errors)

```bash
curl -s -X POST "http://localhost:8000/ui/agent/fleet/stop-all" \
  -H "Cookie: ui_session=SESS_abc; ui_access_token=JWT_abc; ui_csrf=CSRF_abc" \
  -H "x-csrf-token: CSRF_abc"
```

```json
{
  "count": 1,
  "errors": [
    {"worker_id": "w_terminated1", "error": "Cannot stop a terminated worker"}
  ]
}
```

### 11.4 Get Capacity

```bash
curl -s -X GET "http://localhost:8000/ui/agent/fleet/capacity" \
  -H "Cookie: ui_session=SESS_abc; ui_access_token=JWT_abc; ui_csrf=CSRF_abc"
```

```json
{
  "queue_by_type": {"bug": 5, "feature": 2},
  "workers_by_type": {"coder": 2, "qa": 1},
  "workers_by_state": {"idle": 1, "working": 2},
  "recommended_action": "Consider adding 1 more coder worker — 5 bug tickets queued."
}
```

### 11.5 Save Template

```bash
curl -s -X POST "http://localhost:8000/ui/agent/fleet/templates" \
  -H "Cookie: ui_session=SESS_abc; ui_access_token=JWT_abc; ui_csrf=CSRF_abc" \
  -H "x-csrf-token: CSRF_abc" \
  -H "Content-Type: application/json" \
  -d '{
    "label": "Backend Coder Standard",
    "agent_type": "coder",
    "tool": "claude_code",
    "compute_type": "ec2",
    "instance_type": "t3.medium",
    "llm_key_id": "key_abc123",
    "repo_url": "https://github.com/org/repo.git",
    "branch_convention": "feat/{ticket_id}-{slug}",
    "idle_timeout_seconds": 3600,
    "ticket_filter": {"labels": ["type:development"], "complexity": ["low", "medium"]}
  }'
```

```json
{
  "template_id": "tmpl_d4e5f6",
  "label": "Backend Coder Standard",
  "agent_type": "coder",
  "tool": "claude_code",
  "compute_type": "ec2",
  "instance_type": "t3.medium",
  "llm_key_id": "key_abc123",
  "repo_url": "https://github.com/org/repo.git",
  "branch_convention": "feat/{ticket_id}-{slug}",
  "idle_timeout_seconds": 3600,
  "ticket_filter": {"labels": ["type:development"], "complexity": ["low", "medium"]},
  "created_at": 1748520000
}
```

### 11.6 Create Worker from Template

```bash
curl -s -X POST "http://localhost:8000/ui/agent/fleet/templates/tmpl_d4e5f6/create" \
  -H "Cookie: ui_session=SESS_abc; ui_access_token=JWT_abc; ui_csrf=CSRF_abc" \
  -H "x-csrf-token: CSRF_abc" \
  -H "Content-Type: application/json" \
  -d '{"label": "Backend Coder #3"}'
```

```json
{
  "worker_id": "w_new789",
  "label": "Backend Coder #3",
  "agent_type": "coder",
  "tool": "claude_code",
  "worker_status": "provisioning",
  "template_id": "tmpl_d4e5f6",
  "created_at": 1748520100
}
```

### 11.7 Delete Template

```bash
curl -s -X DELETE "http://localhost:8000/ui/agent/fleet/templates/tmpl_d4e5f6" \
  -H "Cookie: ui_session=SESS_abc; ui_access_token=JWT_abc; ui_csrf=CSRF_abc" \
  -H "x-csrf-token: CSRF_abc"
```

```json
{"ok": true}
```

### 11.8 Admin Fleet Metrics

```bash
curl -s -X GET "http://localhost:8000/ui/admin/agent/fleet" \
  -H "Cookie: ui_session=SESS_root; ui_access_token=JWT_root; ui_csrf=CSRF_root"
```

```json
{
  "total_users": 12,
  "total_workers": 47,
  "status_counts": {"ready": 15, "running": 22, "stopped": 8, "error": 2},
  "total_tickets_in_progress": 22,
  "total_cost_cents_today": 18450,
  "top_users": [
    {"user_id": "usr_001", "worker_count": 8, "cost_cents": 4200}
  ]
}
```

---

## 12. Error Handling Matrix

| # | Scenario | HTTP | Error Code | Body | Recovery |
|---|----------|------|------------|------|----------|
| 1 | Unauthenticated request | 401 | `unauthorized` | `{"detail": "Not authenticated"}` | Redirect to login |
| 2 | Non-admin calls admin fleet endpoint | 403 | `forbidden` | `{"detail": "Admin access required"}` | Use admin session |
| 3 | Template not found | 404 | `not_found` | `{"detail": "Template not found"}` | List templates first |
| 4 | Template label too long (>200 chars) | 422 | `validation_error` | Pydantic error detail | Shorten label |
| 5 | idle_timeout_seconds below 600 | 422 | `validation_error` | `{"detail": "ensure this value is >= 600"}` | Use value >= 600 |
| 6 | idle_timeout_seconds above 86400 | 422 | `validation_error` | `{"detail": "ensure this value is <= 86400"}` | Use value <= 86400 |
| 7 | Bulk start with no stopped workers | 200 | -- | `{"count": 0, "errors": []}` | Informational, not error |
| 8 | Bulk stop fails on terminated worker | 200 | -- | `{"count": 1, "errors": [{"worker_id": "...", "error": "Cannot stop terminated"}]}` | Partial success |
| 9 | Worker start fails (compute exhausted) | 200 | -- | Error in `errors[]` array | Check compute quotas |
| 10 | SSE connection dropped (session expired) | -- | -- | EventSource `onerror` fires | Reconnect with fresh session |
| 11 | CSRF token mismatch on POST | 403 | `csrf_error` | `{"detail": "CSRF token mismatch"}` | Refresh page, retry |
| 12 | Template references deleted LLM key | 200 | -- | Worker creation succeeds but worker enters `error` state on first LLM call | Update template llm_key_id |

---

## 13. Expanded Pydantic Models with Validators

```python
from pydantic import BaseModel, Field, field_validator
from typing import Dict, List, Optional

class WorkerTemplateIn(BaseModel):
    label: str = Field(..., min_length=1, max_length=200)
    agent_type: str = Field(..., min_length=1, max_length=50)
    tool: str = Field(..., min_length=1, max_length=50)
    compute_type: str = Field(..., min_length=1, max_length=50)
    instance_type: str = Field(..., min_length=1, max_length=100)
    llm_key_id: str = Field(..., min_length=1, max_length=100)
    repo_url: str = Field(default="", max_length=500)
    branch_convention: str = Field(default="", max_length=200)
    idle_timeout_seconds: int = Field(default=7200, ge=600, le=86400)
    ticket_filter: Optional[TicketFilterConfig] = None

    @field_validator("agent_type")
    @classmethod
    def validate_agent_type(cls, v: str) -> str:
        allowed = {"coder", "qa", "pm", "docs", "security", "stylist", "architect"}
        if v not in allowed:
            raise ValueError(f"agent_type must be one of {sorted(allowed)}")
        return v

    @field_validator("compute_type")
    @classmethod
    def validate_compute_type(cls, v: str) -> str:
        allowed = {"ec2", "k8s", "local"}
        if v not in allowed:
            raise ValueError(f"compute_type must be one of {sorted(allowed)}")
        return v

    @field_validator("tool")
    @classmethod
    def validate_tool(cls, v: str) -> str:
        allowed = {"claude_code", "codex", "custom"}
        if v not in allowed:
            raise ValueError(f"tool must be one of {sorted(allowed)}")
        return v

    @field_validator("repo_url")
    @classmethod
    def validate_repo_url(cls, v: str) -> str:
        if v and not (v.startswith("https://") or v.startswith("git@")):
            raise ValueError("repo_url must start with https:// or git@")
        return v

    @field_validator("branch_convention")
    @classmethod
    def validate_branch_convention(cls, v: str) -> str:
        import re
        if v and not re.match(r'^[a-zA-Z0-9_/{}\-]+$', v):
            raise ValueError("branch_convention must only contain alphanumeric, _, /, {}, -")
        return v


class TicketFilterConfig(BaseModel):
    labels: List[str] = Field(default_factory=list, max_length=20)
    complexity: List[str] = Field(default_factory=list, max_length=4)
    space_ids: List[str] = Field(default_factory=list, max_length=10)

    @field_validator("complexity")
    @classmethod
    def validate_complexity(cls, v: list) -> list:
        allowed = {"low", "medium", "high", "critical"}
        for c in v:
            if c not in allowed:
                raise ValueError(f"complexity must be one of {sorted(allowed)}")
        return v


class FleetStatusOut(BaseModel):
    total_workers: int = Field(ge=0)
    status_counts: Dict[str, int]
    queue_depth: int = Field(ge=0)
    workers: List["WorkerSummary"]

    @field_validator("status_counts")
    @classmethod
    def validate_status_counts(cls, v: dict) -> dict:
        required = {"ready", "running", "stopped", "error", "provisioning"}
        for key in required:
            if key not in v:
                v[key] = 0
        return v
```

---

## 14. Frontend Component Tree

```
AgentsPage
├── FleetHeader
│   ├── Heading ("Agent Fleet")
│   ├── Button ("Create Worker")
│   ├── Button ("Start All")   → useMutation(bulkStart)
│   └── Button ("Stop All")    → useMutation(bulkStop)
├── FleetStatsBar
│   ├── StatCard (Total Workers)
│   ├── StatCard (Active)
│   ├── StatCard (Queue Depth)
│   ├── StatCard (Tickets/Day)
│   └── StatCard (Est. Cost Today)
├── CapacityChart
│   ├── HorizontalBarGroup (queue_by_type)
│   ├── HorizontalBarGroup (workers_by_type)
│   └── RecommendationText
├── WorkerGrid
│   └── WorkerCard[]
│       ├── StatusBadge (color-coded)
│       ├── AgentTypeIcon
│       ├── ToolBadge
│       ├── CurrentTicketLink
│       ├── UptimeLabel
│       └── ActionMenu (Terminal, Pause, Stop, Details)
├── TemplatesSection
│   └── TemplateCard[]
│       ├── TemplateLabel
│       ├── AgentTypeTag
│       ├── Button ("Create from Template")
│       └── Button ("Delete")
└── WorkerDetailDrawer (Sheet)
    ├── DrawerHeader (label, status, type)
    └── Tabs
        ├── Tab("Terminal")  → TerminalEmbed (read-only)
        ├── Tab("Logs")      → ActivityTimeline
        ├── Tab("Metrics")   → MetricsCards + TokenUsageChart
        └── Tab("Config")    → ConfigSummary
```

### Component Props Interfaces

```typescript
interface FleetStatsBarProps {
  status: FleetStatusOut;
  isLoading: boolean;
}

interface WorkerCardProps {
  worker: WorkerSummary;
  onOpenDetail: (workerId: string) => void;
  onStartStop: (workerId: string, action: "start" | "stop") => void;
}

interface CapacityChartProps {
  capacity: CapacityOut | undefined;
  isLoading: boolean;
}

interface WorkerDetailDrawerProps {
  workerId: string | null;
  open: boolean;
  onClose: () => void;
}

interface TemplatesSectionProps {
  templates: WorkerTemplateOut[];
  onCreateFromTemplate: (templateId: string) => void;
  onDeleteTemplate: (templateId: string) => void;
}
```

---

## 15. Observability

### 15.1 Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `fleet_status_requests_total` | Counter | `user_id` | Fleet status endpoint calls |
| `fleet_bulk_action_total` | Counter | `action=start\|stop`, `user_id` | Bulk action invocations |
| `fleet_bulk_action_count` | Histogram | `action` | Number of workers affected per bulk action |
| `fleet_sse_connections_active` | Gauge | -- | Currently open SSE fleet event connections |
| `fleet_sse_events_sent_total` | Counter | `event_type` | SSE events pushed to clients |
| `fleet_template_crud_total` | Counter | `op=create\|delete\|use` | Template lifecycle operations |
| `fleet_worker_state_transitions_total` | Counter | `from_state`, `to_state` | Worker state change frequency |

### 15.2 Logging Events

| Event | Level | Fields | When |
|-------|-------|--------|------|
| `fleet.status.fetched` | INFO | `user_id`, `total_workers`, `queue_depth` | Fleet status requested |
| `fleet.bulk.start` | INFO | `user_id`, `count`, `errors_count` | Bulk start completed |
| `fleet.bulk.stop` | INFO | `user_id`, `count`, `errors_count` | Bulk stop completed |
| `fleet.template.created` | INFO | `user_id`, `template_id`, `agent_type` | Template saved |
| `fleet.template.deleted` | INFO | `user_id`, `template_id` | Template removed |
| `fleet.template.used` | INFO | `user_id`, `template_id`, `new_worker_id` | Worker created from template |
| `fleet.sse.connected` | DEBUG | `user_id` | SSE client connected |
| `fleet.sse.disconnected` | DEBUG | `user_id` | SSE client disconnected |

### 15.3 Alerting Rules

| Alert | Condition | Severity | Channel |
|-------|-----------|----------|---------|
| `FleetSSEConnectionSurge` | `fleet_sse_connections_active > 500` | Warning | Slack #ops |
| `FleetBulkActionHighErrorRate` | `rate(errors) / rate(total) > 0.3 over 5m` | Critical | PagerDuty |
| `FleetWorkerErrorStateSpike` | `fleet_worker_state_transitions_total{to_state="error"} > 10 in 5m` | Critical | Slack #ops + PagerDuty |

---

## 16. Rollout Plan

### 16.1 Feature Flags

| Flag | Scope | Default | Description |
|------|-------|---------|-------------|
| `AGENT_FLEET_DASHBOARD_ENABLED` | Global | `false` | Gates frontend route and all fleet API endpoints |
| `AGENT_FLEET_SSE_ENABLED` | Global | `false` | Gates SSE event streaming (can disable if perf issues) |

### 16.2 Phases

**Phase 1 -- Backend only (Week 1)**
- Deploy fleet service extensions, template CRUD, bulk operations.
- Flag `AGENT_FLEET_DASHBOARD_ENABLED=false` -- endpoints return 404.
- Internal testing via curl and admin scripts.
- Monitor DDB write throughput for template operations.

**Phase 2 -- Limited rollout (Week 2)**
- Enable `AGENT_FLEET_DASHBOARD_ENABLED=true` for internal users (staff flag).
- Enable `AGENT_FLEET_SSE_ENABLED=true` for internal users.
- Frontend route visible only to flagged users.
- Gather feedback on dashboard layout, capacity chart accuracy, SSE reliability.

**Phase 3 -- General availability (Week 3)**
- Enable both flags globally.
- Announce in changelog.
- Monitor SSE connection count, bulk action error rate.
- Add admin fleet endpoint for platform-wide monitoring.

---

## 17. Performance Considerations

### 17.1 Latency Targets

| Endpoint | Target P50 | Target P99 | Notes |
|----------|-----------|-----------|-------|
| `GET /ui/agent/fleet/status` | 80ms | 250ms | Single DDB query + ticket count query |
| `POST /ui/agent/fleet/start-all` | 200ms | 1000ms | Iterates workers; each start is ~50ms |
| `POST /ui/agent/fleet/stop-all` | 200ms | 1000ms | Same as start-all |
| `GET /ui/agent/fleet/capacity` | 100ms | 300ms | Ticket queue count + worker aggregation |
| `POST /ui/agent/fleet/templates` | 30ms | 100ms | Single DDB PutItem |
| `GET /ui/agent/fleet/templates` | 40ms | 150ms | Single DDB query, small result set |
| `GET /ui/agent/fleet/events` (SSE) | <50ms per event | <100ms per event | In-memory queue push |

### 17.2 Caching Strategy

- **Fleet status**: React Query `staleTime: 5_000` with SSE-driven invalidation. SSE events call `queryClient.setQueryData(["fleet", "status"], updater)` to patch individual worker states without full refetch.
- **Templates list**: React Query `staleTime: 30_000`. Invalidated on create/delete mutations.
- **Capacity data**: React Query `staleTime: 10_000`. Ticket queue counts change less frequently.
- **Worker detail**: Fetched on drawer open; not cached (always fresh via SSE updates).

### 17.3 SSE Scalability

- Each user has one `_fleet_event_buses[user_id]` set of queues.
- Memory per SSE connection: ~4KB (asyncio.Queue + event buffer).
- Maximum recommended: 1000 concurrent SSE connections per backend process.
- If SSE is disabled (`AGENT_FLEET_SSE_ENABLED=false`), frontend falls back to `refetchInterval: 5_000` polling.
- SSE auto-reconnect: `EventSource` reconnects on network drop with 3-second backoff.

### 17.4 Bulk Operation Safeguards

- Bulk start/stop process workers sequentially (not concurrently) to avoid DDB write throttling.
- Maximum 50 workers per bulk operation. If user has more, return error suggesting pagination.
- Rate limit: 1 bulk operation per user per 30 seconds (prevent accidental double-click).

---

## 18. Expanded E2E Tests

### Section 639: Input Validation (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 639.1 | Template label empty string rejected | POST template with `label: ""` → 422 |
| 639.2 | Template label exceeds 200 chars rejected | POST template with 201-char label → 422 |
| 639.3 | idle_timeout below 600 rejected | POST template with `idle_timeout_seconds: 100` → 422 |
| 639.4 | idle_timeout above 86400 rejected | POST template with `idle_timeout_seconds: 100000` → 422 |
| 639.5 | Invalid agent_type rejected | POST template with `agent_type: "invalid"` → 422 |

### Section 640: Authorization Boundary (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 640.1 | Unauthenticated fleet status returns 401 | GET status without cookies → 401 |
| 640.2 | User A cannot see User B workers | Alice GET fleet status returns only Alice workers; no Bob workers leak |
| 640.3 | Non-admin cannot call admin fleet endpoint | Alice GET `/ui/admin/agent/fleet` → 403 |
| 640.4 | CSRF required for bulk start | POST start-all without `x-csrf-token` → 403 |

### Section 641: SSE Event Handling (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 641.1 | SSE connection established | Open EventSource to `/ui/agent/fleet/events`; verify `onopen` fires within 2s |
| 641.2 | Worker state change event received | Start a worker; verify `worker:state_change` event received with correct `worker_id`, `new_state` |
| 641.3 | SSE reconnects on drop | Close the SSE connection; verify EventSource reconnects and receives subsequent events |
| 641.4 | Multiple browser tabs receive same events | Open two SSE connections for same user; trigger state change; both receive the event |

### Section 642: Template Edge Cases (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 642.1 | Create worker from deleted template fails | Delete template; POST create from that template_id → 404 "Template not found" |
| 642.2 | Template with stale LLM key creates worker in error state | Delete LLM key; create worker from template referencing it; worker enters `error` state |
| 642.3 | Duplicate template labels allowed | Create two templates with same label → both succeed with different template_ids |
| 642.4 | Template ticket_filter with empty arrays is valid | POST template with `ticket_filter: {"labels": [], "complexity": []}` → 201 |
| 642.5 | List templates returns empty for new user | Bob (with no templates) GET templates → `{"templates": [], "count": 0}` |

---

## Codebase References

| Reference | Path | Line(s) | Status |
|-----------|------|---------|--------|
| Ticket store | `app/services/tickets.py` | 110, 384 | Verified |
| DataTable component | `frontend/src/components/shared/DataTable.tsx` | entire file | Verified — **not** `frontend/src/components/ui/data-table.tsx` |
| shadcn/ui components | `frontend/src/components/ui/` | directory | Verified |
| Alerts service | `app/services/alerts.py` | entire file | Verified |
| Admin auth pattern | `app/auth/policy.py` | 84 (`require_admin_scope`) | Verified — **not** `require_admin_session` |
| Worker provisioner | `app/services/agent_worker_provisioner.py` | — | **Does not exist** — requires AGENT-002 |
| Agent orchestrator | `app/services/agent_orchestrator.py` | — | **Does not exist** — requires AGENT-003 |
| LLM key store | `app/services/llm_provider_keys.py` | — | **Does not exist** — requires AGENT-001 |
| Cost tracking | `app/services/compute_cost.py` | — | **Does not exist** — requires INFRA-005 |

---

## Testing Strategy


### Unit Tests (pytest)


**Test file**: `tests/test_agent_fleet_ui.py`


**Mock setup**: moto for DynamoDB tables, `unittest.mock.patch` for external services (S3, Cognito, Stripe mock). All DDB tables created in-memory via moto `@mock_dynamodb` decorator.


| Test Function | Verifies |
|---|---|
| `test_create_agent_fleet_ui` | Creates record with correct fields and generated ID |
| `test_create_agent_fleet_ui_validation` | Rejects invalid input (missing required fields, out-of-range values) |
| `test_get_agent_fleet_ui_found` | Returns correct record by ID |
| `test_get_agent_fleet_ui_not_found` | Returns None for non-existent ID |
| `test_list_agent_fleet_ui` | Returns all records for the given scope/owner |
| `test_update_agent_fleet_ui` | Updates mutable fields and sets updated_at |
| `test_delete_agent_fleet_ui` | Removes record; subsequent get returns None |
| `test_agent_fleet_ui_owner_check` | Rejects operations from non-owner users |
| `test_agent_fleet_ui_admin_only` | Admin/root endpoints reject USER role with 403 |
| `test_agent_fleet_ui_concurrent_write` | Conditional update prevents stale overwrites |

### Integration Tests


Cross-service tests with real DDB (moto), verifying end-to-end flows:


1. Full CRUD lifecycle: create -> read -> update -> delete with real DDB (moto)
2. Authorization enforcement: non-owner access returns 403/404
3. Admin review/approval workflow with role-gated endpoints
4. Concurrent write safety: conditional updates prevent stale overwrites
5. Edge case: empty list returns `[]` not error; missing optional fields use defaults

### E2E Tests (Playwright)


**Test file**: `frontend/e2e/agent-fleet-ui.spec.ts`


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


- **Feature flags**: None required for dev/test
- **Execution**: E2E tests run serially (1 worker, Chromium only) per `playwright.config.ts`; pytest can run in parallel
- **Retry safety**: All tests are idempotent; unique `TS = Date.now()` suffixed identifiers prevent cross-run collisions
- **Prerequisite**: `just restart` to create DDB tables and seed E2E sessions before running

## Dependencies & Merge Safety


### Depends On


| Ticket | What's Needed | Status | Can Overlap? |
|--------|--------------|--------|-------------|
| AGENT-001 | LLM key display | Pending | No |
| AGENT-002 | Worker provisioning data | Pending | No |
| AGENT-003 | Agent framework lifecycle | Pending | No |

### Depended On By


| Ticket | What It Needs From This |
|--------|------------------------|
| AGENT-008 through AGENT-018 | Fleet UI for agent management |

### Merge Strategy


**Sequential (after AGENT-003)**


- Must merge after: AGENT-001, AGENT-002, AGENT-003
- Branch from `main` after dependencies are merged
- Can begin development in parallel but must rebase before merge
- DDB table creation is additive (no migration needed for new tables)

### Merge Checklist


- [ ] DDB tables verified (uses existing tables only)
- [ ] `.env.local` updated with any new environment variables
- [ ] Router registered in `app/main.py` (from `app/routers/agent_workers.py`)
- [ ] Frontend route(s) added to `App.tsx`: `/agents`
- [ ] All E2E tests passing (`just e2e` or targeted spec file)
- [ ] No breaking changes to existing endpoints or UI components
- [ ] `just restart` succeeds with new table definitions
