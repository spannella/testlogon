# AGENT-004: Worker Fleet Management UI

**Ticket**: AGENT-004
**Author**: Engineering
**Status**: Design
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
| Worker provisioner | `app/services/agent_worker_provisioner.py` (AGENT-002) | Worker CRUD, lifecycle |
| Agent orchestrator | `app/services/agent_orchestrator.py` (AGENT-003) | Agent state, ticket claims, heartbeat |
| LLM key store | `app/services/llm_provider_keys.py` (AGENT-001) | Key usage stats |
| Ticket store | `app/services/tickets.py` | Ticket queue queries for capacity planning |
| SSE patterns | Various routers | `StreamingResponse` + `asyncio.Queue` for real-time push |
| DataTable component | `frontend/src/components/ui/data-table.tsx` | Reusable table with sorting, filtering |
| Card/Sheet/Drawer | `frontend/src/components/ui/` | shadcn/ui layout primitives |
| Cost tracking | `app/services/compute_cost.py` (INFRA-005) | Per-instance cost data |
| Alerts | `app/services/alerts.py` | Notification infrastructure |

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
| `GET` | `/ui/admin/agent/fleet` | `require_admin_session` | Admin: aggregate fleet metrics across users |

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

Fleet endpoints only return workers belonging to the authenticated user. Admin fleet endpoint requires `require_admin_session`.

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
