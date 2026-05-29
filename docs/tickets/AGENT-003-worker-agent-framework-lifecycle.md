# AGENT-003: Worker Agent Framework & Lifecycle

**Ticket**: AGENT-003
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: High
**Estimated effort**: 10-12 days
**Dependencies**: AGENT-002 (Terminal Worker Provisioning), existing ticket system (`app/services/tickets.py`)

---

## 1. Overview & Motivation

### 1.1 Purpose

AGENT-003 implements the core autonomous agent loop that drives all agent types. This is the "brain" of the orchestration platform: the system that queries the ticket system for available work, claims tickets, injects context into agent terminals, monitors execution, detects completion or feedback requests, and transitions tickets through their lifecycle. Each worker agent runs a state machine (`idle` -> `claiming` -> `working` -> `awaiting_feedback` -> `completing` -> `idle`) with heartbeat monitoring, error recovery, and graceful shutdown.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| User | As a user, I want my agent to automatically pick up the next available ticket so that I don't have to manually assign work. | Agent queries ticket system; picks highest-priority unassigned ticket matching its type; claims with optimistic locking. |
| User | As a user, I want to see the agent's current state (idle, working, etc.) so that I know what it's doing. | Worker status reflects agent state in real-time; dashboard shows current ticket and state. |
| User | As a user, I want the agent to resume work if it crashes so that tickets don't get stuck. | On restart, agent checks for in-progress tickets and resumes from last checkpoint. |
| User | As a user, I want to configure which ticket types/tags an agent picks up so that I can specialize agents. | Agent config includes `ticket_filter` with type, tags, space constraints. |
| User | As a user, I want to know if the agent is stuck so that I can intervene. | Heartbeat monitoring; missed heartbeat triggers alert; configurable threshold. |
| User | As a user, I want agents to work through tickets one at a time so that each gets full attention. | Configurable concurrency (default: 1); agent waits for current ticket to complete before picking next. |
| User | As a user, I want to pause an agent without losing its current work so that I can review its progress. | Pause transitions agent to `paused` state; resume picks up where it left off. |

### 1.3 Why This Is Needed

AGENT-002 provisions compute with AI tools, but without AGENT-003 those tools sit idle waiting for manual prompting. The agent framework automates the entire development cycle: reading a ticket's requirements, writing code, running tests, creating PRs, and moving to the next ticket. This is what makes the platform an "agent orchestration" system rather than just an infrastructure launcher.

---

## 2. Current State Analysis

### 2.1 Existing Infrastructure

| Component | Location | Relevance |
|-----------|----------|-----------|
| Ticket store | `app/services/tickets.py` (~500 lines) | `TicketStore` class: `create_ticket`, `get_ticket`, `list_tickets`, `update_ticket_status`; ticket spaces and assignment |
| Ticket models | `app/models.py` | `TicketCreateIn`, `TicketOut`, etc. |
| Worker provisioner | `app/services/agent_worker_provisioner.py` (AGENT-002) | Worker CRUD, compute lifecycle |
| Agent workers DDB | `agent_workers` table | Worker records with `worker_status`, `compute_instance_id`, `host_id` |
| SSE infrastructure | Various routers | Server-Sent Events for real-time state push |
| Alerts service | `app/services/alerts.py` | `audit_event()` for logging; notification infrastructure |
| Background tasks | `app/main.py` | Pattern: `add_event_handler("startup", ...)` for async loops |

### 2.2 Gaps

1. **No agent loop** -- no autonomous ticket-picking mechanism; tickets require manual assignment.
2. **No state machine** -- workers have a `worker_status` field but no formal state machine with transitions.
3. **No ticket claiming** -- no optimistic-locking claim mechanism to prevent two agents from picking the same ticket.
4. **No terminal command injection** -- no way to programmatically send text into a running SSH session.
5. **No completion detection** -- no mechanism to detect when an agent has finished its work.
6. **No heartbeat** -- no monitoring of whether the agent process is still alive.
7. **No ticket filtering** -- no way to constrain which tickets an agent picks up.
8. **No checkpoint/resume** -- no persistence of agent progress for crash recovery.

---

## 3. Technical Design

### 3.1 DynamoDB Schema Extensions

#### 3.1.1 Agent Workers Table — New Fields

Add to existing `agent_workers` items:

| Field | Type | Description |
|-------|------|-------------|
| `agent_state` | S | State machine: `idle`, `claiming`, `working`, `awaiting_feedback`, `completing`, `paused`, `error` |
| `current_ticket_id` | S | Ticket currently being worked |
| `current_ticket_title` | S | Denormalized for display |
| `tickets_completed` | N | Lifetime count |
| `tickets_failed` | N | Lifetime count |
| `heartbeat_at` | N | Unix timestamp of last heartbeat |
| `heartbeat_interval_seconds` | N | Expected heartbeat interval (default: 30) |
| `ticket_filter` | M | `{types: [...], tags: [...], space_ids: [...], priorities: [...]}` |
| `concurrency` | N | Max simultaneous tickets (default: 1) |
| `active_tickets` | L | List of `{ticket_id, claimed_at, checkpoint}` for concurrency > 1 |
| `session_log_key` | S | S3 key for current session's terminal output log |
| `total_session_time_seconds` | N | Accumulated working time |

#### 3.1.2 Agent Ticket Claims Table

New item pattern in `tickets` table (single-table design):

| PK Pattern | SK Pattern | Purpose | Key Fields |
|------------|------------|---------|------------|
| `AGENT_CLAIM#{ticket_id}` | `CLAIM#{worker_id}` | Claim lock record | `worker_id`, `user_id`, `claimed_at`, `status` (active/released/completed/failed), `checkpoint` |

#### 3.1.3 Ticket Extensions

Add to existing ticket items in the `tickets` table:

| Field | Type | Description |
|-------|------|-------------|
| `agent_worker_id` | S | Worker that claimed/is working on this ticket |
| `agent_claimed_at` | N | When the agent claimed the ticket |
| `agent_state` | S | Agent-side state for this ticket |
| `agent_checkpoint` | S | JSON-serialized checkpoint data |
| `agent_eligible` | S | `yes` / `no` — whether this ticket is eligible for agent pickup |

### 3.2 Agent State Machine

```
                  ┌───────────────────┐
                  │       idle        │
                  │  (waiting for     │
                  │   next ticket)    │
                  └───────┬───────────┘
                          │ ticket found
                          v
                  ┌───────────────────┐
                  │     claiming      │
                  │  (optimistic lock │
                  │   on ticket)      │
                  └───────┬───────────┘
                          │ claim acquired
                          v
              ┌───────────────────────────┐
              │         working           │
              │  (injecting context,      │
              │   monitoring terminal)    │
              └──────┬────────┬───────────┘
                     │        │ feedback needed
                     │        v
                     │  ┌──────────────────┐
                     │  │ awaiting_feedback │
                     │  │  (human input    │
                     │  │   required)      │
                     │  └───────┬──────────┘
                     │          │ feedback received
                     │          v
                     │    (back to working)
                     │
                     │ work complete
                     v
              ┌───────────────────┐
              │    completing     │
              │  (PR creation,   │
              │   ticket update) │
              └───────┬──────────┘
                      │ done
                      v
              (back to idle → pick next)
```

### 3.3 Backend Service

**New file**: `app/services/agent_orchestrator.py` (~600 lines)

```python
"""Agent Orchestrator — Core Agent Loop (AGENT-003).

Drives autonomous ticket processing: query → claim → inject →
monitor → complete → loop. Manages agent state machine and
heartbeat monitoring.
"""

from __future__ import annotations
import asyncio
import json
import logging
import re
from typing import Any, Dict, List, Optional
from uuid import uuid4

from boto3.dynamodb.conditions import Attr
from app.core.tables import T
from app.core.time import now_ts
from app.services.tickets import TicketStore

logger = logging.getLogger(__name__)

_ticket_store = TicketStore()

# Agent state transitions
VALID_TRANSITIONS = {
    "idle": {"claiming", "paused"},
    "claiming": {"working", "idle", "error"},
    "working": {"awaiting_feedback", "completing", "paused", "error", "idle"},
    "awaiting_feedback": {"working", "paused", "error", "idle"},
    "completing": {"idle", "error"},
    "paused": {"idle", "working"},
    "error": {"idle"},
}


def transition_agent_state(
    user_id: str,
    worker_id: str,
    new_state: str,
) -> Dict[str, Any]:
    """Transition agent state with validation.

    Enforces valid state transitions. Updates DDB atomically
    with condition expression to prevent race conditions.
    """
    worker = T.agent_workers.get_item(
        Key={"pk": f"USER#{user_id}", "sk": f"WORKER#{worker_id}"}
    ).get("Item")
    if not worker:
        raise ValueError("Worker not found")

    current = worker.get("agent_state", "idle")
    if new_state not in VALID_TRANSITIONS.get(current, set()):
        raise ValueError(f"Invalid transition: {current} -> {new_state}")

    T.agent_workers.update_item(
        Key={"pk": f"USER#{user_id}", "sk": f"WORKER#{worker_id}"},
        UpdateExpression="SET agent_state = :ns, heartbeat_at = :hb",
        ConditionExpression=Attr("agent_state").eq(current),
        ExpressionAttributeValues={":ns": new_state, ":hb": now_ts()},
    )
    return {**worker, "agent_state": new_state}


def find_next_ticket(
    user_id: str,
    worker_id: str,
) -> Dict[str, Any] | None:
    """Find the next eligible ticket for this worker.

    Queries the ticket system with the worker's ticket_filter
    and returns the highest-priority unassigned ticket.

    Eligibility criteria:
    - ticket.agent_eligible == "yes"
    - ticket.status in ("open", "ready")
    - ticket.assignee is empty (not assigned to a human)
    - ticket.agent_worker_id is empty (not claimed by another agent)
    - ticket matches worker's ticket_filter (types, tags, space_ids)
    """
    worker = T.agent_workers.get_item(
        Key={"pk": f"USER#{user_id}", "sk": f"WORKER#{worker_id}"}
    ).get("Item")
    if not worker:
        return None

    ticket_filter = worker.get("ticket_filter", {})
    # Query tickets table for eligible tickets
    # Filter by worker's ticket_filter constraints
    # Sort by priority (critical > high > medium > low)
    # Return first match or None


def claim_ticket(
    user_id: str,
    worker_id: str,
    ticket_id: str,
) -> Dict[str, Any]:
    """Claim a ticket for a worker using optimistic locking.

    Uses DynamoDB conditional write to ensure only one agent
    can claim a ticket. If claim fails (another agent got it first),
    raises ValueError.
    """
    ts = now_ts()

    # 1. Write claim record with condition: no existing active claim
    claim_item = {
        "pk": f"AGENT_CLAIM#{ticket_id}",
        "sk": f"CLAIM#{worker_id}",
        "worker_id": worker_id,
        "user_id": user_id,
        "claimed_at": ts,
        "status": "active",
        "checkpoint": "",
    }
    try:
        T.tickets.put_item(
            Item=claim_item,
            ConditionExpression="attribute_not_exists(pk)",
        )
    except T.tickets.meta.client.exceptions.ConditionalCheckFailedException:
        raise ValueError(f"Ticket {ticket_id} already claimed by another agent")

    # 2. Update ticket with agent_worker_id
    # Use conditional update: agent_worker_id must be empty
    T.tickets.update_item(
        Key={"pk": f"TICKET#{ticket_id}", "sk": "META"},
        UpdateExpression="SET agent_worker_id = :wid, agent_claimed_at = :ts, "
                        "agent_state = :as",
        ConditionExpression="attribute_not_exists(agent_worker_id) OR agent_worker_id = :empty",
        ExpressionAttributeValues={
            ":wid": worker_id, ":ts": ts, ":as": "claimed", ":empty": "",
        },
    )

    # 3. Update worker with current ticket
    T.agent_workers.update_item(
        Key={"pk": f"USER#{user_id}", "sk": f"WORKER#{worker_id}"},
        UpdateExpression="SET current_ticket_id = :tid, agent_state = :as, "
                        "heartbeat_at = :hb",
        ExpressionAttributeValues={
            ":tid": ticket_id, ":as": "working", ":hb": ts,
        },
    )

    return claim_item


def release_ticket(
    user_id: str,
    worker_id: str,
    ticket_id: str,
    *,
    reason: str = "released",
) -> None:
    """Release a claimed ticket back to the queue.

    Clears the claim lock and resets ticket's agent fields.
    """
    # Update claim record status
    # Clear ticket's agent_worker_id
    # Reset worker's current_ticket_id and agent_state to idle


def complete_ticket(
    user_id: str,
    worker_id: str,
    ticket_id: str,
    *,
    summary: str = "",
    pr_url: str = "",
) -> None:
    """Mark a ticket as completed by the agent.

    Updates claim, ticket status, and worker counters.
    Called by AGENT-007 after PR creation.
    """
    ts = now_ts()

    # 1. Update claim status to "completed"
    # 2. Update ticket status and agent fields
    # 3. Increment worker's tickets_completed
    # 4. Clear current_ticket_id, transition to idle


def save_checkpoint(
    user_id: str,
    worker_id: str,
    ticket_id: str,
    checkpoint_data: Dict[str, Any],
) -> None:
    """Save a checkpoint for crash recovery.

    Stores serialized state so the agent can resume after restart.
    """
    T.tickets.update_item(
        Key={"pk": f"AGENT_CLAIM#{ticket_id}", "sk": f"CLAIM#{worker_id}"},
        UpdateExpression="SET checkpoint = :cp",
        ExpressionAttributeValues={":cp": json.dumps(checkpoint_data)},
    )


def resume_from_checkpoint(
    user_id: str,
    worker_id: str,
) -> Dict[str, Any] | None:
    """Check if the worker has an in-progress ticket to resume.

    Called on worker restart. Returns checkpoint data if found.
    """
    worker = T.agent_workers.get_item(
        Key={"pk": f"USER#{user_id}", "sk": f"WORKER#{worker_id}"}
    ).get("Item")
    if not worker or not worker.get("current_ticket_id"):
        return None

    ticket_id = worker["current_ticket_id"]
    claim = T.tickets.get_item(
        Key={"pk": f"AGENT_CLAIM#{ticket_id}", "sk": f"CLAIM#{worker_id}"}
    ).get("Item")
    if claim and claim.get("status") == "active":
        checkpoint = claim.get("checkpoint", "")
        return {
            "ticket_id": ticket_id,
            "checkpoint": json.loads(checkpoint) if checkpoint else {},
            "claimed_at": claim.get("claimed_at", 0),
        }
    return None


def record_heartbeat(user_id: str, worker_id: str) -> None:
    """Record a heartbeat from a worker agent."""
    T.agent_workers.update_item(
        Key={"pk": f"USER#{user_id}", "sk": f"WORKER#{worker_id}"},
        UpdateExpression="SET heartbeat_at = :hb, last_activity_at = :la",
        ExpressionAttributeValues={":hb": now_ts(), ":la": now_ts()},
    )


def check_stale_heartbeats(threshold_seconds: int = 120) -> List[Dict[str, Any]]:
    """Find workers with missed heartbeats.

    Returns list of workers where now - heartbeat_at > threshold.
    Background task calls this every 60 seconds.
    """
    # Scan agent_workers for agent_state in ("working", "awaiting_feedback")
    # where heartbeat_at < now() - threshold_seconds
    # For each stale worker: transition to "error", release ticket


def inject_ticket_context(
    user_id: str,
    worker_id: str,
    ticket_id: str,
) -> str:
    """Build the context injection text for a ticket.

    Generates a formatted prompt that will be pasted into
    the agent's terminal session.
    """
    ticket = _ticket_store.get_ticket(ticket_id)
    if not ticket:
        raise ValueError(f"Ticket {ticket_id} not found")

    context = f"""
--- TICKET: {ticket.get('title', 'Untitled')} ---
ID: {ticket_id}
Priority: {ticket.get('priority', 'medium')}
Status: {ticket.get('status', 'open')}
Type: {ticket.get('type', 'task')}

DESCRIPTION:
{ticket.get('description', '')}

ACCEPTANCE CRITERIA:
{ticket.get('acceptance_criteria', 'None specified')}

INSTRUCTIONS:
1. Create a feature branch: agent/{worker_id}/{ticket_id}
2. Implement the changes described above
3. Run tests to verify your changes
4. Commit with a descriptive message referencing {ticket_id}
5. When complete, indicate DONE by outputting: [AGENT_COMPLETE]
6. If you need human input, output: [AGENT_FEEDBACK_NEEDED] followed by your question
---
""".strip()
    return context


def get_agent_status(user_id: str, worker_id: str) -> Dict[str, Any]:
    """Get comprehensive agent status for display."""
    worker = T.agent_workers.get_item(
        Key={"pk": f"USER#{user_id}", "sk": f"WORKER#{worker_id}"}
    ).get("Item")
    if not worker:
        return {}
    return {
        "worker_id": worker_id,
        "agent_state": worker.get("agent_state", "idle"),
        "current_ticket_id": worker.get("current_ticket_id", ""),
        "current_ticket_title": worker.get("current_ticket_title", ""),
        "tickets_completed": worker.get("tickets_completed", 0),
        "tickets_failed": worker.get("tickets_failed", 0),
        "heartbeat_at": worker.get("heartbeat_at", 0),
        "last_activity_at": worker.get("last_activity_at", 0),
    }
```

### 3.4 Agent Loop (Background Task)

```python
async def run_agent_loop(user_id: str, worker_id: str, *, poll_interval: int = 30):
    """Main agent loop. Runs as a background task per worker.

    1. Check for resumed ticket (crash recovery)
    2. If idle, find next eligible ticket
    3. Claim ticket
    4. Inject context into terminal
    5. Monitor terminal for completion signals
    6. On completion: update ticket, pick next
    7. On error: release ticket, transition to error
    """
    while True:
        try:
            worker = T.agent_workers.get_item(
                Key={"pk": f"USER#{user_id}", "sk": f"WORKER#{worker_id}"}
            ).get("Item")

            if not worker or worker.get("worker_status") != "ready":
                break  # Worker stopped/terminated

            state = worker.get("agent_state", "idle")

            if state == "paused":
                await asyncio.sleep(poll_interval)
                continue

            if state == "idle":
                # Look for next ticket
                ticket = find_next_ticket(user_id, worker_id)
                if ticket:
                    try:
                        claim_ticket(user_id, worker_id, ticket["ticket_id"])
                        context = inject_ticket_context(user_id, worker_id, ticket["ticket_id"])
                        # Send context to terminal (AGENT-006 handles monitoring)
                    except ValueError:
                        pass  # Another agent claimed it; try again next loop
                else:
                    await asyncio.sleep(poll_interval)

            elif state == "working":
                record_heartbeat(user_id, worker_id)
                # AGENT-006 handles terminal monitoring
                await asyncio.sleep(poll_interval)

            elif state == "error":
                # Attempt recovery
                await asyncio.sleep(poll_interval * 2)

        except Exception:
            logger.exception("Agent loop error for worker %s", worker_id)
            await asyncio.sleep(poll_interval)
```

### 3.5 Backend Router

**New file**: `app/routers/agent_orchestrator.py` (~200 lines)

Prefix: `/ui/agent/orchestrator`

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/ui/agent/orchestrator/{worker_id}/status` | `require_ui_session` | Get agent state and status |
| `POST` | `/ui/agent/orchestrator/{worker_id}/start` | `require_ui_session` | Start the agent loop for a worker |
| `POST` | `/ui/agent/orchestrator/{worker_id}/pause` | `require_ui_session` | Pause the agent (finish current work, don't pick new) |
| `POST` | `/ui/agent/orchestrator/{worker_id}/resume` | `require_ui_session` | Resume a paused agent |
| `POST` | `/ui/agent/orchestrator/{worker_id}/stop` | `require_ui_session` | Stop the agent loop (graceful) |
| `POST` | `/ui/agent/orchestrator/{worker_id}/release-ticket` | `require_ui_session` | Manually release the current ticket |
| `GET` | `/ui/agent/orchestrator/{worker_id}/checkpoint` | `require_ui_session` | Get current checkpoint data |
| `POST` | `/ui/agent/orchestrator/{worker_id}/heartbeat` | `require_ui_session` | Manual heartbeat (for debugging) |
| `GET` | `/ui/agent/orchestrator/{worker_id}/eligible-tickets` | `require_ui_session` | Preview tickets the agent would pick up |
| `PUT` | `/ui/agent/orchestrator/{worker_id}/ticket-filter` | `require_ui_session` | Update the ticket filter config |

### 3.6 Pydantic Models

**Add to `app/models.py`**:

```python
# -- Agent Orchestrator (AGENT-003) --

class TicketFilterConfig(BaseModel):
    types: List[str] = Field(default_factory=list)         # e.g., ["bug", "feature", "task"]
    tags: List[str] = Field(default_factory=list)           # e.g., ["backend", "frontend"]
    space_ids: List[str] = Field(default_factory=list)      # limit to specific ticket spaces
    priorities: List[str] = Field(default_factory=list)     # e.g., ["critical", "high"]

class AgentStatusOut(BaseModel):
    worker_id: str
    agent_state: str
    current_ticket_id: str = ""
    current_ticket_title: str = ""
    tickets_completed: int = 0
    tickets_failed: int = 0
    heartbeat_at: int = 0
    last_activity_at: int = 0
    ticket_filter: Optional[TicketFilterConfig] = None

class AgentClaimOut(BaseModel):
    ticket_id: str
    worker_id: str
    claimed_at: int
    status: str
    checkpoint: str = ""

class EligibleTicketsOut(BaseModel):
    tickets: List[Dict[str, Any]]
    count: int
    filter_applied: TicketFilterConfig
```

---

## 4. Implementation Plan

### Phase 1: State Machine + Claim System (3-4 days)

| File | Change |
|------|--------|
| `scripts/local-ddb-init.py` | Extend `agent_workers` with new fields; add AGENT_CLAIM pattern to tickets table |
| `app/services/agent_orchestrator.py` | New file: state machine, claim/release/complete, heartbeat, checkpoint |
| `app/models.py` | Add orchestrator Pydantic models |

### Phase 2: Agent Loop + Ticket Integration (3-4 days)

| File | Change |
|------|--------|
| `app/services/agent_orchestrator.py` | Add `find_next_ticket`, `inject_ticket_context`, `run_agent_loop` |
| `app/services/tickets.py` | Add `agent_eligible`, `agent_worker_id` field handling to queries and updates |
| `app/main.py` | Register heartbeat checker background task |

### Phase 3: Router + API (2 days)

| File | Change |
|------|--------|
| `app/routers/agent_orchestrator.py` | New file: 10 endpoints |
| `app/main.py` | Register `agent_orchestrator_router` |

### Phase 4: E2E Tests (2 days)

| File | Change |
|------|--------|
| `frontend/e2e/agent-orchestrator.spec.ts` | New file: ~16 tests in 4 sections |

---

## 5. E2E Test Plan (`frontend/e2e/agent-orchestrator.spec.ts`)

**Test setup**: Uses `e2e_admin_session_setup.py` sessions. `beforeAll` creates an LLM key (AGENT-001), a worker (AGENT-002), and a ticket space with test tickets.

**Section 631: Agent State Machine API (4 tests)**

1. `Agent starts in idle state` -- GET `/ui/agent/orchestrator/{worker_id}/status`. Verify `agent_state: "idle"`, `current_ticket_id: ""`, `tickets_completed: 0`.
2. `Start agent loop transitions to idle/claiming` -- POST `/ui/agent/orchestrator/{worker_id}/start`. Verify 200. GET status, verify `agent_state` is `"idle"` or `"claiming"` (depends on whether eligible tickets exist).
3. `Pause agent sets state to paused` -- POST `/ui/agent/orchestrator/{worker_id}/pause`. Verify 200. GET status, verify `agent_state: "paused"`.
4. `Resume agent returns to idle` -- POST `/ui/agent/orchestrator/{worker_id}/resume`. Verify 200. GET status, verify `agent_state: "idle"`.

**Section 632: Ticket Claiming API (4 tests)**

5. `Create agent-eligible ticket` -- Create a ticket via ticket API with `agent_eligible: "yes"`. Verify ticket has `agent_eligible: "yes"`, `agent_worker_id: ""`.
6. `Agent claims eligible ticket` -- Start agent loop. Poll status until `agent_state: "working"` (max 15s). Verify `current_ticket_id` matches the created ticket.
7. `Claimed ticket shows agent_worker_id` -- GET the ticket. Verify `agent_worker_id` matches `worker_id`, `agent_claimed_at > 0`.
8. `Double-claim is prevented` -- Create a second worker. Attempt to manually claim the same ticket. Verify 409 or error about ticket already claimed.

**Section 633: Ticket Lifecycle API (5 tests)**

9. `Release ticket returns it to queue` -- POST `/ui/agent/orchestrator/{worker_id}/release-ticket`. Verify agent state returns to `idle`, `current_ticket_id: ""`. GET ticket: `agent_worker_id: ""`.
10. `Eligible tickets preview respects filter` -- PUT `/ui/agent/orchestrator/{worker_id}/ticket-filter` with `types: ["bug"]`. Create a "feature" ticket and a "bug" ticket. GET `/eligible-tickets`. Verify only the "bug" ticket is returned.
11. `Heartbeat updates timestamp` -- POST `/ui/agent/orchestrator/{worker_id}/heartbeat`. Verify 200. GET status, verify `heartbeat_at` is recent (within 5 seconds).
12. `Save and retrieve checkpoint` -- Claim a ticket. POST checkpoint data `{step: "coding", files_changed: 3}`. GET `/checkpoint`. Verify checkpoint matches.
13. `Complete ticket increments counter` -- Simulate ticket completion via API. Verify `tickets_completed` incremented, `agent_state: "idle"`, `current_ticket_id: ""`.

**Section 634: Agent Error Recovery API (3 tests)**

14. `Stop agent loop gracefully` -- POST `/ui/agent/orchestrator/{worker_id}/stop`. Verify 200. GET status, verify agent loop has stopped (state is `idle` and loop is not running).
15. `Resume from checkpoint after restart` -- Claim a ticket, save checkpoint, stop agent. Start agent again. GET status, verify `current_ticket_id` matches the previously claimed ticket.
16. `Invalid state transition returns 400` -- Attempt to transition from `idle` directly to `completing`. Verify 400 with error about invalid transition.

---

## 6. Security Considerations

### 6.1 Optimistic Locking

Ticket claims use DynamoDB conditional writes (`ConditionExpression`) to prevent race conditions. If two agents try to claim the same ticket simultaneously, only one succeeds; the other receives an error and retries with a different ticket.

### 6.2 User Isolation

All agent operations use `user_id` from the session. Workers can only claim tickets in spaces the user owns or has access to. Cross-user ticket access is impossible.

### 6.3 Heartbeat Monitoring

Workers that miss heartbeats for > 120 seconds are transitioned to `error` state and their tickets are released. This prevents tickets from being permanently locked by dead agents.

### 6.4 State Transition Validation

The `VALID_TRANSITIONS` map enforces which state transitions are allowed. Invalid transitions are rejected with 400 errors. This prevents agents from skipping states (e.g., jumping from `idle` to `completing`).

### 6.5 Checkpoint Data Validation

Checkpoint data is JSON-serialized and size-limited (max 64KB) to prevent DDB item size issues. No executable code is stored in checkpoints.

---

## 7. Dependencies

| Dependency | Type | Description |
|------------|------|-------------|
| AGENT-002 | Upstream | Worker records in `agent_workers` table |
| `app/services/tickets.py` | Upstream | Ticket queries, status updates, space membership |
| AGENT-005 | Downstream | Context injection uses memory templates |
| AGENT-006 | Downstream | Terminal monitoring detects completion/feedback signals |
| AGENT-007 | Downstream | PR creation calls `complete_ticket` |

---

## 8. Acceptance Criteria

1. Agent loop autonomously picks up the next eligible ticket from the queue.
2. Ticket claiming uses optimistic locking to prevent double-pickup.
3. Agent state machine enforces valid transitions with DDB conditional writes.
4. Ticket context (title, description, acceptance criteria) is injected into the agent terminal.
5. Heartbeat monitoring detects unresponsive agents within 2 minutes.
6. Crash recovery resumes from the last saved checkpoint.
7. Ticket filters constrain which tickets an agent picks up by type, tags, space, and priority.
8. Pause/resume allows users to temporarily halt an agent without losing progress.
9. Completed tickets increment the worker's `tickets_completed` counter.
10. All state transitions produce audit events.
