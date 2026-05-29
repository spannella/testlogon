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

### 1.4 Architecture Diagram

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                              FRONTEND (React)                               │
│                                                                              │
│  ┌──────────────────────┐  ┌────────────────────┐  ┌─────────────────────┐  │
│  │  AgentDashboard      │  │ TicketFilterEditor │  │  AgentDetailPanel   │  │
│  │  ┌────────────────┐  │  │ ┌────────────────┐ │  │  ┌───────────────┐  │  │
│  │  │ AgentStateCard  │  │  │ │ TypeFilter    │ │  │  │ StateMachine  │  │  │
│  │  │ TicketProgress  │  │  │ │ TagFilter     │ │  │  │   Visualizer  │  │  │
│  │  │ HeartbeatLED    │  │  │ │ SpaceFilter   │ │  │  │ CheckpointView│  │  │
│  │  │ StatsCounters   │  │  │ │ PriorityRange │ │  │  │ TerminalLog   │  │  │
│  │  └────────────────┘  │  │ └────────────────┘ │  │  └───────────────┘  │  │
│  └──────────────────────┘  └────────────────────┘  └─────────────────────┘  │
│                              │  Axios + CSRF / SSE                           │
└──────────────────────────────┼───────────────────────────────────────────────┘
                               │
                        Vite Proxy :3000 → :8000
                               │
┌──────────────────────────────┼───────────────────────────────────────────────┐
│                      BACKEND (FastAPI :8000)                                 │
│                               │                                              │
│  ┌────────────────────────────▼─────────────────────────────────────────┐    │
│  │     app/routers/agent_orchestrator.py  (10 endpoints)                │    │
│  │  GET  /ui/agent/orchestrator/{id}/status         — agent state      │    │
│  │  POST /ui/agent/orchestrator/{id}/start          — start loop       │    │
│  │  POST /ui/agent/orchestrator/{id}/pause          — pause agent      │    │
│  │  POST /ui/agent/orchestrator/{id}/resume         — resume agent     │    │
│  │  POST /ui/agent/orchestrator/{id}/stop           — stop loop        │    │
│  │  POST /ui/agent/orchestrator/{id}/release-ticket — release claim    │    │
│  │  GET  /ui/agent/orchestrator/{id}/checkpoint     — get checkpoint   │    │
│  │  POST /ui/agent/orchestrator/{id}/heartbeat      — manual heartbeat │    │
│  │  GET  /ui/agent/orchestrator/{id}/eligible-tickets — preview queue  │    │
│  │  PUT  /ui/agent/orchestrator/{id}/ticket-filter  — update filter    │    │
│  └────────┬──────────────────────────────────────────────────────────────┘    │
│           │                                                                  │
│  ┌────────▼─────────────────────────────────────────────────────────────┐    │
│  │         app/services/agent_orchestrator.py (~600 lines)              │    │
│  │                                                                      │    │
│  │  ┌─────────────────────┐  ┌──────────────────────────────────────┐  │    │
│  │  │  State Machine       │  │  Agent Loop (background task)        │  │    │
│  │  │  VALID_TRANSITIONS   │  │  run_agent_loop()                    │  │    │
│  │  │  transition_agent_   │  │  ┌────────────────────────────────┐  │  │    │
│  │  │  state()             │  │  │ 1. Check resume from checkpoint│  │  │    │
│  │  └─────────────────────┘  │  │ 2. find_next_ticket()           │  │  │    │
│  │                            │  │ 3. claim_ticket()               │  │  │    │
│  │  ┌─────────────────────┐  │  │ 4. inject_ticket_context()      │  │  │    │
│  │  │  Ticket Operations   │  │  │ 5. Monitor terminal output     │  │  │    │
│  │  │  find_next_ticket()  │  │  │ 6. Detect [AGENT_COMPLETE]     │  │  │    │
│  │  │  claim_ticket()      │  │  │ 7. complete_ticket()           │  │  │    │
│  │  │  release_ticket()    │  │  │ 8. Loop back to step 2         │  │  │    │
│  │  │  complete_ticket()   │  │  └────────────────────────────────┘  │  │    │
│  │  └─────────────────────┘  └──────────────────────────────────────┘  │    │
│  │                                                                      │    │
│  │  ┌─────────────────────┐  ┌──────────────────────────────────────┐  │    │
│  │  │  Checkpoint System   │  │  Heartbeat Monitor (bg task)         │  │    │
│  │  │  save_checkpoint()   │  │  check_stale_heartbeats()            │  │    │
│  │  │  resume_from_        │  │  Runs every 60s; threshold=120s      │  │    │
│  │  │  checkpoint()        │  │  Stale → error state + release ticket│  │    │
│  │  └─────────────────────┘  └──────────────────────────────────────┘  │    │
│  └──────────────────────────────────────────────────────────────────────┘    │
│           │                            │                                     │
│  ┌────────▼────────────┐    ┌──────────▼──────────────────────────┐         │
│  │  tickets.py          │    │  agent_worker_provisioner.py        │         │
│  │  (TicketStore)       │    │  (AGENT-002)                        │         │
│  │  get_ticket()        │    │  get_worker()                       │         │
│  │  update_ticket_      │    │  Worker status / compute lifecycle  │         │
│  │  status()            │    │                                     │         │
│  └──────────┬───────────┘    └──────────┬─────────────────────────┘         │
│             │                           │                                    │
└─────────────┼───────────────────────────┼────────────────────────────────────┘
              │                           │
┌─────────────▼───────────────────────────▼────────────────────────────────────┐
│                         DynamoDB (:8001)                                      │
│                                                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐   │
│  │  Table: agent_workers                                                 │   │
│  │  PK: USER#{user_id}   SK: WORKER#{worker_id}                         │   │
│  │  Extended fields: agent_state, current_ticket_id, heartbeat_at,       │   │
│  │  ticket_filter, tickets_completed, tickets_failed, concurrency,       │   │
│  │  active_tickets, session_log_key, total_session_time_seconds          │   │
│  │  GSIs: ByStatus, ByCreatedAt, ByAgentType                            │   │
│  └───────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐   │
│  │  Table: tickets (single-table design — claim records)                 │   │
│  │  PK: AGENT_CLAIM#{ticket_id}   SK: CLAIM#{worker_id}                 │   │
│  │  Fields: worker_id, user_id, claimed_at, status, checkpoint           │   │
│  │                                                                       │   │
│  │  Existing ticket items extended with:                                 │   │
│  │  PK: TICKET#{ticket_id}  SK: META                                    │   │
│  │  + agent_worker_id, agent_claimed_at, agent_state,                    │   │
│  │    agent_checkpoint, agent_eligible                                   │   │
│  └───────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐   │
│  │  Table: alerts  (audit events for state transitions)                  │   │
│  └───────────────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────────────┘

Data Flow — Autonomous Ticket Processing:
  1. Agent loop (background asyncio task) wakes every 30s
  2. Checks worker status: if not "ready", exit loop
  3. If agent_state == "idle": call find_next_ticket()
  4. find_next_ticket() queries tickets table with worker's ticket_filter
     → returns highest-priority unassigned ticket with agent_eligible="yes"
  5. claim_ticket() writes AGENT_CLAIM record with conditional PutItem
     → if claim fails (ConditionalCheckFailedException), retry next loop
  6. On successful claim: inject_ticket_context() builds prompt from ticket
  7. Context injected into worker's terminal via AGENT-006 (downstream)
  8. Agent loop monitors terminal for [AGENT_COMPLETE] or [AGENT_FEEDBACK_NEEDED]
  9. On complete: complete_ticket() updates claim, ticket, worker counters
 10. Worker transitions back to "idle", loop repeats from step 3

Data Flow — Heartbeat Monitoring:
  1. Background task runs every 60 seconds
  2. Queries agent_workers for agent_state in ("working", "awaiting_feedback")
  3. Filters workers where now() - heartbeat_at > 120 seconds
  4. For each stale worker:
     a. Transition agent_state to "error"
     b. Release claimed ticket back to queue
     c. Emit alert/audit event
```

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

### 3.1.4 DynamoDB Access Patterns

| # | Operation | Table / Index | PK | SK / Condition | Projection | Frequency |
|---|-----------|---------------|----|----|------------|-----------|
| AP-1 | Get worker with agent state | `agent_workers` (base) | `USER#{user_id}` | `WORKER#{worker_id}` | Full item | Every loop iteration (30s per worker) |
| AP-2 | Transition agent state (conditional) | `agent_workers` (base) | `USER#{user_id}` | `WORKER#{worker_id}` + `ConditionExpression: agent_state = :current` | N/A (update) | On every state change |
| AP-3 | Record heartbeat | `agent_workers` (base) | `USER#{user_id}` | `WORKER#{worker_id}` | N/A (update SET heartbeat_at, last_activity_at) | Every 30s per active worker |
| AP-4 | Find stale heartbeats | `ByStatus` GSI + filter | `USER#{user_id}` | `worker_status = "ready"` then filter `agent_state IN (working, awaiting_feedback) AND heartbeat_at < threshold` | worker_id, heartbeat_at, agent_state | Every 60s (background) |
| AP-5 | Write ticket claim | `tickets` (base) | `AGENT_CLAIM#{ticket_id}` | `CLAIM#{worker_id}` + `ConditionExpression: attribute_not_exists(pk)` | N/A (PutItem) | On each claim attempt |
| AP-6 | Update ticket agent fields | `tickets` (base) | `TICKET#{ticket_id}` | `META` + `ConditionExpression: agent_worker_id = :empty` | N/A (update) | On claim success |
| AP-7 | Query eligible tickets | `tickets` GSI (by status) | Depends on ticket table design | `status IN (open, ready)` + filter `agent_eligible = "yes" AND agent_worker_id = ""` | ticket_id, title, priority, type, tags | Every 30s per idle agent |
| AP-8 | Save checkpoint | `tickets` (base) | `AGENT_CLAIM#{ticket_id}` | `CLAIM#{worker_id}` | N/A (update SET checkpoint) | Periodically during work |
| AP-9 | Resume from checkpoint | `tickets` (base) | `AGENT_CLAIM#{ticket_id}` | `CLAIM#{worker_id}` | checkpoint, status, claimed_at | On worker restart |
| AP-10 | Release ticket claim | `tickets` (base) | `AGENT_CLAIM#{ticket_id}` | `CLAIM#{worker_id}` | N/A (update SET status = "released") | On release/error |
| AP-11 | Complete ticket claim | `tickets` (base) | `AGENT_CLAIM#{ticket_id}` | `CLAIM#{worker_id}` | N/A (update SET status = "completed") | On completion |
| AP-12 | Increment tickets_completed | `agent_workers` (base) | `USER#{user_id}` | `WORKER#{worker_id}` | N/A (update ADD tickets_completed :one) | On completion |

#### Example DynamoDB Items

**Agent worker item — Currently working on a ticket:**

```json
{
  "pk": {"S": "USER#a1b2c3d4-e5f6-7890-abcd-ef1234567890"},
  "sk": {"S": "WORKER#w_8f3a1b2c4d5e6f7890abcdef12345678"},
  "worker_id": {"S": "w_8f3a1b2c4d5e6f7890abcdef12345678"},
  "user_id": {"S": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"},
  "label": {"S": "Coder Agent #1"},
  "agent_type": {"S": "coder"},
  "tool": {"S": "claude_code"},
  "worker_status": {"S": "ready"},
  "agent_state": {"S": "working"},
  "current_ticket_id": {"S": "tkt_abc123def456"},
  "current_ticket_title": {"S": "Implement user avatar upload endpoint"},
  "tickets_completed": {"N": "17"},
  "tickets_failed": {"N": "2"},
  "heartbeat_at": {"N": "1748520120"},
  "heartbeat_interval_seconds": {"N": "30"},
  "ticket_filter": {"M": {
    "types": {"L": [{"S": "bug"}, {"S": "feature"}, {"S": "task"}]},
    "tags": {"L": [{"S": "backend"}, {"S": "api"}]},
    "space_ids": {"L": [{"S": "sp_main_project"}]},
    "priorities": {"L": [{"S": "critical"}, {"S": "high"}, {"S": "medium"}]}
  }},
  "concurrency": {"N": "1"},
  "active_tickets": {"L": [
    {"M": {
      "ticket_id": {"S": "tkt_abc123def456"},
      "claimed_at": {"N": "1748520060"},
      "checkpoint": {"S": "{\"step\":\"coding\",\"files_changed\":3}"}
    }}
  ]},
  "session_log_key": {"S": "agent-logs/a1b2c3d4/w_8f3a1b2c/session_2026-05-29T10-00.log"},
  "total_session_time_seconds": {"N": "54300"},
  "last_activity_at": {"N": "1748520120"},
  "created_at": {"N": "1748460000"},
  "started_at": {"N": "1748460055"}
}
```

**Ticket claim record — Active claim:**

```json
{
  "pk": {"S": "AGENT_CLAIM#tkt_abc123def456"},
  "sk": {"S": "CLAIM#w_8f3a1b2c4d5e6f7890abcdef12345678"},
  "worker_id": {"S": "w_8f3a1b2c4d5e6f7890abcdef12345678"},
  "user_id": {"S": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"},
  "claimed_at": {"N": "1748520060"},
  "status": {"S": "active"},
  "checkpoint": {"S": "{\"step\":\"coding\",\"files_changed\":3,\"last_command\":\"git add src/routes/avatar.py\"}"}
}
```

**Ticket claim record — Completed claim:**

```json
{
  "pk": {"S": "AGENT_CLAIM#tkt_xyz789ghi012"},
  "sk": {"S": "CLAIM#w_8f3a1b2c4d5e6f7890abcdef12345678"},
  "worker_id": {"S": "w_8f3a1b2c4d5e6f7890abcdef12345678"},
  "user_id": {"S": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"},
  "claimed_at": {"N": "1748510000"},
  "status": {"S": "completed"},
  "checkpoint": {"S": "{\"step\":\"done\",\"pr_url\":\"https://github.com/acme/webapp/pull/42\",\"files_changed\":7,\"tests_passed\":true}"}
}
```

**Ticket item — Extended with agent fields (eligible, unclaimed):**

```json
{
  "pk": {"S": "TICKET#tkt_newfeature001"},
  "sk": {"S": "META"},
  "ticket_id": {"S": "tkt_newfeature001"},
  "title": {"S": "Add dark mode toggle to settings page"},
  "status": {"S": "open"},
  "priority": {"S": "high"},
  "type": {"S": "feature"},
  "description": {"S": "Users should be able to toggle between light and dark mode from the settings page..."},
  "acceptance_criteria": {"S": "1. Toggle switch visible in settings\n2. Theme persists across sessions\n3. System preference respected as default"},
  "agent_eligible": {"S": "yes"},
  "agent_worker_id": {"S": ""},
  "agent_claimed_at": {"N": "0"},
  "agent_state": {"S": ""},
  "agent_checkpoint": {"S": ""}
}
```

**Ticket item — Claimed by an agent:**

```json
{
  "pk": {"S": "TICKET#tkt_abc123def456"},
  "sk": {"S": "META"},
  "ticket_id": {"S": "tkt_abc123def456"},
  "title": {"S": "Implement user avatar upload endpoint"},
  "status": {"S": "in_progress"},
  "priority": {"S": "high"},
  "type": {"S": "feature"},
  "agent_eligible": {"S": "yes"},
  "agent_worker_id": {"S": "w_8f3a1b2c4d5e6f7890abcdef12345678"},
  "agent_claimed_at": {"N": "1748520060"},
  "agent_state": {"S": "working"},
  "agent_checkpoint": {"S": "{\"step\":\"coding\",\"files_changed\":3}"}
}
```

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

## 6. API Request/Response Examples

### 6.1 Get Agent Status

```bash
curl -s http://localhost:3000/ui/agent/orchestrator/w_8f3a1b2c4d5e6f7890abcdef12345678/status \
  -H "Cookie: ui_session=ses_abc123; ui_csrf=csrf_tok_1; ui_access_token=eyJ..."
```

**Response (200 OK):**

```json
{
  "worker_id": "w_8f3a1b2c4d5e6f7890abcdef12345678",
  "agent_state": "working",
  "current_ticket_id": "tkt_abc123def456",
  "current_ticket_title": "Implement user avatar upload endpoint",
  "tickets_completed": 17,
  "tickets_failed": 2,
  "heartbeat_at": 1748520120,
  "last_activity_at": 1748520120,
  "ticket_filter": {
    "types": ["bug", "feature", "task"],
    "tags": ["backend", "api"],
    "space_ids": ["sp_main_project"],
    "priorities": ["critical", "high", "medium"]
  }
}
```

### 6.2 Start Agent Loop

```bash
curl -s -X POST http://localhost:3000/ui/agent/orchestrator/w_8f3a1b2c4d5e6f7890abcdef12345678/start \
  -H "Cookie: ui_session=ses_abc123; ui_csrf=csrf_tok_1; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_tok_1"
```

**Response (200 OK):**

```json
{
  "ok": true,
  "worker_id": "w_8f3a1b2c4d5e6f7890abcdef12345678",
  "agent_state": "idle",
  "message": "Agent loop started. Will begin picking up eligible tickets."
}
```

### 6.3 Pause Agent

```bash
curl -s -X POST http://localhost:3000/ui/agent/orchestrator/w_8f3a1b2c4d5e6f7890abcdef12345678/pause \
  -H "Cookie: ui_session=ses_abc123; ui_csrf=csrf_tok_1; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_tok_1"
```

**Response (200 OK):**

```json
{
  "ok": true,
  "worker_id": "w_8f3a1b2c4d5e6f7890abcdef12345678",
  "agent_state": "paused",
  "current_ticket_id": "tkt_abc123def456",
  "message": "Agent paused. Current ticket retained. Resume to continue."
}
```

### 6.4 Resume Agent

```bash
curl -s -X POST http://localhost:3000/ui/agent/orchestrator/w_8f3a1b2c4d5e6f7890abcdef12345678/resume \
  -H "Cookie: ui_session=ses_abc123; ui_csrf=csrf_tok_1; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_tok_1"
```

**Response (200 OK):**

```json
{
  "ok": true,
  "worker_id": "w_8f3a1b2c4d5e6f7890abcdef12345678",
  "agent_state": "idle",
  "message": "Agent resumed."
}
```

### 6.5 Release Ticket

```bash
curl -s -X POST http://localhost:3000/ui/agent/orchestrator/w_8f3a1b2c4d5e6f7890abcdef12345678/release-ticket \
  -H "Cookie: ui_session=ses_abc123; ui_csrf=csrf_tok_1; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_tok_1"
```

**Response (200 OK):**

```json
{
  "ok": true,
  "worker_id": "w_8f3a1b2c4d5e6f7890abcdef12345678",
  "released_ticket_id": "tkt_abc123def456",
  "agent_state": "idle"
}
```

### 6.6 Get Checkpoint

```bash
curl -s http://localhost:3000/ui/agent/orchestrator/w_8f3a1b2c4d5e6f7890abcdef12345678/checkpoint \
  -H "Cookie: ui_session=ses_abc123; ui_csrf=csrf_tok_1; ui_access_token=eyJ..."
```

**Response (200 OK):**

```json
{
  "ticket_id": "tkt_abc123def456",
  "checkpoint": {
    "step": "coding",
    "files_changed": 3,
    "last_command": "git add src/routes/avatar.py",
    "branch": "agent/w_8f3a1b2c/tkt_abc123def456"
  },
  "claimed_at": 1748520060
}
```

### 6.7 Manual Heartbeat

```bash
curl -s -X POST http://localhost:3000/ui/agent/orchestrator/w_8f3a1b2c4d5e6f7890abcdef12345678/heartbeat \
  -H "Cookie: ui_session=ses_abc123; ui_csrf=csrf_tok_1; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_tok_1"
```

**Response (200 OK):**

```json
{
  "ok": true,
  "heartbeat_at": 1748520300
}
```

### 6.8 Preview Eligible Tickets

```bash
curl -s http://localhost:3000/ui/agent/orchestrator/w_8f3a1b2c4d5e6f7890abcdef12345678/eligible-tickets \
  -H "Cookie: ui_session=ses_abc123; ui_csrf=csrf_tok_1; ui_access_token=eyJ..."
```

**Response (200 OK):**

```json
{
  "tickets": [
    {
      "ticket_id": "tkt_newfeature001",
      "title": "Add dark mode toggle to settings page",
      "priority": "high",
      "type": "feature",
      "tags": ["frontend", "settings"],
      "space_id": "sp_main_project",
      "created_at": 1748500000
    },
    {
      "ticket_id": "tkt_bugfix042",
      "title": "Fix null pointer in user search",
      "priority": "critical",
      "type": "bug",
      "tags": ["backend", "api"],
      "space_id": "sp_main_project",
      "created_at": 1748510000
    }
  ],
  "count": 2,
  "filter_applied": {
    "types": ["bug", "feature", "task"],
    "tags": ["backend", "api"],
    "space_ids": ["sp_main_project"],
    "priorities": ["critical", "high", "medium"]
  }
}
```

### 6.9 Update Ticket Filter

```bash
curl -s -X PUT http://localhost:3000/ui/agent/orchestrator/w_8f3a1b2c4d5e6f7890abcdef12345678/ticket-filter \
  -H "Content-Type: application/json" \
  -H "Cookie: ui_session=ses_abc123; ui_csrf=csrf_tok_1; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_tok_1" \
  -d '{
    "types": ["bug"],
    "tags": ["backend"],
    "space_ids": [],
    "priorities": ["critical", "high"]
  }'
```

**Response (200 OK):**

```json
{
  "ok": true,
  "ticket_filter": {
    "types": ["bug"],
    "tags": ["backend"],
    "space_ids": [],
    "priorities": ["critical", "high"]
  }
}
```

### 6.10 Stop Agent Loop

```bash
curl -s -X POST http://localhost:3000/ui/agent/orchestrator/w_8f3a1b2c4d5e6f7890abcdef12345678/stop \
  -H "Cookie: ui_session=ses_abc123; ui_csrf=csrf_tok_1; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_tok_1"
```

**Response (200 OK):**

```json
{
  "ok": true,
  "worker_id": "w_8f3a1b2c4d5e6f7890abcdef12345678",
  "agent_state": "idle",
  "message": "Agent loop stopped. Ticket retained if in progress."
}
```

---

## 7. Error Handling Matrix

| # | Error Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|---|---------------|-------------|------------|---------------------|----------------|
| E-1 | Worker not found | 404 | `worker_not_found` | "Worker not found." | Check worker_id |
| E-2 | Worker not in ready state | 400 | `worker_not_ready` | "Agent operations require worker in 'ready' state. Current: {state}." | Wait for provisioning or start worker first |
| E-3 | Invalid state transition | 400 | `invalid_state_transition` | "Cannot transition from {current} to {target}." | Check current state; use allowed transition |
| E-4 | State transition race condition | 409 | `state_conflict` | "Agent state changed concurrently. Refresh and try again." | Retry after refresh |
| E-5 | Ticket already claimed | 409 | `ticket_already_claimed` | "Ticket {id} is already claimed by another agent." | Agent picks next ticket automatically |
| E-6 | No eligible tickets | 200 (empty) | N/A | Response shows empty tickets list | Adjust ticket_filter; create more eligible tickets |
| E-7 | Ticket not found (during claim) | 400 | `ticket_not_found` | "Ticket {id} not found or no longer available." | Ticket may have been deleted; agent picks next |
| E-8 | No current ticket to release | 400 | `no_active_ticket` | "Worker has no active ticket to release." | No action needed |
| E-9 | Checkpoint too large | 400 | `checkpoint_too_large` | "Checkpoint data exceeds 64KB limit." | Reduce checkpoint payload |
| E-10 | Agent loop already running | 409 | `loop_already_running` | "Agent loop is already running for this worker." | Use pause/resume instead of start |
| E-11 | Agent loop not running | 400 | `loop_not_running` | "Agent loop is not running. Start it first." | Call start endpoint |
| E-12 | Session expired | 401 | `unauthorized` | "Session expired. Please log in again." | Re-login |
| E-13 | Missing CSRF token | 403 | `csrf_missing` | "CSRF token required." | Include x-csrf-token header |
| E-14 | Invalid ticket filter | 422 | `validation_error` | "Invalid ticket filter: {detail}." | Fix filter configuration |
| E-15 | Heartbeat on non-active agent | 400 | `agent_not_active` | "Cannot record heartbeat: agent is not in an active state." | Start agent loop first |
| E-16 | Ticket space access denied | 403 | `space_access_denied` | "Worker's owner does not have access to ticket space {space_id}." | Remove space from filter or join space |
| E-17 | Concurrent claim on same worker | 409 | `worker_busy` | "Worker is already processing a ticket." | Wait for current work to complete |
| E-18 | Checkpoint not found | 404 | `no_checkpoint` | "No checkpoint data found for this worker." | Worker has no in-progress ticket |

---

## 8. Observability & Monitoring

### 8.1 Metrics

| Metric Name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `agent_tickets_claimed_total` | Counter | `agent_type`, `ticket_type`, `priority` | Total tickets claimed by agents |
| `agent_tickets_completed_total` | Counter | `agent_type`, `ticket_type` | Tickets successfully completed |
| `agent_tickets_failed_total` | Counter | `agent_type`, `failure_reason` | Tickets that failed or were released |
| `agent_claim_attempts_total` | Counter | `result` (success/conflict/error) | Claim attempts including conflicts |
| `agent_ticket_duration_seconds` | Histogram | `agent_type`, `ticket_type` | Time from claim to completion |
| `agent_heartbeat_age_seconds` | Gauge | `worker_id` | Seconds since last heartbeat (per worker) |
| `agent_state_transitions_total` | Counter | `from_state`, `to_state` | State machine transition counts |
| `agent_idle_time_seconds` | Histogram | `agent_type` | Time between ticket completions |
| `agent_eligible_tickets_gauge` | Gauge | `space_id` | Number of agent-eligible tickets in queue |
| `agent_stale_heartbeat_total` | Counter | — | Workers detected as stale |

### 8.2 Log Events

| Event | Level | Fields | When |
|-------|-------|--------|------|
| `agent.loop.started` | INFO | `worker_id`, `user_id`, `poll_interval` | Agent loop begins |
| `agent.loop.stopped` | INFO | `worker_id`, `uptime_seconds` | Agent loop stops (manual or worker shutdown) |
| `agent.ticket.claimed` | INFO | `worker_id`, `ticket_id`, `title`, `priority`, `type` | Successful ticket claim |
| `agent.ticket.claim_conflict` | WARN | `worker_id`, `ticket_id` | Claim failed due to another agent |
| `agent.ticket.completed` | INFO | `worker_id`, `ticket_id`, `duration_seconds`, `pr_url` | Ticket finished |
| `agent.ticket.released` | WARN | `worker_id`, `ticket_id`, `reason` | Ticket released back to queue |
| `agent.ticket.failed` | ERROR | `worker_id`, `ticket_id`, `error`, `traceback` | Agent failed working on ticket |
| `agent.state.transition` | INFO | `worker_id`, `from`, `to` | State machine transition |
| `agent.heartbeat.stale` | WARN | `worker_id`, `age_seconds`, `threshold` | Stale heartbeat detected |
| `agent.heartbeat.recovery` | INFO | `worker_id`, `ticket_id` | Agent recovered from stale state |
| `agent.checkpoint.saved` | DEBUG | `worker_id`, `ticket_id`, `checkpoint_size_bytes` | Checkpoint saved |
| `agent.context.injected` | INFO | `worker_id`, `ticket_id`, `context_length_chars` | Ticket context sent to terminal |

### 8.3 Alert Rules

| Alert | Condition | Severity | Action |
|-------|-----------|----------|--------|
| Agent stuck working | `agent_ticket_duration_seconds{quantile="0.99"} > 3600` | P2 | Check terminal output; may need manual intervention |
| High claim conflict rate | `rate(agent_claim_attempts_total{result="conflict"}[5m]) / rate(agent_claim_attempts_total[5m]) > 0.5` | P3 | Too many agents competing for too few tickets; rebalance |
| Stale heartbeat spike | `rate(agent_stale_heartbeat_total[5m]) > 3` | P2 | Check worker infrastructure health; possible network issue |
| No completions in 1 hour | `increase(agent_tickets_completed_total[1h]) == 0 AND agent_eligible_tickets_gauge > 5` | P3 | Check agent logs; may be stuck or misconfigured |
| High failure rate | `rate(agent_tickets_failed_total[1h]) / rate(agent_tickets_claimed_total[1h]) > 0.3` | P2 | Investigate failure reasons; check ticket quality |

### 8.4 Dashboard Queries

```promql
# Tickets processed per hour by agent type
sum(rate(agent_tickets_completed_total[1h])) by (agent_type) * 3600

# Average ticket completion time
histogram_quantile(0.5, rate(agent_ticket_duration_seconds_bucket[1h]))

# Claim success rate
sum(rate(agent_claim_attempts_total{result="success"}[5m])) /
sum(rate(agent_claim_attempts_total[5m]))

# Current heartbeat freshness (should be < 60s)
agent_heartbeat_age_seconds

# Eligible ticket queue depth
agent_eligible_tickets_gauge
```

---

## 9. Rollout Plan

### 9.1 Feature Flags

| Flag | Default | Description |
|------|---------|-------------|
| `AGENT_ORCHESTRATOR_ENABLED` | `false` | Master toggle -- disables agent loop start endpoint and hides orchestration UI |
| `AGENT_AUTO_CLAIM_ENABLED` | `false` | When false, agents only show eligible tickets but require manual "Claim" click; when true, auto-claim is active |
| `AGENT_HEARTBEAT_MONITOR_ENABLED` | `true` | Enable/disable background heartbeat monitoring (disable during initial testing) |

### 9.2 Migration Steps

| Phase | Action | Duration | Rollback |
|-------|--------|----------|----------|
| 1. Schema | Add `agent_state`, `ticket_filter`, `heartbeat_at`, etc. fields to existing `agent_workers` items; add AGENT_CLAIM pattern to `tickets` table init | 1 min | Fields are optional; no migration needed for rollback |
| 2. Backend (manual mode) | Deploy `agent_orchestrator.py` service + router; `AGENT_AUTO_CLAIM_ENABLED=false` | Instant | Remove router from `main.py` |
| 3. Manual claim testing | Enable `AGENT_ORCHESTRATOR_ENABLED=true`; users manually browse eligible tickets and click "Claim" | 3 days | Flip flag off |
| 4. Auto-claim alpha | Enable `AGENT_AUTO_CLAIM_ENABLED=true` for internal accounts | 1 week | Flip auto-claim off; agents keep working manually |
| 5. Heartbeat monitoring | Enable `AGENT_HEARTBEAT_MONITOR_ENABLED=true`; tune threshold (start at 300s, lower to 120s) | 1 week | Disable monitor; manually check stale agents |
| 6. Full GA | Enable all flags for all users | Permanent | Flip master flag to disable |

### 9.3 Canary Deployment

- Deploy behind feature flag to all instances
- Enable for 5 internal users with small ticket queues (< 20 tickets)
- Monitor: claim conflict rate, completion time, heartbeat freshness, error rate
- If failure rate > 10% or stale heartbeat rate > 5%: disable auto-claim
- Ramp: internal -> 5% beta users -> 25% -> 100% over 3 weeks
- Keep heartbeat monitor threshold conservative (300s) during ramp; tighten to 120s at GA

---

## 10. Performance Considerations

### 10.1 Agent Loop Cost per Worker

| Operation | RCU/WCU | Frequency | Cost per Worker per Hour |
|-----------|---------|-----------|--------------------------|
| Get worker status (loop check) | 0.5 RCU | Every 30s (120/hr) | 60 RCU |
| Record heartbeat (UpdateItem) | 1 WCU | Every 30s (120/hr) | 120 WCU |
| Find eligible tickets (Query + Filter) | 5-20 RCU | Every 30s when idle | 600-2400 RCU |
| Claim ticket (PutItem + 2 UpdateItems) | 3 WCU | ~1-5/hr (once per ticket) | 3-15 WCU |
| Save checkpoint | 1 WCU | Every 5 min during work | 12 WCU |
| **Total per idle worker** | — | — | **~660 RCU + 132 WCU/hr** |
| **Total per busy worker** | — | — | **~60 RCU + 135 WCU/hr** |

At 100 concurrent workers (platform-wide), the eligible-ticket query dominates at ~60K-240K RCU/hr. On-demand DDB handles this; for provisioned mode, reserve 100 RCU + 50 WCU for the agent workload.

### 10.2 Eligible Ticket Query Optimization

The `find_next_ticket()` query is the most expensive operation because it must:
1. Query tickets by status (open/ready)
2. Filter by `agent_eligible = "yes"` AND `agent_worker_id = ""`
3. Apply the worker's ticket_filter (types, tags, space_ids, priorities)
4. Sort by priority

**Optimization strategy:**
- Add a GSI `ByAgentEligible` with `GSI1PK = ELIGIBLE#yes`, `GSI1SK = priority#created_at` on the tickets table
- This reduces the query from a full table scan to a targeted GSI query
- With < 1000 eligible tickets, a single query page suffices
- For > 1000 eligible tickets, add per-space GSIs: `GSI1PK = ELIGIBLE#{space_id}`

### 10.3 Claim Conflict Rate

With N agents and M eligible tickets, the probability of a claim conflict is approximately `N / M` per claim attempt. For 10 agents and 50 tickets, conflict rate is ~20% -- acceptable because the agent immediately retries.

At high contention (50 agents, 10 tickets), conflict rate approaches 100%. Mitigation:
- Randomize ticket selection order (don't always pick the highest priority)
- Add jitter to poll_interval (25-35s instead of exactly 30s)
- If conflict detected, back off exponentially: 30s -> 60s -> 120s

### 10.4 Heartbeat Monitoring Scalability

The heartbeat checker scans all active workers across all users. At scale:
- 100 workers: Single scan, < 100ms
- 1000 workers: Need per-user queries via ByStatus GSI; batch across users
- 10000 workers: Add global GSI `ByAgentState` with `GSI1PK = AGENT_STATE#working` to avoid scanning inactive workers

For the initial rollout (< 100 total workers), the current per-user scan approach is sufficient.

### 10.5 Checkpoint Storage

Checkpoints are stored as JSON strings in the DDB claim record. Size limit: 64KB (leaving 336KB of the 400KB DDB item limit for other fields). For typical checkpoints (step, files_changed, last_command), payloads are 200-500 bytes. Large checkpoints (full diff context) should be offloaded to S3 with only the S3 key stored in DDB.

### 10.6 Rate Limiting

| Endpoint | Limit | Window | Reason |
|----------|-------|--------|--------|
| POST `/{id}/start` | 5 | 1 hour | Prevent rapid loop start/stop cycling |
| POST `/{id}/pause` | 10 | 1 minute | Allow frequent pause/resume during debugging |
| POST `/{id}/resume` | 10 | 1 minute | Same as pause |
| POST `/{id}/stop` | 5 | 1 hour | Prevent rapid cycling |
| POST `/{id}/release-ticket` | 10 | 1 minute | Prevent ticket thrashing |
| POST `/{id}/heartbeat` | 120 | 1 minute | Aligned with 30s heartbeat interval |
| GET `/{id}/status` | 120 | 1 minute | Frontend polling |
| GET `/{id}/eligible-tickets` | 30 | 1 minute | Preview query is expensive |
| PUT `/{id}/ticket-filter` | 10 | 1 minute | Configuration changes |

---

## 11. Frontend Component Tree

```
AgentOrchestratorPage (or embedded in WorkerDetailPanel)
├── AgentControlBar
│   ├── Button "Start Agent" (if loop not running, agent_state == idle)
│   ├── Button "Pause Agent" (if agent_state in working/idle/claiming)
│   ├── Button "Resume Agent" (if agent_state == paused)
│   ├── Button "Stop Agent" (if loop running)
│   └── Button "Release Ticket" (if current_ticket_id is non-empty)
├── AgentStateCard
│   ├── StateMachineVisualizer
│   │   └── SVG diagram showing states as circles, current state highlighted
│   │       ├── Circle "idle" (green when active)
│   │       ├── Circle "claiming" (yellow flash)
│   │       ├── Circle "working" (blue pulse animation)
│   │       ├── Circle "awaiting_feedback" (orange)
│   │       ├── Circle "completing" (green flash)
│   │       ├── Circle "paused" (gray)
│   │       └── Circle "error" (red)
│   ├── HeartbeatIndicator
│   │   ├── LED (green: < 30s ago, yellow: 30-90s, red: > 90s)
│   │   └── Text "Last heartbeat: {seconds}s ago"
│   └── CurrentTicketCard (if current_ticket_id)
│       ├── Badge (priority: critical=red, high=orange, medium=yellow)
│       ├── Text (ticket title, linked to /tickets/{id})
│       ├── Text (ticket type + tags)
│       └── Text "Claimed {duration} ago"
├── AgentStatsRow
│   ├── StatCard "Tickets Completed" → tickets_completed
│   ├── StatCard "Tickets Failed" → tickets_failed
│   ├── StatCard "Session Time" → total_session_time_seconds formatted
│   └── StatCard "Avg Time per Ticket" → computed
├── TicketFilterEditor
│   ├── MultiSelect "Types" (bug, feature, task, etc.)
│   ├── MultiSelect "Tags" (backend, frontend, api, etc.)
│   ├── MultiSelect "Spaces" (loaded from ticket spaces API)
│   ├── MultiSelect "Priorities" (critical, high, medium, low)
│   └── Button "Save Filter" → PUT /ticket-filter
├── EligibleTicketsPreview
│   ├── Button "Refresh Preview" → GET /eligible-tickets
│   └── DataTable
│       └── TicketRow (for each eligible ticket)
│           ├── Badge (priority)
│           ├── Text (title)
│           ├── Text (type)
│           ├── Text (tags)
│           └── Text (created_at formatted)
└── CheckpointViewer (collapsible)
    ├── h3 "Checkpoint Data"
    ├── JSONViewer (formatted checkpoint JSON)
    └── Text "Last saved: {timestamp}"
```

### 11.1 TypeScript Interfaces

```typescript
// frontend/src/api/types.ts

export interface TicketFilterConfig {
  types: string[];
  tags: string[];
  space_ids: string[];
  priorities: string[];
}

export interface AgentStatus {
  worker_id: string;
  agent_state: "idle" | "claiming" | "working" | "awaiting_feedback" | "completing" | "paused" | "error";
  current_ticket_id: string;
  current_ticket_title: string;
  tickets_completed: number;
  tickets_failed: number;
  heartbeat_at: number;
  last_activity_at: number;
  ticket_filter: TicketFilterConfig | null;
}

export interface AgentClaim {
  ticket_id: string;
  worker_id: string;
  claimed_at: number;
  status: "active" | "released" | "completed" | "failed";
  checkpoint: string;
}

export interface EligibleTicket {
  ticket_id: string;
  title: string;
  priority: string;
  type: string;
  tags: string[];
  space_id: string;
  created_at: number;
}

export interface EligibleTicketsResponse {
  tickets: EligibleTicket[];
  count: number;
  filter_applied: TicketFilterConfig;
}

export interface CheckpointData {
  ticket_id: string;
  checkpoint: Record<string, unknown>;
  claimed_at: number;
}
```

### 11.2 State Management

```typescript
// React Query keys and hooks

const orchestratorKeys = {
  status: (workerId: string) => ["agent-orchestrator", "status", workerId] as const,
  checkpoint: (workerId: string) => ["agent-orchestrator", "checkpoint", workerId] as const,
  eligibleTickets: (workerId: string) => ["agent-orchestrator", "eligible", workerId] as const,
};

// useAgentStatus(workerId) — refetchInterval=5s for live state updates
// useStartAgent() — mutation, invalidates status
// usePauseAgent() — mutation, invalidates status
// useResumeAgent() — mutation, invalidates status
// useStopAgent() — mutation, invalidates status
// useReleaseTicket() — mutation, invalidates status
// useUpdateTicketFilter() — mutation, invalidates status + eligible tickets
// useEligibleTickets(workerId) — manual refetch, staleTime=30s
// useCheckpoint(workerId) — enabled only when current_ticket_id is non-empty
```

---

## 12. Expanded E2E Test Details

Expanding the original 4 sections (16 tests) to 7 sections (28 tests).

**Section 631: Agent State Machine API (5 tests)**

1. `Agent starts in idle state` -- GET `/ui/agent/orchestrator/{worker_id}/status`. Verify `agent_state: "idle"`, `current_ticket_id: ""`, `tickets_completed: 0`.
2. `Start agent loop transitions to idle/claiming` -- POST `/ui/agent/orchestrator/{worker_id}/start`. Verify 200. GET status, verify `agent_state` is `"idle"` or `"claiming"`.
3. `Pause agent sets state to paused` -- POST `/ui/agent/orchestrator/{worker_id}/pause`. Verify 200. GET status, verify `agent_state: "paused"`.
4. `Resume agent returns to idle` -- POST `/ui/agent/orchestrator/{worker_id}/resume`. Verify 200. GET status, verify `agent_state: "idle"`.
5. `Invalid state transition returns 400` -- With agent in "idle" state, POST a direct transition to "completing" (via internal test helper or direct DDB manipulation check). Verify 400 with error about invalid transition.

**Section 632: Ticket Claiming API (5 tests)**

6. `Create agent-eligible ticket` -- Create a ticket via ticket API with `agent_eligible: "yes"`. Verify ticket has `agent_eligible: "yes"`, `agent_worker_id: ""`.
7. `Agent claims eligible ticket` -- Start agent loop. Poll status until `agent_state: "working"` (max 15s). Verify `current_ticket_id` matches the created ticket.
8. `Claimed ticket shows agent_worker_id` -- GET the ticket. Verify `agent_worker_id` matches `worker_id`, `agent_claimed_at > 0`.
9. `Double-claim is prevented` -- Create a second worker. Attempt to manually claim the same ticket. Verify 409 or error about ticket already claimed.
10. `Non-eligible ticket is skipped` -- Create a ticket with `agent_eligible: "no"`. Verify it does not appear in `/eligible-tickets` response.

**Section 633: Ticket Lifecycle API (5 tests)**

11. `Release ticket returns it to queue` -- POST `/ui/agent/orchestrator/{worker_id}/release-ticket`. Verify agent state returns to `idle`, `current_ticket_id: ""`. GET ticket: `agent_worker_id: ""`.
12. `Eligible tickets preview respects filter` -- PUT `/ui/agent/orchestrator/{worker_id}/ticket-filter` with `types: ["bug"]`. Create a "feature" ticket and a "bug" ticket. GET `/eligible-tickets`. Verify only the "bug" ticket is returned.
13. `Heartbeat updates timestamp` -- POST `/ui/agent/orchestrator/{worker_id}/heartbeat`. Verify 200. GET status, verify `heartbeat_at` is recent (within 5 seconds).
14. `Save and retrieve checkpoint` -- Claim a ticket. Save checkpoint data `{step: "coding", files_changed: 3}` via API or internal helper. GET `/checkpoint`. Verify checkpoint matches.
15. `Complete ticket increments counter` -- Simulate ticket completion via API. Verify `tickets_completed` incremented, `agent_state: "idle"`, `current_ticket_id: ""`.

**Section 634: Agent Error Recovery API (4 tests)**

16. `Stop agent loop gracefully` -- POST `/ui/agent/orchestrator/{worker_id}/stop`. Verify 200. GET status, verify agent loop has stopped.
17. `Resume from checkpoint after restart` -- Claim a ticket, save checkpoint, stop agent. Start agent again. GET status, verify `current_ticket_id` matches the previously claimed ticket.
18. `Release ticket clears agent fields on ticket` -- Claim ticket, then release. GET the ticket directly. Verify `agent_worker_id` is empty, `agent_state` is empty.
19. `Starting already-running loop returns 409` -- Start agent loop. POST start again. Verify 409 with "loop already running" error.

**Section 635: Ticket Filter Configuration (3 tests)**

20. `Empty filter matches all tickets` -- PUT filter with all empty arrays. Create tickets of various types. GET eligible-tickets. Verify all agent-eligible tickets appear.
21. `Priority filter narrows results` -- PUT filter with `priorities: ["critical"]`. Create tickets with "critical", "high", "low" priorities. GET eligible-tickets. Verify only "critical" ticket appears.
22. `Space filter restricts to specific spaces` -- PUT filter with `space_ids: ["sp_test_space"]`. Create tickets in two different spaces. GET eligible-tickets. Verify only the ticket in "sp_test_space" appears.

**Section 636: Input Validation & Edge Cases (3 tests)**

23. `Heartbeat on non-existent worker returns 404` -- POST heartbeat with fake worker_id. Verify 404.
24. `Release ticket with no active ticket returns 400` -- Ensure worker has no active ticket. POST release-ticket. Verify 400 with "no active ticket" error.
25. `Checkpoint on idle agent returns 404` -- GET checkpoint when worker has no current ticket. Verify 404 or empty checkpoint.

**Section 637: Concurrent Access & Stress (3 tests)**

26. `Two agents competing for same ticket` -- Create two workers with overlapping filters. Create one eligible ticket. Start both agent loops simultaneously. Wait until one claims. Verify exactly one worker has `current_ticket_id` set, the other remains idle. The claimed ticket has exactly one `agent_worker_id`.
27. `Rapid pause-resume cycle` -- Start agent, pause, resume, pause, resume 5 times in rapid succession. Verify final state is consistent (no error state).
28. `Multiple tickets processed sequentially` -- Create 3 eligible tickets. Start agent loop. Poll until `tickets_completed >= 3` (max 60s). Verify all 3 tickets were claimed and completed. Agent returns to idle after the last ticket.

---

## 13. Security Considerations

### 13.1 Optimistic Locking

Ticket claims use DynamoDB conditional writes (`ConditionExpression`) to prevent race conditions. If two agents try to claim the same ticket simultaneously, only one succeeds; the other receives an error and retries with a different ticket.

### 13.2 User Isolation

All agent operations use `user_id` from the session. Workers can only claim tickets in spaces the user owns or has access to. Cross-user ticket access is impossible.

### 13.3 Heartbeat Monitoring

Workers that miss heartbeats for > 120 seconds are transitioned to `error` state and their tickets are released. This prevents tickets from being permanently locked by dead agents.

### 13.4 State Transition Validation

The `VALID_TRANSITIONS` map enforces which state transitions are allowed. Invalid transitions are rejected with 400 errors. This prevents agents from skipping states (e.g., jumping from `idle` to `completing`).

### 13.5 Checkpoint Data Validation

Checkpoint data is JSON-serialized and size-limited (max 64KB) to prevent DDB item size issues. No executable code is stored in checkpoints.

---

## 14. Dependencies

| Dependency | Type | Description |
|------------|------|-------------|
| AGENT-002 | Upstream | Worker records in `agent_workers` table |
| `app/services/tickets.py` | Upstream | Ticket queries, status updates, space membership |
| AGENT-005 | Downstream | Context injection uses memory templates |
| AGENT-006 | Downstream | Terminal monitoring detects completion/feedback signals |
| AGENT-007 | Downstream | PR creation calls `complete_ticket` |

---

## 15. Acceptance Criteria

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
