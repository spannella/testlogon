# AGENT-003: Worker Agent Framework & Lifecycle — Investigation & Implementation Write-up

> ~5 pages. Read the real code before writing; cite `file:line`. Be concrete, not generic.

## 1. Summary & Classification

AGENT-003 implements the autonomous "brain" of the agent platform: a state machine and claim system that queries the ticket backlog, acquires exclusive ownership of a ticket using DynamoDB conditional writes, injects formatted context into the worker's terminal, monitors for completion/feedback signals, and transitions the ticket through its lifecycle. It also runs a heartbeat-monitoring background task that detects stale workers and releases their claimed tickets. This is the service that converts a provisioned worker (AGENT-002) into an autonomous coding agent.

- **Type**: Feature (core orchestration service)
- **Priority**: High — unblocks AGENT-004, AGENT-005, AGENT-006
- **Status**: Implemented
- **Owning area**: AI Agents / Orchestration
- **User persona**: Developer who starts an agent loop and expects tickets to be processed autonomously
- **Cross-references**: [[AGENT-002]] (worker provisioner), [[AGENT-005]] (memory/context injection), [[AGENT-006]] (terminal monitoring), [[SEC-021]] (ticket context injection safety), [[SECOPS-007]] (dev parity — no real LLM call in dev mode)

---

## 2. Current-State Investigation (what exists today)

### 2.1 Service file

`app/services/agent_orchestrator.py` (803 lines) is fully present.

**State machine:** `VALID_TRANSITIONS` dict (line 26) maps each state to its allowed target states:
```
idle → {claiming, paused}
claiming → {working, idle, error}
working → {awaiting_feedback, completing, paused, error, idle}
awaiting_feedback → {working, paused, error, idle}
completing → {idle, error}
paused → {idle, working}
error → {idle}
```

**`transition_agent_state`** (line 83): gets the current state from DDB, validates the transition, then issues an `UpdateItem` with `ConditionExpression: Attr("agent_state").eq(current)` to prevent race conditions. Returns the updated worker dict. This is the atomic gate for all state changes.

**`find_next_ticket`** (line 238): queries the tickets table for `agent_eligible="yes"`, `status IN (open, ready)`, no existing `agent_worker_id`, filtered against the worker's `ticket_filter` (types, tags, space_ids, priorities). Returns the highest-priority match. In practice it uses a GSI query plus Python-side filtering since DDB does not support multi-value `IN` conditions natively.

**`claim_ticket`** (line 255): two-phase claim:
1. `PutItem` on `AGENT_CLAIM#{ticket_id}` SK `CLAIM#{worker_id}` with `attribute_not_exists(pk)` condition — raises `ConditionalCheckFailedException` if another agent already holds the claim.
2. `UpdateItem` on the ticket item itself setting `agent_worker_id`, `agent_claimed_at`, `agent_state="claimed"` with condition `agent_worker_id = "" OR attribute_not_exists(agent_worker_id)`.
3. Updates the worker item with `current_ticket_id` and `agent_state="working"`.

This double-write approach means there is a brief inconsistency window if step 2 or 3 fails after step 1 succeeds. Mitigation: a `release_ticket` operation (line 343) clears both records, and the heartbeat checker calls it for stale workers.

**`complete_ticket`** (line 403): marks claim as `"completed"`, updates ticket status, increments `tickets_completed`, clears `current_ticket_id`, transitions agent to `"idle"`.

**`inject_ticket_context`** (line 598): builds the text prompt injected into the terminal — includes ticket title, ID, priority, description, acceptance criteria, and step-by-step agent instructions ending with `[AGENT_COMPLETE]` and `[AGENT_FEEDBACK_NEEDED]` signal tokens.

**`record_heartbeat`** (line 556): simple `UpdateItem` setting `heartbeat_at = now_ts()`.

**`check_stale_heartbeats`** (line 567): queries `ByStatus` GSI for `worker_status="ready"`, Python-filters for `heartbeat_at < now - threshold`, and for each stale worker transitions to `"error"` and calls `release_ticket`. Returns count of workers affected.

**`start_agent_loop`** / `stop_agent_loop`** (lines 705, 739): these set `agent_state` in DDB but do not actually launch an async background loop task per-worker. The comment at line 708 acknowledges this: "The actual background task loop (run_agent_loop) is managed by the router's startup/shutdown handlers." In practice, the dev mode loop is not a running coroutine — the agent is driven by explicit API calls and polling, not a persistent background task. This is a significant gap for autonomous operation (see §3.3).

**`get_eligible_tickets`** (line 135): used by the "preview" endpoint to show the user which tickets a worker would pick up given its current filter.

### 2.2 Router

`app/routers/agent_orchestrator.py` (357 lines) provides 10 endpoints under `/ui/agent/orchestrator/{worker_id}` — status, start, pause, resume, stop, release-ticket, checkpoint, heartbeat, eligible-tickets, ticket-filter. Registered at `app/main.py:737`. All use `require_ui_session`.

### 2.3 Data model

`app/models.py:5989` — `AgentStatusOut`, `TicketFilterConfig`, `AgentClaimOut`, `EligibleTicketsOut`. The `TicketFilterConfig` model at line 6174+ (also used in AGENT-004 fleet templates) carries `types`, `tags`, `space_ids`, `priorities` as free-form string lists — no enum validation, which means a malformed filter silently matches nothing rather than erroring.

### 2.4 DynamoDB access patterns

The orchestrator extends the existing `tickets` table with new item patterns:
- `TICKET#{ticket_id}` SK `META` gets new fields: `agent_eligible`, `agent_worker_id`, `agent_claimed_at`, `agent_state`, `agent_checkpoint`
- `AGENT_CLAIM#{ticket_id}` SK `CLAIM#{worker_id}` — claim lock records, written only at claim time

The `agent_workers` table gets new fields: `agent_state`, `current_ticket_id`, `tickets_completed`, `tickets_failed`, `heartbeat_at`, `ticket_filter`, `concurrency`, `active_tickets`, `session_log_key`, `total_session_time_seconds`.

### 2.5 Dev vs prod parity (SECOPS-007)

The orchestrator service is entirely AWS-agnostic in its business logic — it reads/writes DDB, constructs text strings, and calls the `TicketStore`. There is no LLM call in this layer. The `inject_ticket_context` function builds a static text prompt; it does not call any external API. Dev parity is therefore automatic. The only external interaction is DynamoDB, which is DDB Local in dev. The background loop timing is not implemented (see §3.3), but that affects functionality, not dev/prod parity.

### 2.6 E2E tests

`frontend/e2e/agent-orchestrator.spec.ts` covers sections 631-634 (16 tests): state machine API, ticket claiming, lifecycle, error recovery.

---

## 3. Gap / Threat Analysis

### 3.1 Double-write claim race

`claim_ticket` writes to `AGENT_CLAIM#` and then to `TICKET#META` in sequence. If the second write fails (network partition, DDB throttle), the claim lock exists but the ticket's `agent_worker_id` is still empty. The next loop iteration of the same or another worker would find the ticket eligible but fail the claim PutItem (claim record already exists). The ticket is permanently blocked until an operator deletes the orphaned claim record. Fix: wrap both writes in a DDB transaction (`TransactWriteItems`).

### 3.2 Ticket filter validation gap

`TicketFilterConfig.types` is `List[str]` with no validation of allowed values. A filter `{"types": ["$exists_all"]}` silently returns zero tickets. While this is not a security risk, it is a UX footgun. Add a validator checking against the ticket type enum (`bug`, `feature`, `task`, `chore`).

### 3.3 Agent loop not running as a background task

`start_agent_loop` (line 705) sets `agent_state="idle"` in DDB but does not spawn an `asyncio` coroutine. The autonomous loop described in the ticket design (`run_agent_loop` polling every 30 seconds) does not exist in the current implementation. The agent can only pick up tickets when:
1. A user calls the start endpoint, AND
2. The orchestrator has a mechanism to actually execute the loop.

In prod this is a critical gap: the agent appears to start but never does anything autonomously. The implementation needs either a per-worker `asyncio.create_task(run_agent_loop(...))` stored in a registry, or a persistent background process (Celery, background threads) that polls DDB for workers with `agent_state="idle"` and drives the loop.

### 3.4 inject_ticket_context: prompt injection risk

`inject_ticket_context` (line 598) interpolates ticket fields directly into the context string:
```python
context = f"""
--- TICKET: {ticket.get('title', 'Untitled')} ---
...
DESCRIPTION:
{ticket.get('description', '')}
```
If a ticket title or description contains `[AGENT_COMPLETE]` or `[AGENT_FEEDBACK_NEEDED]`, the terminal monitor will detect a false signal. A user who can create tickets with adversarial content could trigger a fake completion event. Mitigation: escape or strip the signal tokens from ticket fields before injection, or use a sentinel that cannot be reproduced in normal text (e.g., a UUID-based signal appended by the agent itself after verification).

### 3.5 Stale heartbeat scan covers all users

`check_stale_heartbeats` scans ALL users' workers (it queries the GSI without a per-user partition filter). In a multi-tenant prod environment with many workers, this is a full-table scan every 60 seconds. Fix: partition the background task to process one user at a time, or add a `ByHeartbeat` GSI sorted by `heartbeat_at` for efficient range queries.

### 3.6 Checkpoint JSON size limit

`save_checkpoint` (line 469) stores `json.dumps(checkpoint_data)` as a DDB string attribute. DDB item size limit is 400KB; if the checkpoint data includes large diffs or file listings, the update will silently fail or throw `ValidationException`. Add a max-size check before the write.

---

## 4. Proposed Design / Fix

### 4.1 Atomic claim with DDB transactions

Replace the two-step `claim_ticket` with a single `TransactWriteItems`:
```python
client.transact_write_items(TransactItems=[
    {"Put": {
        "TableName": T.tickets.name,
        "Item": claim_item,
        "ConditionExpression": "attribute_not_exists(pk)",
    }},
    {"Update": {
        "TableName": T.tickets.name,
        "Key": {"pk": f"TICKET#{ticket_id}", "sk": "META"},
        "UpdateExpression": "SET agent_worker_id = :wid, agent_claimed_at = :ts, agent_state = :as",
        "ConditionExpression": "agent_worker_id = :empty OR attribute_not_exists(agent_worker_id)",
        "ExpressionAttributeValues": {":wid": worker_id, ":ts": ts, ":as": "claimed", ":empty": ""},
    }},
])
```

### 4.2 Background loop implementation

Add a `_running_loops: Dict[str, asyncio.Task]` registry in the orchestrator module. `start_agent_loop` creates and stores a task; `stop_agent_loop` cancels and removes it. The loop body polls DDB every 30 seconds, calls `find_next_ticket`, `claim_ticket`, notifies AGENT-006 to monitor the terminal, and handles `[AGENT_COMPLETE]` signals.

In dev mode: the loop runs the same code but uses the mock DDB, completing instantly (since dev tickets are synthetic).

### 4.3 Signal token sanitization

```python
AGENT_SIGNALS = {"[AGENT_COMPLETE]", "[AGENT_FEEDBACK_NEEDED]", "[AGENT_ERROR]"}

def _sanitize_ticket_field(text: str) -> str:
    for sig in AGENT_SIGNALS:
        text = text.replace(sig, sig.replace("[", "﹝").replace("]", "﹞"))
    return text
```

Apply `_sanitize_ticket_field` to `title`, `description`, `acceptance_criteria` before interpolating into the context payload.

### 4.4 Heartbeat scan efficiency

Add `ByHeartbeat` GSI to `agent_workers` table: PK=`STATUS#{worker_status}`, SK=`heartbeat_at` (N). `check_stale_heartbeats` then queries `GSI PK="STATUS#ready"` with `SK < threshold` — O(stale workers) instead of O(all workers).

### 4.5 Dev/Prod parity (SECOPS-007)

No changes needed for parity. The orchestrator contains zero AWS-specific calls. DDB Local in dev behaves identically for all access patterns used (PutItem with condition, UpdateItem with condition, Query with GSI). The background loop timing is environment-agnostic once implemented.

---

## 5. Testing, Verification & Rollout

### 5.1 pytest unit tests (`tests/test_agent_orchestrator.py`)

| Test | What it pins |
|---|---|
| `test_valid_state_transitions` | Each valid transition in `VALID_TRANSITIONS` succeeds; invalid ones raise `ValueError` |
| `test_claim_ticket_prevents_double_claim` | Two concurrent `claim_ticket` calls → second raises `ConditionalCheckFailedException` |
| `test_release_ticket_clears_both_records` | Post-release: claim record status="released", ticket `agent_worker_id=""` |
| `test_inject_context_escapes_signal_tokens` | Ticket with `[AGENT_COMPLETE]` in title → context does not contain raw signal |
| `test_heartbeat_stale_detection` | Worker with `heartbeat_at = now - 300` → `check_stale_heartbeats` returns it |
| `test_find_next_ticket_respects_filter` | Filter `types=["bug"]` → `find_next_ticket` does not return a "feature" ticket |
| `test_complete_ticket_increments_counter` | `tickets_completed` increments from 0 to 1 after `complete_ticket` |
| `test_checkpoint_roundtrip` | `save_checkpoint({...})` → `get_checkpoint()` returns same data |

All tests use `@mock_dynamodb` (moto), DDB Local table created in-memory, no AWS credentials needed.

### 5.2 E2E tests (Playwright)

`frontend/e2e/agent-orchestrator.spec.ts` sections 631-634:
- Section 632.7: GET ticket after agent claims it → `agent_worker_id` matches `worker_id`
- Section 632.8: double-claim prevention → 409 or error on second claim attempt
- Section 633.9: release ticket → `agent_worker_id=""`, agent state = `"idle"`
- Section 634.15: resume from checkpoint after restart — requires `save_checkpoint` + `stop` + `start` sequence

### 5.3 Manual QA

```bash
# Start agent loop
curl -X POST http://localhost:8000/ui/agent/orchestrator/$WORKER_ID/start \
  -H "x-csrf-token: $CSRF" -b "$COOKIES"

# Check state
curl http://localhost:8000/ui/agent/orchestrator/$WORKER_ID/status -b "$COOKIES"

# Create an eligible ticket (needs agent_eligible=yes)
curl -X POST http://localhost:8000/ui/ticket-spaces/$SPACE_ID/tickets \
  -d '{"title":"Test","agent_eligible":true,...}' ...

# Trigger one manual loop iteration (via heartbeat endpoint as a proxy)
curl -X POST http://localhost:8000/ui/agent/orchestrator/$WORKER_ID/heartbeat ...
```

### 5.4 Observability

Add structured log events: `agent.claim.success`, `agent.claim.failed` (with worker_id, ticket_id), `agent.complete` (ticket_id, tickets_completed), `agent.heartbeat.stale` (worker_id, seconds_since_heartbeat). These feed into SECOPS-001 security telemetry and allow alerting on agents that are stuck.

### 5.5 Rollout

1. Deploy with `start_agent_loop` as a no-op (current state) — UI works, manual ticket claiming via API works.
2. Implement background loop (§4.2) in a follow-on PR; gate with `AGENT_LOOP_ENABLED` flag.
3. Enable for one test user in staging; verify heartbeat and claim-release cycle.
4. Enable globally after 2-week burn-in.

### 5.6 Rollback

Set `AGENT_LOOP_ENABLED=false`. Running agents complete their current ticket (or timeout via heartbeat); new tickets are not picked up. State in DDB is preserved — workers resume when the flag is re-enabled.

### 5.7 Effort estimate: **M** (5-7 days) — background loop implementation + DDB transaction + signal sanitization. State machine and claim system are already implemented.
