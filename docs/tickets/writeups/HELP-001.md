# HELP-001: Helpdesk No-Agent-Available Improvements — Investigation & Implementation Write-up

## 1. Summary & Classification

HELP-001 proposes four bounded-wait improvements to the existing helpdesk "no agents available" path: (1) an SLA timeout that escalates unclaimed conversations after a configurable period by auto-creating a support ticket and notifying the customer, (2) business-hours / out-of-hours awareness so conversations arriving outside operating hours route to a fallback (auto-ticket or email capture) instead of an indefinite pause, (3) real-time queue-position feedback ("You're #3 in line") shown in the customer's ConversationView banner, and (4) optional CSAT on close.

**Type**: feature | **Priority**: Medium | **Status**: UNBUILT | **Area**: helpdesk/messaging  
**Persona**: customers waiting in the helpdesk queue; support admins who need SLA guarantees  
**Cross-refs**: tickets system (tickets router/service), `SECOPS-007` (dev/prod parity for the background SLA sweep), `SEC-010` (realtime stream IDOR — queue position must not leak other customers' conversation IDs)

---

## 2. Current-State Investigation (what exists today)

### 2.1 The existing no-agent path

When a customer creates a helpdesk conversation (`POST /messaging/conversations` with `routing_mode="helpdesk_bridge"`), the router at `app/routers/messaging.py:5877` sets `routing_state="awaiting_agent"` and writes `routing_state_group_pk=f"awaiting_agent#{group_id}"` to the conversation record.

`fanout_helpdesk_alert()` at `app/routers/messaging.py:5354` scans online agents for the group. If none are online, `app/services/messaging_routing.py:168` transitions the conversation to `routing_state="paused_no_agents_online"` and calls `_emit_no_agents_online_notice()` at `app/routers/messaging.py:5401`. This notice is throttled by `NO_AGENTS_NOTICE_THROTTLE_SEC = 600` (`line:1266`) — a system message is posted at most once per 10 minutes per conversation.

When an agent comes online, `_handle_helpdesk_presence_event()` at `app/routers/messaging.py:5264` scans `paused_no_agents_online#<group_id>` conversations via `tbl_convos.scan(FilterExpression=..., Limit=200)` at `line:5246`, transitions each back to `awaiting_agent`, and fans out alerts.

State machine lives in `app/services/messaging_routing.py:77-246`. The `RoutingState` type is `Literal["none","awaiting_agent","assigned","paused_no_agents_online","closed"]` (`line:7`).

Frontend banner in `frontend/src/pages/messages/ConversationView.tsx:1484-1502` renders:
- `awaiting_agent` → amber "Waiting for agent" + Claim button (agents)
- `paused_no_agents_online` → red "No agents online — will resume when an agent comes online"

**No SLA timer, no queue position, no business-hours check, no auto-ticket, no CSAT.** None of the four proposed improvements have been implemented.

### 2.2 Queue-age data available today

Each conversation has `created_at` (Unix seconds, set at `messaging.py:5921` no, that is `no_agents_notice_sent_at:0` — `created_at` is at `line:5916` via the common conversation creation path). The state-transition timestamp is implicitly `no_agents_notice_sent_at` (updated whenever the notice is sent). There is no dedicated `last_state_change_at` or `entered_queue_at` field. The conversation `created_at` is the best proxy for queue age.

### 2.3 Tickets system

Support tickets exist (`app/routers/tickets.py`, `app/services/tickets.py`, `T.tickets` table). `create_ticket` accepts `subject`, `body`, `user_sub`, `space_id` (optional). Auto-ticket creation from a conversation is a new linkage, not yet present.

---

## 3. Gap / Threat Analysis

### 3.1 Unbounded wait (SLA gap)
A customer can wait indefinitely. The current code has no timer. If all agents go home for the day and no one comes back online, the conversation stays in `paused_no_agents_online` forever. This violates standard support SLA contracts.

### 3.2 No business-hours signal
There is no concept of "support is closed". The system cannot distinguish "all agents are on calls" from "it is 3am Sunday and support opens Monday". Both result in the same passive pause with the same notice text.

### 3.3 Queue position not computable at runtime
Queue position requires counting `awaiting_agent` conversations for the group ordered by `created_at`. The `routing_state_group_pk` index (`app/services/messaging_routing.py:128`) exists but there is no sort key on `created_at` — `routing_state_group_sk` is just `conversation_id`. Accurate queue position requires a scan + sort of all `awaiting_agent#<group_id>` items.

### 3.4 Auto-ticket linkage missing
The ticket service at `app/services/tickets.py` does not accept a `source_conversation_id` field. No link between a helpdesk conversation and its escalated ticket is tracked.

### 3.5 Abuse potential
Queue position must only be shown to the customer whose conversation it is — do not reveal other customers' queue positions or conversation IDs (cross-ref **SEC-010**). The SLA sweep must be a server-side background task, not triggerable by the customer.

---

## 4. Proposed Design / Fix

### 4.1 Settings additions (`app/core/settings.py`)

```python
helpdesk_unclaimed_timeout_minutes: int = int(os.environ.get("HELPDESK_UNCLAIMED_TIMEOUT_MINUTES", "30"))
# 0 = disabled
helpdesk_auto_ticket_on_timeout: bool = os.environ.get("HELPDESK_AUTO_TICKET_ON_TIMEOUT", "1") not in ("0","false","False")
helpdesk_business_hours_json: str = os.environ.get("HELPDESK_BUSINESS_HOURS_JSON", "")
# JSON: {"tz": "UTC", "hours": {"mon": [9,17], "tue": [9,17], ..., "sat": null, "sun": null}}
helpdesk_out_of_hours_fallback: str = os.environ.get("HELPDESK_OUT_OF_HOURS_FALLBACK", "notice")
# "none" | "notice" | "auto_ticket"
helpdesk_queue_position_enabled: bool = os.environ.get("HELPDESK_QUEUE_POSITION_ENABLED", "1") not in ("0","false","False")
```

### 4.2 SLA background sweep

Add a new periodic task alongside the existing scheduled-message promotion loop (`app/routers/messaging.py` background tasks). The sweep:

1. Queries `awaiting_agent#<group_id>` and `paused_no_agents_online#<group_id>` routing-state indexes for all helpdesk groups.
2. For each conversation where `now_ts() - created_at > helpdesk_unclaimed_timeout_minutes * 60`:
   a. If `helpdesk_auto_ticket_on_timeout=True`: call `create_ticket(subject=f"Helpdesk escalation: {first_message[:80]}", body=transcript_link, user_sub=customer_id, source_conversation_id=conversation_id)` in `app/services/tickets.py`. Post a system message: "Your request has been escalated to ticket #{ticket_id}. We'll follow up by email."
   b. Transition routing_state to `"closed"` (or new state `"escalated"`) via `messaging_routing.py`.
   c. Notify any configured escalation group/admin.
3. Run every 60 seconds. In dev mode (`S.dev_mode=True`) use a shorter sweep interval (5s) for testability — **SECOPS-007** parity: same code path, dev just has shorter timeout and mock email.

**New function**: `_run_helpdesk_sla_sweep()` in `app/routers/messaging.py` (alongside `_run_scheduled_message_promotion_loop`).

### 4.3 Business-hours check

In `app/routers/messaging.py` at the conversation-creation path (~`line:5946`), before calling `fanout_helpdesk_alert`, add:

```python
if not _is_helpdesk_open(group_id=group_id, now=created_at):
    fallback = S.helpdesk_out_of_hours_fallback
    if fallback == "auto_ticket":
        # immediately create ticket, skip queue entirely
        ...
    elif fallback == "notice":
        # post out-of-hours notice, route to paused_no_agents_online
        ...
    # else "none": fall through to existing behavior
```

`_is_helpdesk_open()` parses `S.helpdesk_business_hours_json`, converts `now` to the configured timezone, and returns bool. Empty config = always open (preserves existing behavior).

### 4.4 Queue position

Add `GET /ui/helpdesk/conversations/{id}/queue-position` endpoint:

```python
@router.get("/helpdesk/conversations/{conversation_id}/queue-position")
def get_queue_position(conversation_id: str, session=Depends(require_ui_session)):
    convo = get_conversation_or_404(conversation_id)
    if convo["created_by"] != session["user_sub"]:
        raise HTTPException(403, "Access denied")  # SEC-010: no cross-customer leak
    if convo.get("routing_state") not in ("awaiting_agent",):
        return {"position": None, "state": convo["routing_state"]}
    # Count convos queued before this one (same group, same state, created_at < this one's)
    group_id = convo["routing_mode_group_id"]
    position = _count_queued_before(group_id=group_id, before_ts=convo["created_at"])
    return {"position": position + 1, "estimated_wait_minutes": position * 5}
```

`_count_queued_before` scans `awaiting_agent#<group_id>` index and counts items with `created_at < this_convo_created_at`. This is eventually consistent but acceptable for a UX hint.

### 4.5 Tickets linkage

Add `source_conversation_id: Optional[str]` to `CreateTicketIn` in `app/models.py` and to the `tickets` table. `create_ticket` in `app/services/tickets.py` stores it. The SLA sweep passes this when auto-creating.

### 4.6 Frontend changes

`frontend/src/pages/messages/ConversationView.tsx:1484-1502`:
- `awaiting_agent` banner: add queue position display if `helpdesk_queue_position_enabled` and position is available. Poll `GET /ui/helpdesk/conversations/{id}/queue-position` every 30s via React Query.
- `paused_no_agents_online` banner: add out-of-hours message if business hours configured.
- `closed` / new `escalated` state: show "Your request was escalated to ticket #X."

### 4.7 Dev/Prod parity (SECOPS-007)

| Concern | Dev | Prod |
|---------|-----|------|
| SLA sweep interval | 5s configurable via env | 60s |
| Email on escalation | Log to stdout | SES / SendGrid |
| Ticket creation | Same `T.tickets` DDB table | Same path |
| Business-hours check | UTC only acceptable | Timezone-aware via pytz |

---

## 5. Testing, Verification & Rollout

### 5.1 pytest unit tests (`tests/test_helpdesk_sla.py`)

- `test_sla_sweep_escalates_after_timeout`: seed `awaiting_agent` convo with `created_at = now - 31*60`; run sweep; assert ticket created + system message posted + state closed.
- `test_sla_sweep_no_action_before_timeout`: `created_at = now - 29*60`; run sweep; assert no ticket.
- `test_sla_sweep_disabled_when_timeout_zero`: `HELPDESK_UNCLAIMED_TIMEOUT_MINUTES=0`; run sweep; no action.
- `test_business_hours_open`: mock `now` inside business hours; assert `_is_helpdesk_open` True.
- `test_business_hours_closed`: mock `now` outside hours; assert False.
- `test_out_of_hours_auto_ticket_fallback`: convo created outside hours with `fallback=auto_ticket`; assert ticket created immediately, no queue entry.
- `test_queue_position_customer_only`: Alice's convo position returns correctly; Bob's attempt to get Alice's position returns 403.
- `test_queue_position_returns_none_when_assigned`: convo in `assigned` state returns `position: null`.

### 5.2 Playwright E2E (`frontend/e2e/helpdesk-sla.spec.ts`)

Sections:
- **65.1** SLA escalation: seed convo with `created_at` far in past → run `POST /internal/helpdesk/run-sla-sweep` (dev-only trigger) → assert system message "ticket #X" in conversation view.
- **65.2** Queue position: two convos in queue; verify customer sees "You're #2 in line" badge.
- **65.3** Out-of-hours: set business hours to exclude current time; start helpdesk chat; assert out-of-hours notice appears; assert ticket auto-created.
- **65.4** Resume-on-agent-online still works after changes (regression).

### 5.3 Rollout plan

1. Deploy settings with all flags defaulting to `0`/`false`/`"none"` → zero behavior change.
2. Enable `HELPDESK_QUEUE_POSITION_ENABLED=1` first (read-only, no state change).
3. Enable `HELPDESK_BUSINESS_HOURS_JSON` for one test group.
4. Enable `HELPDESK_UNCLAIMED_TIMEOUT_MINUTES=60` + `HELPDESK_AUTO_TICKET_ON_TIMEOUT=1`.
5. Monitor ticket creation rate and customer satisfaction.

**Rollback**: set all new flags to off; the background sweep does nothing; existing behavior restored.

**Effort**: M (backend sweep + settings + ticket linkage + queue position endpoint = ~3 days; frontend banner updates = ~1 day; E2E = ~1 day)
