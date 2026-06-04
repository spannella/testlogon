# AGENT-006: Terminal Monitoring & Feedback Loop — Investigation & Implementation Write-up

> ~5 pages. Read the real code before writing; cite `file:line`. Be concrete, not generic.

## 1. Summary & Classification

AGENT-006 implements the human-in-the-loop mechanism for the agent platform: it watches agent terminal output for signal tokens (`[AGENT_COMPLETE]`, `[AGENT_FEEDBACK_NEEDED]`, `[AGENT_ERROR]`), creates structured feedback request records when the agent needs input, notifies the user, and — upon receiving a user response — injects the text back into the agent's terminal so work can resume. It also maintains a per-worker in-memory ring buffer of recent terminal output for searching and live streaming, and provides configurable per-agent-type regex patterns so operators can tune sensitivity.

- **Type**: Feature (real-time monitoring / human escalation)
- **Priority**: High — required for practical autonomous agent operation
- **Status**: Implemented (feedback CRUD and pattern matching); terminal injection and SSE streaming are partial
- **Owning area**: AI Agents / Monitoring
- **User persona**: Developer watching agent progress who needs to respond to clarification requests without SSH access
- **Cross-references**: [[AGENT-002]] (worker `host_id` for SSH), [[AGENT-003]] (agent state machine, `awaiting_feedback` state), [[AGENT-004]] (FeedbackPanel in fleet dashboard), [[SEC-021]] (injection safety — response text into terminal), [[SECOPS-007]] (terminal inject uses mock buffer in dev, SSH in prod)

---

## 2. Current-State Investigation (what exists today)

### 2.1 Service file

`app/services/terminal_monitor.py` (475 lines) is fully present.

**`TerminalOutputBuffer`** (line 104): ring buffer class with `max_chars=50_000` and `max_lines=1000`. The `append` method adds data to a string buffer, trims to max_chars, splits by newline into a `deque`, and notifies registered listeners. `get_recent(chars)` returns the tail; `search(keyword)` does a case-insensitive substring search over lines. Listeners are a plain list of callables — used by the SSE endpoint to push new data to connected clients.

**`PatternMatcher`** (line 157): compiles a dict of `{signal_name: List[str]}` regex patterns. The `match` method iterates all categories in order (`completion` first, then `feedback_needed`, then `error`) and returns the first match as `{"signal": name, "pattern": p, "match": text}`. Patterns are pre-compiled at init time, not on each call.

**DEFAULT_FEEDBACK_PATTERNS** (line 25): three patterns defined at module level:
- `completion`: `[AGENT_COMPLETE]`, `[TASK_DONE]`
- `feedback_needed`: `[AGENT_FEEDBACK_NEEDED]`, `[NEEDS_INPUT]`
- `error`: `[AGENT_ERROR]`

The ticket design shows richer per-type patterns (`AGENT_TYPE_PATTERNS` dict with coder/qa/reviewer/devops entries); the current implementation has only the three base patterns. The per-type expansion is a gap (see §3.1).

**`create_feedback_request`** (line 191): writes a `FEEDBACK#{request_id}` record to `agent_feedback` table with `feedback_status="pending"`, `question`, `terminal_context` (last 2000 chars of buffer), `timeout_at = now + timeout_seconds`. Does NOT call `transition_agent_state` (the AGENT-003 hook described in the ticket design is absent — see §3.2). Does NOT send a notification alert (the call to `_notify_feedback_needed` shown in the design is replaced by a `logger.info`). This means feedback requests are created but agents are not paused and users are not notified.

**`respond_to_feedback`** (line 233): validates the request exists and is `"pending"`, updates status to `"responded"`, stores `response_text`. Does NOT inject the response into the terminal — `_inject_into_terminal` is called in the ticket design but is absent from the current implementation. Agent state is not transitioned back to `"working"`. This is a significant functionality gap (see §3.2, §3.3).

**`skip_feedback`** (line 325): updates status to `"skipped"`. Same gap: no terminal injection, no state transition.

**`check_feedback_timeouts`** (line 349): queries `agent_feedback` for `feedback_status="pending"` items where `timeout_at < now()`, and for each applies the `timeout_action` (`skip`, `escalate`, `release_ticket`). The basic skeleton is present but `escalate` and `release_ticket` actions may not be fully wired to the orchestrator.

**`update_pattern_config`** (line 410): validates patterns (max 50 per category, valid regex) and stores in `agent_feedback` with SK `"CONFIG#patterns"`. Regex patterns are compiled and checked for syntax errors; DoS from ReDoS is partially addressed by compile-time check but not by a runtime timeout.

**`test_patterns`** (line 456): applies user-provided patterns to sample text and returns matches. Used by the PatternEditor UI.

**`get_terminal_output`** / **`search_terminal_output`** (lines 379, 391): read from the in-memory `_worker_buffers` dict. If the backend restarts, all buffers are lost — there is no persistence to DDB or S3.

### 2.2 Router

`app/routers/agent_feedback.py` (301 lines) provides 11 endpoints. Registered at `app/main.py:754` (imported conditionally). All endpoints use `require_ui_session`. Worker ownership is validated via `get_worker(user_id, worker_id)`.

The SSE stream endpoint at `GET /ui/agent/terminal/{worker_id}/stream` delivers live terminal output by registering a queue as a buffer listener and yielding data as `text/event-stream`. This is architecturally correct but requires the buffer to be populated — which only happens when terminal output is routed through `process_terminal_output`. If the WebSocket SSH terminal in `browser_ssh_terminal.py` is not wired to call `process_terminal_output`, the SSE stream is empty.

### 2.3 Alerts service compatibility

The ticket design shows calls to `create_alert(user_id, ...)` for notifying users of pending feedback. However, `app/services/alerts.py` does not have a `create_alert` function (this is confirmed in the AGENT-006 ticket's codebase references section). The actual notification infrastructure uses `audit_event(event, user_sub, request, **fields)` at line 695 of the alerts service, which has a different signature. The current implementation correctly avoids the non-existent function and uses `logger.info` instead — but this means no user notifications are sent.

### 2.4 Data model

`app/models.py:6303` — `FeedbackRequestOut`, `FeedbackListOut`, `CreateFeedbackRequestIn`, `FeedbackRespondIn` (response_text max 5000), `TerminalOutputOut`, `TerminalSearchOut`, `PatternConfigOut`, `PatternUpdateIn`, `PatternTestIn`, `PatternTestOut`.

### 2.5 DynamoDB table

`scripts/local-ddb-init.py:1936` creates `agent_feedback`:
- PK `WORKER#{worker_id}`, SK multi-pattern: `FEEDBACK#{request_id}`, `CONFIG#patterns`
- GSIs: `ByStatus` (pk + feedback_status), `ByCreatedAt` (pk + created_at), `ByUser` (user_id + created_at)

`app/core/settings.py:2167` adds `agent_feedback_table_name` and `agent_feedback_timeout_seconds` (default 14400 = 4 hours).

### 2.6 Dev vs prod parity (SECOPS-007)

The terminal monitoring service is the most complex parity case:

| Concern | Dev path | Prod path |
|---|---|---|
| Terminal output capture | Must hook into `browser_ssh_terminal.py` WebSocket handler | Same hook — WebSocket data tapped server-side |
| Terminal inject | Write to mock buffer (in-memory `TerminalOutputBuffer.append`) | Send text to SSH channel of the worker's session |
| Notification alert | `logger.info` (no real alert) | Call the alerts service (after `create_alert` is implemented) |
| Buffer persistence | In-memory only | Optional S3 flush every 60s |

The prod path for injection (`_inject_into_terminal`) needs to call the SSH client associated with the worker's `host_id`. This is the only AWS-touching operation in this service (the SSH target may be an EC2 instance), and it should use a provider interface with a mock in dev.

### 2.7 E2E tests

`frontend/e2e/agent-feedback.spec.ts` covers sections 643-646 (16 tests): feedback request CRUD, response/skip API, terminal output and patterns, and UI.

---

## 3. Gap / Threat Analysis

### 3.1 Per-type pattern expansion not implemented

The `DEFAULT_FEEDBACK_PATTERNS` at line 25 only has the three bare signal tokens. The `AGENT_TYPE_PATTERNS` dict from the ticket design (with richer patterns for coder, qa, reviewer, devops — e.g., "breaking change detected", "flaky test detected") is not present. `process_terminal_output` always uses the global `PatternMatcher` initialized from `DEFAULT_FEEDBACK_PATTERNS`. Worker-type-specific patterns are not consulted. This limits detection sensitivity significantly in practice.

### 3.2 `create_feedback_request` does not pause the agent

After a feedback pattern is detected, the agent should be transitioned to `awaiting_feedback` (AGENT-003's state machine). Currently `create_feedback_request` only writes a DDB record and logs. The agent continues running, potentially outputting more `[AGENT_FEEDBACK_NEEDED]` signals and creating duplicate feedback records. Fix: add `transition_agent_state(user_id, worker_id, "awaiting_feedback")` inside `create_feedback_request`, or as a post-create hook in the router.

### 3.3 `respond_to_feedback` does not inject or resume

`respond_to_feedback` updates the DDB record but does not:
1. Call `_inject_into_terminal` to send the response to the agent
2. Call `transition_agent_state(user_id, worker_id, "working")` to resume the agent

The agent remains in `awaiting_feedback` indefinitely. From the user's perspective, submitting a response has no effect. This is the highest-priority implementation gap.

### 3.4 Terminal injection — SEC-021 concerns

When `_inject_into_terminal` is implemented (prod path), response text from the user will be written to the SSH channel. A malicious user could craft a response containing ANSI escape sequences to alter the terminal display (`\x1b[2J` to clear), or inject shell commands that the agent might execute if it echoes the text to a shell. Mitigation:
- Strip ANSI control characters (bytes `\x1b` through `\x1f`, `\x7f`)
- Enforce `max_length=5000` (already in `FeedbackRespondIn`)
- Append `\n` at the end so the agent's stdin readline receives the full response

### 3.5 ReDoS via user-provided patterns

`update_pattern_config` validates regex syntax (line 427, `re.compile(p)`) but does not guard against catastrophic backtracking. A pattern like `(a+)+$` compiles fine but times out exponentially on long inputs. Mitigation: run `re.compile(p)` in a subprocess with a 100ms timeout, or use the `regex` library's timeout support, or apply a static analysis check for common ReDoS patterns.

### 3.6 In-memory buffer lost on restart

The `_worker_buffers` dict is ephemeral. After a backend restart, `get_terminal_output` returns an empty string. For long-running sessions this may lose hours of diagnostic output. Periodic flush to S3 (as described in the ticket) would preserve it. In dev, the in-process moto S3 can be used; in prod, real S3.

### 3.7 WebSocket hook not wired

`app/routers/browser_ssh_terminal.py` currently proxies WebSocket data directly between the browser and the SSH server without calling `process_terminal_output`. Until this hook is added, the entire detection pipeline (buffer → pattern match → feedback request) never fires automatically. The feedback creation endpoint exists for testing (manual `POST`), but autonomous detection is not yet wired.

---

## 4. Proposed Design / Fix

### 4.1 Wire WebSocket hook in browser_ssh_terminal.py

Find the WebSocket data forwarding loop in `browser_ssh_terminal.py` (the point where server-side SSH output is forwarded to the browser). Add a tap:

```python
# After receiving data from SSH channel, before forwarding to browser:
detection = process_terminal_output(user_id, worker_id, data.decode("utf-8", errors="replace"))
if detection:
    if detection["signal"] == "completion":
        complete_ticket(user_id, worker_id, current_ticket_id)
    elif detection["signal"] == "feedback_needed":
        create_feedback_request(user_id, worker_id, current_ticket_id,
            question=detection["context"][-500:],
            terminal_context=get_terminal_output(worker_id, chars=2000),
            detected_pattern=detection["pattern"])
    elif detection["signal"] == "error":
        transition_agent_state(user_id, worker_id, "error")
```

### 4.2 Complete respond_to_feedback

```python
def respond_to_feedback(user_id: str, worker_id: str, request_id: str, response_text: str):
    # ... existing DDB update ...

    # 1. Sanitize and inject response into terminal
    safe_response = _sanitize_terminal_input(response_text)
    _inject_into_terminal(user_id, worker_id, safe_response + "\n")

    # 2. Resume agent
    from app.services.agent_orchestrator import transition_agent_state
    transition_agent_state(user_id, worker_id, "working")

    return get_feedback_request(worker_id, request_id)
```

**`_inject_into_terminal` dev/prod factory (SECOPS-007)**:
```python
def _inject_into_terminal(user_id: str, worker_id: str, text: str) -> None:
    if S.dev_mode:
        buf = get_or_create_buffer(worker_id)
        buf.append(f"[USER_RESPONSE] {text}")  # Simulate injection in buffer
        return
    # Prod: look up worker's host_id, SSH session, send to stdin channel
    ...
```

### 4.3 Per-type pattern expansion

Move `AGENT_TYPE_PATTERNS` from the ticket design into the service module. `process_terminal_output` reads `agent_type` from the worker record and selects the appropriate pattern set (with fallback to defaults):

```python
patterns_config = get_worker_pattern_config(worker_id)  # custom overrides
if not patterns_config:
    agent_type = worker.get("agent_type", "coder")
    patterns_config = AGENT_TYPE_PATTERNS.get(agent_type, DEFAULT_FEEDBACK_PATTERNS)
matcher = PatternMatcher(patterns_config)
return matcher.match(data)
```

### 4.4 State transition in create_feedback_request

```python
def create_feedback_request(...) -> Dict[str, Any]:
    # ... existing DDB PutItem ...

    # Pause the agent
    from app.services.agent_orchestrator import transition_agent_state
    try:
        transition_agent_state(user_id, worker_id, "awaiting_feedback")
    except ValueError:
        pass  # Worker already paused or in error state

    # Notify (when create_alert is available)
    # For now: push SSE event to fleet event bus
    from app.services.agent_fleet import emit_fleet_event
    emit_fleet_event(user_id, {
        "type": "worker:feedback_needed",
        "data": {"worker_id": worker_id, "request_id": request_id, "question": question[:200]},
    })
    return item
```

### 4.5 ReDoS mitigation

Use `signal.alarm` (Unix only) or `threading.Timer` to abort slow regex matches:

```python
import signal

def _safe_compile(pattern: str, timeout_ms: int = 100) -> Optional[re.Pattern]:
    try:
        compiled = re.compile(pattern)
        # Quick test on a 1000-char string for performance
        def _handler(sig, frame): raise TimeoutError("ReDoS detected")
        signal.signal(signal.SIGALRM, _handler)
        signal.setitimer(signal.ITIMER_REAL, timeout_ms / 1000)
        compiled.search("a" * 1000)
        signal.setitimer(signal.ITIMER_REAL, 0)
        return compiled
    except (TimeoutError, re.error):
        return None
```

Reject patterns that time out on the probe.

---

## 5. Testing, Verification & Rollout

### 5.1 pytest unit tests (`tests/test_agent_monitoring.py`)

| Test | What it pins |
|---|---|
| `test_pattern_matcher_detects_completion` | Buffer containing `[AGENT_COMPLETE]` → `{"signal": "completion"}` |
| `test_pattern_matcher_detects_feedback` | Buffer containing `[AGENT_FEEDBACK_NEEDED]` → `{"signal": "feedback_needed"}` |
| `test_buffer_ring_limits` | Appending 60_000 chars → buffer stays ≤ 50_000 chars |
| `test_create_feedback_transitions_state` | After create, worker `agent_state="awaiting_feedback"` |
| `test_respond_injects_and_resumes` | After respond, buffer contains response text; agent state = `"working"` |
| `test_skip_resumes_agent` | After skip, agent state = `"working"` |
| `test_respond_rejected_on_non_pending` | Respond to responded request → `ValueError` |
| `test_feedback_timeout_applies_action` | Set `timeout_at = past`, run `check_feedback_timeouts`, verify status = `"skipped"` |
| `test_redos_pattern_rejected` | Pattern `"(a+)+$"` → `update_pattern_config` raises `ValueError` |
| `test_terminal_inject_sanitizes_ansi` | Response `"\x1b[2J evil_command"` → injected text has control chars stripped |

All tests use `@mock_dynamodb`, no WebSocket or SSH infrastructure needed.

### 5.2 E2E tests (Playwright)

`frontend/e2e/agent-feedback.spec.ts` sections 643-646:
- Section 643.1: POST to internal mock endpoint creates feedback record with `feedback_status: "pending"`
- Section 644.5: Respond → `feedback_status: "responded"`, agent status GET shows `agent_state: "working"`
- Section 645.9: GET terminal output returns string with `char_count >= 0`
- Section 645.12: POST `patterns/test` with sample text → matches array non-empty
- Section 646.15: UI response form submits and card transitions to "responded"

### 5.3 Manual QA

```bash
# Create a feedback request (simulating agent detection)
curl -X POST http://localhost:8000/ui/agent/feedback/$WORKER_ID \
  -H "x-csrf-token: $CSRF" -b "$COOKIES" \
  -d '{"ticket_id":"TKT_001","question":"Should I use async or sync?","terminal_context":"...","detected_pattern":"[AGENT_FEEDBACK_NEEDED]"}'

# List pending feedback
curl http://localhost:8000/ui/agent/feedback/pending -b "$COOKIES"

# Respond
curl -X POST http://localhost:8000/ui/agent/feedback/$WORKER_ID/$REQUEST_ID/respond \
  -H "x-csrf-token: $CSRF" -b "$COOKIES" \
  -d '{"response_text":"Use async for all I/O"}'

# Verify agent state returned to working
curl http://localhost:8000/ui/agent/orchestrator/$WORKER_ID/status -b "$COOKIES"
```

### 5.4 Observability

Add metrics: `agent_feedback_requests_total{status}` counter, `agent_feedback_response_latency_seconds` histogram (time from creation to response). Add `logger.warn` for timed-out requests. Emit `worker:feedback_timeout` SSE events so the fleet dashboard shows unresponded requests prominently.

### 5.5 Rollout

1. Deploy with current implementation (feedback CRUD functional, injection/state transition absent).
2. Wire WebSocket hook (§4.1) in a follow-on PR; gate with `AGENT_TERMINAL_MONITORING_ENABLED=true` flag.
3. Implement `respond_to_feedback` injection (§4.2) after hook is verified.
4. Enable per-type patterns (§4.3) after monitoring tuning.

### 5.6 Rollback

Set `AGENT_TERMINAL_MONITORING_ENABLED=false`. The WebSocket hook is disabled; no pattern matching or feedback creation occurs. Existing feedback records in DDB are inert. Agent lifecycle is unaffected (state transitions continue via the orchestrator API).

### 5.7 Effort estimate: **M** (5-7 days) — WebSocket hook wiring + complete respond/skip implementation + state transition wiring + per-type patterns + ReDoS mitigation. Core feedback CRUD is already implemented.
