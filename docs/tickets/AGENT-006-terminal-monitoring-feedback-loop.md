# AGENT-006: Terminal Monitoring & Feedback Loop

**Ticket**: AGENT-006
**Author**: Engineering
**Status**: Implemented
**Date**: 2026-05-29
**Priority**: High
**Estimated effort**: 9-11 days
**Dependencies**: AGENT-003 (Agent Framework), AGENT-002 (Worker Provisioning)

---

## 1. Overview & Motivation

### 1.1 Purpose

AGENT-006 implements the terminal monitoring system that watches agent terminal output for signals indicating the agent needs human input, has completed its work, or has encountered an error. When a feedback request is detected, the system extracts the question from terminal output, creates a feedback request record, notifies the user, and pauses the agent until the user responds. The user's response is then injected back into the terminal and the agent resumes. This is the human-in-the-loop mechanism that makes autonomous agents practical for real work.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| User | As a user, I want to be notified when an agent needs my input so that I can unblock it quickly. | Dashboard badge, push notification, and optional email when agent enters `awaiting_feedback` state. |
| User | As a user, I want to see what the agent is asking so that I can provide the right answer. | Feedback request shows extracted question, surrounding terminal output context, and the ticket reference. |
| User | As a user, I want to type my response and have it injected into the agent's terminal so that I don't have to SSH in manually. | Response textarea in UI; submit injects text into terminal; agent resumes automatically. |
| User | As a user, I want to configure what patterns trigger a feedback request so that I can tune sensitivity. | Pattern config per agent type; regex/keyword list; test mode to preview matches on sample output. |
| User | As a user, I want feedback requests to timeout so that a stuck agent doesn't wait forever. | Configurable timeout (default: 4 hours); on timeout, skip/escalate/release ticket. |
| User | As a user, I want to see a searchable log of all terminal output so that I can audit what the agent did. | Terminal output stored in DDB/S3; searchable by keyword, date range, ticket ID. |
| User | As a user, I want to see live terminal output in the dashboard so that I can watch the agent work in real-time. | Worker detail drawer streams terminal output via SSE. |

### 1.3 Why This Is Needed

Autonomous agents occasionally get stuck on ambiguous requirements, need clarification on business logic, require approval for destructive actions, or encounter unexpected situations. Without a feedback mechanism, these agents would either make wrong assumptions (causing rework) or hang indefinitely (wasting compute). The feedback loop enables a collaborative workflow where agents work autonomously on routine tasks but escalate to humans for judgment calls.

---

## 2. Current State Analysis

### 2.1 Existing Infrastructure

| Component | Location | Relevance |
|-----------|----------|-----------|
| Agent orchestrator | `app/services/agent_orchestrator.py` (AGENT-003) | <!-- NOTE: does not exist yet — requires AGENT-003 --> Agent state machine; `awaiting_feedback` state |
| WebSocket terminal | `app/routers/browser_ssh_terminal.py` | <!-- NOTE: was listed as `app/routers/terminal.py` which does not exist. The actual SSH terminal router is `app/routers/browser_ssh_terminal.py` (see app/main.py:404) --> SSH terminal via WebSocket; bidirectional data channel |
| Worker provisioner | `app/services/agent_worker_provisioner.py` (AGENT-002) | <!-- NOTE: does not exist yet — requires AGENT-002 --> Worker records with `host_id` for SSH |
| Alerts service | `app/services/alerts.py` | <!-- NOTE: `audit_event` exists at line 695 with signature `audit_event(event, user_sub, request, **fields)` — NOT `audit_event(user_id, event, outcome, details)` as used in the code samples below. `create_alert` does NOT exist in this file — new implementation required --> Notification system; push, email, in-app alerts |
| SSE patterns | Various routers | Server-Sent Events for real-time push to frontend |
| S3 storage | `app/core/dev_s3.py` | Object storage for large terminal logs |
| Ticket messaging | `app/services/tickets.py` | Ticket comment/message system; feedback can be posted as comments |

### 2.2 Gaps

1. **No terminal output capture** -- WebSocket terminal data flows directly between browser and SSH server; there is no server-side tap to capture output.
2. **No pattern matching** -- no mechanism to scan terminal output for feedback-needed signals.
3. **No feedback request model** -- no DDB structure for tracking feedback requests.
4. **No response injection** -- no API to programmatically send text into a running SSH session.
5. **No terminal output buffering** -- no ring buffer or log of recent terminal output.
6. **No timeout handling** -- no mechanism to auto-escalate unanswered feedback requests.
7. **No configurable patterns** -- no per-agent-type pattern configuration.

---

## 3. Technical Design

### 3.1 DynamoDB Table: `agent_feedback`

```python
# scripts/local-ddb-init.py
TableDef(
    _resolve_table_name(S.agent_feedback_table_name, "agent_feedback"),
    "pk",              # WORKER#{worker_id}
    "sk",              # FEEDBACK#{request_id}
    gsis=[
        {"index_name": "ByStatus", "partition_key": "pk", "sort_key": "feedback_status"},
        {"index_name": "ByCreatedAt", "partition_key": "pk", "sort_key": "created_at"},
        {"index_name": "ByUser", "partition_key": "user_id", "sort_key": "created_at"},
    ],
    attr_types={"created_at": "N"},
)
```

**Item schema**:

| Field | Type | Description |
|-------|------|-------------|
| `pk` | S (PK) | `WORKER#{worker_id}` |
| `sk` | S (SK) | `FEEDBACK#{request_id}` |
| `request_id` | S | UUID hex identifier |
| `user_id` | S | Worker owner (for ByUser GSI) |
| `worker_id` | S | Worker that generated the request |
| `ticket_id` | S | Ticket the agent was working on |
| `feedback_status` | S | `pending`, `responded`, `timed_out`, `skipped` |
| `question` | S | Extracted question/context from terminal output |
| `terminal_context` | S | Surrounding terminal output (last 2000 chars) |
| `detected_pattern` | S | The pattern that triggered the feedback request |
| `response_text` | S | User's response (filled when responded) |
| `responded_at` | N | Timestamp of user response |
| `timeout_at` | N | Unix timestamp when request times out |
| `timeout_action` | S | `skip`, `escalate`, `release_ticket` |
| `created_at` | N | Unix timestamp of detection |
| `notified` | BOOL | Whether notification was sent |

### 3.2 Terminal Output Buffer

```python
# In app/services/terminal_monitor.py

class TerminalOutputBuffer:
    """Ring buffer for capturing terminal output.

    Maintains a sliding window of the last N characters/lines
    from the agent's terminal for pattern matching and context extraction.
    """

    def __init__(self, max_chars: int = 50_000, max_lines: int = 1000):
        self._buffer: str = ""
        self._lines: deque = deque(maxlen=max_lines)
        self._max_chars = max_chars
        self._listeners: List[Callable] = []

    def append(self, data: str) -> None:
        """Append new terminal output data."""
        self._buffer += data
        if len(self._buffer) > self._max_chars:
            self._buffer = self._buffer[-self._max_chars:]

        for line in data.split("\n"):
            if line.strip():
                self._lines.append(line)

        # Notify listeners
        for listener in self._listeners:
            listener(data)

    def get_recent(self, chars: int = 2000) -> str:
        """Get the most recent N characters."""
        return self._buffer[-chars:]

    def get_recent_lines(self, count: int = 50) -> List[str]:
        """Get the most recent N lines."""
        return list(self._lines)[-count:]

    def search(self, keyword: str) -> List[str]:
        """Search buffer for lines containing keyword."""
        return [l for l in self._lines if keyword.lower() in l.lower()]

    def add_listener(self, callback: Callable[[str], None]) -> None:
        """Add a listener for new data."""
        self._listeners.append(callback)

    def remove_listener(self, callback: Callable) -> None:
        """Remove a data listener."""
        self._listeners.remove(callback)
```

### 3.3 Pattern Matching Configuration

```python
# In app/services/terminal_monitor.py

DEFAULT_FEEDBACK_PATTERNS = {
    "completion": [
        r"\[AGENT_COMPLETE\]",
        r"\[TASK_DONE\]",
        r"All tests passed",
    ],
    "feedback_needed": [
        r"\[AGENT_FEEDBACK_NEEDED\]",
        r"\[NEEDS_INPUT\]",
        r"(?i)waiting for (?:user |human )?input",
        r"(?i)please confirm",
        r"(?i)which option (?:should|do)",
        r"(?i)need(?:s)? clarification",
        r"(?i)cannot proceed without",
        r"(?i)ambiguous requirement",
    ],
    "error": [
        r"\[AGENT_ERROR\]",
        r"(?i)fatal error",
        r"(?i)unrecoverable",
        r"Traceback \(most recent call last\)",
        r"(?i)permission denied.*(?:key|auth|access)",
    ],
}

AGENT_TYPE_PATTERNS = {
    "coder": {
        "completion": DEFAULT_FEEDBACK_PATTERNS["completion"] + [
            r"(?i)pull request created",
            r"(?i)branch pushed",
        ],
        "feedback_needed": DEFAULT_FEEDBACK_PATTERNS["feedback_needed"] + [
            r"(?i)should I (?:refactor|rewrite|delete)",
            r"(?i)multiple approaches? (?:possible|available)",
            r"(?i)breaking change detected",
        ],
    },
    "qa": {
        "completion": DEFAULT_FEEDBACK_PATTERNS["completion"] + [
            r"(?i)test suite (?:passed|complete)",
            r"(?i)\d+ tests? passed, 0 failed",
        ],
        "feedback_needed": DEFAULT_FEEDBACK_PATTERNS["feedback_needed"] + [
            r"(?i)is this expected behavior",
            r"(?i)bug or feature",
            r"(?i)flaky test detected",
        ],
    },
    "reviewer": {
        "completion": DEFAULT_FEEDBACK_PATTERNS["completion"] + [
            r"(?i)review (?:posted|submitted)",
            r"(?i)approved with",
        ],
        "feedback_needed": DEFAULT_FEEDBACK_PATTERNS["feedback_needed"],
    },
    "devops": {
        "completion": DEFAULT_FEEDBACK_PATTERNS["completion"] + [
            r"(?i)deployment (?:complete|successful)",
            r"(?i)pipeline (?:passed|green)",
        ],
        "feedback_needed": DEFAULT_FEEDBACK_PATTERNS["feedback_needed"] + [
            r"(?i)destructive operation",
            r"(?i)production (?:change|deployment)",
        ],
    },
}
```

### 3.4 Backend Service

**New file**: `app/services/terminal_monitor.py` (~500 lines)

```python
"""Terminal Monitoring & Feedback Loop service (AGENT-006).

Captures terminal output, matches patterns for completion/feedback/error
signals, creates feedback requests, and injects user responses.
"""

from __future__ import annotations
import asyncio
import logging
import re
from collections import deque
from typing import Any, Callable, Dict, List, Optional
from uuid import uuid4

from app.core.tables import T
from app.core.time import now_ts
from app.services.agent_orchestrator import transition_agent_state, complete_ticket
from app.services.alerts import audit_event

logger = logging.getLogger(__name__)

DEFAULT_FEEDBACK_TIMEOUT_SECONDS = 14400  # 4 hours
OUTPUT_LOG_FLUSH_INTERVAL = 60  # Flush buffer to S3 every 60 seconds

# In-memory buffers per worker
_worker_buffers: Dict[str, TerminalOutputBuffer] = {}


def get_or_create_buffer(worker_id: str) -> TerminalOutputBuffer:
    """Get or create a terminal output buffer for a worker."""
    if worker_id not in _worker_buffers:
        _worker_buffers[worker_id] = TerminalOutputBuffer()
    return _worker_buffers[worker_id]


def process_terminal_output(
    user_id: str,
    worker_id: str,
    data: str,
) -> Dict[str, Any] | None:
    """Process new terminal output data.

    Appends to buffer and scans for patterns.
    Returns a detection result if a signal is found, else None.
    """
    buf = get_or_create_buffer(worker_id)
    buf.append(data)

    # Get worker's agent type for pattern selection
    worker = T.agent_workers.get_item(
        Key={"pk": f"USER#{user_id}", "sk": f"WORKER#{worker_id}"}
    ).get("Item")
    if not worker:
        return None

    agent_type = worker.get("agent_type", "coder")
    patterns = AGENT_TYPE_PATTERNS.get(agent_type, DEFAULT_FEEDBACK_PATTERNS)

    # Check for completion
    for pattern in patterns.get("completion", []):
        if re.search(pattern, data):
            logger.info("Completion signal detected for worker %s", worker_id)
            return {"signal": "completion", "pattern": pattern, "context": data}

    # Check for feedback needed
    for pattern in patterns.get("feedback_needed", []):
        if re.search(pattern, data):
            logger.info("Feedback signal detected for worker %s", worker_id)
            return {"signal": "feedback_needed", "pattern": pattern, "context": data}

    # Check for error
    for pattern in patterns.get("error", []):
        if re.search(pattern, data):
            logger.info("Error signal detected for worker %s", worker_id)
            return {"signal": "error", "pattern": pattern, "context": data}

    return None


def create_feedback_request(
    user_id: str,
    worker_id: str,
    ticket_id: str,
    *,
    question: str,
    terminal_context: str,
    detected_pattern: str = "",
    timeout_seconds: int = DEFAULT_FEEDBACK_TIMEOUT_SECONDS,
    timeout_action: str = "skip",
) -> Dict[str, Any]:
    """Create a feedback request when the agent needs human input.

    1. Creates a DDB record with pending status
    2. Transitions agent state to awaiting_feedback
    3. Sends notification to user
    """
    request_id = uuid4().hex
    ts = now_ts()

    item = {
        "pk": f"WORKER#{worker_id}",
        "sk": f"FEEDBACK#{request_id}",
        "request_id": request_id,
        "user_id": user_id,
        "worker_id": worker_id,
        "ticket_id": ticket_id,
        "feedback_status": "pending",
        "question": question,
        "terminal_context": terminal_context[-2000:],  # Last 2000 chars
        "detected_pattern": detected_pattern,
        "response_text": "",
        "responded_at": 0,
        "timeout_at": ts + timeout_seconds,
        "timeout_action": timeout_action,
        "created_at": ts,
        "notified": False,
    }
    T.agent_feedback.put_item(Item=item)

    # Transition agent state
    transition_agent_state(user_id, worker_id, "awaiting_feedback")

    # Send notification
    _notify_feedback_needed(user_id, worker_id, request_id, question)

    audit_event(user_id, event="agent.feedback_request", outcome="created",
                details={"worker_id": worker_id, "ticket_id": ticket_id, "request_id": request_id})

    return item


def respond_to_feedback(
    user_id: str,
    worker_id: str,
    request_id: str,
    response_text: str,
) -> Dict[str, Any]:
    """Submit a user's response to a feedback request.

    1. Updates the feedback record
    2. Injects response text into the agent's terminal
    3. Transitions agent state back to working
    """
    ts = now_ts()

    T.agent_feedback.update_item(
        Key={"pk": f"WORKER#{worker_id}", "sk": f"FEEDBACK#{request_id}"},
        UpdateExpression="SET feedback_status = :st, response_text = :rt, responded_at = :ra",
        ExpressionAttributeValues={":st": "responded", ":rt": response_text, ":ra": ts},
    )

    # Inject response into terminal
    _inject_into_terminal(user_id, worker_id, response_text)

    # Resume agent
    transition_agent_state(user_id, worker_id, "working")

    audit_event(user_id, event="agent.feedback_response", outcome="success",
                details={"worker_id": worker_id, "request_id": request_id})

    return get_feedback_request(worker_id, request_id)


def get_feedback_request(worker_id: str, request_id: str) -> Dict[str, Any] | None:
    """Get a single feedback request."""
    resp = T.agent_feedback.get_item(
        Key={"pk": f"WORKER#{worker_id}", "sk": f"FEEDBACK#{request_id}"}
    )
    return resp.get("Item")


def list_feedback_requests(
    worker_id: str,
    *,
    status: str | None = None,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """List feedback requests for a worker, optionally filtered by status."""
    if status:
        resp = T.agent_feedback.query(
            IndexName="ByStatus",
            KeyConditionExpression="pk = :pk AND feedback_status = :st",
            ExpressionAttributeValues={
                ":pk": f"WORKER#{worker_id}", ":st": status,
            },
            Limit=limit,
        )
    else:
        resp = T.agent_feedback.query(
            KeyConditionExpression="pk = :pk AND begins_with(sk, :prefix)",
            ExpressionAttributeValues={
                ":pk": f"WORKER#{worker_id}", ":prefix": "FEEDBACK#",
            },
            Limit=limit,
            ScanIndexForward=False,
        )
    return resp.get("Items", [])


def list_pending_feedback_for_user(
    user_id: str,
    *,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """List all pending feedback requests across all workers for a user."""
    resp = T.agent_feedback.query(
        IndexName="ByUser",
        KeyConditionExpression="user_id = :uid",
        FilterExpression="feedback_status = :pending",
        ExpressionAttributeValues={":uid": user_id, ":pending": "pending"},
        Limit=limit,
        ScanIndexForward=False,
    )
    return resp.get("Items", [])


def skip_feedback(
    user_id: str,
    worker_id: str,
    request_id: str,
) -> Dict[str, Any]:
    """Skip a feedback request. Agent resumes without input."""
    T.agent_feedback.update_item(
        Key={"pk": f"WORKER#{worker_id}", "sk": f"FEEDBACK#{request_id}"},
        UpdateExpression="SET feedback_status = :st",
        ExpressionAttributeValues={":st": "skipped"},
    )

    # Inject skip signal into terminal
    _inject_into_terminal(user_id, worker_id, "[USER_SKIPPED] Please continue with your best judgment.\n")

    # Resume agent
    transition_agent_state(user_id, worker_id, "working")
    return get_feedback_request(worker_id, request_id)


def check_feedback_timeouts() -> int:
    """Background task: find and handle timed-out feedback requests.

    Scans for pending requests where now > timeout_at.
    Applies the configured timeout_action (skip, escalate, release_ticket).
    Returns count of timed-out requests handled.
    """
    # Scan agent_feedback for feedback_status="pending" where timeout_at < now()
    # For each: apply timeout_action
    handled = 0
    # Implementation: batch scan + process
    return handled


def get_terminal_output(
    worker_id: str,
    *,
    chars: int = 5000,
) -> str:
    """Get recent terminal output from the buffer."""
    buf = _worker_buffers.get(worker_id)
    if not buf:
        return ""
    return buf.get_recent(chars)


def search_terminal_output(
    worker_id: str,
    keyword: str,
) -> List[str]:
    """Search terminal output buffer for keyword matches."""
    buf = _worker_buffers.get(worker_id)
    if not buf:
        return []
    return buf.search(keyword)


def get_pattern_config(agent_type: str) -> Dict[str, List[str]]:
    """Get the current pattern configuration for an agent type."""
    return AGENT_TYPE_PATTERNS.get(agent_type, DEFAULT_FEEDBACK_PATTERNS)


def update_pattern_config(
    user_id: str,
    worker_id: str,
    patterns: Dict[str, List[str]],
) -> Dict[str, List[str]]:
    """Update custom pattern configuration for a worker.

    Stored in the agent_workers table as custom_patterns field.
    """
    T.agent_workers.update_item(
        Key={"pk": f"USER#{user_id}", "sk": f"WORKER#{worker_id}"},
        UpdateExpression="SET custom_patterns = :cp",
        ExpressionAttributeValues={":cp": patterns},
    )
    return patterns


def _inject_into_terminal(user_id: str, worker_id: str, text: str) -> None:
    """Inject text into a worker's terminal session.

    In dev mode: writes to the worker's mock terminal buffer.
    In prod: sends text via SSH channel to the worker's session.
    """
    # Look up worker's host_id and active SSH session
    # Send text as stdin to the SSH channel
    logger.info("Injecting %d chars into terminal for worker %s", len(text), worker_id)


def _notify_feedback_needed(
    user_id: str,
    worker_id: str,
    request_id: str,
    question: str,
) -> None:
    """Send notification that feedback is needed.

    Channels: in-app alert, push notification, optional email.
    """
    from app.services.alerts import create_alert
    create_alert(
        user_id=user_id,
        alert_type="agent_feedback",
        title="Agent needs your input",
        body=f"Worker is waiting for feedback: {question[:200]}",
        metadata={
            "worker_id": worker_id,
            "request_id": request_id,
        },
    )

    # Push SSE event to fleet event bus
    # Email notification if user has email alerts enabled
```

### 3.5 Backend Router

**New file**: `app/routers/agent_feedback.py` (~300 lines)

Prefix: `/ui/agent/feedback`

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/ui/agent/feedback/pending` | `require_ui_session` | List all pending feedback across workers |
| `GET` | `/ui/agent/feedback/{worker_id}` | `require_ui_session` | List feedback requests for a worker |
| `GET` | `/ui/agent/feedback/{worker_id}/{request_id}` | `require_ui_session` | Get a single feedback request |
| `POST` | `/ui/agent/feedback/{worker_id}/{request_id}/respond` | `require_ui_session` | Submit response to feedback |
| `POST` | `/ui/agent/feedback/{worker_id}/{request_id}/skip` | `require_ui_session` | Skip a feedback request |
| `GET` | `/ui/agent/terminal/{worker_id}/output` | `require_ui_session` | Get recent terminal output |
| `GET` | `/ui/agent/terminal/{worker_id}/search` | `require_ui_session` | Search terminal output |
| `GET` | `/ui/agent/terminal/{worker_id}/stream` | `require_ui_session` | SSE stream of live terminal output |
| `GET` | `/ui/agent/feedback/patterns/{agent_type}` | `require_ui_session` | Get pattern config for agent type |
| `PUT` | `/ui/agent/feedback/patterns/{worker_id}` | `require_ui_session` | Update custom patterns for worker |
| `POST` | `/ui/agent/feedback/patterns/test` | `require_ui_session` | Test patterns against sample text |

### 3.6 Pydantic Models

**Add to `app/models.py`**:

```python
# -- Agent Feedback & Terminal Monitoring (AGENT-006) --

class FeedbackRequestOut(BaseModel):
    request_id: str
    worker_id: str
    ticket_id: str
    feedback_status: str   # pending, responded, timed_out, skipped
    question: str
    terminal_context: str = ""
    detected_pattern: str = ""
    response_text: str = ""
    responded_at: int = 0
    timeout_at: int = 0
    timeout_action: str = "skip"
    created_at: int = 0

class FeedbackListOut(BaseModel):
    requests: List[FeedbackRequestOut]
    count: int
    pending_count: int

class FeedbackRespondIn(BaseModel):
    response_text: str = Field(..., min_length=1, max_length=5000)

class TerminalOutputOut(BaseModel):
    worker_id: str
    output: str
    char_count: int

class TerminalSearchOut(BaseModel):
    worker_id: str
    keyword: str
    matches: List[str]
    match_count: int

class PatternConfigOut(BaseModel):
    agent_type: str
    completion: List[str]
    feedback_needed: List[str]
    error: List[str]

class PatternUpdateIn(BaseModel):
    completion: Optional[List[str]] = None
    feedback_needed: Optional[List[str]] = None
    error: Optional[List[str]] = None

class PatternTestIn(BaseModel):
    patterns: Dict[str, List[str]]
    sample_text: str = Field(..., min_length=1, max_length=10000)

class PatternTestOut(BaseModel):
    matches: List[Dict[str, str]]   # [{signal: "completion", pattern: "...", match: "..."}]
    match_count: int
```

### 3.7 Frontend Components

#### FeedbackPanel (`frontend/src/pages/agents/FeedbackPanel.tsx`)

Component (~300 lines):

- **Pending badge**: Shows count of pending feedback requests in nav/header
- **Feedback list**: Cards for each pending request showing: worker label, ticket title, question text, time elapsed, terminal context (expandable)
- **Response form**: Textarea with send button; shows "Responding..." loading state
- **Skip button**: "Skip & Continue" with confirmation
- **Timeout indicator**: Countdown to timeout with `timeout_action` label

#### TerminalViewer (`frontend/src/pages/agents/TerminalViewer.tsx`)

Component (~200 lines):

- **Terminal emulator view**: Dark background, monospace font, auto-scroll
- **Live streaming**: SSE connection to `/ui/agent/terminal/{worker_id}/stream`
- **Search bar**: Keyword search with highlighted matches
- **Pause/resume**: Toggle auto-scroll

#### PatternEditor (`frontend/src/pages/agents/PatternEditor.tsx`)

Component (~200 lines):

- **Pattern groups**: Sections for Completion, Feedback Needed, Error
- **Pattern list**: Editable list of regex patterns per group
- **Test area**: Textarea for sample output, "Test Patterns" button, match results display
- **Reset to defaults**: Button to restore agent-type defaults

#### Route Integration

Feedback panel integrated into the fleet dashboard (AGENT-004) as a prominent section. Also accessible via `/agents/feedback` for a dedicated view.

```tsx
<Route path="/agents/feedback" element={<FeedbackPage />} />
```

---

## 4. Implementation Plan

### Phase 1: Terminal Buffer + Pattern Matching (2-3 days)

| File | Change |
|------|--------|
| `app/services/terminal_monitor.py` | New file: TerminalOutputBuffer, pattern matching, process_terminal_output |

### Phase 2: Feedback Service + DDB (3-4 days)

| File | Change |
|------|--------|
| `app/core/settings.py` | Add `agent_feedback_table_name`, `agent_feedback_timeout_seconds` |
| `app/core/tables.py` | Add `agent_feedback` table handle |
| `scripts/local-ddb-init.py` | Add `agent_feedback` TableDef with 3 GSIs |
| `app/services/terminal_monitor.py` | Add feedback CRUD, response injection, timeout checker |
| `app/models.py` | Add feedback Pydantic models |

### Phase 3: Router + SSE (2 days)

| File | Change |
|------|--------|
| `app/routers/agent_feedback.py` | New file: 11 endpoints + SSE stream |
| `app/main.py` | Register `agent_feedback_router` + timeout checker background task |

### Phase 4: Frontend (2-3 days)

| File | Change |
|------|--------|
| `frontend/src/api/types.ts` | Add feedback TypeScript types |
| `frontend/src/api/endpoints/agentFeedback.ts` | New file: API wrappers |
| `frontend/src/pages/agents/FeedbackPanel.tsx` | New file: feedback UI |
| `frontend/src/pages/agents/TerminalViewer.tsx` | New file: live terminal viewer |
| `frontend/src/pages/agents/PatternEditor.tsx` | New file: pattern configuration |
| `frontend/src/pages/agents/AgentsPage.tsx` | Integrate FeedbackPanel |
| `frontend/src/App.tsx` | Add `/agents/feedback` route |

### Phase 5: E2E Tests (1-2 days)

| File | Change |
|------|--------|
| `frontend/e2e/agent-feedback.spec.ts` | New file: ~16 tests in 4 sections |

---

## 5. E2E Test Plan (`frontend/e2e/agent-feedback.spec.ts`)

**Test setup**: Uses `e2e_admin_session_setup.py` sessions. `beforeAll` creates an LLM key, a worker, and a ticket. Starts the agent loop and claims the ticket so feedback can be simulated.

**Section 643: Feedback Request API (4 tests)**

1. `Create a feedback request` -- POST (internal/mock endpoint) to simulate feedback detection with `question: "Should I use async or sync?"`, `terminal_context: "...multiple approaches available..."`. Verify 201 with `request_id`, `feedback_status: "pending"`, `timeout_at > 0`.
2. `List pending feedback for worker` -- GET `/ui/agent/feedback/{worker_id}`. Verify `count >= 1`, `pending_count >= 1`, first request matches created request.
3. `List pending feedback across all workers` -- GET `/ui/agent/feedback/pending`. Verify at least 1 pending request with `worker_id` and `question` populated.
4. `Get single feedback request` -- GET `/ui/agent/feedback/{worker_id}/{request_id}`. Verify all fields: `question`, `terminal_context`, `detected_pattern`, `feedback_status: "pending"`.

**Section 644: Feedback Response API (4 tests)**

5. `Respond to feedback request` -- POST `/ui/agent/feedback/{worker_id}/{request_id}/respond` with `response_text: "Use async for all I/O operations"`. Verify 200 with `feedback_status: "responded"`, `response_text` matches, `responded_at > 0`.
6. `Agent resumes after response` -- GET agent status. Verify `agent_state: "working"` (no longer `awaiting_feedback`).
7. `Skip feedback request` -- Create a second feedback request. POST `/ui/agent/feedback/{worker_id}/{request_id2}/skip`. Verify `feedback_status: "skipped"`. Agent state returns to `working`.
8. `Cannot respond to already-responded request` -- POST respond to the first (already responded) request. Verify 400 or 409.

**Section 645: Terminal Output & Patterns API (4 tests)**

9. `Get terminal output` -- GET `/ui/agent/terminal/{worker_id}/output`. Verify response has `output` (string), `char_count >= 0`.
10. `Search terminal output` -- GET `/ui/agent/terminal/{worker_id}/search?keyword=error`. Verify response has `matches` array and `match_count`.
11. `Get pattern config for agent type` -- GET `/ui/agent/feedback/patterns/coder`. Verify response has `completion`, `feedback_needed`, `error` arrays. Verify `completion` contains `AGENT_COMPLETE`.
12. `Test patterns against sample text` -- POST `/ui/agent/feedback/patterns/test` with patterns and `sample_text: "waiting for user input on the schema design"`. Verify `matches` contains at least 1 match for `feedback_needed`.

**Section 646: Feedback UI (4 tests)**

13. `Fleet dashboard shows pending feedback count` -- Navigate to `/agents`. Verify a badge or indicator showing pending feedback count > 0.
14. `Feedback panel shows pending request` -- Navigate to `/agents/feedback` or expand feedback section. Verify card showing worker name, question text, and time elapsed.
15. `Response form submits and updates` -- Type response in textarea, click "Send Response". Verify card updates to "responded" status and disappears from pending list.
16. `Pattern editor shows configurable patterns` -- Navigate to pattern editor for a worker. Verify sections for Completion, Feedback Needed, Error. Verify patterns are editable.

---

## 6. Security Considerations

### 6.1 Terminal Output Privacy

Terminal output may contain sensitive data (API keys, passwords, file contents). Output buffers are held in-memory only (not persisted to DDB by default). S3 persistence is opt-in and uses the same encryption as other S3 objects.

### 6.2 Response Injection Safety

Response text is injected as stdin to the SSH session. Text is sanitized to prevent terminal escape sequence injection (strip ANSI control characters). Maximum response length is 5000 characters.

### 6.3 Feedback Request Authorization

All feedback endpoints validate that the authenticated user owns the worker. Feedback requests are partitioned by `WORKER#{worker_id}` and cross-checked against the worker's `user_id`.

### 6.4 Pattern Regex Safety

User-provided regex patterns are compiled with `re.compile()` and guarded by a timeout to prevent ReDoS attacks. Maximum pattern count is 50 per category.

### 6.5 Timeout Enforcement

Feedback timeouts are enforced by a background task running every 60 seconds. Timed-out requests are automatically handled per the configured `timeout_action` to prevent agents from being stuck indefinitely.

---

## 7. Dependencies

| Dependency | Type | Description |
|------------|------|-------------|
| AGENT-003 | Upstream | Agent state machine (`awaiting_feedback` state), `transition_agent_state()` |
| AGENT-002 | Upstream | Worker records with `host_id` for terminal access |
| AGENT-004 | Downstream | Fleet dashboard integrates FeedbackPanel |
| `app/services/alerts.py` | Upstream | Notification system for feedback alerts |
| `app/routers/browser_ssh_terminal.py` | Upstream | WebSocket terminal for output capture and text injection <!-- NOTE: actual file is browser_ssh_terminal.py, not terminal.py --> |

---

## 8. Acceptance Criteria

1. Terminal output is captured and buffered for pattern matching.
2. Configurable regex patterns detect completion, feedback-needed, and error signals.
3. Feedback requests are created automatically when feedback patterns are matched.
4. Users are notified of pending feedback via in-app alerts and dashboard badges.
5. User responses are injected into the agent's terminal session.
6. Agent state transitions to `awaiting_feedback` and back to `working` correctly.
7. Feedback requests timeout after configurable period with skip/escalate/release action.
8. Terminal output is searchable by keyword.
9. Live terminal output streams to the UI via SSE.
10. Pattern configuration is customizable per worker with test functionality.

---

## Codebase References

| Reference | File | Line(s) | Notes |
|-----------|------|---------|-------|
| WebSocket terminal router | `app/routers/browser_ssh_terminal.py` | 1-1125 | Actual file (ticket originally listed `app/routers/terminal.py` which does not exist) |
| Router registration | `app/main.py` | 82-84, 404 | `browser_ssh_terminal_router` import and `include_router` |
| Terminal enable check | `app/main.py` | 275 | `browser_ssh_terminal_enabled()` gate |
| `audit_event` | `app/services/alerts.py` | 695 | Signature: `audit_event(event, user_sub, request, **fields)` — NOT `(user_id, event, outcome, details)` as used in code samples |
| `create_alert` | `app/services/alerts.py` | — | Does NOT exist; new implementation required |
| Ticket store | `app/services/tickets.py` | 110 | `TicketStore` class; `add_message` at 621, `update_status` at 683 |
| S3 mock | `app/core/dev_s3.py` | — | In-process moto S3 mock (no separate process) |
| Agent orchestrator | `app/services/agent_orchestrator.py` | — | Does NOT exist yet — requires AGENT-003 |
| Worker provisioner | `app/services/agent_worker_provisioner.py` | — | Does NOT exist yet — requires AGENT-002 |
| `agent_workers` DDB table | `scripts/local-ddb-init.py` | — | Does NOT exist yet — requires AGENT-002 |
| `agent_feedback` DDB table | `scripts/local-ddb-init.py` | — | Does NOT exist yet — new table proposed in this ticket |
| Settings singleton | `app/core/settings.py` | 1-1494 | Frozen `Settings` dataclass; singleton `S` |

---

## Testing Strategy


### Unit Tests (pytest)


**Test file**: `tests/test_agent_monitoring.py`


**Mock setup**: moto for DynamoDB tables, `unittest.mock.patch` for external services (S3, Cognito, Stripe mock). All DDB tables created in-memory via moto `@mock_dynamodb` decorator.


| Test Function | Verifies |
|---|---|
| `test_create_agent_monitoring` | Creates record with correct fields and generated ID |
| `test_create_agent_monitoring_validation` | Rejects invalid input (missing required fields, out-of-range values) |
| `test_get_agent_monitoring_found` | Returns correct record by ID |
| `test_get_agent_monitoring_not_found` | Returns None for non-existent ID |
| `test_list_agent_monitoring` | Returns all records for the given scope/owner |
| `test_update_agent_monitoring` | Updates mutable fields and sets updated_at |
| `test_delete_agent_monitoring` | Removes record; subsequent get returns None |
| `test_agent_monitoring_owner_check` | Rejects operations from non-owner users |
| `test_agent_monitoring_admin_only` | Admin/root endpoints reject USER role with 403 |
| `test_agent_monitoring_concurrent_write` | Conditional update prevents stale overwrites |

### Integration Tests


Cross-service tests with real DDB (moto), verifying end-to-end flows:


1. Full CRUD lifecycle: create -> read -> update -> delete with real DDB (moto)
2. Authorization enforcement: non-owner access returns 403/404
3. Admin review/approval workflow with role-gated endpoints
4. Concurrent write safety: conditional updates prevent stale overwrites
5. Edge case: empty list returns `[]` not error; missing optional fields use defaults

### E2E Tests (Playwright)


**Test file**: `frontend/e2e/agent-monitoring.spec.ts`


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


**DDB seed data**:


| Table | PK/SK Pattern | Notes |
|-------|--------------|-------|
| `AgentLogs` | See DDB schema in technical design section | Created by `scripts/local-ddb-init.py` |

### CI/Pipeline


- **Feature flags**: None required for dev/test
- **Execution**: E2E tests run serially (1 worker, Chromium only) per `playwright.config.ts`; pytest can run in parallel
- **Retry safety**: All tests are idempotent; unique `TS = Date.now()` suffixed identifiers prevent cross-run collisions
- **Prerequisite**: `just restart` to create DDB tables and seed E2E sessions before running

## Dependencies & Merge Safety


### Depends On


| Ticket | What's Needed | Status | Can Overlap? |
|--------|--------------|--------|-------------|
| AGENT-003 | Agent framework (status) | Pending | No |
| AGENT-002 | Worker provisioning (terminal) | Pending | No |

### Depended On By


| Ticket | What It Needs From This |
|--------|------------------------|
| AGENT-007 | Monitoring for PR/ticket integration |
| AGENT-008 through AGENT-018 | Monitoring for specialized agents |

### Merge Strategy


**Sequential (after AGENT-003)**


- Must merge after: AGENT-003, AGENT-002
- Branch from `main` after dependencies are merged
- Can begin development in parallel but must rebase before merge
- DDB table creation is additive (no migration needed for new tables)

### Merge Checklist


- [ ] DDB table(s) added to `scripts/local-ddb-init.py`: `AgentLogs`
- [ ] Settings added to `app/core/settings.py` + `app/core/tables.py`: `agent_logs_table_name`
- [ ] `.env.local` updated with any new environment variables
- [ ] Router registered in `app/main.py` (from `app/routers/agent_workers.py`)
- [ ] All E2E tests passing (`just e2e` or targeted spec file)
- [ ] No breaking changes to existing endpoints or UI components
- [ ] `just restart` succeeds with new table definitions
