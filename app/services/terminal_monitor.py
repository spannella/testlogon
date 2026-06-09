"""Terminal Monitoring & Feedback Loop service (AGENT-006).

Captures terminal output, matches patterns for completion/feedback/error
signals, creates feedback requests, and injects user responses.
"""

from __future__ import annotations

import logging
import re
from collections import deque
from typing import Any, Callable, Dict, List, Optional
from uuid import uuid4

from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

DEFAULT_FEEDBACK_TIMEOUT_SECONDS = 14400  # 4 hours

# ─── ReDoS guards for user-supplied patterns (GAP-0087) ─────────────────────
# User-submitted regexes are validated only for syntax by re.compile, which does
# not catch catastrophic backtracking (e.g. "(a+)+$" or "(x+x+)+y"). A
# pathological pattern would later pin a CPU core and hang the single-worker
# monitoring loop on live terminal output.
#
# Guard at write time with (1) a length cap and (2) a static structural check
# that rejects nested unbounded quantifiers — the canonical catastrophic shape
# where a quantifier (+, *, {n,}) is applied to a group whose body itself
# contains an unbounded quantifier. The structural check NEVER executes the
# candidate regex, so a malicious pattern cannot pin a CPU core or starve the
# GIL even during validation. Pure-Python, no AWS dependency, identical in dev
# and prod (SECOPS-007).
_PATTERN_MAX_LEN = 500

# Matches a group "(...)" whose body contains an unbounded quantifier (+ or *),
# immediately followed by another quantifier (+, *, ?, or {). This catches
# (a+)+, (a*)*, (x+x+)+, ([0-9]+)+, (a+){2,}, etc., while leaving simple
# anchored/keyword patterns and bounded quantifiers untouched.
_NESTED_QUANTIFIER = re.compile(r"\([^()]*[+*][^()]*\)[+*?{]")


def _is_safe_pattern(pattern: str) -> bool:
    """Return False if *pattern* exhibits the canonical catastrophic-
    backtracking shape (a nested unbounded quantifier).

    Performed by static inspection of the pattern source — the candidate regex
    is never run, so this guard cannot itself be used as a DoS vector.
    """
    return not _NESTED_QUANTIFIER.search(pattern)

# ─── Default patterns ───────────────────────────────────────────────────────

DEFAULT_PATTERNS: List[Dict[str, str]] = [
    {"name": "feedback_needed", "regex": r"\[AGENT_FEEDBACK_NEEDED\]", "action": "create_feedback"},
    {"name": "complete", "regex": r"\[AGENT_COMPLETE\]", "action": "complete_ticket"},
    {"name": "error", "regex": r"\[AGENT_ERROR\]", "action": "mark_error"},
]

DEFAULT_FEEDBACK_PATTERNS: Dict[str, List[str]] = {
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

AGENT_TYPE_PATTERNS: Dict[str, Dict[str, List[str]]] = {
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
        "error": DEFAULT_FEEDBACK_PATTERNS["error"],
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
        "error": DEFAULT_FEEDBACK_PATTERNS["error"],
    },
    "reviewer": {
        "completion": DEFAULT_FEEDBACK_PATTERNS["completion"] + [
            r"(?i)review (?:posted|submitted)",
            r"(?i)approved with",
        ],
        "feedback_needed": DEFAULT_FEEDBACK_PATTERNS["feedback_needed"],
        "error": DEFAULT_FEEDBACK_PATTERNS["error"],
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
        "error": DEFAULT_FEEDBACK_PATTERNS["error"],
    },
}


# ─── Terminal Output Buffer ─────────────────────────────────────────────────

class TerminalOutputBuffer:
    """Ring buffer for capturing terminal output."""

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
        return [line for line in self._lines if keyword.lower() in line.lower()]

    def add_listener(self, callback: Callable[[str], None]) -> None:
        self._listeners.append(callback)

    def remove_listener(self, callback: Callable) -> None:
        self._listeners.remove(callback)


# In-memory buffers per worker
_worker_buffers: Dict[str, TerminalOutputBuffer] = {}


def get_or_create_buffer(worker_id: str) -> TerminalOutputBuffer:
    """Get or create a terminal output buffer for a worker."""
    if worker_id not in _worker_buffers:
        _worker_buffers[worker_id] = TerminalOutputBuffer()
    return _worker_buffers[worker_id]


# ─── Pattern Matching ───────────────────────────────────────────────────────


class PatternMatcher:
    """Configurable regex pattern matcher for terminal output."""

    def __init__(self, patterns: Optional[Dict[str, List[str]]] = None):
        self._patterns = patterns or DEFAULT_FEEDBACK_PATTERNS
        self._compiled: Dict[str, List[re.Pattern]] = {}
        self._compile_all()

    def _compile_all(self) -> None:
        for category, pattern_list in self._patterns.items():
            self._compiled[category] = []
            for p in pattern_list:
                try:
                    self._compiled[category].append(re.compile(p))
                except re.error:
                    logger.warning("Invalid regex pattern: %s", p)

    def match(self, text: str) -> Optional[Dict[str, str]]:
        """Check text against all patterns. Returns first match or None."""
        for category, compiled_list in self._compiled.items():
            for pattern in compiled_list:
                m = pattern.search(text)
                if m:
                    return {
                        "signal": category,
                        "pattern": pattern.pattern,
                        "match": m.group(0),
                    }
        return None


# ─── Integration: output → buffer → pattern match ───────────────────────────


def get_default_patterns_for_worker(worker_id: str) -> Dict[str, List[str]]:
    """Return per-worker pattern config, falling back to defaults.

    If a custom pattern config has been stored for the worker, use it;
    otherwise fall back to the built-in defaults.
    """
    custom = get_worker_pattern_config(worker_id)
    return custom or DEFAULT_FEEDBACK_PATTERNS


def process_terminal_output(
    worker_id: str,
    chunk: str,
) -> Optional[Dict[str, str]]:
    """Feed a chunk of terminal output through the buffer and pattern matcher.

    Appends *chunk* to the worker's ring buffer, then runs the PatternMatcher
    against the most recent 2000 characters of buffered output.

    Returns a signal dict ``{"signal": <category>, "pattern": ..., "match": ...}``
    if a pattern fires, else ``None``. This is the integration point the SSH
    WebSocket output forwarding loop taps into so live agent terminal output
    flows through the AGENT-006 detection pipeline.
    """
    buf = get_or_create_buffer(worker_id)
    buf.append(chunk)
    recent = buf.get_recent(2000)
    patterns = get_default_patterns_for_worker(worker_id)
    matcher = PatternMatcher(patterns)
    signal = matcher.match(recent)
    if signal:
        logger.info(
            "Terminal signal '%s' detected for worker %s",
            signal["signal"], worker_id,
        )
    return signal


# ─── Feedback CRUD ───────────────────────────────────────────────────────────


def create_feedback_request(
    user_id: str,
    worker_id: str,
    ticket_id: str,
    *,
    question: str,
    terminal_context: str = "",
    detected_pattern: str = "",
    timeout_seconds: int = DEFAULT_FEEDBACK_TIMEOUT_SECONDS,
    timeout_action: str = "skip",
) -> Dict[str, Any]:
    """Create a feedback request when the agent needs human input."""
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
        "terminal_context": terminal_context[-2000:] if terminal_context else "",
        "detected_pattern": detected_pattern,
        "response_text": "",
        "responded_at": 0,
        "timeout_at": ts + timeout_seconds,
        "timeout_action": timeout_action,
        "created_at": ts,
        "notified": False,
    }
    T.agent_feedback.put_item(Item=item)

    # Pause the agent so it stops processing until the human responds. Mirrors
    # the symmetric "working" resume in respond_to_feedback (GAP-0011). The
    # worker may already be in awaiting_feedback (duplicate signal), in a
    # terminal state, or deleted in the meantime; log and continue so the
    # feedback record is still returned to the caller. (GAP-0086)
    from app.services import agent_orchestrator
    try:
        agent_orchestrator.transition_agent_state(
            user_id, worker_id, "awaiting_feedback"
        )
        logger.info(
            "Agent %s transitioned to awaiting_feedback for request %s",
            worker_id, request_id,
        )
    except (ValueError, LookupError) as exc:
        logger.warning(
            "Could not transition worker %s to awaiting_feedback for "
            "request %s: %s",
            worker_id, request_id, exc,
        )

    logger.info(
        "Created feedback request %s for worker %s (ticket %s)",
        request_id, worker_id, ticket_id,
    )
    return item


def respond_to_feedback(
    user_id: str,
    worker_id: str,
    request_id: str,
    response_text: str,
) -> Dict[str, Any]:
    """Submit a user's response to a feedback request."""
    ts = now_ts()

    # Verify the request exists and is pending
    existing = get_feedback_request(worker_id, request_id)
    if not existing:
        raise LookupError("Feedback request not found")
    if existing.get("feedback_status") != "pending":
        raise ValueError(
            f"Cannot respond to feedback in status '{existing.get('feedback_status')}'"
        )

    T.agent_feedback.update_item(
        Key={"pk": f"WORKER#{worker_id}", "sk": f"FEEDBACK#{request_id}"},
        UpdateExpression="SET feedback_status = :st, response_text = :rt, responded_at = :ra",
        ExpressionAttributeValues={
            ":st": "responded",
            ":rt": response_text,
            ":ra": ts,
        },
    )

    logger.info(
        "Responded to feedback %s for worker %s",
        request_id, worker_id,
    )

    # Inject the response into the worker's terminal buffer so subsequent
    # pattern-matching rounds (and any live terminal viewers) have context.
    buf = get_or_create_buffer(worker_id)
    buf.append(f"\n[User response]: {response_text}\n")

    # Transition the agent back to "working" so it resumes instead of staying
    # stuck in "awaiting_feedback". The worker may have been manually
    # transitioned or deleted in the meantime; log and continue if so.
    from app.services import agent_orchestrator
    try:
        agent_orchestrator.transition_agent_state(user_id, worker_id, "working")
        logger.info(
            "Agent %s transitioned to working after feedback response %s",
            worker_id, request_id,
        )
    except (ValueError, LookupError) as exc:
        logger.warning(
            "Could not transition worker %s to working after feedback "
            "response %s: %s",
            worker_id, request_id, exc,
        )

    return get_feedback_request(worker_id, request_id)


def mark_feedback_responded(
    worker_id: str,
    request_id: str,
    response_text: str,
) -> Optional[Dict[str, Any]]:
    """Mark a pending feedback request as responded WITHOUT re-injecting the
    response into the worker's terminal ring buffer.

    This is the variant used by the *interactive* agent-session terminal
    (ACS-005). In that path the user's answer is typed straight into the live
    Claude PTY via ``bridge.send_input``; the PTY echoes it back and that echo
    is already tapped into ``process_terminal_output`` on the next poll. So the
    response text reaches the monitor buffer through the normal output tap —
    calling ``respond_to_feedback`` (which also ``buf.append``s
    ``[User response]: …``) would inject the same answer a SECOND time and skew
    pattern matching. This helper therefore only flips the feedback record's
    status (keeping the monitor's feedback CRUD view consistent) and does NOT
    touch the buffer or the orchestrator state.

    Idempotent: a non-pending or missing request is a no-op (returns the
    current record or ``None``). Never raises — a bookkeeping failure must not
    interrupt the live terminal.
    """
    ts = now_ts()
    existing = get_feedback_request(worker_id, request_id)
    if not existing or existing.get("feedback_status") != "pending":
        return existing
    try:
        T.agent_feedback.update_item(
            Key={"pk": f"WORKER#{worker_id}", "sk": f"FEEDBACK#{request_id}"},
            UpdateExpression=(
                "SET feedback_status = :st, response_text = :rt, responded_at = :ra"
            ),
            ExpressionAttributeValues={
                ":st": "responded",
                ":rt": response_text,
                ":ra": ts,
            },
        )
    except Exception:  # pragma: no cover - defensive bookkeeping
        logger.exception(
            "mark_feedback_responded failed worker=%s request=%s",
            worker_id, request_id,
        )
        return existing
    logger.info(
        "Marked feedback %s responded (interactive, no buffer re-inject) "
        "for worker %s",
        request_id, worker_id,
    )
    return get_feedback_request(worker_id, request_id)


def get_feedback_request(
    worker_id: str, request_id: str,
) -> Optional[Dict[str, Any]]:
    """Get a single feedback request."""
    resp = T.agent_feedback.get_item(
        Key={"pk": f"WORKER#{worker_id}", "sk": f"FEEDBACK#{request_id}"}
    )
    return resp.get("Item")


def list_feedback_requests(
    worker_id: str,
    *,
    status: Optional[str] = None,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """List feedback requests for a worker, optionally filtered by status."""
    if status:
        resp = T.agent_feedback.query(
            IndexName="ByStatus",
            KeyConditionExpression="pk = :pk AND feedback_status = :st",
            ExpressionAttributeValues={
                ":pk": f"WORKER#{worker_id}",
                ":st": status,
            },
            Limit=limit,
        )
    else:
        resp = T.agent_feedback.query(
            KeyConditionExpression="pk = :pk AND begins_with(sk, :prefix)",
            ExpressionAttributeValues={
                ":pk": f"WORKER#{worker_id}",
                ":prefix": "FEEDBACK#",
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
    existing = get_feedback_request(worker_id, request_id)
    if not existing:
        raise LookupError("Feedback request not found")
    if existing.get("feedback_status") != "pending":
        raise ValueError(
            f"Cannot skip feedback in status '{existing.get('feedback_status')}'"
        )

    T.agent_feedback.update_item(
        Key={"pk": f"WORKER#{worker_id}", "sk": f"FEEDBACK#{request_id}"},
        UpdateExpression="SET feedback_status = :st",
        ExpressionAttributeValues={":st": "skipped"},
    )

    logger.info("Skipped feedback %s for worker %s", request_id, worker_id)
    return get_feedback_request(worker_id, request_id)


def check_feedback_timeouts() -> int:
    """Background task: find and handle timed-out feedback requests.

    Scans for pending requests where now > timeout_at.
    Returns count of timed-out requests handled.
    """
    handled = 0
    ts = now_ts()
    # Scan is acceptable here as this runs on a background interval
    resp = T.agent_feedback.scan(
        FilterExpression="feedback_status = :pending AND timeout_at < :now",
        ExpressionAttributeValues={":pending": "pending", ":now": ts},
        Limit=100,
    )
    for item in resp.get("Items", []):
        worker_id = item["worker_id"]
        request_id = item["request_id"]
        T.agent_feedback.update_item(
            Key={"pk": f"WORKER#{worker_id}", "sk": f"FEEDBACK#{request_id}"},
            UpdateExpression="SET feedback_status = :st",
            ExpressionAttributeValues={":st": "timed_out"},
        )
        handled += 1
        logger.info("Timed out feedback %s for worker %s", request_id, worker_id)
    return handled


# ─── Terminal Output ─────────────────────────────────────────────────────────


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


# ─── Pattern Config ──────────────────────────────────────────────────────────


def get_pattern_config(agent_type: str) -> Dict[str, List[str]]:
    """Get the current pattern configuration for an agent type."""
    return AGENT_TYPE_PATTERNS.get(agent_type, DEFAULT_FEEDBACK_PATTERNS)


def update_pattern_config(
    user_id: str,
    worker_id: str,
    patterns: Dict[str, List[str]],
) -> Dict[str, List[str]]:
    """Update custom pattern configuration for a worker.

    Validates each regex pattern before storing.
    """
    # Validate all patterns compile
    for category, pattern_list in patterns.items():
        if category not in ("completion", "feedback_needed", "error"):
            raise ValueError(f"Invalid pattern category: {category}")
        if len(pattern_list) > 50:
            raise ValueError(f"Too many patterns in category {category} (max 50)")
        for p in pattern_list:
            # Length cap — reject absurdly long patterns outright (GAP-0087).
            if len(p) > _PATTERN_MAX_LEN:
                raise ValueError(
                    f"Pattern too long (max {_PATTERN_MAX_LEN} chars): "
                    f"'{p[:80]}...'"
                )
            # ReDoS safety check — reject catastrophic backtracking before
            # compiling/storing (GAP-0087). Done first so a pathological
            # pattern is never executed.
            if not _is_safe_pattern(p):
                raise ValueError(
                    f"Pattern '{p}' rejected by safety check "
                    f"(possible catastrophic backtracking from nested "
                    f"quantifiers). Use a simpler pattern."
                )
            # Syntax check.
            try:
                re.compile(p)
            except re.error as exc:
                raise ValueError(f"Invalid regex pattern '{p}': {exc}")

    # Store in feedback table as a config record
    T.agent_feedback.put_item(
        Item={
            "pk": f"WORKER#{worker_id}",
            "sk": "CONFIG#patterns",
            "user_id": user_id,
            "worker_id": worker_id,
            "patterns": patterns,
            "updated_at": now_ts(),
        }
    )
    return patterns


def get_worker_pattern_config(worker_id: str) -> Optional[Dict[str, List[str]]]:
    """Get custom pattern config for a worker, if any."""
    resp = T.agent_feedback.get_item(
        Key={"pk": f"WORKER#{worker_id}", "sk": "CONFIG#patterns"}
    )
    item = resp.get("Item")
    if item:
        return item.get("patterns")
    return None


def test_patterns(
    patterns: Dict[str, List[str]],
    sample_text: str,
) -> List[Dict[str, str]]:
    """Test patterns against sample text. Returns list of matches."""
    matches = []
    for category, pattern_list in patterns.items():
        for p in pattern_list:
            try:
                compiled = re.compile(p)
                m = compiled.search(sample_text)
                if m:
                    matches.append({
                        "signal": category,
                        "pattern": p,
                        "match": m.group(0),
                    })
            except re.error:
                continue
    return matches
