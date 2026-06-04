"""QA Agent service (AGENT-009).

The QA Agent is a *type config* that plugs into the Worker Agent Framework
(AGENT-003). It owns:

* qa_config storage/validation on the ``agent_types`` table
* discovery + atomic claiming of QA-eligible tickets (``code_complete`` status
  or carrying a ``type:qa`` label) on the ``tickets`` table
* a deterministic, mockable lifecycle state machine
  (claim -> checkout -> gen_tests -> run -> evaluate -> file_bugs -> review ->
  update_ticket)
* structured qa_output storage on the ``agent_runs`` table
* auto-filing of structured bug tickets (with reproduction metadata)
* QA report rendering + screenshot presigned-URL retrieval
* QA throughput / defect-detection metrics aggregation

Real shell/git/test/PR/S3 execution is gated behind
``S.agent_qa_execute_commands``. When disabled (the default, and always in E2E),
the workflow is generated and its transitions are driven in-memory so tests are
deterministic.

The ``agent_types`` and ``agent_runs`` tables are shared with the Coder Agent
(AGENT-008); QA reuses them and the idempotent ``ensure_tables`` bootstrap.
"""

from __future__ import annotations

import logging
import re
from decimal import Decimal
from typing import Any, Dict, List, Optional

from botocore.exceptions import ClientError

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services import agent_coder as coder_svc
from app.services import tickets as tickets_svc

logger = logging.getLogger("app.agent_qa")

QA_AGENT_TYPE = "qa"
QA_LABEL = "type:qa"

_TEST_FRAMEWORKS = ("playwright", "cypress", "pytest")
_BROWSERS = ("chromium", "firefox", "webkit")
_REGRESSION_SCOPES = ("full", "affected", "none")
_CODING_TOOLS = ("claude_code", "codex")
_OUTPUT_TAIL_MAX = 5_000  # cap per test_output stored on a bug ticket (security §7)

_CONFIG_FIELDS = (
    "test_framework",
    "browser",
    "test_dir",
    "test_file_pattern",
    "test_run_command",
    "test_run_specific_command",
    "regression_scope",
    "regression_command",
    "screenshot_enabled",
    "screenshot_on_failure",
    "screenshot_s3_prefix",
    "visual_diff_threshold",
    "max_test_time_seconds",
    "flaky_retry_count",
    "bug_ticket_space_id",
    "pr_review_enabled",
    "coding_tool",
    "coding_tool_model",
)

_CONFIG_DEFAULTS: Dict[str, Any] = {
    "test_framework": "playwright",
    "browser": "chromium",
    "test_dir": "frontend/e2e/",
    "test_file_pattern": "{feature}.spec.ts",
    "test_run_command": "cd frontend && npx playwright test",
    "test_run_specific_command": "cd frontend && npx playwright test e2e/{file}",
    "regression_scope": "affected",
    "regression_command": "just e2e",
    "screenshot_enabled": True,
    "screenshot_on_failure": False,
    "screenshot_s3_prefix": "qa-screenshots/",
    "visual_diff_threshold": 0.01,
    "max_test_time_seconds": 1800,
    "flaky_retry_count": 2,
    "pr_review_enabled": True,
    "coding_tool": "claude_code",
}

_INT_FIELDS = ("max_test_time_seconds", "flaky_retry_count")
_FLOAT_FIELDS = ("visual_diff_threshold",)


# ---------------------------------------------------------------------------
# Table bootstrap (shared with the coder agent; tables are additive)
# ---------------------------------------------------------------------------


def ensure_tables() -> None:
    coder_svc.ensure_tables()


def _type_pk(type_id: str) -> str:
    return f"TYPE#{type_id}"


def _run_pk(run_id: str) -> str:
    return f"RUN#{run_id}"


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def validate_qa_config(config: Dict[str, Any]) -> List[str]:
    """Return list of validation errors (empty = valid)."""
    errors: List[str] = []

    framework = config.get("test_framework", "playwright")
    if framework not in _TEST_FRAMEWORKS:
        errors.append("test_framework must be one of: playwright, cypress, pytest")

    browser = config.get("browser", "chromium")
    if browser not in _BROWSERS:
        errors.append("browser must be one of: chromium, firefox, webkit")

    scope = config.get("regression_scope", "affected")
    if scope not in _REGRESSION_SCOPES:
        errors.append("regression_scope must be one of: full, affected, none")

    coding_tool = config.get("coding_tool", "claude_code")
    if coding_tool not in _CODING_TOOLS:
        errors.append("coding_tool must be claude_code or codex")

    for cmd_field in ("test_run_command", "test_run_specific_command"):
        val = config.get(cmd_field, _CONFIG_DEFAULTS[cmd_field])
        if val is not None and not str(val).strip():
            errors.append(f"{cmd_field} cannot be empty")

    threshold = config.get("visual_diff_threshold")
    if threshold is not None:
        try:
            t = float(threshold)
            if t < 0.0 or t > 1.0:
                errors.append("visual_diff_threshold must be between 0.0 and 1.0")
        except (TypeError, ValueError):
            errors.append("visual_diff_threshold must be a number")

    max_time = config.get("max_test_time_seconds")
    if max_time is not None:
        try:
            if int(max_time) < 300:
                errors.append("max_test_time_seconds must be at least 300")
        except (TypeError, ValueError):
            errors.append("max_test_time_seconds must be an integer")

    retries = config.get("flaky_retry_count")
    if retries is not None:
        try:
            r = int(retries)
            if r < 0 or r > 5:
                errors.append("flaky_retry_count must be between 0 and 5")
        except (TypeError, ValueError):
            errors.append("flaky_retry_count must be an integer")

    return errors


def _normalize_config(config: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for key in _CONFIG_FIELDS:
        if key in config and config[key] is not None:
            out[key] = config[key]
    for key, default in _CONFIG_DEFAULTS.items():
        out.setdefault(key, default)
    return _coerce_numbers(out)


def _coerce_numbers(config: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(config)
    for field in _INT_FIELDS:
        if field in out and out[field] is not None:
            try:
                out[field] = int(out[field])
            except (TypeError, ValueError):
                pass
    for field in _FLOAT_FIELDS:
        if field in out and out[field] is not None:
            try:
                out[field] = float(out[field])
            except (TypeError, ValueError):
                pass
    return out


def get_agent_type(*, agent_type_id: str) -> Optional[Dict[str, Any]]:
    ensure_tables()
    resp = T.agent_types.get_item(Key={"pk": _type_pk(agent_type_id), "sk": "META"})
    return resp.get("Item")


def get_qa_config(*, agent_type_id: str) -> Optional[Dict[str, Any]]:
    """Fetch qa_config from agent_types table (CONFIG item)."""
    ensure_tables()
    resp = T.agent_types.get_item(Key={"pk": _type_pk(agent_type_id), "sk": "CONFIG"})
    item = resp.get("Item")
    if not item:
        return None
    config = item.get("qa_config")
    if not config:
        return None
    return _coerce_numbers(config)


def update_qa_config(
    *, agent_type_id: str, owner_sub: str, config: Dict[str, Any]
) -> Dict[str, Any]:
    """Validate and persist qa_config. Auto-creates the type META if absent."""
    ensure_tables()
    if get_agent_type(agent_type_id=agent_type_id) is None:
        coder_svc.create_agent_type(
            agent_type_id=agent_type_id, owner_sub=owner_sub, agent_type=QA_AGENT_TYPE
        )
    normalized = _normalize_config(config)
    ts = now_ts()
    # DynamoDB rejects Python floats; persist float fields as Decimal. The read
    # path (_coerce_numbers) converts them back to float for the API response.
    persisted = dict(normalized)
    for field in _FLOAT_FIELDS:
        if field in persisted and persisted[field] is not None:
            persisted[field] = Decimal(str(persisted[field]))
    T.agent_types.put_item(
        Item={
            "pk": _type_pk(agent_type_id),
            "sk": "CONFIG",
            "agent_type_id": agent_type_id,
            "agent_type": QA_AGENT_TYPE,
            "owner_sub": owner_sub,
            "qa_config": persisted,
            "updated_at": ts,
        }
    )
    T.agent_types.update_item(
        Key={"pk": _type_pk(agent_type_id), "sk": "META"},
        UpdateExpression="SET agent_type = :t, updated_at = :u",
        ExpressionAttributeValues={":t": QA_AGENT_TYPE, ":u": ts},
    )
    result = dict(normalized)
    result["updated_at"] = ts
    return result


def config_schema() -> Dict[str, Any]:
    return {
        "fields": {
            "test_framework": {"type": "enum", "values": list(_TEST_FRAMEWORKS), "default": "playwright"},
            "browser": {"type": "enum", "values": list(_BROWSERS), "default": "chromium"},
            "test_dir": {"type": "string", "default": "frontend/e2e/"},
            "test_file_pattern": {"type": "string", "default": "{feature}.spec.ts"},
            "test_run_command": {"type": "string"},
            "test_run_specific_command": {"type": "string"},
            "regression_scope": {"type": "enum", "values": list(_REGRESSION_SCOPES), "default": "affected"},
            "regression_command": {"type": "string", "default": "just e2e"},
            "screenshot_enabled": {"type": "boolean", "default": True},
            "screenshot_on_failure": {"type": "boolean", "default": False},
            "screenshot_s3_prefix": {"type": "string", "default": "qa-screenshots/"},
            "visual_diff_threshold": {"type": "number", "min": 0.0, "max": 1.0, "default": 0.01},
            "max_test_time_seconds": {"type": "integer", "min": 300, "max": 14400, "default": 1800},
            "flaky_retry_count": {"type": "integer", "min": 0, "max": 5, "default": 2},
            "bug_ticket_space_id": {"type": "string"},
            "pr_review_enabled": {"type": "boolean", "default": True},
            "coding_tool": {"type": "enum", "values": list(_CODING_TOOLS), "default": "claude_code"},
            "coding_tool_model": {"type": "string"},
        }
    }


# ---------------------------------------------------------------------------
# Ticket & PR resolution
# ---------------------------------------------------------------------------


def resolve_pr_from_ticket(*, ticket: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Extract PR info from ticket metadata (set by the Coder Agent)."""
    meta = ticket.get("metadata") or {}
    pr_url = meta.get("pr_url") or ""
    if not pr_url:
        return None
    pr_branch = meta.get("pr_branch") or ""
    pr_number = 0
    match = re.search(r"/pull/(\d+)", pr_url)
    if match:
        pr_number = int(match.group(1))
    return {"pr_url": pr_url, "pr_branch": pr_branch, "pr_number": pr_number}


def find_qa_eligible_tickets(
    *,
    space_id: Optional[str] = None,
    limit: int = 10,
) -> List[Dict[str, Any]]:
    """Return QA-eligible tickets: status=code_complete OR carrying a type:qa label.

    Skips tickets already claimed by a QA agent (status qa_in_progress /
    qa_approved or with a qa_agent_run_id). Returns oldest-first (FIFO).
    """
    ensure_tables()
    seen: Dict[str, Dict[str, Any]] = {}

    def _consider(ticket: Dict[str, Any]) -> None:
        tid = ticket.get("ticket_id")
        if not tid or tid in seen:
            return
        status = ticket.get("status")
        labels = list(ticket.get("labels", []) or [])
        is_eligible = status == "code_complete" or QA_LABEL in labels
        if not is_eligible:
            return
        if ticket.get("qa_agent_run_id"):
            return
        if status in ("qa_in_progress", "qa_approved"):
            return
        if space_id is not None and ticket.get("space_id") != space_id:
            return
        pr = resolve_pr_from_ticket(ticket=ticket)
        seen[tid] = {
            "ticket_id": tid,
            "subject": ticket.get("subject", ""),
            "status": status,
            "pr_url": (pr or {}).get("pr_url"),
            "pr_branch": (pr or {}).get("pr_branch"),
            "created_at": int(ticket.get("created_at", 0) or 0),
            "labels": sorted(labels),
        }

    # 1) code_complete tickets via the status index.
    table = tickets_svc.STORE._table  # noqa: SLF001 - internal reuse
    try:
        resp = table.query(
            IndexName=S.tickets_status_index_name,
            KeyConditionExpression="gsi2pk = :pk",
            ExpressionAttributeValues={":pk": tickets_svc._status_index_pk("code_complete")},  # noqa: SLF001
            ScanIndexForward=True,
        )
        for row in resp.get("Items", []):
            ticket = tickets_svc.STORE.get_ticket(row.get("ticket_id", ""))
            if ticket:
                _consider(ticket)
    except ClientError:
        logger.debug("find_qa_eligible_tickets: status index query failed; relying on label scan")

    # 2) type:qa labelled tickets via the label fan-out partition.
    try:
        resp = table.query(
            KeyConditionExpression="pk = :pk",
            ExpressionAttributeValues={":pk": tickets_svc.label_index_pk(QA_LABEL)},
            ScanIndexForward=True,
        )
        for row in resp.get("Items", []):
            ticket = tickets_svc.STORE.get_ticket(row.get("ticket_id", ""))
            if ticket:
                _consider(ticket)
    except ClientError:
        logger.debug("find_qa_eligible_tickets: label query failed")

    out = sorted(seen.values(), key=lambda t: (t["created_at"], t["ticket_id"]))
    return out[:limit]


def claim_qa_ticket(*, agent_run_id: str, ticket_id: str, agent_sub: str) -> Dict[str, Any]:
    """Atomically claim a code_complete ticket for QA.

    Sets status to qa_in_progress and stamps qa_agent_run_id. Raises LookupError
    if the ticket does not exist, ValueError("invalid_status") if the ticket is
    not in code_complete status, and ValueError("already_claimed") if another
    QA agent already holds it.
    """
    ticket = tickets_svc.STORE.get_ticket(ticket_id)
    if not ticket:
        raise LookupError("Ticket not found")
    if ticket.get("status") != "code_complete":
        raise ValueError("invalid_status")
    table = tickets_svc.STORE._table  # noqa: SLF001
    ts = now_ts()
    try:
        table.update_item(
            Key={"pk": f"TICKET#{ticket_id}", "sk": "META"},
            UpdateExpression=(
                "SET #st = :qa, qa_agent_run_id = :run, gsi2pk = :gpk, gsi2sk = :gsk, updated_at = :ts"
            ),
            ConditionExpression=(
                "#st = :cc AND attribute_not_exists(qa_agent_run_id)"
            ),
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={
                ":qa": "qa_in_progress",
                ":cc": "code_complete",
                ":run": agent_run_id,
                ":gpk": tickets_svc._status_index_pk("qa_in_progress"),  # noqa: SLF001
                ":gsk": tickets_svc._updated_index_sk(ts, ticket_id),  # noqa: SLF001
                ":ts": ts,
            },
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code == "ConditionalCheckFailedException":
            # Re-read to disambiguate already-claimed vs status drift.
            cur = tickets_svc.STORE.get_ticket(ticket_id)
            if cur and cur.get("status") != "code_complete" and not cur.get("qa_agent_run_id"):
                raise ValueError("invalid_status") from exc
            raise ValueError("already_claimed") from exc
        raise
    return {
        "ok": True,
        "ticket_id": ticket_id,
        "status": "qa_in_progress",
        "qa_agent_run_id": agent_run_id,
        "claimed_at": ts,
    }


# ---------------------------------------------------------------------------
# Acceptance criteria extraction
# ---------------------------------------------------------------------------

_AC_HEADER_RE = re.compile(r"acceptance\s+criteria", re.IGNORECASE)
_CHECKLIST_RE = re.compile(r"^\s*[-*]\s*\[[ xX]\]\s*(.+)$")
_BULLET_RE = re.compile(r"^\s*[-*]\s+(.+)$")
_NUMBERED_RE = re.compile(r"^\s*\d+[.)]\s+(.+)$")
_AC_CAP = 20


def extract_acceptance_criteria(*, ticket: Dict[str, Any]) -> List[str]:
    """Parse ticket description/messages for acceptance criteria.

    Recognises markdown checklists, bullet/numbered lists (especially under an
    'Acceptance Criteria' header). Capped at 20 items.
    """
    text = ""
    meta = ticket.get("metadata") or {}
    if meta.get("acceptance_criteria"):
        ac = meta["acceptance_criteria"]
        if isinstance(ac, list):
            return [str(x).strip() for x in ac if str(x).strip()][:_AC_CAP]
        text = str(ac)
    if not text:
        messages = ticket.get("messages") or []
        if messages:
            text = str(messages[0].get("body", ""))

    lines = text.splitlines()
    criteria: List[str] = []
    in_ac_section = False
    for line in lines:
        if _AC_HEADER_RE.search(line):
            in_ac_section = True
            continue
        m = _CHECKLIST_RE.match(line)
        if m:
            criteria.append(m.group(1).strip())
            continue
        if in_ac_section:
            m = _BULLET_RE.match(line) or _NUMBERED_RE.match(line)
            if m:
                criteria.append(m.group(1).strip())
                continue
            if line.strip() and not line.startswith((" ", "\t")):
                # A non-indented, non-list line ends the AC section unless it is a header.
                if not line.lstrip().startswith("#"):
                    in_ac_section = False

    # de-dupe preserving order
    out: List[str] = []
    for c in criteria:
        if c and c not in out:
            out.append(c)
    return out[:_AC_CAP]


# ---------------------------------------------------------------------------
# Prompt / command builders
# ---------------------------------------------------------------------------


def feature_slug_from_ticket(*, ticket: Dict[str, Any]) -> str:
    return coder_svc.slugify(ticket.get("subject", "")) or "feature"


def render_test_file_name(*, pattern: str, feature: str) -> str:
    return (pattern or "{feature}.spec.ts").replace("{feature}", feature)


def build_test_generation_prompt(
    *,
    ticket: Dict[str, Any],
    acceptance_criteria: List[str],
    pr_diff: str,
    test_framework: str,
    test_file_pattern: str,
    existing_test_files: Optional[List[str]] = None,
) -> str:
    feature = feature_slug_from_ticket(ticket=ticket)
    test_file = render_test_file_name(pattern=test_file_pattern, feature=feature)
    ac_block = "\n".join(f"- {c}" for c in acceptance_criteria) or "(none extracted)"
    diff_tail = (pr_diff or "")[:_OUTPUT_TAIL_MAX]
    examples = ", ".join((existing_test_files or [])[:10]) or "(none)"
    parts = [
        f"Write {test_framework} E2E tests for ticket "
        f"{ticket.get('ticket_id', '')}: {ticket.get('subject', '')}.",
        "",
        "Acceptance criteria to cover:",
        ac_block,
        "",
        "PR diff (truncated):",
        diff_tail or "(no diff available)",
        "",
        f"Follow existing conventions from these test files: {examples}.",
        f"Write the new tests to: {test_file}",
        "Do NOT modify production source code — only add the test file.",
    ]
    return "\n".join(parts)


def _affected_test_files(*, changed_files: List[str], test_dir: str) -> List[str]:
    """Heuristic source -> test mapping (see spec §4.8)."""
    out: List[str] = []
    for f in changed_files or []:
        m = re.match(r"app/services/([a-zA-Z0-9_]+)\.py$", f)
        if m:
            name = m.group(1)
            out.append(f"tests/test_{name}.py")
            out.append(f"frontend/e2e/{name}.spec.ts")
            continue
        m = re.match(r"frontend/src/pages/([a-zA-Z0-9_]+)/", f)
        if m:
            out.append(f"frontend/e2e/{m.group(1)}.spec.ts")
    # de-dupe preserving order
    seen: List[str] = []
    for f in out:
        if f not in seen:
            seen.append(f)
    return seen


def build_test_run_commands(
    *,
    test_file: str,
    test_run_specific_command: str,
    regression_scope: str,
    regression_command: str,
    affected_files: Optional[List[str]] = None,
) -> List[str]:
    """Return ordered shell commands: (1) run new tests, (2) regression suite."""
    commands: List[str] = []
    new_cmd = (test_run_specific_command or "").replace("{file}", test_file.replace("frontend/e2e/", ""))
    commands.append(new_cmd)
    if regression_scope == "full":
        commands.append(regression_command)
    elif regression_scope == "affected":
        for f in affected_files or []:
            commands.append(f"npx playwright test {f}" if f.endswith(".spec.ts") else f"pytest {f}")
    # scope == none -> no regression command
    return commands


# ---------------------------------------------------------------------------
# Test result parsing / flaky detection / verdict
# ---------------------------------------------------------------------------


def parse_test_results(*, stdout: str, stderr: str, framework: str) -> Dict[str, Any]:
    """Best-effort parse of test framework stdout to counts + failing names."""
    text = f"{stdout or ''}\n{stderr or ''}"
    passed = 0
    failed = 0
    failures: List[str] = []
    if framework in ("playwright", "cypress"):
        m_pass = re.search(r"(\d+)\s+passed", text)
        m_fail = re.search(r"(\d+)\s+failed", text)
        passed = int(m_pass.group(1)) if m_pass else 0
        failed = int(m_fail.group(1)) if m_fail else 0
        for line in text.splitlines():
            fm = re.search(r"✘|✗|failed:?\s+(.+)", line)
            if fm and fm.lastindex:
                failures.append(fm.group(1).strip())
    else:  # pytest
        m = re.search(r"(\d+)\s+passed", text)
        passed = int(m.group(1)) if m else 0
        m = re.search(r"(\d+)\s+failed", text)
        failed = int(m.group(1)) if m else 0
        for line in text.splitlines():
            fm = re.match(r"FAILED\s+(\S+)", line.strip())
            if fm:
                failures.append(fm.group(1))
    return {"passed": passed, "failed": failed, "failures": failures}


def detect_flaky_tests(*, initial_failures: List[str], retry_results: Dict[str, bool]) -> List[str]:
    """Tests that failed initially but passed on retry are flaky.

    ``retry_results`` maps test name -> passed-on-retry bool.
    """
    flaky: List[str] = []
    for name in initial_failures or []:
        if retry_results.get(name) is True:
            flaky.append(name)
    return flaky


def determine_verdict(
    *,
    new_tests_pass: int,
    new_tests_fail: int,
    regression_fail: int,
    flaky_tests: List[str],
    infra_error: bool = False,
) -> str:
    """pass (all green) / fail (real failures) / flaky (only flaky) / error."""
    if infra_error:
        return "error"
    real_failures = new_tests_fail + regression_fail
    if real_failures == 0:
        return "pass"
    # If every recorded failure is accounted for by flaky retries, it's a soft pass.
    if flaky_tests and real_failures <= len(flaky_tests):
        return "flaky"
    return "fail"


# ---------------------------------------------------------------------------
# Bug filing
# ---------------------------------------------------------------------------


def _classify_severity(*, failure: Dict[str, Any]) -> str:
    kind = (failure.get("kind") or "").lower()
    if kind in ("crash", "error", "exception"):
        return "critical"
    if kind in ("timeout",):
        return "minor"
    return "major"  # assertion failures default to major


def build_bug_ticket(
    *,
    source_ticket: Dict[str, Any],
    pr_url: str,
    agent_run_id: str,
    failure: Dict[str, Any],
    screenshots: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Construct bug ticket data (subject + description + structured metadata)."""
    test_name = failure.get("name", "unknown test")
    expected = failure.get("expected", "Test should pass")
    actual = failure.get("actual", "Test failed")
    repro = failure.get(
        "reproduction_steps",
        f"1. Check out {pr_url}\n2. Run the test `{test_name}`\n3. Observe the failure",
    )
    test_output = str(failure.get("test_output", ""))[-_OUTPUT_TAIL_MAX:]
    severity = _classify_severity(failure=failure)
    shot_urls = [s.get("s3_key", "") for s in (screenshots or []) if s.get("status") == "fail"]
    subject = f"Bug: {test_name}"
    description = (
        f"Auto-filed by QA agent for failing test `{test_name}`.\n\n"
        f"**Expected:** {expected}\n\n"
        f"**Actual:** {actual}\n\n"
        f"**Reproduction:**\n{repro}\n"
    )
    metadata = {
        "bug_source": "qa_agent",
        "source_ticket_id": source_ticket.get("ticket_id", ""),
        "source_pr_url": pr_url,
        "agent_run_id": agent_run_id,
        "reproduction_steps": repro,
        "expected_behavior": expected,
        "actual_behavior": actual,
        "test_output": test_output,
        "screenshot_urls": shot_urls,
        "severity": severity,
    }
    return {
        "subject": subject,
        "description": description,
        "labels": ["type:bugfix", "source:qa_agent", "complexity:low"],
        "metadata": metadata,
        "severity": severity,
    }


def _existing_bug_for_source(*, source_ticket_id: str) -> set[str]:
    """Return the set of test names already covered by an open qa_agent bug for
    this source ticket (for deduplication)."""
    table = tickets_svc.STORE._table  # noqa: SLF001
    covered: set[str] = set()
    try:
        resp = table.query(
            KeyConditionExpression="pk = :pk",
            ExpressionAttributeValues={":pk": tickets_svc.label_index_pk("source:qa_agent")},
            ScanIndexForward=True,
        )
    except ClientError:
        return covered
    for row in resp.get("Items", []):
        ticket = tickets_svc.STORE.get_ticket(row.get("ticket_id", ""))
        if not ticket:
            continue
        meta = ticket.get("metadata") or {}
        if meta.get("source_ticket_id") != source_ticket_id:
            continue
        subj = ticket.get("subject", "")
        if subj.startswith("Bug: "):
            covered.add(subj[len("Bug: "):])
    return covered


def file_bug_tickets(
    *, bugs: List[Dict[str, Any]], space_id: Optional[str], agent_sub: str, source_ticket_id: str = ""
) -> List[str]:
    """Create bug tickets in the ticket system (with dedup). Return ticket IDs."""
    ensure_tables()
    already = _existing_bug_for_source(source_ticket_id=source_ticket_id) if source_ticket_id else set()
    out: List[str] = []
    for bug in bugs:
        test_name = bug["subject"][len("Bug: "):] if bug["subject"].startswith("Bug: ") else bug["subject"]
        if test_name in already:
            continue
        ticket = tickets_svc.STORE.create_ticket(
            owner_sub=agent_sub,
            subject=bug["subject"],
            description=bug["description"],
            space_id=space_id,
            labels=bug.get("labels", []),
            metadata=bug.get("metadata", {}),
        )
        tid = ticket.get("ticket_id")
        if tid:
            out.append(tid)
            already.add(test_name)
    return out


# ---------------------------------------------------------------------------
# PR review
# ---------------------------------------------------------------------------


def build_pr_review_command(*, pr_number: int, verdict: str, report: str) -> str:
    body = (report or "").replace('"', "'")
    if verdict in ("pass", "flaky"):
        return f"gh pr review {pr_number} --approve --body \"{body}\""
    return f"gh pr review {pr_number} --request-changes --body \"{body}\""


def pr_review_action_for_verdict(verdict: str) -> str:
    if verdict in ("pass", "flaky"):
        return "approved"
    if verdict == "fail":
        return "changes_requested"
    return "none"


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def build_qa_report(*, verdict: str, output: Dict[str, Any]) -> str:
    lines: List[str] = []
    lines.append("## Summary")
    lines.append("")
    lines.append(f"**Verdict:** {verdict}")
    lines.append(f"**PR:** {output.get('pr_url', '')}")
    lines.append(f"**Ticket:** {output.get('ticket_id', '')}")
    lines.append(f"**Acceptance criteria covered:** {output.get('acceptance_criteria_count', 0)}")
    lines.append(f"**Duration:** {output.get('total_duration_seconds', 0)}s")
    lines.append("")
    lines.append("## Test Results")
    lines.append("")
    lines.append(
        f"New tests: {output.get('new_tests_pass_count', 0)} passed, "
        f"{output.get('new_tests_fail_count', 0)} failed "
        f"(of {output.get('new_tests_written', 0)} written)"
    )
    lines.append(
        f"Regression: {output.get('regression_tests_pass', 0)} passed, "
        f"{output.get('regression_tests_fail', 0)} failed "
        f"(of {output.get('regression_tests_run', 0)} run)"
    )
    failures = output.get("regression_failures") or []
    if failures:
        lines.append("")
        lines.append("### Regression Failures")
        for f in failures:
            lines.append(f"- {f}")
    flaky = output.get("flaky_tests") or []
    if flaky:
        lines.append("")
        lines.append("## Flaky Tests")
        for f in flaky:
            lines.append(f"- {f}")
    screenshots = output.get("screenshots") or []
    if screenshots:
        lines.append("")
        lines.append("## Screenshots")
        for s in screenshots:
            lines.append(f"- {s.get('name', '')} ({s.get('status', '')}) — {s.get('s3_key', '')}")
    bugs = output.get("bug_ticket_ids") or []
    if bugs:
        lines.append("")
        lines.append("## Bug Tickets Filed")
        for b in bugs:
            lines.append(f"- {b}")
    lines.append("")
    lines.append(f"**PR Review:** {output.get('pr_review_action', 'none')}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Screenshots
# ---------------------------------------------------------------------------


def screenshot_presigned_urls(*, run_id: str) -> List[Dict[str, Any]]:
    """Return screenshots from the stored output with presigned S3 GET URLs.

    In dev/mock mode (or when execution is disabled), the screenshots are stored
    on the run output; we still attempt to mint a presigned URL via the
    in-process moto S3 mock so the contract is exercised. Any S3 error falls
    back to the raw s3_key as the URL.
    """
    output = get_qa_output(run_id=run_id) or {}
    screenshots = output.get("screenshots") or []
    out: List[Dict[str, Any]] = []
    ttl = max(60, int(getattr(S, "agent_qa_screenshot_url_ttl_seconds", 900) or 900))
    bucket = str(getattr(S, "agent_qa_screenshot_bucket", "local-bucket") or "local-bucket")
    s3 = None
    try:
        from app.core.aws_clients import s3_client  # lazy import

        s3 = s3_client()
    except Exception:  # pragma: no cover - defensive
        s3 = None
    for s in screenshots:
        key = s.get("s3_key", "")
        url = key
        if s3 is not None and key:
            try:
                url = s3.generate_presigned_url(
                    ClientMethod="get_object",
                    Params={"Bucket": bucket, "Key": key},
                    ExpiresIn=ttl,
                )
            except Exception:
                url = key
        out.append(
            {
                "name": s.get("name", ""),
                "presigned_url": url,
                "step": s.get("step", ""),
                "status": s.get("status", "pass"),
            }
        )
    return out


# ---------------------------------------------------------------------------
# Output storage
# ---------------------------------------------------------------------------


def build_qa_output(
    *,
    verdict: str,
    pr_url: str,
    pr_branch: str,
    ticket_id: str,
    acceptance_criteria_count: int = 0,
    new_tests_written: int = 0,
    new_test_file: str = "",
    new_tests_pass_count: int = 0,
    new_tests_fail_count: int = 0,
    regression_tests_run: int = 0,
    regression_tests_pass: int = 0,
    regression_tests_fail: int = 0,
    regression_failures: Optional[List[str]] = None,
    screenshots: Optional[List[Dict[str, Any]]] = None,
    bug_ticket_ids: Optional[List[str]] = None,
    pr_review_action: str = "none",
    total_duration_seconds: int = 0,
    flaky_tests: Optional[List[str]] = None,
) -> Dict[str, Any]:
    max_shots = int(getattr(S, "agent_qa_max_screenshots", 50) or 50)
    shots = list(screenshots or [])[:max_shots]
    return {
        "verdict": verdict,
        "pr_url": pr_url,
        "pr_branch": pr_branch,
        "ticket_id": ticket_id,
        "acceptance_criteria_count": int(acceptance_criteria_count or 0),
        "new_tests_written": int(new_tests_written or 0),
        "new_test_file": new_test_file,
        "new_tests_pass_count": int(new_tests_pass_count or 0),
        "new_tests_fail_count": int(new_tests_fail_count or 0),
        "regression_tests_run": int(regression_tests_run or 0),
        "regression_tests_pass": int(regression_tests_pass or 0),
        "regression_tests_fail": int(regression_tests_fail or 0),
        "regression_failures": list(regression_failures or []),
        "screenshots": shots,
        "bug_ticket_ids": list(bug_ticket_ids or []),
        "pr_review_action": pr_review_action,
        "total_duration_seconds": int(total_duration_seconds or 0),
        "flaky_tests": list(flaky_tests or []),
    }


def store_qa_output(*, run_id: str, agent_type_id: str, output: Dict[str, Any]) -> Dict[str, Any]:
    """Persist QA output on the agent_runs table + a metrics rollup row."""
    ensure_tables()
    ts = now_ts()
    item = {
        "pk": _run_pk(run_id),
        "sk": "QA_OUTPUT",
        "run_id": run_id,
        "agent_type_id": agent_type_id,
        "qa_output": output,
        "created_at": ts,
        "completed_at": ts,
        # Metrics index (per-type rollup query).
        "gsi_type_date_pk": f"QA#{agent_type_id}",
        "gsi_type_date_sk": f"DATE#{ts}",
    }
    T.agent_runs.put_item(Item=item)
    return output


def get_qa_output(*, run_id: str) -> Optional[Dict[str, Any]]:
    ensure_tables()
    resp = T.agent_runs.get_item(Key={"pk": _run_pk(run_id), "sk": "QA_OUTPUT"})
    item = resp.get("Item")
    if not item:
        return None
    return item.get("qa_output")


# ---------------------------------------------------------------------------
# Status updates
# ---------------------------------------------------------------------------


def _set_ticket_status(*, ticket_id: str, status: str, report: str) -> Dict[str, Any]:
    ticket = tickets_svc.STORE.get_ticket(ticket_id)
    if not ticket:
        raise LookupError("Ticket not found")
    table = tickets_svc.STORE._table  # noqa: SLF001
    ts = now_ts()
    meta = dict(ticket.get("metadata") or {})
    meta["qa_report"] = (report or "")[:_OUTPUT_TAIL_MAX]
    table.update_item(
        Key={"pk": f"TICKET#{ticket_id}", "sk": "META"},
        UpdateExpression=(
            "SET #st = :s, metadata = :m, gsi2pk = :gpk, gsi2sk = :gsk, updated_at = :ts"
        ),
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={
            ":s": status,
            ":m": meta,
            ":gpk": tickets_svc._status_index_pk(status),  # noqa: SLF001
            ":gsk": tickets_svc._updated_index_sk(ts, ticket_id),  # noqa: SLF001
            ":ts": ts,
        },
    )
    return {"ok": True, "ticket_id": ticket_id, "status": status}


def mark_ticket_qa_approved(*, ticket_id: str, agent_sub: str, report: str) -> Dict[str, Any]:
    return _set_ticket_status(ticket_id=ticket_id, status="qa_approved", report=report)


def mark_ticket_qa_failed(
    *, ticket_id: str, agent_sub: str, report: str, bug_ticket_ids: List[str]
) -> Dict[str, Any]:
    result = _set_ticket_status(ticket_id=ticket_id, status="in_progress", report=report)
    result["bug_ticket_ids"] = list(bug_ticket_ids or [])
    return result


# ---------------------------------------------------------------------------
# Workflow orchestration (state machine)
# ---------------------------------------------------------------------------

WORKFLOW_STEP_TYPES = (
    "checkout_pr",
    "install_deps",
    "read_ticket",
    "read_pr_diff",
    "generate_tests",
    "run_new_tests",
    "retry_failures",
    "run_regression",
    "capture_screenshots",
    "upload_artifacts",
    "evaluate_results",
    "file_bugs",
    "review_pr",
    "update_ticket",
    "generate_report",
)


def build_qa_workflow(
    *, agent_run_id: str, config: Dict[str, Any], ticket: Dict[str, Any], pr_info: Dict[str, Any]
) -> Dict[str, Any]:
    """Generate ordered workflow steps for the Worker Agent Framework.

    Pure / no I/O so it is safe for dry-run preview and as the basis for the
    deterministic mock state machine. Returns
    {steps, new_test_file, pr_branch, total_timeout_seconds}.
    """
    cfg = _normalize_config(config)
    pr_branch = pr_info.get("pr_branch") or "main"
    pr_number = int(pr_info.get("pr_number", 0) or 0)
    feature = feature_slug_from_ticket(ticket=ticket)
    new_test_file = render_test_file_name(pattern=cfg["test_file_pattern"], feature=feature)
    max_time = int(cfg["max_test_time_seconds"])
    gen_timeout = max_time // 3
    run_timeout = max_time // 2
    coding_tool = cfg["coding_tool"]

    test_run_cmds = build_test_run_commands(
        test_file=new_test_file,
        test_run_specific_command=cfg["test_run_specific_command"],
        regression_scope=cfg["regression_scope"],
        regression_command=cfg["regression_command"],
        affected_files=[],
    )
    new_test_cmd = test_run_cmds[0] if test_run_cmds else ""
    regression_cmds = test_run_cmds[1:]
    review_cmd = build_pr_review_command(pr_number=pr_number, verdict="pass", report="QA report") if cfg["pr_review_enabled"] else None

    steps: List[Dict[str, Any]] = [
        {"step_id": 1, "type": "checkout_pr", "command": f"git fetch origin && git checkout {pr_branch}", "timeout_seconds": 120, "on_failure": "escalate"},
        {"step_id": 2, "type": "install_deps", "command": "npm install && pip install -r requirements.txt", "timeout_seconds": 300, "on_failure": "escalate"},
        {"step_id": 3, "type": "read_ticket", "command": None, "timeout_seconds": 10, "on_failure": "escalate"},
        {"step_id": 4, "type": "read_pr_diff", "command": "git diff origin/main...HEAD", "timeout_seconds": 30, "on_failure": "next"},
        {"step_id": 5, "type": "generate_tests", "command": f"{coding_tool}: write {cfg['test_framework']} tests -> {new_test_file}", "timeout_seconds": gen_timeout, "on_failure": "escalate"},
        {"step_id": 6, "type": "run_new_tests", "command": new_test_cmd, "timeout_seconds": run_timeout, "on_failure": "next"},
        {"step_id": 7, "type": "retry_failures", "command": new_test_cmd, "timeout_seconds": run_timeout, "on_failure": "next"},
    ]
    step_id = 8
    if cfg["regression_scope"] != "none":
        for cmd in (regression_cmds or [cfg["regression_command"]]):
            steps.append({"step_id": step_id, "type": "run_regression", "command": cmd, "timeout_seconds": run_timeout, "on_failure": "next"})
            step_id += 1
    if cfg["screenshot_enabled"]:
        steps.append({"step_id": step_id, "type": "capture_screenshots", "command": None, "timeout_seconds": 30, "on_failure": "next"})
        step_id += 1
        steps.append({"step_id": step_id, "type": "upload_artifacts", "command": None, "timeout_seconds": 60, "on_failure": "next"})
        step_id += 1
    steps.append({"step_id": step_id, "type": "evaluate_results", "command": None, "timeout_seconds": 10, "on_failure": "escalate"})
    step_id += 1
    steps.append({"step_id": step_id, "type": "file_bugs", "command": None, "timeout_seconds": 30, "on_failure": "next"})
    step_id += 1
    steps.append({"step_id": step_id, "type": "review_pr", "command": review_cmd, "timeout_seconds": 60, "on_failure": "next"})
    step_id += 1
    steps.append({"step_id": step_id, "type": "update_ticket", "command": None, "timeout_seconds": 30, "on_failure": "next"})
    step_id += 1
    steps.append({"step_id": step_id, "type": "generate_report", "command": None, "timeout_seconds": 10, "on_failure": "next"})

    return {
        "steps": steps,
        "new_test_file": new_test_file,
        "pr_branch": pr_branch,
        "total_timeout_seconds": max_time,
    }


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


def qa_metrics(*, agent_type_id: str, period_days: int = 30) -> Dict[str, Any]:
    """Aggregate QA throughput / defect-detection metrics from stored runs."""
    ensure_tables()
    now = now_ts()
    period_start = now - period_days * 86400
    pk_val = f"QA#{agent_type_id}"
    try:
        resp = T.agent_runs.query(
            IndexName="ByTypeDate",
            KeyConditionExpression="gsi_type_date_pk = :pk",
            ExpressionAttributeValues={":pk": pk_val},
        )
        items = resp.get("Items", [])
    except ClientError:
        resp = T.agent_runs.scan(
            FilterExpression="gsi_type_date_pk = :pk",
            ExpressionAttributeValues={":pk": pk_val},
        )
        items = resp.get("Items", [])

    tested = 0
    passed = 0
    bugs_found = 0
    durations: List[int] = []
    regression_run_total = 0
    flaky_total = 0
    for it in items:
        if int(it.get("created_at", 0) or 0) < period_start:
            continue
        output = it.get("qa_output") or {}
        tested += 1
        verdict = output.get("verdict")
        if verdict in ("pass", "flaky"):
            passed += 1
        bugs_found += len(output.get("bug_ticket_ids") or [])
        durations.append(int(output.get("total_duration_seconds", 0) or 0))
        regression_run_total += int(output.get("regression_tests_run", 0) or 0)
        flaky_total += len(output.get("flaky_tests") or [])

    pass_rate = (passed / tested) if tested else 0.0
    avg_duration = (sum(durations) / len(durations)) if durations else 0.0
    flaky_rate = (flaky_total / regression_run_total) if regression_run_total else 0.0
    return {
        "tested_count": tested,
        "pass_rate": round(pass_rate, 4),
        "bugs_found_count": bugs_found,
        "avg_duration_seconds": round(avg_duration, 2),
        "flaky_test_rate": round(min(flaky_rate, 1.0), 4),
        "period_start": period_start,
        "period_end": now,
    }


# ---------------------------------------------------------------------------
# Mock lifecycle driver (deterministic E2E transitions)
# ---------------------------------------------------------------------------


def run_mock_workflow(
    *,
    run_id: str,
    agent_type_id: str,
    ticket: Dict[str, Any],
    config: Dict[str, Any],
    agent_sub: str,
    scenario: str = "fail",
) -> Dict[str, Any]:
    """Drive the full QA lifecycle in mock mode (no real command execution).

    Gated: when ``S.agent_qa_execute_commands`` is true this would dispatch to
    the real Worker Agent Framework. For now mock is the only path so the state
    machine is fully driveable/testable.

    ``scenario`` selects a deterministic outcome:
      * ``pass``  – all green, PR approved, ticket -> qa_approved
      * ``fail``  – regression failure, bug filed, PR changes-requested, ticket -> in_progress
      * ``flaky`` – only flaky failures, PR approved, ticket -> qa_approved
      * ``error`` – infrastructure error, ticket stays qa_in_progress
    """
    cfg = _normalize_config(config)
    ticket_id = ticket.get("ticket_id", "")
    pr_info = resolve_pr_from_ticket(ticket=ticket) or {"pr_url": "", "pr_branch": "main", "pr_number": 0}
    workflow = build_qa_workflow(agent_run_id=run_id, config=cfg, ticket=ticket, pr_info=pr_info)
    new_test_file = workflow["new_test_file"]
    acceptance = extract_acceptance_criteria(ticket=ticket)

    screenshots = []
    bug_ids: List[str] = []
    flaky: List[str] = []
    regression_failures: List[str] = []
    new_pass, new_fail = 8, 0
    reg_run, reg_pass, reg_fail = 1070, 1070, 0
    infra_error = False

    if cfg["screenshot_enabled"]:
        screenshots.append(
            {
                "name": f"{feature_slug_from_ticket(ticket=ticket)}-visible.png",
                "s3_key": f"{cfg['screenshot_s3_prefix']}{run_id}/feature-visible.png",
                "step": "run_new_tests",
                "status": "pass",
            }
        )

    # Regression failures observed *before* flaky retries; drives the verdict so a
    # test that failed initially but passed on retry is classified as flaky (not pass).
    initial_reg_fail = 0

    if scenario == "pass":
        pass  # all green
    elif scenario == "flaky":
        flaky = ["flaky regression test"]
        initial_reg_fail = len(flaky)  # failed initially
        reg_fail = 0  # resolved on retry
    elif scenario == "error":
        infra_error = True
    else:  # fail (default)
        new_fail = 2
        new_pass = 6
        reg_fail = 1
        initial_reg_fail = reg_fail
        reg_pass = reg_run - reg_fail
        regression_failures = ["messaging-features > section 11 > tip flow"]
        screenshots.append(
            {
                "name": "failure.png",
                "s3_key": f"{cfg['screenshot_s3_prefix']}{run_id}/failure.png",
                "step": "run_regression",
                "status": "fail",
            }
        )

    verdict = determine_verdict(
        new_tests_pass=new_pass,
        new_tests_fail=new_fail,
        regression_fail=initial_reg_fail,
        flaky_tests=flaky,
        infra_error=infra_error,
    )

    # File bugs for real failures (not flaky / not error).
    if verdict == "fail":
        failures = [
            {
                "name": fn,
                "kind": "assertion",
                "expected": "Test should pass",
                "actual": "Assertion failed",
                "test_output": "Error: expected true to be false",
            }
            for fn in regression_failures
        ]
        bugs = [
            build_bug_ticket(
                source_ticket=ticket,
                pr_url=pr_info.get("pr_url", ""),
                agent_run_id=run_id,
                failure=f,
                screenshots=screenshots,
            )
            for f in failures
        ]
        bug_ids = file_bug_tickets(
            bugs=bugs,
            space_id=cfg.get("bug_ticket_space_id"),
            agent_sub=agent_sub,
            source_ticket_id=ticket_id,
        )

    pr_review_action = pr_review_action_for_verdict(verdict) if cfg["pr_review_enabled"] else "none"

    output = build_qa_output(
        verdict=verdict,
        pr_url=pr_info.get("pr_url", ""),
        pr_branch=pr_info.get("pr_branch", "main"),
        ticket_id=ticket_id,
        acceptance_criteria_count=len(acceptance),
        new_tests_written=new_pass + new_fail,
        new_test_file=new_test_file,
        new_tests_pass_count=new_pass,
        new_tests_fail_count=new_fail,
        regression_tests_run=reg_run if cfg["regression_scope"] != "none" else 0,
        regression_tests_pass=reg_pass if cfg["regression_scope"] != "none" else 0,
        regression_tests_fail=reg_fail if cfg["regression_scope"] != "none" else 0,
        regression_failures=regression_failures,
        screenshots=screenshots,
        bug_ticket_ids=bug_ids,
        pr_review_action=pr_review_action,
        total_duration_seconds=120,
        flaky_tests=flaky,
    )
    store_qa_output(run_id=run_id, agent_type_id=agent_type_id, output=output)

    report = build_qa_report(verdict=verdict, output=output)
    try:
        if verdict in ("pass", "flaky"):
            mark_ticket_qa_approved(ticket_id=ticket_id, agent_sub=agent_sub, report=report)
        elif verdict == "fail":
            mark_ticket_qa_failed(
                ticket_id=ticket_id, agent_sub=agent_sub, report=report, bug_ticket_ids=bug_ids
            )
        elif verdict == "error":
            # Infrastructure error: the ticket is held by the QA agent and must
            # not return to the eligible queue. If it is still in code_complete
            # (e.g. execute-qa was invoked without an explicit prior claim),
            # transition it to qa_in_progress so it is excluded from eligibility
            # (spec §7.1).
            if ticket.get("status") == "code_complete":
                try:
                    claim_qa_ticket(
                        agent_run_id=run_id, ticket_id=ticket_id, agent_sub=agent_sub
                    )
                except ValueError:
                    # Already claimed / status drifted — leave as-is.
                    pass
    except LookupError:
        pass
    return output
