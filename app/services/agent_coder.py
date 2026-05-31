"""Coder Agent service (AGENT-008).

The Coder Agent is a *type config* that plugs into the Worker Agent Framework
(AGENT-003). It owns:

* coder_config storage/validation on the ``agent_types`` table
* ticket label/skill filtering + atomic claiming on the ``tickets`` table
* a deterministic, mockable lifecycle state machine
  (claim -> branch -> implement -> test -> PR -> status)
* structured coder output storage on the ``agent_runs`` table
* throughput metrics aggregation

Real shell/git/PR execution is gated behind ``S.agent_coder_execute_commands``.
When disabled (the default, and always in E2E), the workflow is generated and
its transitions are driven in-memory so tests are deterministic.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional

from botocore.exceptions import ClientError

from app.core.aws import ddb
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services import tickets as tickets_svc

logger = logging.getLogger("app.agent_coder")

CODER_AGENT_TYPE = "coder"
_SKILL_LEVELS = ("junior", "mid", "senior")
_DEFAULT_COMPLEXITY_LABELS: Dict[str, List[str]] = {
    "junior": ["complexity:low"],
    "mid": ["complexity:low", "complexity:medium"],
    "senior": ["complexity:low", "complexity:medium", "complexity:high", "complexity:critical"],
}
_DEV_LABELS = ("type:development", "type:bugfix")
_OUTPUT_TAIL_MAX = 10_000  # 10KB cap per stdout/stderr tail (security §7)

_CONFIG_FIELDS = (
    "repo_url",
    "repo_branch_base",
    "branch_pattern",
    "test_commands",
    "test_timeout_seconds",
    "test_retry_limit",
    "pr_template",
    "pr_base_branch",
    "skill_level",
    "max_ticket_time_seconds",
    "complexity_labels",
    "coding_tool",
    "coding_tool_model",
    "pre_commands",
    "post_commands",
    "file_exclude_patterns",
)


# ---------------------------------------------------------------------------
# Table bootstrap (idempotent; tables are additive per AGENT-001/008)
# ---------------------------------------------------------------------------

_BOOTSTRAPPED = False


def ensure_tables() -> None:
    """Create the agent_types / agent_runs tables on first use if absent.

    The shared local-ddb-init script is the canonical place tables are defined,
    but the coder feature is fully self-contained so it works in any environment
    (E2E live DDB, fresh stacks) without requiring a stack re-init.
    """
    global _BOOTSTRAPPED
    if _BOOTSTRAPPED:
        return
    client = ddb.meta.client
    specs = [
        (
            S.agent_types_table_name,
            [
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            [
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
        ),
        (
            S.agent_runs_table_name,
            [
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            [
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
                {"AttributeName": "gsi_type_date_pk", "AttributeType": "S"},
                {"AttributeName": "gsi_type_date_sk", "AttributeType": "S"},
            ],
            [
                {
                    "IndexName": "ByTypeDate",
                    "KeySchema": [
                        {"AttributeName": "gsi_type_date_pk", "KeyType": "HASH"},
                        {"AttributeName": "gsi_type_date_sk", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                }
            ],
        ),
    ]
    for name, key_schema, attr_defs, *gsi in specs:
        kwargs: Dict[str, Any] = {
            "TableName": name,
            "KeySchema": key_schema,
            "AttributeDefinitions": attr_defs,
            "BillingMode": "PAY_PER_REQUEST",
        }
        if gsi and gsi[0]:
            kwargs["GlobalSecondaryIndexes"] = gsi[0]
        try:
            client.create_table(**kwargs)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code not in ("ResourceInUseException",):
                logger.warning("ensure_tables: could not create %s: %s", name, exc)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("ensure_tables: %s create error: %s", name, exc)
    _BOOTSTRAPPED = True


# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------


def _type_pk(type_id: str) -> str:
    return f"TYPE#{type_id}"


def _run_pk(run_id: str) -> str:
    return f"RUN#{run_id}"


# ---------------------------------------------------------------------------
# Slug / branch helpers
# ---------------------------------------------------------------------------


def slugify(text: str, *, max_len: int = 50) -> str:
    s = (text or "").lower()
    s = re.sub(r"[^a-z0-9]+", "-", s).strip("-")
    if len(s) > max_len:
        s = s[:max_len].rstrip("-")
    return s or "ticket"


def generate_branch_name(*, pattern: str, ticket_id: str, subject: str) -> str:
    """Render branch pattern with slugified subject. Sanitized + max 80 chars."""
    slug = slugify(subject)
    name = pattern.replace("{ticket_id}", ticket_id).replace("{slug}", slug)
    # Sanitize to git-safe chars only.
    name = re.sub(r"[^a-zA-Z0-9_/\-]", "-", name)
    name = re.sub(r"-{2,}", "-", name)
    if len(name) > 80:
        name = name[:80].rstrip("-/")
    return name


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def validate_coder_config(config: Dict[str, Any]) -> List[str]:
    """Return list of validation errors (empty = valid)."""
    errors: List[str] = []

    repo_url = str(config.get("repo_url", "") or "")
    if not repo_url:
        errors.append("Repository URL is required")
    elif not (repo_url.startswith("https://") or repo_url.startswith("git@")):
        errors.append("Repository URL must be a valid git URL (https:// or git@)")
    elif " " in repo_url:
        errors.append("Repository URL must not contain spaces")

    branch_pattern = str(config.get("branch_pattern", "feat/{ticket_id}-{slug}") or "")
    if "{ticket_id}" not in branch_pattern:
        errors.append("Branch pattern must include {ticket_id} placeholder")

    test_commands = config.get("test_commands") or []
    if not test_commands:
        errors.append("At least one test command is required")

    skill_level = config.get("skill_level", "mid")
    if skill_level not in _SKILL_LEVELS:
        errors.append("Skill level must be junior, mid, or senior")

    for field in ("test_timeout_seconds", "max_ticket_time_seconds"):
        val = config.get(field)
        if val is not None and int(val) <= 0:
            errors.append(f"{field} must be positive")

    coding_tool = config.get("coding_tool", "claude_code")
    if coding_tool not in ("claude_code", "codex"):
        errors.append("Coding tool must be claude_code or codex")

    return errors


def _normalize_config(config: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for key in _CONFIG_FIELDS:
        if key in config and config[key] is not None:
            out[key] = config[key]
    out.setdefault("repo_branch_base", "main")
    out.setdefault("branch_pattern", "feat/{ticket_id}-{slug}")
    out.setdefault("test_timeout_seconds", 600)
    out.setdefault("test_retry_limit", 3)
    out.setdefault("pr_template", "Closes #{ticket_id}\n\n{summary}")
    out.setdefault("pr_base_branch", "main")
    out.setdefault("skill_level", "mid")
    out.setdefault("max_ticket_time_seconds", 3600)
    out.setdefault("coding_tool", "claude_code")
    if not out.get("complexity_labels"):
        out["complexity_labels"] = _DEFAULT_COMPLEXITY_LABELS
    return out


def get_agent_type(*, agent_type_id: str) -> Optional[Dict[str, Any]]:
    ensure_tables()
    resp = T.agent_types.get_item(Key={"pk": _type_pk(agent_type_id), "sk": "META"})
    return resp.get("Item")


def create_agent_type(
    *, agent_type_id: str, owner_sub: str, name: str = "", agent_type: str = CODER_AGENT_TYPE
) -> Dict[str, Any]:
    ensure_tables()
    ts = now_ts()
    item = {
        "pk": _type_pk(agent_type_id),
        "sk": "META",
        "agent_type_id": agent_type_id,
        "agent_type": agent_type,
        "name": name or agent_type_id,
        "owner_sub": owner_sub,
        "created_at": ts,
        "updated_at": ts,
    }
    T.agent_types.put_item(Item=item)
    return item


def get_coder_config(*, agent_type_id: str) -> Optional[Dict[str, Any]]:
    """Fetch coder_config from agent_types table (CONFIG item)."""
    ensure_tables()
    resp = T.agent_types.get_item(Key={"pk": _type_pk(agent_type_id), "sk": "CONFIG"})
    item = resp.get("Item")
    if not item:
        return None
    config = item.get("coder_config")
    if not config:
        return None
    return _coerce_numbers(config)


def update_coder_config(
    *, agent_type_id: str, owner_sub: str, config: Dict[str, Any]
) -> Dict[str, Any]:
    """Validate and persist coder_config. Auto-creates the type META if absent."""
    ensure_tables()
    if get_agent_type(agent_type_id=agent_type_id) is None:
        create_agent_type(agent_type_id=agent_type_id, owner_sub=owner_sub)
    normalized = _normalize_config(config)
    ts = now_ts()
    T.agent_types.put_item(
        Item={
            "pk": _type_pk(agent_type_id),
            "sk": "CONFIG",
            "agent_type_id": agent_type_id,
            "agent_type": CODER_AGENT_TYPE,
            "owner_sub": owner_sub,
            "coder_config": normalized,
            "updated_at": ts,
        }
    )
    # Keep META agent_type=coder so the type is discoverable as a coder.
    T.agent_types.update_item(
        Key={"pk": _type_pk(agent_type_id), "sk": "META"},
        UpdateExpression="SET agent_type = :t, updated_at = :u",
        ExpressionAttributeValues={":t": CODER_AGENT_TYPE, ":u": ts},
    )
    result = dict(normalized)
    result["updated_at"] = ts
    return result


def _coerce_numbers(config: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(config)
    for field in ("test_timeout_seconds", "test_retry_limit", "max_ticket_time_seconds"):
        if field in out and out[field] is not None:
            try:
                out[field] = int(out[field])
            except (TypeError, ValueError):
                pass
    return out


def config_schema() -> Dict[str, Any]:
    """Return a lightweight JSON schema describing coder_config fields."""
    return {
        "fields": {
            "repo_url": {"type": "string", "required": True},
            "repo_branch_base": {"type": "string", "default": "main"},
            "branch_pattern": {"type": "string", "default": "feat/{ticket_id}-{slug}"},
            "test_commands": {"type": "array", "items": "string", "required": True},
            "test_timeout_seconds": {"type": "integer", "min": 60, "max": 7200, "default": 600},
            "test_retry_limit": {"type": "integer", "min": 0, "max": 10, "default": 3},
            "pr_template": {"type": "string"},
            "pr_base_branch": {"type": "string", "default": "main"},
            "skill_level": {"type": "enum", "values": list(_SKILL_LEVELS), "default": "mid"},
            "max_ticket_time_seconds": {"type": "integer", "min": 300, "max": 28800, "default": 3600},
            "complexity_labels": {"type": "object"},
            "coding_tool": {"type": "enum", "values": ["claude_code", "codex"], "default": "claude_code"},
            "coding_tool_model": {"type": "string"},
            "pre_commands": {"type": "array", "items": "string"},
            "post_commands": {"type": "array", "items": "string"},
            "file_exclude_patterns": {"type": "array", "items": "string"},
        }
    }


# ---------------------------------------------------------------------------
# Ticket filtering & claiming
# ---------------------------------------------------------------------------


def _allowed_complexity_labels(skill_level: str, complexity_labels: Optional[Dict[str, List[str]]]) -> set[str]:
    table = complexity_labels or _DEFAULT_COMPLEXITY_LABELS
    return set(table.get(skill_level, _DEFAULT_COMPLEXITY_LABELS.get(skill_level, [])))


def find_eligible_tickets(
    *,
    skill_level: str,
    complexity_labels: Optional[Dict[str, List[str]]] = None,
    space_id: Optional[str] = None,
    limit: int = 10,
) -> List[Dict[str, Any]]:
    """Return open, unassigned dev/bugfix tickets matching the skill level.

    Queries the label index partitions (type:development / type:bugfix), merges,
    filters by complexity-against-skill-level, drops already-claimed tickets, and
    returns oldest-first (FIFO).
    """
    ensure_tables()
    allowed = _allowed_complexity_labels(skill_level, complexity_labels)
    seen: dict[str, Dict[str, Any]] = {}
    for label in _DEV_LABELS:
        resp = tickets_svc.STORE._table.query(  # noqa: SLF001 - internal reuse
            KeyConditionExpression="pk = :pk",
            ExpressionAttributeValues={":pk": tickets_svc.label_index_pk(label)},
            ScanIndexForward=True,
        )
        for row in resp.get("Items", []):
            tid = row.get("ticket_id")
            if not tid:
                continue
            ticket = tickets_svc.STORE.get_ticket(tid)
            if not ticket:
                continue
            if ticket.get("status") != "open":
                continue
            if ticket.get("assigned_to_sub"):
                continue
            if space_id is not None and ticket.get("space_id") != space_id:
                continue
            # Complexity gate: if the ticket carries a complexity label, it must be allowed.
            tlabels = set(ticket.get("labels", []))
            complexity_label = next((l for l in tlabels if l.startswith("complexity:")), None)
            if complexity_label and complexity_label not in allowed:
                continue
            seen[tid] = {
                "ticket_id": tid,
                "subject": ticket.get("subject", ""),
                "labels": sorted(tlabels),
                "complexity": ticket.get("complexity"),
                "estimated_effort_hours": ticket.get("estimated_effort_hours"),
                "created_at": int(ticket.get("created_at", 0) or 0),
            }
    out = sorted(seen.values(), key=lambda t: (t["created_at"], t["ticket_id"]))
    return out[:limit]


def claim_ticket(*, ticket_id: str, agent_sub: str) -> Dict[str, Any]:
    """Atomically claim a ticket for an agent.

    Returns the claim result. Raises LookupError if the ticket does not exist and
    ValueError("already_claimed") if another agent holds it.
    """
    ticket = tickets_svc.STORE.get_ticket(ticket_id)
    if not ticket:
        raise LookupError("Ticket not found")
    table = tickets_svc.STORE._table  # noqa: SLF001
    ts = now_ts()
    try:
        table.update_item(
            Key={"pk": f"TICKET#{ticket_id}", "sk": "META"},
            UpdateExpression=(
                "SET assigned_to_sub = :sub, #st = :inprog, assigned_at = :ts, updated_at = :ts"
            ),
            ConditionExpression=(
                "attribute_not_exists(assigned_to_sub) OR assigned_to_sub = :none"
            ),
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={
                ":sub": agent_sub,
                ":inprog": "in_progress",
                ":ts": ts,
                ":none": None,
            },
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code == "ConditionalCheckFailedException":
            raise ValueError("already_claimed") from exc
        raise
    return {
        "ok": True,
        "ticket_id": ticket_id,
        "status": "in_progress",
        "assigned_to_sub": agent_sub,
        "claimed_at": ts,
    }


# ---------------------------------------------------------------------------
# Prompt / command builders
# ---------------------------------------------------------------------------


def build_coding_prompt(
    *, ticket: Dict[str, Any], coding_tool: str, model: Optional[str], file_exclude_patterns: List[str]
) -> str:
    subject = ticket.get("subject", "")
    description = ""
    messages = ticket.get("messages") or []
    if messages:
        description = messages[0].get("body", "")
    parts = [
        f"Implement ticket {ticket.get('ticket_id', '')}: {subject}",
        "",
        "Description:",
        description or "(no description provided)",
    ]
    meta = ticket.get("metadata") or {}
    acceptance = meta.get("acceptance_criteria")
    if acceptance:
        parts += ["", "Acceptance criteria:", str(acceptance)]
    if file_exclude_patterns:
        parts += ["", "Do NOT modify files matching: " + ", ".join(file_exclude_patterns)]
    parts += ["", "When done, ensure the project test suite passes."]
    return "\n".join(parts)


def build_fix_prompt(*, test_output: str, retry_number: int, max_retries: int) -> str:
    tail = (test_output or "")[-_OUTPUT_TAIL_MAX:]
    return (
        f"The test suite failed (fix attempt {retry_number} of {max_retries}). "
        "Focus only on making the failing tests pass without breaking others.\n\n"
        f"Test output:\n{tail}"
    )


def build_pr_command(
    *, branch_name: str, base_branch: str, ticket_id: str, ticket_subject: str, template: str, summary: str
) -> str:
    body = render_pr_template(template=template, ticket_id=ticket_id, ticket_subject=ticket_subject, summary=summary)
    title = ticket_subject.replace('"', "'")
    body_escaped = body.replace('"', "'")
    return f'gh pr create --title "{title}" --body "{body_escaped}" --base {base_branch} --head {branch_name}'


def render_pr_template(*, template: str, ticket_id: str, ticket_subject: str, summary: str) -> str:
    return (
        (template or "Closes #{ticket_id}\n\n{summary}")
        .replace("{ticket_id}", ticket_id)
        .replace("{ticket_subject}", ticket_subject)
        .replace("{summary}", summary)
    )


def parse_pr_output(stdout: str) -> Dict[str, Any]:
    """Extract PR URL and number from `gh pr create` stdout."""
    url = ""
    number = 0
    match = re.search(r"https?://\S+/pull/(\d+)", stdout or "")
    if match:
        url = match.group(0)
        number = int(match.group(1))
    return {"pr_url": url, "pr_number": number}


# ---------------------------------------------------------------------------
# Workflow orchestration (state machine)
# ---------------------------------------------------------------------------

WORKFLOW_STEP_TYPES = (
    "clone_repo",
    "create_branch",
    "run_pre_commands",
    "inject_coding_prompt",
    "wait_for_coding",
    "run_tests",
    "evaluate_tests",
    "create_pr",
    "capture_output",
    "update_ticket",
)


def build_coder_workflow(
    *, agent_run_id: str, config: Dict[str, Any], ticket: Dict[str, Any]
) -> Dict[str, Any]:
    """Generate the ordered workflow steps for the Worker Agent Framework.

    Returns {steps, branch_name, total_timeout_seconds}. Pure / no I/O so it is
    safe to use for dry-run preview and as the basis for the mock state machine.
    """
    cfg = _normalize_config(config)
    repo_url = cfg.get("repo_url", "")
    base_branch = cfg.get("repo_branch_base", "main")
    pr_base = cfg.get("pr_base_branch", "main")
    ticket_id = ticket.get("ticket_id", "")
    subject = ticket.get("subject", "")
    branch_name = generate_branch_name(
        pattern=cfg.get("branch_pattern", "feat/{ticket_id}-{slug}"),
        ticket_id=ticket_id,
        subject=subject,
    )
    max_time = int(cfg.get("max_ticket_time_seconds", 3600))
    coding_timeout = max_time // 2
    test_timeout = int(cfg.get("test_timeout_seconds", 600))
    coding_tool = cfg.get("coding_tool", "claude_code")
    model = cfg.get("coding_tool_model")
    pre_commands = cfg.get("pre_commands") or []
    file_excludes = cfg.get("file_exclude_patterns") or []

    prompt = build_coding_prompt(
        ticket=ticket, coding_tool=coding_tool, model=model, file_exclude_patterns=file_excludes
    )
    if coding_tool == "codex":
        coding_cmd = f'codex -q "{prompt[:200]}..."'
    else:
        model_flag = f" --model {model}" if model else ""
        coding_cmd = f'claude --dangerously-skip-permissions{model_flag} -p "{prompt[:200]}..."'

    pr_command = build_pr_command(
        branch_name=branch_name,
        base_branch=pr_base,
        ticket_id=ticket_id,
        ticket_subject=subject,
        template=cfg.get("pr_template", "Closes #{ticket_id}\n\n{summary}"),
        summary="{summary}",
    )

    steps: List[Dict[str, Any]] = [
        {
            "step_id": 1,
            "type": "clone_repo",
            "command": f"git clone {repo_url} /workspace && cd /workspace && git fetch origin",
            "timeout_seconds": 120,
            "on_failure": "escalate",
        },
        {
            "step_id": 2,
            "type": "create_branch",
            "command": f"git checkout -b {branch_name} origin/{base_branch}",
            "timeout_seconds": 30,
            "on_failure": "escalate",
        },
        {
            "step_id": 3,
            "type": "run_pre_commands",
            "command": " && ".join(pre_commands) if pre_commands else None,
            "timeout_seconds": 60,
            "on_failure": "escalate",
        },
        {
            "step_id": 4,
            "type": "inject_coding_prompt",
            "command": coding_cmd,
            "timeout_seconds": coding_timeout,
            "on_failure": "escalate",
        },
        {
            "step_id": 5,
            "type": "wait_for_coding",
            "command": None,
            "timeout_seconds": coding_timeout,
            "on_failure": "escalate",
        },
    ]
    step_id = 6
    for cmd in cfg.get("test_commands", []):
        steps.append(
            {
                "step_id": step_id,
                "type": "run_tests",
                "command": cmd,
                "timeout_seconds": test_timeout,
                "on_failure": "retry",
            }
        )
        step_id += 1
    steps.append(
        {
            "step_id": step_id,
            "type": "evaluate_tests",
            "command": None,
            "timeout_seconds": 10,
            "on_failure": "escalate",
        }
    )
    step_id += 1
    steps.append(
        {
            "step_id": step_id,
            "type": "create_pr",
            "command": pr_command,
            "timeout_seconds": 60,
            "on_failure": "escalate",
        }
    )
    step_id += 1
    steps.append(
        {
            "step_id": step_id,
            "type": "capture_output",
            "command": f"git diff --stat origin/{base_branch}...HEAD",
            "timeout_seconds": 30,
            "on_failure": "next",
        }
    )
    step_id += 1
    steps.append(
        {
            "step_id": step_id,
            "type": "update_ticket",
            "command": None,
            "timeout_seconds": 30,
            "on_failure": "next",
        }
    )
    return {
        "steps": steps,
        "branch_name": branch_name,
        "total_timeout_seconds": max_time,
    }


# ---------------------------------------------------------------------------
# Output assembly & storage
# ---------------------------------------------------------------------------


def _parse_diff_stat(git_diff_stat: str) -> Dict[str, int]:
    insertions = 0
    deletions = 0
    m_ins = re.search(r"(\d+)\s+insertion", git_diff_stat or "")
    m_del = re.search(r"(\d+)\s+deletion", git_diff_stat or "")
    if m_ins:
        insertions = int(m_ins.group(1))
    if m_del:
        deletions = int(m_del.group(1))
    return {"insertions": insertions, "deletions": deletions}


def build_coder_output(
    *,
    branch_name: str,
    pr_url: str,
    pr_number: int,
    files_changed: List[str],
    files_added: Optional[List[str]] = None,
    files_deleted: Optional[List[str]] = None,
    git_diff_stat: str = "",
    test_results: Optional[List[Dict[str, Any]]] = None,
    retry_count: int = 0,
    duration_seconds: int = 0,
    escalated: bool = False,
    escalation_reason: Optional[str] = None,
) -> Dict[str, Any]:
    diff = _parse_diff_stat(git_diff_stat)
    truncated: List[Dict[str, Any]] = []
    for r in test_results or []:
        rr = dict(r)
        if "stdout_tail" in rr and isinstance(rr["stdout_tail"], str):
            rr["stdout_tail"] = rr["stdout_tail"][-_OUTPUT_TAIL_MAX:]
        if "stderr_tail" in rr and isinstance(rr["stderr_tail"], str):
            rr["stderr_tail"] = rr["stderr_tail"][-_OUTPUT_TAIL_MAX:]
        truncated.append(rr)
    return {
        "branch_name": branch_name,
        "pr_url": pr_url,
        "pr_number": int(pr_number or 0),
        "files_changed": list(files_changed or []),
        "files_added": list(files_added or []),
        "files_deleted": list(files_deleted or []),
        "insertions": diff["insertions"],
        "deletions": diff["deletions"],
        "test_results": truncated,
        "test_retry_count": int(retry_count or 0),
        "total_duration_seconds": int(duration_seconds or 0),
        "escalated": bool(escalated),
        "escalation_reason": escalation_reason,
    }


def store_coder_output(*, run_id: str, agent_type_id: str, skill_level: str, output: Dict[str, Any]) -> Dict[str, Any]:
    """Persist coder output on the agent_runs table + a metrics rollup row."""
    ensure_tables()
    ts = now_ts()
    item = {
        "pk": _run_pk(run_id),
        "sk": "OUTPUT",
        "run_id": run_id,
        "agent_type_id": agent_type_id,
        "skill_level": skill_level,
        "coder_output": output,
        "created_at": ts,
        # Metrics index (per-type rollup query).
        "gsi_type_date_pk": f"CODER#{agent_type_id}",
        "gsi_type_date_sk": f"DATE#{ts}",
    }
    T.agent_runs.put_item(Item=item)
    return output


def get_coder_output(*, run_id: str) -> Optional[Dict[str, Any]]:
    ensure_tables()
    resp = T.agent_runs.get_item(Key={"pk": _run_pk(run_id), "sk": "OUTPUT"})
    item = resp.get("Item")
    if not item:
        return None
    return item.get("coder_output")


# ---------------------------------------------------------------------------
# Status updates
# ---------------------------------------------------------------------------


def mark_ticket_code_complete(*, ticket_id: str, agent_sub: str, pr_url: str) -> Dict[str, Any]:
    ticket = tickets_svc.STORE.get_ticket(ticket_id)
    if not ticket:
        raise LookupError("Ticket not found")
    table = tickets_svc.STORE._table  # noqa: SLF001
    ts = now_ts()
    meta = dict(ticket.get("metadata") or {})
    meta["pr_url"] = pr_url
    table.update_item(
        Key={"pk": f"TICKET#{ticket_id}", "sk": "META"},
        UpdateExpression="SET #st = :s, metadata = :m, updated_at = :ts",
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={":s": "code_complete", ":m": meta, ":ts": ts},
    )
    return {"ok": True, "ticket_id": ticket_id, "status": "code_complete", "pr_url": pr_url}


def mark_ticket_blocked(*, ticket_id: str, agent_sub: str, reason: str) -> Dict[str, Any]:
    ticket = tickets_svc.STORE.get_ticket(ticket_id)
    if not ticket:
        raise LookupError("Ticket not found")
    table = tickets_svc.STORE._table  # noqa: SLF001
    ts = now_ts()
    meta = dict(ticket.get("metadata") or {})
    meta["escalation_reason"] = reason
    table.update_item(
        Key={"pk": f"TICKET#{ticket_id}", "sk": "META"},
        UpdateExpression="SET #st = :s, metadata = :m, updated_at = :ts",
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={":s": "blocked", ":m": meta, ":ts": ts},
    )
    return {"ok": True, "ticket_id": ticket_id, "status": "blocked", "reason": reason}


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


def coder_metrics(*, agent_type_id: str, period_days: int = 30) -> Dict[str, Any]:
    """Aggregate throughput metrics from stored coder runs."""
    ensure_tables()
    now = now_ts()
    period_start = now - period_days * 86400
    pk_val = f"CODER#{agent_type_id}"
    try:
        resp = T.agent_runs.query(
            IndexName="ByTypeDate",
            KeyConditionExpression="gsi_type_date_pk = :pk",
            ExpressionAttributeValues={":pk": pk_val},
        )
        items = resp.get("Items", [])
    except ClientError:
        # GSI missing (table pre-existed without it) — fall back to a filtered scan.
        resp = T.agent_runs.scan(
            FilterExpression="gsi_type_date_pk = :pk",
            ExpressionAttributeValues={":pk": pk_val},
        )
        items = resp.get("Items", [])
    durations: List[int] = []
    failures = 0
    escalations = 0
    by_skill: Dict[str, int] = {}
    completed = 0
    for it in items:
        if int(it.get("created_at", 0) or 0) < period_start:
            continue
        output = it.get("coder_output") or {}
        completed += 1
        durations.append(int(output.get("total_duration_seconds", 0) or 0))
        if output.get("escalated"):
            escalations += 1
        # A failure = run with no PR url produced.
        if not output.get("pr_url"):
            failures += 1
        skill = it.get("skill_level") or "mid"
        by_skill[skill] = by_skill.get(skill, 0) + 1
    avg_duration = (sum(durations) / len(durations)) if durations else 0.0
    failure_rate = (failures / completed) if completed else 0.0
    escalation_rate = (escalations / completed) if completed else 0.0
    return {
        "completed_count": completed,
        "avg_duration_seconds": round(avg_duration, 2),
        "failure_rate": round(failure_rate, 4),
        "escalation_rate": round(escalation_rate, 4),
        "tickets_by_skill_level": by_skill,
        "period_start": period_start,
        "period_end": now,
    }


# ---------------------------------------------------------------------------
# Mock lifecycle driver (deterministic E2E transitions)
# ---------------------------------------------------------------------------


def run_mock_workflow(
    *, run_id: str, agent_type_id: str, ticket: Dict[str, Any], config: Dict[str, Any], agent_sub: str
) -> Dict[str, Any]:
    """Drive the full lifecycle in mock mode (no real command execution).

    Gated: when ``S.agent_coder_execute_commands`` is true this would dispatch to
    the real Worker Agent Framework instead. For now mock is the only path so the
    state machine is fully driveable/testable.
    """
    cfg = _normalize_config(config)
    workflow = build_coder_workflow(agent_run_id=run_id, config=cfg, ticket=ticket)
    branch_name = workflow["branch_name"]
    ticket_id = ticket.get("ticket_id", "")
    test_results = [
        {"command": c, "exit_code": 0, "duration_seconds": 5, "stdout_tail": "ok", "stderr_tail": ""}
        for c in cfg.get("test_commands", [])
    ]
    pr_url = f"https://example.com/repo/pull/1?ticket={ticket_id}"
    output = build_coder_output(
        branch_name=branch_name,
        pr_url=pr_url,
        pr_number=1,
        files_changed=["app/example.py"],
        git_diff_stat=" 1 file changed, 10 insertions(+), 2 deletions(-)",
        test_results=test_results,
        retry_count=0,
        duration_seconds=120,
        escalated=False,
    )
    store_coder_output(
        run_id=run_id, agent_type_id=agent_type_id, skill_level=cfg.get("skill_level", "mid"), output=output
    )
    try:
        mark_ticket_code_complete(ticket_id=ticket_id, agent_sub=agent_sub, pr_url=pr_url)
    except LookupError:
        pass
    return output
