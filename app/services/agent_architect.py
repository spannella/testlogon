"""Solution Architect Agent service (AGENT-011).

The Solution Architect Agent is an *agent type config* that plugs into the
Worker Agent Framework (AGENT-003). It picks up ``type:feature_request`` tickets
and decomposes them into ordered, dependent development tickets. It owns:

* ``architect_config`` storage/validation on the ``agent_types`` table (REUSED
  from AGENT-008 — same table, distinct CONFIG payload + ``agent_type`` discriminator)
* feature-request ticket filtering (skip already-decomposed features)
* a deterministic, mockable lifecycle/workflow state machine
  (clone -> read docs -> scan -> analyze -> design -> estimate -> graph -> tickets)
* structured architect output storage on the ``agent_runs`` table
* the ``feature_decompositions`` table linking a feature request to its dev tickets
* decomposition metrics aggregation

Real shell/git/coding-tool execution is gated behind
``S.architect_execute_commands``. When disabled (the default, and always in
E2E), the workflow is generated and driven in-memory so tests are deterministic.

May draw project context from AGENT-005 agent memory (``app.services.agent_memory``)
when a worker_id is supplied.
"""

from __future__ import annotations

import json
import logging
import re
import shlex
from decimal import Decimal
from typing import Any, Dict, List, Optional

from botocore.exceptions import ClientError

from app.core.aws import ddb
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.core.validate_url import validate_repo_url
from app.services import agent_coder as coder_svc
from app.services import tickets as tickets_svc

logger = logging.getLogger("app.agent_architect")

ARCHITECT_AGENT_TYPE = "architect"
FEATURE_REQUEST_LABEL = "type:feature_request"
_COMPLEXITY_LEVELS = ("low", "medium", "high", "critical")
_TICKET_TYPES = ("development", "bugfix", "infrastructure")
_SPEC_STYLES = ("full", "compact")
_SUMMARY_MAX = 10_000

_REQUIRED_TEMPLATE_PLACEHOLDERS = ("{subject}", "{overview}")

_DEFAULT_REFERENCE_DOCS = ["CLAUDE.md", "docs/dynamodb.md", "docs/file-reference.md"]
_DEFAULT_SCAN_PATHS = ["app/services/", "app/routers/", "app/models.py", "frontend/src/"]
_DEFAULT_COMPLEXITY_ESTIMATION = {
    "new_table": 16.0,
    "new_endpoint": 4.0,
    "new_page": 12.0,
    "modify_file": 2.0,
    "test_section": 8.0,
}
_DEFAULT_TICKET_TEMPLATE = (
    "# {subject}\n\n"
    "**Parent feature**: {feature_ticket_id}\n"
    "**Complexity**: {complexity}\n"
    "**Estimated effort**: {estimated_hours}h\n"
    "**Build order**: {build_order}\n"
    "**Depends on**: {depends_on}\n\n"
    "## Overview\n{overview}\n\n"
    "## Current State\n{current_state}\n\n"
    "## Data Model\n{data_model}\n\n"
    "## API Design\n{api_design}\n\n"
    "## Frontend\n{frontend_design}\n\n"
    "## E2E Test Plan\n{e2e_test_plan}\n\n"
    "## Error Handling\n{error_handling}\n\n"
    "## Security\n{security}\n\n"
    "## Dependencies\n{dependencies}\n"
)

_CONFIG_FIELDS = (
    "repo_url",
    "repo_branch",
    "reference_docs",
    "scan_paths",
    "ticket_template",
    "architecture_guidelines",
    "tech_stack_constraints",
    "naming_conventions",
    "max_tickets_per_feature",
    "target_ticket_space_id",
    "complexity_estimation",
    "coding_tool",
    "coding_tool_model",
    "max_analysis_time_seconds",
    "require_design_review",
    "ticket_spec_style",
)

# GAP-0094: conservative allowlist for git branch names used in validation. The
# clone command additionally sanitizes + shlex-quotes the branch (GAP-0079).
_SAFE_BRANCH_RE = re.compile(r"^[a-zA-Z0-9_./-]{1,200}$")


# ---------------------------------------------------------------------------
# Table bootstrap (idempotent; tables are additive)
# ---------------------------------------------------------------------------

_BOOTSTRAPPED = False


def ensure_tables() -> None:
    """Create the feature_decompositions table on first use if absent.

    The agent_types / agent_runs tables are bootstrapped by AGENT-008's coder
    service (REUSED here). This adds only the new decomposition link table so the
    feature is self-contained in any environment (E2E live DDB, fresh stacks).
    """
    global _BOOTSTRAPPED
    coder_svc.ensure_tables()
    if _BOOTSTRAPPED:
        return
    client = ddb.meta.client
    try:
        client.create_table(
            TableName=S.feature_decompositions_table_name,
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
                {"AttributeName": "GSI1PK", "AttributeType": "S"},
                {"AttributeName": "GSI1SK", "AttributeType": "N"},
            ],
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "GSI1",
                    "KeySchema": [
                        {"AttributeName": "GSI1PK", "KeyType": "HASH"},
                        {"AttributeName": "GSI1SK", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                }
            ],
            BillingMode="PAY_PER_REQUEST",
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code not in ("ResourceInUseException",):
            logger.warning("ensure_tables: could not create feature_decompositions: %s", exc)
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("ensure_tables: feature_decompositions create error: %s", exc)
    _BOOTSTRAPPED = True


# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------


def _ddb_safe(value: Any) -> Any:
    """Recursively convert Python floats to Decimal (DynamoDB rejects floats)."""
    if isinstance(value, float):
        return Decimal(str(value))
    if isinstance(value, dict):
        return {k: _ddb_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_ddb_safe(v) for v in value]
    return value


def _type_pk(type_id: str) -> str:
    return coder_svc._type_pk(type_id)  # noqa: SLF001 - shared key scheme


def _feature_pk(feature_ticket_id: str) -> str:
    return f"FEATURE#{feature_ticket_id}"


def _dev_sk(dev_ticket_id: str) -> str:
    return f"DEV#{dev_ticket_id}"


def _run_gsi_pk(agent_run_id: str) -> str:
    return f"AGENT_RUN#{agent_run_id}"


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def _is_safe_path(path: str) -> bool:
    """Return True only for safe relative repository paths (GAP-0096).

    Rejects: absolute paths (``/...``), tilde-expansion (``~...``), path
    traversal components (``..`` as a full segment), Windows backslash paths,
    and drive-letter / colon paths (``C:``). Mirrors
    ``agent_docs.validate_path`` — keep in sync.
    """
    if not path or not isinstance(path, str):
        return False
    if path.startswith("/") or path.startswith("~"):
        return False
    if ".." in path.split("/"):
        return False
    if "\\" in path or ":" in path:
        return False
    return True


def validate_architect_config(config: Dict[str, Any]) -> List[str]:
    """Return list of validation errors (empty = valid)."""
    errors: List[str] = []

    repo_url = str(config.get("repo_url", "") or "")
    if not repo_url:
        errors.append("Repository URL is required")
    elif not (repo_url.startswith("https://") or repo_url.startswith("git@")):
        errors.append("Repository URL must be a valid git URL (https:// or git@)")
    elif " " in repo_url:
        errors.append("Repository URL must not contain spaces")

    reference_docs = config.get("reference_docs")
    if reference_docs is not None and len(reference_docs) == 0:
        errors.append("At least one reference document path is required")
    for path in reference_docs or []:
        if not _is_safe_path(str(path)):
            errors.append(f"Reference doc path must be a safe relative path: {path}")

    scan_paths = config.get("scan_paths")
    if scan_paths is not None and len(scan_paths) == 0:
        errors.append("At least one scan path is required")
    for path in scan_paths or []:
        if not _is_safe_path(str(path)):
            errors.append(f"Scan path must be a safe relative path: {path}")

    template = config.get("ticket_template")
    if template:
        for placeholder in _REQUIRED_TEMPLATE_PLACEHOLDERS:
            if placeholder not in template:
                errors.append(f"Ticket template missing required placeholder: {placeholder}")

    max_tickets = config.get("max_tickets_per_feature")
    if max_tickets is not None and not (1 <= int(max_tickets) <= 20):
        errors.append("max_tickets_per_feature must be between 1 and 20")

    spec_style = config.get("ticket_spec_style", "compact")
    if spec_style not in _SPEC_STYLES:
        errors.append("ticket_spec_style must be 'full' or 'compact'")

    coding_tool = config.get("coding_tool", "claude_code")
    if coding_tool not in ("claude_code", "codex"):
        errors.append("Coding tool must be claude_code or codex")

    # GAP-0094: reject repo_branch values containing shell metacharacters. The
    # clone command sanitizes + shlex-quotes the branch (GAP-0079), but we also
    # surface a clear error at the config-write boundary so admins cannot store a
    # branch that would silently be rewritten.
    repo_branch = str(config.get("repo_branch", "") or "")
    if repo_branch:
        if not _SAFE_BRANCH_RE.match(repo_branch):
            errors.append(
                "repo_branch contains disallowed characters; allowed: "
                "alphanumerics, '-', '_', '/', '.'"
            )
        elif repo_branch.startswith("-"):
            errors.append("repo_branch must not start with '-'")
        elif ".." in repo_branch or "@{" in repo_branch:
            errors.append("repo_branch must not contain '..' or '@{'")

    return errors


def _normalize_config(config: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for key in _CONFIG_FIELDS:
        if key in config and config[key] is not None:
            out[key] = config[key]
    out.setdefault("repo_branch", "main")
    # GAP-0094: defence-in-depth — sanitize the branch on every normalisation pass
    # so service-code callers that bypass validate_architect_config still get a
    # git-safe branch name.
    out["repo_branch"] = _sanitize_branch(str(out["repo_branch"]))
    out.setdefault("reference_docs", list(_DEFAULT_REFERENCE_DOCS))
    out.setdefault("scan_paths", list(_DEFAULT_SCAN_PATHS))
    out.setdefault("ticket_template", _DEFAULT_TICKET_TEMPLATE)
    out.setdefault("architecture_guidelines", "")
    out.setdefault("max_tickets_per_feature", 8)
    out.setdefault("max_analysis_time_seconds", 900)
    out.setdefault("require_design_review", bool(S.architect_design_review_required))
    out.setdefault("coding_tool", "claude_code")
    out.setdefault("ticket_spec_style", "compact")
    if not out.get("complexity_estimation"):
        out["complexity_estimation"] = dict(_DEFAULT_COMPLEXITY_ESTIMATION)
    return out


def _coerce_numbers(config: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(config)
    for field in ("max_tickets_per_feature", "max_analysis_time_seconds"):
        if field in out and out[field] is not None:
            try:
                out[field] = int(out[field])
            except (TypeError, ValueError):
                pass
    est = out.get("complexity_estimation")
    if isinstance(est, dict):
        out["complexity_estimation"] = {
            k: float(v) for k, v in est.items() if v is not None
        }
    return out


def get_architect_config(*, agent_type_id: str) -> Optional[Dict[str, Any]]:
    """Fetch architect_config from agent_types table (ARCHITECT_CONFIG item)."""
    ensure_tables()
    resp = T.agent_types.get_item(
        Key={"pk": _type_pk(agent_type_id), "sk": "ARCHITECT_CONFIG"}
    )
    item = resp.get("Item")
    if not item:
        return None
    config = item.get("architect_config")
    if not config:
        return None
    return _coerce_numbers(config)


def update_architect_config(
    *, agent_type_id: str, owner_sub: str, config: Dict[str, Any]
) -> Dict[str, Any]:
    """Validate and persist architect_config. Auto-creates the type META if absent."""
    ensure_tables()
    if coder_svc.get_agent_type(agent_type_id=agent_type_id) is None:
        coder_svc.create_agent_type(
            agent_type_id=agent_type_id, owner_sub=owner_sub, agent_type=ARCHITECT_AGENT_TYPE
        )
    normalized = _normalize_config(config)
    ts = now_ts()
    T.agent_types.put_item(
        Item=_ddb_safe({
            "pk": _type_pk(agent_type_id),
            "sk": "ARCHITECT_CONFIG",
            "agent_type_id": agent_type_id,
            "agent_type": ARCHITECT_AGENT_TYPE,
            "owner_sub": owner_sub,
            "architect_config": normalized,
            "updated_at": ts,
        })
    )
    T.agent_types.update_item(
        Key={"pk": _type_pk(agent_type_id), "sk": "META"},
        UpdateExpression="SET agent_type = :t, updated_at = :u",
        ExpressionAttributeValues={":t": ARCHITECT_AGENT_TYPE, ":u": ts},
    )
    result = dict(normalized)
    result["updated_at"] = ts
    return result


def config_schema() -> Dict[str, Any]:
    """Return a lightweight JSON schema describing architect_config fields."""
    return {
        "fields": {
            "repo_url": {"type": "string", "required": True},
            "repo_branch": {"type": "string", "default": "main"},
            "reference_docs": {"type": "array", "items": "string", "default": _DEFAULT_REFERENCE_DOCS},
            "scan_paths": {"type": "array", "items": "string", "default": _DEFAULT_SCAN_PATHS},
            "ticket_template": {"type": "string"},
            "architecture_guidelines": {"type": "string", "max": 10000},
            "tech_stack_constraints": {"type": "object"},
            "naming_conventions": {"type": "object"},
            "max_tickets_per_feature": {"type": "integer", "min": 1, "max": 20, "default": 8},
            "target_ticket_space_id": {"type": "string"},
            "complexity_estimation": {"type": "object"},
            "coding_tool": {"type": "enum", "values": ["claude_code", "codex"], "default": "claude_code"},
            "coding_tool_model": {"type": "string"},
            "max_analysis_time_seconds": {"type": "integer", "min": 120, "max": 3600, "default": 900},
            "require_design_review": {"type": "boolean", "default": False},
            "ticket_spec_style": {"type": "enum", "values": list(_SPEC_STYLES), "default": "compact"},
        }
    }


# ---------------------------------------------------------------------------
# Ticket filtering & claiming
# ---------------------------------------------------------------------------


def is_feature_decomposed(*, feature_ticket_id: str) -> bool:
    ensure_tables()
    resp = T.feature_decompositions.get_item(
        Key={"pk": _feature_pk(feature_ticket_id), "sk": "META"}
    )
    return resp.get("Item") is not None


def find_architect_eligible_tickets(
    *, agent_type_id: str, limit: int = 10
) -> List[Dict[str, Any]]:
    """Return open feature_request tickets that have NOT been decomposed yet."""
    ensure_tables()
    seen: Dict[str, Dict[str, Any]] = {}
    resp = tickets_svc.STORE._table.query(  # noqa: SLF001 - internal reuse
        KeyConditionExpression="pk = :pk",
        ExpressionAttributeValues={":pk": tickets_svc.label_index_pk(FEATURE_REQUEST_LABEL)},
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
        if is_feature_decomposed(feature_ticket_id=tid):
            continue
        seen[tid] = {
            "ticket_id": tid,
            "subject": ticket.get("subject", ""),
            "labels": sorted(set(ticket.get("labels", []))),
            "status": ticket.get("status", "open"),
            "created_at": int(ticket.get("created_at", 0) or 0),
        }
    out = sorted(seen.values(), key=lambda t: (t["created_at"], t["ticket_id"]))
    return out[:limit]


def claim_architect_ticket(
    *, agent_run_id: str, ticket_id: str, agent_sub: str
) -> Dict[str, Any]:
    """Assign a feature ticket to the architect run and set status=analyzing.

    Raises LookupError if the ticket does not exist and ValueError("already_claimed")
    if the feature has already been decomposed or claimed.
    """
    ticket = tickets_svc.STORE.get_ticket(ticket_id)
    if not ticket:
        raise LookupError("Ticket not found")
    if is_feature_decomposed(feature_ticket_id=ticket_id):
        raise ValueError("already_claimed")
    table = tickets_svc.STORE._table  # noqa: SLF001
    ts = now_ts()
    try:
        table.update_item(
            Key={"pk": f"TICKET#{ticket_id}", "sk": "META"},
            UpdateExpression=(
                "SET assigned_to_sub = :sub, #st = :analyzing, assigned_at = :ts, updated_at = :ts"
            ),
            ConditionExpression="attribute_not_exists(assigned_to_sub) OR assigned_to_sub = :none",
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={
                ":sub": agent_sub,
                ":analyzing": "analyzing",
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
        "status": "analyzing",
        "assigned_to_sub": agent_sub,
        "agent_run_id": agent_run_id,
        "claimed_at": ts,
    }


# ---------------------------------------------------------------------------
# Prompt builders (codebase analysis + solution design)
# ---------------------------------------------------------------------------


def _ticket_description(ticket: Dict[str, Any]) -> str:
    messages = ticket.get("messages") or []
    if messages:
        return messages[0].get("body", "") or ""
    return ""


def build_analysis_prompt(
    *,
    ticket: Dict[str, Any],
    reference_docs: List[str],
    scan_paths: List[str],
    guidelines: str,
    tech_constraints: Optional[Dict[str, str]] = None,
    naming_conventions: Optional[Dict[str, str]] = None,
) -> str:
    parts = [
        f"You are a solution architect. Analyze the codebase to ground a design for "
        f"feature request {ticket.get('ticket_id', '')}: {ticket.get('subject', '')}",
        "",
        "Feature request description:",
        _ticket_description(ticket) or "(no description provided)",
        "",
        "Step 1 — Read these reference documents to understand architecture and conventions:",
        *[f"  - {doc}" for doc in reference_docs],
        "",
        "Step 2 — Scan these paths for existing patterns (use find/ls/grep, cap at 500 files):",
        *[f"  - {path}" for path in scan_paths],
        "",
        "Step 3 — Identify existing code related to this feature and classify each file as "
        "reuse / modify / create.",
    ]
    if guidelines:
        parts += ["", "Architecture guidelines:", guidelines]
    if tech_constraints:
        parts += ["", "Tech stack constraints:", json.dumps(tech_constraints)]
    if naming_conventions:
        parts += ["", "Naming conventions:", json.dumps(naming_conventions)]
    parts += [
        "",
        "Output a JSON object with keys: files_scanned (int), patterns_found (list of str), "
        "existing_related_files (list of str), suggested_approach (str).",
    ]
    return "\n".join(parts)


def parse_codebase_analysis(*, tool_output: str) -> Dict[str, Any]:
    """Extract structured analysis with JSON-then-default fallback."""
    data = _extract_json(tool_output) or {}
    return {
        "files_scanned": int(data.get("files_scanned", 0) or 0),
        "patterns_found": list(data.get("patterns_found", []) or []),
        "existing_related_files": list(data.get("existing_related_files", []) or []),
        "suggested_approach": str(data.get("suggested_approach", "") or ""),
    }


def build_design_prompt(
    *,
    ticket: Dict[str, Any],
    analysis: Dict[str, Any],
    guidelines: str,
    tech_constraints: Optional[Dict[str, str]],
    naming_conventions: Optional[Dict[str, str]],
    complexity_estimation: Dict[str, float],
    max_tickets: int,
    ticket_spec_style: str,
) -> str:
    parts = [
        f"Design a technical solution for feature request {ticket.get('ticket_id', '')}: "
        f"{ticket.get('subject', '')}",
        "",
        "Codebase analysis:",
        json.dumps(analysis),
        "",
        "Produce a design that:",
        "  1. Defines the data model (DynamoDB tables / TableDef extensions)",
        "  2. Defines API endpoints (method, path, auth, request/response models)",
        "  3. Defines frontend components (pages, routes, types)",
        "  4. Defines an E2E test plan",
        f"  5. Breaks the work into at most {max_tickets} ordered development tickets",
        "  6. Assigns a complexity (low/medium/high/critical) and effort estimate to each",
        "  7. Establishes a dependency graph (no cycles)",
        "",
        f"Ticket spec style: {ticket_spec_style}.",
        f"Effort heuristics (days): {json.dumps(complexity_estimation)}",
    ]
    if guidelines:
        parts += ["", "Architecture guidelines:", guidelines]
    if tech_constraints:
        parts += ["", "Tech stack constraints:", json.dumps(tech_constraints)]
    if naming_conventions:
        parts += ["", "Naming conventions:", json.dumps(naming_conventions)]
    parts += [
        "",
        "Output a JSON object with keys: summary (str), tickets (list of "
        "{key, subject, ticket_type, complexity, estimated_hours, order, depends_on, "
        "overview, current_state, data_model, api_design, frontend_design, e2e_test_plan, "
        "error_handling, security, dependencies}), design_decisions (list of "
        "{decision, rationale, alternatives_considered}).",
    ]
    return "\n".join(parts)


def parse_solution_design(*, tool_output: str) -> Dict[str, Any]:
    """Extract: tickets list, design_decisions, summary."""
    data = _extract_json(tool_output) or {}
    return {
        "summary": str(data.get("summary", "") or "")[:_SUMMARY_MAX],
        "tickets": list(data.get("tickets", []) or []),
        "design_decisions": list(data.get("design_decisions", []) or []),
    }


def _extract_json(text: str) -> Optional[Dict[str, Any]]:
    if not text:
        return None
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        pass
    # Fallback: find first {...} block.
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end > start:
        try:
            return json.loads(text[start : end + 1])
        except (ValueError, TypeError):
            return None
    return None


# ---------------------------------------------------------------------------
# Complexity estimation
# ---------------------------------------------------------------------------


def estimate_complexity(*, ticket_data: Dict[str, Any], heuristics: Dict[str, float]) -> Dict[str, Any]:
    """Estimate effort using configured heuristics (in days), returns hours.

    Inputs read from ticket_data counts: new_tables, new_endpoints, new_pages,
    files_to_modify, test_sections. Falls back to ticket_data.estimated_hours when
    provided directly by the design output.
    """
    h = {**_DEFAULT_COMPLEXITY_ESTIMATION, **(heuristics or {})}
    breakdown: Dict[str, float] = {}
    counts = {
        "new_table": int(ticket_data.get("new_tables", 0) or 0),
        "new_endpoint": int(ticket_data.get("new_endpoints", 0) or 0),
        "new_page": int(ticket_data.get("new_pages", 0) or 0),
        "modify_file": int(ticket_data.get("files_to_modify", 0) or 0),
        "test_section": int(ticket_data.get("test_sections", 0) or 0),
    }
    total = 0.0
    for key, count in counts.items():
        if count:
            cost = h.get(key, 0.0) * count
            breakdown[key] = round(cost, 2)
            total += cost
    if total <= 0 and ticket_data.get("estimated_hours") is not None:
        total = float(ticket_data["estimated_hours"])
    if total <= 0:
        total = 4.0  # minimum baseline
    if total <= 6:
        complexity = "low"
    elif total <= 16:
        complexity = "medium"
    elif total <= 40:
        complexity = "high"
    else:
        complexity = "critical"
    declared = ticket_data.get("complexity")
    if declared in _COMPLEXITY_LEVELS:
        complexity = declared
    return {"complexity": complexity, "estimated_hours": round(total, 2), "breakdown": breakdown}


# ---------------------------------------------------------------------------
# Dependency graph
# ---------------------------------------------------------------------------


def build_dependency_graph(*, tickets: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    """Construct {ticket_id: [depends_on_ids]} from ticket metadata.

    Validates no circular dependencies and that all references resolve. Raises
    ValueError("circular_dependency") on a cycle.
    """
    graph: Dict[str, List[str]] = {}
    ids = {t.get("ticket_id") for t in tickets if t.get("ticket_id")}
    for t in tickets:
        tid = t.get("ticket_id")
        if not tid:
            continue
        deps = [d for d in (t.get("depends_on") or []) if d in ids]
        graph[tid] = deps
    # Cycle detection via DFS.
    WHITE, GRAY, BLACK = 0, 1, 2
    color = {tid: WHITE for tid in graph}

    def visit(node: str) -> None:
        color[node] = GRAY
        for dep in graph.get(node, []):
            if color.get(dep) == GRAY:
                raise ValueError("circular_dependency")
            if color.get(dep) == WHITE:
                visit(dep)
        color[node] = BLACK

    for tid in graph:
        if color[tid] == WHITE:
            visit(tid)
    return graph


def build_graph_view(*, tickets: List[Dict[str, Any]], graph: Dict[str, List[str]]) -> Dict[str, Any]:
    """Render nodes/edges for the dependency graph visualization."""
    by_id = {t.get("ticket_id"): t for t in tickets}
    nodes = []
    for t in tickets:
        nodes.append(
            {
                "id": t.get("ticket_id"),
                "subject": t.get("subject", ""),
                "complexity": t.get("complexity", "medium"),
                "order": int(t.get("order", 0) or 0),
                "status": t.get("status", "open"),
            }
        )
    edges = []
    for tid, deps in graph.items():
        for dep in deps:
            if dep in by_id:
                edges.append({"from": dep, "to": tid})
    return {"nodes": nodes, "edges": edges}


# ---------------------------------------------------------------------------
# Ticket content rendering
# ---------------------------------------------------------------------------


def generate_ticket_content(
    *, ticket_data: Dict[str, Any], template: str, ticket_spec_style: str, feature_ticket: Dict[str, Any]
) -> str:
    """Render the ticket template with placeholders filled from design data."""
    tmpl = template or _DEFAULT_TICKET_TEMPLATE
    depends_on = ticket_data.get("depends_on") or []
    values = {
        "{ticket_id}": str(ticket_data.get("ticket_id", "")),
        "{subject}": str(ticket_data.get("subject", "")),
        "{feature_ticket_id}": str(feature_ticket.get("ticket_id", "")),
        "{overview}": str(ticket_data.get("overview", "") or ticket_data.get("subject", "")),
        "{current_state}": str(ticket_data.get("current_state", "")),
        "{data_model}": str(ticket_data.get("data_model", "")),
        "{api_design}": str(ticket_data.get("api_design", "")),
        "{frontend_design}": str(ticket_data.get("frontend_design", "")),
        "{e2e_test_plan}": str(ticket_data.get("e2e_test_plan", "")),
        "{error_handling}": str(ticket_data.get("error_handling", "")),
        "{security}": str(ticket_data.get("security", "")),
        "{dependencies}": str(ticket_data.get("dependencies", "")),
        "{complexity}": str(ticket_data.get("complexity", "medium")),
        "{estimated_hours}": str(ticket_data.get("estimated_hours", 0)),
        "{depends_on}": ", ".join(depends_on) if depends_on else "none",
        "{build_order}": str(ticket_data.get("order", 0)),
    }
    out = tmpl
    for placeholder, value in values.items():
        out = out.replace(placeholder, value)
    if ticket_spec_style == "compact":
        out = out[:8000]
    return out


# ---------------------------------------------------------------------------
# Ticket generation + decomposition persistence
# ---------------------------------------------------------------------------


def create_dev_tickets(
    *,
    feature_ticket_id: str,
    agent_run_id: str,
    tickets_data: List[Dict[str, Any]],
    template: str,
    ticket_spec_style: str,
    space_id: Optional[str],
    agent_sub: str,
) -> List[Dict[str, Any]]:
    """Create dev tickets in the ticket system and link them via feature_decompositions."""
    ensure_tables()
    feature_ticket = tickets_svc.STORE.get_ticket(feature_ticket_id) or {"ticket_id": feature_ticket_id}
    created: List[Dict[str, Any]] = []
    ts = now_ts()
    # First pass: create tickets so we get real ticket_ids, map design keys -> ids.
    key_to_id: Dict[str, str] = {}
    pending: List[Dict[str, Any]] = []
    for idx, td in enumerate(tickets_data, start=1):
        est = estimate_complexity(
            ticket_data=td, heuristics={}
        ) if td.get("estimated_hours") is None else {
            "complexity": td.get("complexity", "medium"),
            "estimated_hours": float(td.get("estimated_hours", 0) or 0),
        }
        complexity = est["complexity"]
        estimated_hours = est["estimated_hours"]
        order = int(td.get("order", idx) or idx)
        ticket_type = td.get("ticket_type", "development")
        if ticket_type not in _TICKET_TYPES:
            ticket_type = "development"
        labels = [f"type:{ticket_type}", f"complexity:{complexity}"]
        ticket = tickets_svc.STORE.create_ticket(
            owner_sub=agent_sub,
            subject=td.get("subject", "Untitled"),
            description=td.get("overview", "") or td.get("subject", ""),
            space_id=space_id,
            labels=labels,
            estimated_effort_hours=int(round(estimated_hours)),
            metadata=_ddb_safe({
                "feature_request_id": feature_ticket_id,
                "depends_on": [],  # filled in second pass once IDs known
                "estimated_effort_hours": estimated_hours,
                "build_order": order,
            }),
        )
        dev_id = ticket.get("ticket_id")
        design_key = td.get("key") or td.get("ticket_id") or f"t{idx}"
        key_to_id[str(design_key)] = dev_id
        pending.append(
            {
                "dev_id": dev_id,
                "td": td,
                "complexity": complexity,
                "estimated_hours": estimated_hours,
                "order": order,
                "ticket_type": ticket_type,
            }
        )
    # Second pass: resolve depends_on keys to real ids, render content, persist links.
    for p in pending:
        td = p["td"]
        dev_id = p["dev_id"]
        raw_deps = td.get("depends_on") or []
        resolved_deps = [key_to_id.get(str(d), d) for d in raw_deps if str(d) in key_to_id]
        td_for_render = dict(td)
        td_for_render.update(
            {
                "ticket_id": dev_id,
                "complexity": p["complexity"],
                "estimated_hours": p["estimated_hours"],
                "order": p["order"],
                "depends_on": resolved_deps,
            }
        )
        content = generate_ticket_content(
            ticket_data=td_for_render,
            template=template,
            ticket_spec_style=ticket_spec_style,
            feature_ticket=feature_ticket,
        )
        # Persist resolved deps + rendered spec on the ticket metadata. We store the
        # spec in metadata rather than via add_message to avoid flipping the new
        # ticket's status away from "open".
        _update_ticket_metadata(dev_id, depends_on=resolved_deps, spec_content=content)
        # Write decomposition DEV# link row.
        T.feature_decompositions.put_item(
            Item=_ddb_safe({
                "pk": _feature_pk(feature_ticket_id),
                "sk": _dev_sk(dev_id),
                "feature_ticket_id": feature_ticket_id,
                "dev_ticket_id": dev_id,
                "agent_run_id": agent_run_id,
                "subject": td.get("subject", ""),
                "order": p["order"],
                "complexity": p["complexity"],
                "estimated_hours": p["estimated_hours"],
                "ticket_type": p["ticket_type"],
                "depends_on": resolved_deps,
                "created_at": ts,
                "GSI1PK": _run_gsi_pk(agent_run_id),
                "GSI1SK": ts,
            })
        )
        created.append(
            {
                "ticket_id": dev_id,
                "subject": td.get("subject", ""),
                "complexity": p["complexity"],
                "estimated_hours": p["estimated_hours"],
                "order": p["order"],
                "depends_on": resolved_deps,
            }
        )
    created.sort(key=lambda t: (t["order"], t["ticket_id"]))
    return created


def _update_ticket_metadata(ticket_id: str, *, depends_on: List[str], spec_content: str = "") -> None:
    ticket = tickets_svc.STORE.get_ticket(ticket_id)
    if not ticket:
        return
    table = tickets_svc.STORE._table  # noqa: SLF001
    meta = dict(ticket.get("metadata") or {})
    meta["depends_on"] = depends_on
    if spec_content:
        meta["spec_content"] = spec_content[:20000]
    table.update_item(
        Key={"pk": f"TICKET#{ticket_id}", "sk": "META"},
        UpdateExpression="SET metadata = :m, updated_at = :ts",
        ExpressionAttributeValues={":m": meta, ":ts": now_ts()},
    )


def write_decomposition_meta(
    *,
    feature_ticket_id: str,
    agent_run_id: str,
    summary: str,
    total_tickets: int,
    total_hours: float,
    dependency_graph: Dict[str, List[str]],
) -> None:
    """Write the META record to feature_decompositions (idempotent overwrite)."""
    ensure_tables()
    ts = now_ts()
    T.feature_decompositions.put_item(
        Item=_ddb_safe({
            "pk": _feature_pk(feature_ticket_id),
            "sk": "META",
            "feature_ticket_id": feature_ticket_id,
            "agent_run_id": agent_run_id,
            "decomposition_summary": (summary or "")[:_SUMMARY_MAX],
            "total_tickets_created": int(total_tickets),
            "total_estimated_hours": float(total_hours),
            "dependency_graph": json.dumps(dependency_graph),
            "created_at": ts,
            "GSI1PK": _run_gsi_pk(agent_run_id),
            "GSI1SK": ts,
        })
    )


def get_decomposition(*, feature_ticket_id: str) -> Optional[Dict[str, Any]]:
    """Return the decomposition (summary + dev tickets + graph) for a feature."""
    ensure_tables()
    resp = T.feature_decompositions.query(
        KeyConditionExpression="pk = :pk",
        ExpressionAttributeValues={":pk": _feature_pk(feature_ticket_id)},
    )
    items = resp.get("Items", [])
    meta = next((i for i in items if i.get("sk") == "META"), None)
    if meta is None:
        return None
    dev_items = [i for i in items if str(i.get("sk", "")).startswith("DEV#")]
    tickets = sorted(
        (
            {
                "ticket_id": i.get("dev_ticket_id"),
                "subject": i.get("subject", ""),
                "complexity": i.get("complexity", "medium"),
                "estimated_hours": float(i.get("estimated_hours", 0) or 0),
                "order": int(i.get("order", 0) or 0),
                "depends_on": list(i.get("depends_on", []) or []),
            }
            for i in dev_items
        ),
        key=lambda t: (t["order"], t["ticket_id"] or ""),
    )
    try:
        graph = json.loads(meta.get("dependency_graph", "{}"))
    except (ValueError, TypeError):
        graph = {}
    return {
        "feature_ticket_id": feature_ticket_id,
        "decomposition_summary": meta.get("decomposition_summary", ""),
        "total_tickets_created": int(meta.get("total_tickets_created", 0) or 0),
        "total_estimated_hours": float(meta.get("total_estimated_hours", 0) or 0),
        "dependency_graph": graph,
        "tickets": tickets,
    }


def get_dev_tickets_for_feature(*, feature_ticket_id: str) -> List[Dict[str, Any]]:
    ensure_tables()
    resp = T.feature_decompositions.query(
        KeyConditionExpression="pk = :pk AND begins_with(sk, :sk)",
        ExpressionAttributeValues={":pk": _feature_pk(feature_ticket_id), ":sk": "DEV#"},
    )
    rows = resp.get("Items", [])
    out = [
        {
            "ticket_id": r.get("dev_ticket_id"),
            "subject": r.get("subject", ""),
            "complexity": r.get("complexity", "medium"),
            "estimated_hours": float(r.get("estimated_hours", 0) or 0),
            "order": int(r.get("order", 0) or 0),
            "ticket_type": r.get("ticket_type", "development"),
            "depends_on": list(r.get("depends_on", []) or []),
        }
        for r in rows
    ]
    out.sort(key=lambda t: (t["order"], t["ticket_id"] or ""))
    return out


def get_dependency_graph_view(*, feature_ticket_id: str) -> Optional[Dict[str, Any]]:
    decomp = get_decomposition(feature_ticket_id=feature_ticket_id)
    if decomp is None:
        return None
    tickets = decomp["tickets"]
    graph = decomp["dependency_graph"]
    return build_graph_view(tickets=tickets, graph=graph)


# ---------------------------------------------------------------------------
# Architect output storage
# ---------------------------------------------------------------------------


def build_architect_output(
    *,
    feature_ticket_id: str,
    summary: str,
    tickets_created: List[Dict[str, Any]],
    dependency_graph: Dict[str, List[str]],
    codebase_analysis: Dict[str, Any],
    design_decisions: List[Dict[str, Any]],
    feedback_requested: bool = False,
    feedback_response: Optional[str] = None,
    duration_seconds: int = 0,
) -> Dict[str, Any]:
    total_hours = sum(float(t.get("estimated_hours", 0) or 0) for t in tickets_created)
    return {
        "feature_ticket_id": feature_ticket_id,
        "decomposition_summary": (summary or "")[:_SUMMARY_MAX],
        "tickets_created": list(tickets_created or []),
        "total_tickets": len(tickets_created or []),
        "total_estimated_hours": round(total_hours, 2),
        "dependency_graph": dependency_graph or {},
        "codebase_analysis": {
            "files_scanned": int(codebase_analysis.get("files_scanned", 0) or 0),
            "patterns_found": list(codebase_analysis.get("patterns_found", []) or []),
            "existing_related_files": list(codebase_analysis.get("existing_related_files", []) or []),
        },
        "design_decisions": list(design_decisions or []),
        "feedback_requested": bool(feedback_requested),
        "feedback_response": feedback_response,
        "total_duration_seconds": int(duration_seconds or 0),
    }


def store_architect_output(
    *, run_id: str, agent_type_id: str, output: Dict[str, Any]
) -> Dict[str, Any]:
    """Persist architect output on the agent_runs table + a metrics rollup row."""
    coder_svc.ensure_tables()
    ts = now_ts()
    item = {
        "pk": coder_svc._run_pk(run_id),  # noqa: SLF001 - shared key scheme
        "sk": "ARCHITECT_OUTPUT",
        "run_id": run_id,
        "agent_type_id": agent_type_id,
        "architect_output": output,
        "created_at": ts,
        "gsi_type_date_pk": f"ARCHITECT#{agent_type_id}",
        "gsi_type_date_sk": f"DATE#{ts}",
    }
    T.agent_runs.put_item(Item=_ddb_safe(item))
    return output


def get_architect_output(*, run_id: str) -> Optional[Dict[str, Any]]:
    coder_svc.ensure_tables()
    resp = T.agent_runs.get_item(
        Key={"pk": coder_svc._run_pk(run_id), "sk": "ARCHITECT_OUTPUT"}  # noqa: SLF001
    )
    item = resp.get("Item")
    if not item:
        return None
    return item.get("architect_output")


# ---------------------------------------------------------------------------
# Design review (AGENT-006 feedback loop)
# ---------------------------------------------------------------------------


def request_design_review(
    *,
    agent_run_id: str,
    feature_ticket_id: str,
    summary: str,
    design_decisions: List[Dict[str, Any]],
    tickets_preview: List[Dict[str, Any]],
) -> str:
    """Create a feedback request for human design review. Returns request id."""
    feedback_request_id = f"review_{agent_run_id}"
    logger.info(
        "architect_feedback_requested run=%s feature=%s decisions=%d",
        agent_run_id,
        feature_ticket_id,
        len(design_decisions),
    )
    return feedback_request_id


def apply_design_feedback(*, feedback: str, original_design: Dict[str, Any]) -> Dict[str, Any]:
    """Return a revised-design prompt context incorporating human feedback."""
    revised = dict(original_design)
    revised["feedback_response"] = feedback
    revised["revision_prompt"] = (
        "Revise the design based on this human feedback while preserving the "
        f"established structure:\n{feedback}"
    )
    return revised


# ---------------------------------------------------------------------------
# Status updates
# ---------------------------------------------------------------------------


def mark_feature_tickets_created(
    *, feature_ticket_id: str, agent_sub: str, summary: str, dev_ticket_ids: List[str]
) -> Dict[str, Any]:
    """Update feature request ticket status to tickets_created + add summary message."""
    ticket = tickets_svc.STORE.get_ticket(feature_ticket_id)
    if not ticket:
        raise LookupError("Feature request ticket not found")
    table = tickets_svc.STORE._table  # noqa: SLF001
    # Add the architecture summary message first; add_message would otherwise flip
    # the status away from "tickets_created", so we set the final status after it.
    body = (
        f"## Architecture Summary\n\n{summary}\n\n"
        f"### Generated development tickets ({len(dev_ticket_ids)})\n"
        + "\n".join(f"- {tid}" for tid in dev_ticket_ids)
    )
    try:
        tickets_svc.STORE.add_message(
            ticket_id=feature_ticket_id,
            sender_sub=agent_sub,
            sender_role="agent",
            body=body,
            email_targets=[],
        )
    except Exception:  # pragma: no cover - defensive
        pass
    ts = now_ts()
    meta = dict((tickets_svc.STORE.get_ticket(feature_ticket_id) or {}).get("metadata") or {})
    meta["dev_ticket_ids"] = dev_ticket_ids
    table.update_item(
        Key={"pk": f"TICKET#{feature_ticket_id}", "sk": "META"},
        UpdateExpression="SET #st = :s, metadata = :m, updated_at = :ts",
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={":s": "tickets_created", ":m": meta, ":ts": ts},
    )
    return {
        "ok": True,
        "ticket_id": feature_ticket_id,
        "status": "tickets_created",
        "dev_ticket_ids": dev_ticket_ids,
    }


# ---------------------------------------------------------------------------
# Workflow orchestration (state machine)
# ---------------------------------------------------------------------------

WORKFLOW_STEP_TYPES = (
    "clone_repo",
    "read_reference_docs",
    "scan_codebase",
    "analyze_feature",
    "design_solution",
    "estimate_effort",
    "build_dependency_graph",
    "request_review",
    "apply_feedback",
    "generate_tickets",
    "write_decomposition",
    "update_feature_ticket",
)


def _sanitize_branch(branch: str) -> str:
    """Sanitize a branch name to git-safe chars (GAP-0079).

    Mirrors the branch sanitization in ``agent_coder.generate_branch_name``:
    only ``[A-Za-z0-9_/-]`` survive, runs of ``-`` are collapsed, length capped.
    """
    name = re.sub(r"[^a-zA-Z0-9_/\-]", "-", branch or "main")
    name = re.sub(r"-{2,}", "-", name).strip("-/")
    if len(name) > 80:
        name = name[:80].rstrip("-/")
    return name or "main"


def build_architect_workflow(
    *, agent_run_id: str, config: Dict[str, Any], ticket: Dict[str, Any]
) -> Dict[str, Any]:
    """Generate ordered workflow steps. Pure / no I/O (safe for dry-run preview)."""
    cfg = _normalize_config(config)
    # GAP-0079 / SEC-021: validate the repo URL and sanitize the branch name to
    # git-safe chars before either is f-stringed into the clone_repo shell command.
    repo_url = validate_repo_url(cfg.get("repo_url", ""))
    branch = _sanitize_branch(cfg.get("repo_branch", "main"))
    # GAP-0096: defence-in-depth — drop any unsafe (absolute / traversal /
    # backslash / drive-letter) paths before they are spliced into the
    # read_reference_docs / scan_codebase shell commands, even if a stale
    # config bypassed validate_architect_config.
    reference_docs = [p for p in cfg.get("reference_docs", []) if _is_safe_path(str(p))]
    scan_paths = [p for p in cfg.get("scan_paths", []) if _is_safe_path(str(p))]
    max_time = int(cfg.get("max_analysis_time_seconds", 900))
    coding_tool = cfg.get("coding_tool", "claude_code")
    model = cfg.get("coding_tool_model")
    require_review = bool(cfg.get("require_design_review", False))

    analysis_prompt = build_analysis_prompt(
        ticket=ticket,
        reference_docs=reference_docs,
        scan_paths=scan_paths,
        guidelines=cfg.get("architecture_guidelines", ""),
        tech_constraints=cfg.get("tech_stack_constraints"),
        naming_conventions=cfg.get("naming_conventions"),
    )
    # GAP-0095: the analysis prompt embeds the user-controlled ticket subject.
    # shlex.quote it into a single shell token so embedded ``"``, ``$()``,
    # backticks, newlines, etc. cannot break out and execute when the command
    # string is run with shell=True. The full prompt is quoted (the prior
    # 160-char truncation + "..." was a display artefact of the unsafe path).
    prompt_arg = shlex.quote(analysis_prompt)
    if coding_tool == "codex":
        analyze_cmd = f"codex -q {prompt_arg}"
    else:
        model_flag = f" --model {shlex.quote(model)}" if model else ""
        analyze_cmd = f"claude --dangerously-skip-permissions{model_flag} -p {prompt_arg}"

    half = max_time // 2
    steps: List[Dict[str, Any]] = [
        {"step_id": 1, "type": "clone_repo",
         "command": f"git clone --depth 1 -b {shlex.quote(branch)} -- {shlex.quote(repo_url)} /workspace",
         "timeout_seconds": 120, "on_failure": "escalate"},
        {"step_id": 2, "type": "read_reference_docs",
         "command": "cat " + " ".join(reference_docs) if reference_docs else None,
         "timeout_seconds": 60, "on_failure": "next"},
        {"step_id": 3, "type": "scan_codebase",
         "command": "find " + " ".join(scan_paths) + " -type f | head -500" if scan_paths else None,
         "timeout_seconds": 120, "on_failure": "next"},
        {"step_id": 4, "type": "analyze_feature", "command": analyze_cmd,
         "timeout_seconds": half, "on_failure": "escalate"},
        {"step_id": 5, "type": "design_solution", "command": None,
         "timeout_seconds": half, "on_failure": "escalate"},
        {"step_id": 6, "type": "estimate_effort", "command": None,
         "timeout_seconds": 10, "on_failure": "next"},
        {"step_id": 7, "type": "build_dependency_graph", "command": None,
         "timeout_seconds": 10, "on_failure": "escalate"},
    ]
    step_id = 8
    if require_review:
        steps.append({"step_id": step_id, "type": "request_review", "command": None,
                      "timeout_seconds": 30, "on_failure": "pause"})
        step_id += 1
        steps.append({"step_id": step_id, "type": "apply_feedback", "command": None,
                      "timeout_seconds": half, "on_failure": "next"})
        step_id += 1
    steps.append({"step_id": step_id, "type": "generate_tickets", "command": None,
                  "timeout_seconds": 60, "on_failure": "escalate"})
    step_id += 1
    steps.append({"step_id": step_id, "type": "write_decomposition", "command": None,
                  "timeout_seconds": 30, "on_failure": "next"})
    step_id += 1
    steps.append({"step_id": step_id, "type": "update_feature_ticket", "command": None,
                  "timeout_seconds": 30, "on_failure": "next"})
    return {
        "steps": steps,
        "feature_ticket_id": ticket.get("ticket_id", ""),
        "require_design_review": require_review,
        "total_timeout_seconds": max_time,
    }


# ---------------------------------------------------------------------------
# Mock lifecycle driver (deterministic E2E transitions)
# ---------------------------------------------------------------------------


def _mock_design(*, ticket: Dict[str, Any], max_tickets: int) -> Dict[str, Any]:
    """Produce a deterministic 5-ticket design for the given feature request."""
    subject = ticket.get("subject", "feature")
    base = [
        {"key": "t1", "subject": f"Add data model for {subject}", "ticket_type": "development",
         "complexity": "low", "estimated_hours": 4, "order": 1, "depends_on": [],
         "overview": "Define the DynamoDB table and TableDef.",
         "data_model": "New table with pk/sk + GSI1."},
        {"key": "t2", "subject": f"Implement service layer for {subject}", "ticket_type": "development",
         "complexity": "medium", "estimated_hours": 12, "order": 2, "depends_on": ["t1"],
         "overview": "Business logic + DDB access."},
        {"key": "t3", "subject": f"Add API endpoints for {subject}", "ticket_type": "development",
         "complexity": "medium", "estimated_hours": 8, "order": 2, "depends_on": ["t1"],
         "overview": "Router with CRUD endpoints."},
        {"key": "t4", "subject": f"Build frontend for {subject}", "ticket_type": "development",
         "complexity": "medium", "estimated_hours": 10, "order": 3, "depends_on": ["t2", "t3"],
         "overview": "Pages, types, API endpoints."},
        {"key": "t5", "subject": f"Write E2E tests for {subject}", "ticket_type": "development",
         "complexity": "low", "estimated_hours": 8, "order": 4, "depends_on": ["t4"],
         "overview": "Playwright spec covering the feature."},
    ]
    tickets = base[: max(1, min(max_tickets, len(base)))]
    decisions = [
        {
            "decision": "Use a dedicated DynamoDB table",
            "rationale": "Keeps the access patterns isolated and matches existing single-table-per-domain convention.",
            "alternatives_considered": ["Reuse an existing table with new sk prefixes"],
        },
        {
            "decision": "Split service and router into separate tickets",
            "rationale": "Enables parallel work once the data model lands.",
            "alternatives_considered": ["Single combined backend ticket"],
        },
    ]
    summary = (
        f"## {subject}\n\nDecomposed into {len(tickets)} development tickets following the "
        f"project's data model -> service -> API -> frontend -> tests layering."
    )
    return {"summary": summary, "tickets": tickets, "design_decisions": decisions}


def run_mock_workflow(
    *,
    run_id: str,
    agent_type_id: str,
    ticket: Dict[str, Any],
    config: Dict[str, Any],
    agent_sub: str,
) -> Dict[str, Any]:
    """Drive the full decomposition lifecycle in mock mode (no real execution).

    Gated: when ``S.architect_execute_commands`` is true this would dispatch
    to the real Worker Agent Framework. For now mock is the only path so the state
    machine is fully driveable/testable.
    """
    ensure_tables()
    cfg = _normalize_config(config)
    feature_ticket_id = ticket.get("ticket_id", "")
    max_tickets = int(cfg.get("max_tickets_per_feature", 8))

    analysis = parse_codebase_analysis(
        tool_output=json.dumps(
            {
                "files_scanned": 42,
                "patterns_found": ["single-table DynamoDB", "router-per-domain", "React Query hooks"],
                "existing_related_files": ["app/services/messaging.py", "frontend/src/pages/messages/"],
                "suggested_approach": "Mirror the messaging domain layout.",
            }
        )
    )
    design = _mock_design(ticket=ticket, max_tickets=max_tickets)

    created = create_dev_tickets(
        feature_ticket_id=feature_ticket_id,
        agent_run_id=run_id,
        tickets_data=design["tickets"],
        template=cfg.get("ticket_template", _DEFAULT_TICKET_TEMPLATE),
        ticket_spec_style=cfg.get("ticket_spec_style", "compact"),
        space_id=cfg.get("target_ticket_space_id"),
        agent_sub=agent_sub,
    )
    # Build dependency graph keyed by real ticket ids.
    graph = build_dependency_graph(tickets=created)
    total_hours = sum(float(t.get("estimated_hours", 0) or 0) for t in created)

    feedback_requested = bool(cfg.get("require_design_review", False))
    if feedback_requested:
        request_design_review(
            agent_run_id=run_id,
            feature_ticket_id=feature_ticket_id,
            summary=design["summary"],
            design_decisions=design["design_decisions"],
            tickets_preview=created,
        )

    output = build_architect_output(
        feature_ticket_id=feature_ticket_id,
        summary=design["summary"],
        tickets_created=created,
        dependency_graph=graph,
        codebase_analysis=analysis,
        design_decisions=design["design_decisions"],
        feedback_requested=feedback_requested,
        duration_seconds=120,
    )
    store_architect_output(run_id=run_id, agent_type_id=agent_type_id, output=output)
    write_decomposition_meta(
        feature_ticket_id=feature_ticket_id,
        agent_run_id=run_id,
        summary=design["summary"],
        total_tickets=len(created),
        total_hours=total_hours,
        dependency_graph=graph,
    )
    try:
        mark_feature_tickets_created(
            feature_ticket_id=feature_ticket_id,
            agent_sub=agent_sub,
            summary=design["summary"],
            dev_ticket_ids=[t["ticket_id"] for t in created],
        )
    except LookupError:
        pass
    return output


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


def get_architect_metrics(*, agent_type_id: str, period_days: int = 30) -> Dict[str, Any]:
    """Aggregate decomposition metrics from stored architect runs."""
    coder_svc.ensure_tables()
    now = now_ts()
    period_start = now - period_days * 86400
    pk_val = f"ARCHITECT#{agent_type_id}"
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
    features = 0
    total_tickets = 0
    total_hours = 0.0
    for it in items:
        if int(it.get("created_at", 0) or 0) < period_start:
            continue
        output = it.get("architect_output") or {}
        features += 1
        total_tickets += int(output.get("total_tickets", 0) or 0)
        total_hours += float(output.get("total_estimated_hours", 0) or 0)
    avg_tickets = (total_tickets / features) if features else 0.0
    avg_hours = (total_hours / features) if features else 0.0
    decomposition_rate = (features / period_days) if period_days else 0.0
    return {
        "features_decomposed": features,
        "avg_tickets_per_feature": round(avg_tickets, 2),
        "avg_hours_per_feature": round(avg_hours, 2),
        "decomposition_rate": round(decomposition_rate, 4),
        "period_start": period_start,
        "period_end": now,
    }
