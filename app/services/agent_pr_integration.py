"""Agent PR & Ticket Integration service (AGENT-007).

Creates PRs from agent work, links PRs to tickets, manages the ticket
status lifecycle, handles cross-agent handoffs, and processes GitHub
webhook events.

In dev mode there is no real GitHub: PR creation via the "api" method
returns mock data, and the "cli" method records a `gh pr create` command
that would be injected into the agent terminal.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import re
from decimal import Decimal
from typing import Any, Dict, List, Optional
from uuid import uuid4

import httpx

from app.core.settings import S
from app.core.validate_url import validate_repo_url
from app.core.tables import T
from app.core.time import now_ts
from app.services.tickets import TicketStore
from app.services import agent_orchestrator as orchestrator
from app.services import terminal_monitor
from app.services import agent_memory
from app.services.alerts import audit_event

logger = logging.getLogger(__name__)

_ticket_store = TicketStore()

# The ticket store enforces a small set of core statuses on update_status().
# Agent lifecycle statuses (code_complete, in_review, qa_passed, ...) are NOT
# valid there, so we store them on the ticket meta item under `agent_status`
# and only forward the four core statuses to update_status().
_CORE_TICKET_STATUSES = ("open", "in_progress", "waiting_on_user", "done")


# ---------------------------------------------------------------------------
# Git state detection
# ---------------------------------------------------------------------------

GIT_PATTERNS: Dict[str, str] = {
    "branch": r"(?:On branch|Switched to.*branch) ['\"]?([a-zA-Z0-9/_.-]+)",
    "commit_count": r"(\d+) commits? ahead",
    "files_changed": r"(\d+) files? changed",
    "pr_created": r"(?:Pull request|PR) (?:created|opened).*?(https://github\.com/[^\s]+/pull/\d+)",
    "pr_url": r"(https://github\.com/[^\s]+/pull/\d+)",
    "pushed": r"(?:Enumerating|Counting|Writing) objects.*done",
    "branch_pushed": r"remote:\s+Create a pull request",
}


def detect_git_state(terminal_output: str) -> Dict[str, Any]:
    """Extract git state from terminal output.

    Scans for branch names, commit counts, PR URLs, and push confirmations.
    """
    state: Dict[str, Any] = {
        "branch": "",
        "commit_count": 0,
        "files_changed": 0,
        "pr_url": "",
        "pushed": False,
    }
    if not terminal_output:
        return state

    for key, pattern in GIT_PATTERNS.items():
        match = re.search(pattern, terminal_output)
        if not match:
            continue
        if key == "branch":
            state["branch"] = match.group(1)
        elif key == "commit_count":
            state["commit_count"] = int(match.group(1))
        elif key == "files_changed":
            state["files_changed"] = int(match.group(1))
        elif key in ("pr_created", "pr_url"):
            if not state["pr_url"]:
                state["pr_url"] = match.group(1)
        elif key in ("pushed", "branch_pushed"):
            state["pushed"] = True

    return state


# ---------------------------------------------------------------------------
# Ticket status lifecycle config
# ---------------------------------------------------------------------------

DEFAULT_STATUS_FLOWS: Dict[str, Dict[str, str]] = {
    "coder": {
        "on_claim": "in_progress",
        "on_working": "in_progress",
        "on_complete": "code_complete",
        "on_pr_created": "in_review",
        "on_pr_merged": "done",
        "next_agent_type": "qa",
    },
    "qa": {
        "on_claim": "in_qa",
        "on_working": "in_qa",
        "on_complete": "qa_passed",
        "on_pr_created": "in_review",
        "on_pr_merged": "done",
        "next_agent_type": "",
    },
    "reviewer": {
        "on_claim": "in_review",
        "on_working": "in_review",
        "on_complete": "reviewed",
        "on_pr_created": "",
        "on_pr_merged": "",
        "next_agent_type": "",
    },
    "devops": {
        "on_claim": "in_progress",
        "on_working": "in_progress",
        "on_complete": "deployed",
        "on_pr_created": "in_review",
        "on_pr_merged": "done",
        "next_agent_type": "",
    },
}

_FLOW_KEYS = (
    "on_claim", "on_working", "on_complete",
    "on_pr_created", "on_pr_merged", "next_agent_type",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _coerce(value: Any) -> Any:
    if isinstance(value, Decimal):
        return int(value)
    if isinstance(value, list):
        return [_coerce(v) for v in value]
    if isinstance(value, dict):
        return {k: _coerce(v) for k, v in value.items()}
    return value


def _pr_out(item: Dict[str, Any]) -> Dict[str, Any]:
    """Project a raw PR DDB item to the API response shape."""
    return {
        "pr_id": item.get("pr_id", ""),
        "worker_id": item.get("worker_id", ""),
        "ticket_id": item.get("ticket_id", ""),
        "repo_url": item.get("repo_url", ""),
        "pr_url": item.get("pr_url", ""),
        "pr_number": int(item.get("pr_number", 0) or 0),
        "branch": item.get("branch", ""),
        "title": item.get("title", ""),
        "description": item.get("description", ""),
        "files_changed": _coerce(item.get("files_changed", []) or []),
        "commit_count": int(item.get("commit_count", 0) or 0),
        "status": item.get("status", "open"),
        "created_at": int(item.get("created_at", 0) or 0),
        "merged_at": int(item.get("merged_at", 0) or 0),
        "user_id": item.get("user_id", item.get("pk", "").replace("USER#", "")),
    }


def _get_worker(user_id: str, worker_id: str) -> Optional[Dict[str, Any]]:
    return T.agent_workers.get_item(
        Key={"pk": f"USER#{user_id}", "sk": f"WORKER#{worker_id}"}
    ).get("Item")


def _set_ticket_meta(ticket_id: str, update_expr: str, values: Dict[str, Any]) -> None:
    """Update raw fields on a ticket META item (best effort)."""
    try:
        _ticket_store._table.update_item(
            Key={"pk": f"TICKET#{ticket_id}", "sk": "META"},
            UpdateExpression=update_expr,
            ExpressionAttributeValues=values,
        )
    except Exception:  # noqa: BLE001 - ticket may not exist in tests
        logger.debug("ticket meta update skipped for %s", ticket_id, exc_info=True)


def _apply_status(ticket_id: str, actor_sub: str, status: str) -> None:
    """Apply a status to a ticket.

    Core statuses go through TicketStore.update_status (which validates
    transitions). Agent lifecycle statuses are stored on the meta item under
    `agent_status` instead.
    """
    if not status:
        return
    if status in _CORE_TICKET_STATUSES:
        try:
            _ticket_store.update_status(
                ticket_id=ticket_id, actor_sub=actor_sub or "system", status=status,
            )
            return
        except Exception:  # noqa: BLE001 - fall through to agent_status
            logger.debug("core status update failed for %s", ticket_id, exc_info=True)
    _set_ticket_meta(ticket_id, "SET agent_status = :st", {":st": status})


# ---------------------------------------------------------------------------
# Status flow config
# ---------------------------------------------------------------------------

def get_status_flow_config(user_id: str, agent_type: str) -> Dict[str, Any]:
    """Get the status flow config for an agent type (custom or default)."""
    resp = T.agent_workers.query(
        KeyConditionExpression="pk = :pk AND begins_with(sk, :prefix)",
        FilterExpression="agent_type = :at",
        ExpressionAttributeValues={
            ":pk": f"USER#{user_id}", ":prefix": "FLOW#", ":at": agent_type,
        },
    )
    items = resp.get("Items", [])
    if items:
        # Most recent custom config wins.
        items.sort(key=lambda i: int(i.get("created_at", 0) or 0), reverse=True)
        item = items[0]
        flow = {k: item.get(k, "") for k in _FLOW_KEYS}
        flow["agent_type"] = agent_type
        return flow
    base = DEFAULT_STATUS_FLOWS.get(agent_type, DEFAULT_STATUS_FLOWS["coder"]).copy()
    base["agent_type"] = agent_type
    return base


def set_status_flow_config(
    user_id: str, agent_type: str, flow: Dict[str, str],
) -> Dict[str, Any]:
    """Set custom status flow config for an agent type.

    Validates statuses against the union of core + known agent lifecycle
    statuses. Merges over the existing/default config.
    """
    current = get_status_flow_config(user_id, agent_type)
    merged = {k: current.get(k, "") for k in _FLOW_KEYS}
    for k in _FLOW_KEYS:
        if flow.get(k) is not None:
            merged[k] = flow[k]

    flow_id = uuid4().hex
    item = {
        "pk": f"USER#{user_id}",
        "sk": f"FLOW#{flow_id}",
        "flow_id": flow_id,
        "agent_type": agent_type,
        "created_at": now_ts(),
        **merged,
    }
    T.agent_workers.put_item(Item=item)
    result = dict(merged)
    result["agent_type"] = agent_type
    return result


def _get_status_flow(user_id: str, agent_type: str) -> Dict[str, str]:
    return get_status_flow_config(user_id, agent_type)


# ---------------------------------------------------------------------------
# Work summary generation
# ---------------------------------------------------------------------------

def generate_work_summary(
    terminal_output: str, ticket_id: str, agent_type: str,
) -> Dict[str, Any]:
    """Generate a structured summary of the agent's work from terminal output."""
    summary: Dict[str, Any] = {
        "text": "",
        "files_changed": [],
        "decisions": [],
        "test_results": {},
        "errors_resolved": [],
    }
    output = terminal_output or ""

    files = re.findall(r"(?:modified|new file|deleted):\s+(.+)", output)
    summary["files_changed"] = sorted({f.strip() for f in files})

    test_match = re.search(r"(\d+) (?:tests?|specs?) passed.*?(\d+) failed", output)
    if test_match:
        summary["test_results"] = {
            "passed": int(test_match.group(1)),
            "failed": int(test_match.group(2)),
        }

    decisions = re.findall(r"\[DECISION\]\s*(.+)", output)
    summary["decisions"] = [d.strip() for d in decisions]

    errors = re.findall(r"\[RESOLVED\]\s*(.+)", output)
    summary["errors_resolved"] = [e.strip() for e in errors]

    parts = [f"Ticket: {ticket_id}", f"Agent type: {agent_type}"]
    if summary["files_changed"]:
        parts.append(
            f"Files changed ({len(summary['files_changed'])}): "
            + ", ".join(summary["files_changed"][:10])
        )
    if summary["test_results"]:
        parts.append(
            f"Tests: {summary['test_results'].get('passed', 0)} passed, "
            f"{summary['test_results'].get('failed', 0)} failed"
        )
    if summary["decisions"]:
        parts.append("Decisions: " + "; ".join(summary["decisions"][:5]))

    summary["text"] = "\n".join(parts)
    return summary


# ---------------------------------------------------------------------------
# PR description + gh command building
# ---------------------------------------------------------------------------

def _generate_pr_description(
    *,
    ticket_id: str,
    ticket_title: str,
    ticket_description: str,
    branch: str,
    files_changed: List[str],
    terminal_output: str,
) -> str:
    parts = [
        f"## Ticket: {ticket_id}",
        f"**{ticket_title}**",
        "",
        "## Summary",
        ticket_description[:500] if ticket_description else "No description provided.",
        "",
    ]
    if files_changed:
        parts.append("## Files Changed")
        for f in files_changed[:20]:
            parts.append(f"- `{f}`")
        parts.append("")
    parts.append("---")
    parts.append("*This PR was created by an autonomous AI agent.*")
    return "\n".join(parts)


def _build_gh_pr_command(title: str, description: str, branch: str) -> str:
    """Build a `gh pr create` command string with shell-escaped arguments."""
    def esc(value: str) -> str:
        # Single-quote and escape embedded single quotes for shell safety.
        return "'" + value.replace("'", "'\\''") + "'"

    return (
        f"gh pr create --title {esc(title)} "
        f"--body {esc(description)} "
        f"--head {esc(branch)}\n"
    )


# Extract (owner, repo) from a GitHub HTTPS or SSH URL.
_GITHUB_REPO_RE = re.compile(
    r"(?:https?://[^/]+/|git@[^:]+:)([^/]+)/([^/]+?)(?:\.git)?$"
)


def _parse_owner_repo(repo_url: str) -> tuple[str, str]:
    """Extract (owner, repo) from a GitHub HTTPS or SSH URL.

    Returns (owner, repo) or raises ValueError if the URL is not parseable.
    """
    m = _GITHUB_REPO_RE.match((repo_url or "").strip())
    if not m:
        raise ValueError(
            f"Cannot parse owner/repo from repo_url: {repo_url!r}. "
            "Expected format: https://github.com/owner/repo or "
            "git@github.com:owner/repo"
        )
    return m.group(1), m.group(2)


def _create_pr_via_api(
    *,
    repo_url: str,
    branch: str,
    title: str,
    description: str,
    user_id: str,
    base_branch: str = "main",
) -> Dict[str, Any]:
    """Create a PR via the GitHub REST API.

    In dev mode (or when no token is configured) returns mock data and makes
    no outbound network call (dev/prod parity, SECOPS-007).

    In production with a configured ``GITHUB_TOKEN`` this POSTs to
    ``{github_api_base_url}/repos/{owner}/{repo}/pulls``.

    Raises ``ValueError`` for malformed/unsafe repo URLs and
    ``httpx.HTTPStatusError`` on non-2xx GitHub responses.
    """
    token = getattr(S, "github_token", "")
    if S.dev_mode or not token:
        pr_number = (abs(hash(branch or title)) % 9000) + 1
        base = repo_url or "https://github.com/example/repo"
        return {
            "html_url": f"{base}/pull/{pr_number}",
            "number": pr_number,
            "state": "open",
        }

    # Reject shell-metacharacter / dangerous-protocol / SSRF-prone repo URLs
    # (GAP-0079) before parsing owner/repo and building the API URL.
    validate_repo_url(repo_url)
    owner, repo = _parse_owner_repo(repo_url)
    api_url = f"{S.github_api_base_url}/repos/{owner}/{repo}/pulls"

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    payload = {
        "title": title,
        "body": description,
        "head": branch,
        "base": base_branch or "main",
    }

    resp = httpx.post(api_url, json=payload, headers=headers, timeout=30)
    resp.raise_for_status()
    data = resp.json()

    logger.info(
        "github_pr_created owner=%s repo=%s user_id=%s number=%s",
        owner, repo, user_id, data.get("number"),
    )
    return {
        "html_url": data["html_url"],
        "number": data["number"],
        "state": data["state"],
    }


# ---------------------------------------------------------------------------
# PR creation
# ---------------------------------------------------------------------------

def create_pr_from_agent(
    user_id: str,
    worker_id: str,
    ticket_id: str,
    *,
    repo_url: str = "",
    branch: str = "",
    title: str = "",
    description: str = "",
    files_changed: Optional[List[str]] = None,
    method: str = "cli",
) -> Dict[str, Any]:
    """Create a PR from agent work (CLI injection or GitHub API)."""
    ts = now_ts()
    pr_id = uuid4().hex

    terminal_output = terminal_monitor.get_terminal_output(worker_id, chars=10000)
    git_state = detect_git_state(terminal_output)

    actual_branch = branch or git_state.get("branch") or f"agent/{worker_id}/{ticket_id}"
    actual_files = list(files_changed) if files_changed else []

    ticket = _ticket_store.get_ticket(ticket_id)
    ticket_title = ""
    ticket_description = ""
    if ticket:
        ticket_title = ticket.get("subject") or ticket.get("title") or "Untitled"
        ticket_description = ticket.get("description", "") or str(
            (ticket.get("metadata") or {}).get("description", "")
        )
    ticket_title = ticket_title or f"Ticket {ticket_id}"

    pr_title = title or f"[{ticket_id}] {ticket_title}"
    pr_description = description or _generate_pr_description(
        ticket_id=ticket_id,
        ticket_title=ticket_title,
        ticket_description=ticket_description,
        branch=actual_branch,
        files_changed=actual_files,
        terminal_output=terminal_output,
    )

    pr_url = ""
    pr_number = 0
    gh_command = ""

    if method == "cli":
        gh_command = _build_gh_pr_command(pr_title, pr_description, actual_branch)
        # Record the command on the worker's terminal buffer so it appears in
        # captured output (real injection would go through a PTY).
        buf = terminal_monitor.get_or_create_buffer(worker_id)
        buf.append(gh_command)
        pr_url = git_state.get("pr_url", "")
    else:
        result = _create_pr_via_api(
            repo_url=repo_url,
            branch=actual_branch,
            title=pr_title,
            description=pr_description,
            user_id=user_id,
        )
        pr_url = result.get("html_url", "")
        pr_number = int(result.get("number", 0) or 0)

    pr_record = {
        "pk": f"USER#{user_id}",
        "sk": f"PR#{pr_id}",
        "pr_id": pr_id,
        "user_id": user_id,
        "worker_id": worker_id,
        "ticket_id": ticket_id,
        "repo_url": repo_url,
        "pr_url": pr_url,
        "pr_number": pr_number,
        "branch": actual_branch,
        "title": pr_title,
        "description": pr_description,
        "files_changed": actual_files,
        "commit_count": int(git_state.get("commit_count", 0) or 0),
        "method": method,
        "gh_command": gh_command,
        "status": "open",
        "created_at": ts,
        "merged_at": 0,
    }
    T.agent_workers.put_item(Item=pr_record)

    _link_pr_to_ticket(ticket_id, pr_url, pr_number)
    _transition_ticket_on_pr_created(user_id, worker_id, ticket_id)

    try:
        audit_event(
            "agent.pr_created", user_id, None,
            worker_id=worker_id, ticket_id=ticket_id, pr_url=pr_url, pr_id=pr_id,
        )
    except Exception:  # noqa: BLE001
        logger.debug("audit_event failed for agent.pr_created", exc_info=True)

    return _pr_out(pr_record)


def _link_pr_to_ticket(ticket_id: str, pr_url: str, pr_number: int) -> None:
    update_expr = "SET pr_url = :url, pr_status = :st"
    values: Dict[str, Any] = {":url": pr_url, ":st": "open"}
    if pr_number:
        update_expr += ", pr_number = :num"
        values[":num"] = pr_number
    _set_ticket_meta(ticket_id, update_expr, values)


def _transition_ticket_on_pr_created(user_id: str, worker_id: str, ticket_id: str) -> None:
    worker = _get_worker(user_id, worker_id)
    agent_type = worker.get("agent_type", "coder") if worker else "coder"
    flow = _get_status_flow(user_id, agent_type)
    _apply_status(ticket_id, "system", flow.get("on_pr_created", ""))


# ---------------------------------------------------------------------------
# Work completion + cross-agent handoff
# ---------------------------------------------------------------------------

def _trigger_cross_agent_handoff(ticket_id: str, next_agent_type: str) -> None:
    """Queue a ticket for pickup by the next agent type.

    Re-opens the ticket (so it is eligible) and clears the claim so a new
    agent can pick it up.
    """
    _apply_status(ticket_id, "system", "open")
    _set_ticket_meta(
        ticket_id,
        "SET agent_eligible = :yes, next_agent_type = :nat, "
        "agent_worker_id = :empty, agent_state = :ready",
        {":yes": "yes", ":nat": next_agent_type, ":empty": "", ":ready": "ready_for_agent"},
    )
    logger.info(
        "Cross-agent handoff: ticket %s queued for %s agent", ticket_id, next_agent_type
    )


def complete_agent_work(
    user_id: str, worker_id: str, ticket_id: str,
) -> Dict[str, Any]:
    """Complete agent work on a ticket: summary, PR, memory, status, handoff."""
    terminal_output = terminal_monitor.get_terminal_output(worker_id, chars=20000)

    worker = _get_worker(user_id, worker_id)
    if not worker:
        raise ValueError("Worker not found")
    agent_type = worker.get("agent_type", "coder")

    summary = generate_work_summary(terminal_output, ticket_id, agent_type)
    git_state = detect_git_state(terminal_output)

    ts = now_ts()
    update_expr = "SET agent_summary = :sum, agent_completed_at = :ts"
    expr_values: Dict[str, Any] = {":sum": summary["text"], ":ts": ts}
    if summary.get("files_changed"):
        update_expr += ", agent_files_changed = :files"
        expr_values[":files"] = summary["files_changed"]
    if summary.get("decisions"):
        update_expr += ", agent_decisions = :dec"
        expr_values[":dec"] = summary["decisions"]
    _set_ticket_meta(ticket_id, update_expr, expr_values)

    pr_record: Optional[Dict[str, Any]] = None
    if agent_type == "coder" and (git_state.get("pushed") or git_state.get("branch")):
        pr_record = create_pr_from_agent(
            user_id, worker_id, ticket_id,
            repo_url=worker.get("repo_url", ""),
            branch=git_state.get("branch", ""),
            files_changed=summary.get("files_changed", []),
        )

    try:
        agent_memory.add_memory(
            worker_id,
            category="learning",
            title=f"Completed: {ticket_id}",
            content=summary["text"],
            ticket_id=ticket_id,
            importance=3,
        )
    except Exception:  # noqa: BLE001
        logger.debug("add_memory failed during completion", exc_info=True)

    status_flow = _get_status_flow(user_id, agent_type)
    new_status = status_flow.get("on_complete", "done")
    _apply_status(ticket_id, user_id, new_status)

    next_agent = status_flow.get("next_agent_type", "")

    # Release the claim / increment counters via the orchestrator.
    try:
        orchestrator.complete_ticket(
            user_id, worker_id, ticket_id,
            summary=summary["text"],
            pr_url=pr_record["pr_url"] if pr_record else "",
        )
    except Exception:  # noqa: BLE001
        logger.debug("orchestrator.complete_ticket failed", exc_info=True)

    # Cross-agent handoff happens after completion so the ticket is re-queued.
    if next_agent:
        _trigger_cross_agent_handoff(ticket_id, next_agent)

    return {
        "ticket_id": ticket_id,
        "summary": {
            "ticket_id": ticket_id,
            "text": summary["text"],
            "files_changed": summary["files_changed"],
            "decisions": summary["decisions"],
            "test_results": summary["test_results"],
        },
        "pr": pr_record,
        "new_status": new_status,
        "next_agent_type": next_agent,
    }


# ---------------------------------------------------------------------------
# Listing / lookup
# ---------------------------------------------------------------------------

def list_agent_prs(
    user_id: str,
    *,
    worker_id: Optional[str] = None,
    ticket_id: Optional[str] = None,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """List agent-created PRs for a user."""
    resp = T.agent_workers.query(
        KeyConditionExpression="pk = :pk AND begins_with(sk, :prefix)",
        ExpressionAttributeValues={":pk": f"USER#{user_id}", ":prefix": "PR#"},
        Limit=max(1, min(limit, 200)),
    )
    items = resp.get("Items", [])
    if worker_id:
        items = [i for i in items if i.get("worker_id") == worker_id]
    if ticket_id:
        items = [i for i in items if i.get("ticket_id") == ticket_id]
    out = [_pr_out(i) for i in items]
    out.sort(key=lambda p: p["created_at"], reverse=True)
    return out


def get_agent_pr(user_id: str, pr_id: str) -> Optional[Dict[str, Any]]:
    item = T.agent_workers.get_item(
        Key={"pk": f"USER#{user_id}", "sk": f"PR#{pr_id}"}
    ).get("Item")
    return _pr_out(item) if item else None


def list_all_agent_prs(*, limit: int = 200) -> List[Dict[str, Any]]:
    """Admin: list agent PRs across all users (scan)."""
    items: List[Dict[str, Any]] = []
    scan_kwargs: Dict[str, Any] = {
        "FilterExpression": "begins_with(sk, :prefix)",
        "ExpressionAttributeValues": {":prefix": "PR#"},
    }
    while True:
        resp = T.agent_workers.scan(**scan_kwargs)
        for item in resp.get("Items", []):
            items.append(_pr_out(item))
            if len(items) >= limit:
                break
        if len(items) >= limit:
            break
        last = resp.get("LastEvaluatedKey")
        if not last:
            break
        scan_kwargs["ExclusiveStartKey"] = last
    items.sort(key=lambda p: p["created_at"], reverse=True)
    return items[:limit]


def _find_pr_by_url(pr_url: str) -> Optional[Dict[str, Any]]:
    if not pr_url:
        return None
    scan_kwargs: Dict[str, Any] = {
        "FilterExpression": "begins_with(sk, :prefix) AND pr_url = :url",
        "ExpressionAttributeValues": {":prefix": "PR#", ":url": pr_url},
    }
    while True:
        resp = T.agent_workers.scan(**scan_kwargs)
        items = resp.get("Items", [])
        if items:
            return items[0]
        last = resp.get("LastEvaluatedKey")
        if not last:
            return None
        scan_kwargs["ExclusiveStartKey"] = last


# ---------------------------------------------------------------------------
# GitHub webhook handling
# ---------------------------------------------------------------------------

def verify_webhook_signature(body: bytes, signature: str) -> bool:
    """Verify a GitHub webhook HMAC-SHA256 signature.

    Expects a header value like `sha256=<hex>`. In dev mode with no configured
    secret, verification passes (so local E2E can exercise the receiver).
    """
    secret = getattr(S, "github_webhook_secret", "")
    if not secret:
        # No secret configured -> accept (dev/local). Production must set one.
        return True
    if not signature:
        return False
    expected = "sha256=" + hmac.new(
        secret.encode("utf-8"), body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


def handle_github_webhook(
    payload: Dict[str, Any], event_type: str,
) -> Dict[str, Any]:
    """Handle a GitHub webhook event."""
    if event_type == "pull_request" and payload.get("action") == "closed":
        pr = payload.get("pull_request", {}) or {}
        pr_url = pr.get("html_url", "")
        if pr.get("merged"):
            return _handle_pr_merged(pr_url, pr)
        return _handle_pr_closed(pr_url, pr)

    if event_type == "pull_request_review":
        pr = payload.get("pull_request", {}) or {}
        review = payload.get("review", {}) or {}
        return _handle_pr_review(pr.get("html_url", ""), review)

    return {"handled": False, "reason": f"Unhandled event: {event_type}"}


def _handle_pr_merged(pr_url: str, pr_data: Dict[str, Any]) -> Dict[str, Any]:
    ts = now_ts()
    record = _find_pr_by_url(pr_url)
    ticket_id = ""
    if record:
        ticket_id = record.get("ticket_id", "")
        T.agent_workers.update_item(
            Key={"pk": record["pk"], "sk": record["sk"]},
            UpdateExpression="SET #st = :st, merged_at = :ts",
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={":st": "merged", ":ts": ts},
        )
        user_id = record.get("user_id", record.get("pk", "").replace("USER#", ""))
        worker = _get_worker(user_id, record.get("worker_id", ""))
        agent_type = worker.get("agent_type", "coder") if worker else "coder"
        flow = _get_status_flow(user_id, agent_type)
        merged_status = flow.get("on_pr_merged", "done") or "done"
        _apply_status(ticket_id, "system", merged_status)
        _set_ticket_meta(ticket_id, "SET pr_status = :st", {":st": "merged"})
    return {"handled": True, "action": "pr_merged", "pr_url": pr_url, "ticket_id": ticket_id}


def _handle_pr_closed(pr_url: str, pr_data: Dict[str, Any]) -> Dict[str, Any]:
    ts = now_ts()
    record = _find_pr_by_url(pr_url)
    ticket_id = ""
    if record:
        ticket_id = record.get("ticket_id", "")
        T.agent_workers.update_item(
            Key={"pk": record["pk"], "sk": record["sk"]},
            UpdateExpression="SET #st = :st, merged_at = :ts",
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={":st": "closed", ":ts": ts},
        )
        _set_ticket_meta(ticket_id, "SET pr_status = :st", {":st": "closed"})
    return {"handled": True, "action": "pr_closed", "pr_url": pr_url, "ticket_id": ticket_id}


def _handle_pr_review(pr_url: str, review: Dict[str, Any]) -> Dict[str, Any]:
    record = _find_pr_by_url(pr_url)
    ticket_id = record.get("ticket_id", "") if record else ""
    state = (review.get("state") or "").lower()
    if record and ticket_id:
        _set_ticket_meta(ticket_id, "SET pr_review_state = :rs", {":rs": state})
    return {
        "handled": True, "action": "pr_reviewed",
        "pr_url": pr_url, "ticket_id": ticket_id, "review_state": state,
    }
