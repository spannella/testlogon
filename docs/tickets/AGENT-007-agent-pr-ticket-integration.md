# AGENT-007: Agent PR & Ticket Integration

**Ticket**: AGENT-007
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: High
**Estimated effort**: 8-10 days
**Dependencies**: AGENT-003 (Agent Framework), AGENT-006 (Terminal Monitoring), existing ticket system (`app/services/tickets.py`)

---

## 1. Overview & Motivation

### 1.1 Purpose

AGENT-007 closes the loop between autonomous agent work and the ticket/PR workflow. When a coder agent completes work on a ticket, this system detects the git branch and changes in terminal output, creates a pull request on GitHub (or injects a `gh pr create` command into the terminal), links the PR to the ticket, updates the ticket status through defined lifecycle transitions, and generates a summary of what was done. It also handles cross-agent ticket flows where one agent type triggers another (e.g., coder marks "code complete" which triggers QA agent pickup) and GitHub webhook integration where PR merge events update ticket status.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| User | As a user, I want agents to automatically create PRs when they finish coding so that I don't have to manually push and create PRs. | Agent completes work; system detects branch; creates PR via GitHub API or `gh` CLI; PR URL stored on ticket. |
| User | As a user, I want PRs to include a clear description of what the agent did so that reviewers have context. | PR description includes ticket title, changes summary, files modified, decisions made. |
| User | As a user, I want ticket status to update automatically as agents work so that I can track progress. | Status transitions: Open -> In Progress -> Code Complete -> In Review -> Merged/Done. |
| User | As a user, I want QA agents to automatically pick up tickets after coder agents finish so that testing is seamless. | Coder marks "code complete"; ticket transitions to "ready for QA"; QA agent's filter matches and claims it. |
| User | As a user, I want merged PRs to automatically close tickets so that the workflow is fully automated. | GitHub webhook fires on PR merge; system finds linked ticket; transitions to "Done". |
| User | As a user, I want agents to generate a summary of their work so that I can review what was done without reading all the code. | Agent summary includes: ticket ID, changes made, files touched, test results, decisions taken. |
| User | As a user, I want to configure ticket status transitions per agent type so that my workflow matches my team's process. | Configurable transition map: which statuses each agent type can set. |
| Admin | As an admin, I want to see all agent-generated PRs across users for audit so that I can monitor platform-generated code. | Admin endpoint lists all agent PRs with ticket links, worker IDs, and timestamps. |

### 1.3 Why This Is Needed

The agent framework (AGENT-003) can drive agents through tickets, and the terminal monitor (AGENT-006) can detect completion. But without AGENT-007, completed work sits in a terminal with no PR, no ticket update, and no handoff to the next agent. This is the integration layer that connects agent output to the development workflow tools (GitHub, ticket system) that teams actually use.

---

## 2. Current State Analysis

### 2.1 Existing Infrastructure

| Component | Location | Relevance |
|-----------|----------|-----------|
| Ticket store | `app/services/tickets.py` | `update_ticket_status`, `add_message_to_ticket`; status field on ticket items |
| Agent orchestrator | `app/services/agent_orchestrator.py` (AGENT-003) | `complete_ticket()`, `claim_ticket()`, `release_ticket()` |
| Terminal monitor | `app/services/terminal_monitor.py` (AGENT-006) | Completion signal detection, terminal output capture |
| Alerts service | `app/services/alerts.py` | `audit_event()`, `create_alert()` |
| Agent memory | `app/services/agent_memory.py` (AGENT-005) | `add_memory()` for recording learnings after ticket completion |
| Settings | `app/core/settings.py` | GitHub token, webhook secret configuration |
| Webhook patterns | `app/services/delegation_api.py` | Webhook delivery with HMAC signing; reference for GitHub webhook verification |

### 2.2 Gaps

1. **No GitHub API integration** -- no client for creating PRs, posting comments, or reading PR status.
2. **No PR-to-ticket linking** -- tickets have no `pr_url` or `pr_number` fields.
3. **No agent work summary generation** -- no mechanism to extract and structure what an agent did.
4. **No cross-agent ticket flow** -- no trigger mechanism for one agent type to hand off to another.
5. **No GitHub webhook receiver** -- no endpoint to receive GitHub webhook events (PR merged, review submitted).
6. **No ticket status lifecycle config** -- ticket status transitions are not formalized per agent type.
7. **No git state detection** -- no mechanism to determine the current branch, commit count, or changed files from terminal output.

---

## 3. Technical Design

### 3.1 DynamoDB Schema Extensions

#### 3.1.1 Ticket Extensions

Add to existing ticket items in the `tickets` table:

| Field | Type | Description |
|-------|------|-------------|
| `pr_url` | S | GitHub PR URL (e.g., `https://github.com/org/repo/pull/42`) |
| `pr_number` | N | PR number (e.g., 42) |
| `pr_status` | S | `open`, `merged`, `closed` |
| `agent_summary` | S | Agent-generated work summary |
| `agent_files_changed` | L | List of file paths the agent modified |
| `agent_decisions` | L | List of decisions the agent made during work |
| `agent_completed_at` | N | When the agent finished work |
| `next_agent_type` | S | Agent type that should pick up next (cross-agent flow) |

#### 3.1.2 Agent PR Records

New item pattern in `agent_workers` table:

| PK Pattern | SK Pattern | Purpose | Key Fields |
|------------|------------|---------|------------|
| `USER#{user_id}` | `PR#{pr_id}` | Agent-created PR record | `pr_id`, `worker_id`, `ticket_id`, `repo_url`, `pr_url`, `pr_number`, `branch`, `title`, `description`, `files_changed`, `commit_count`, `status`, `created_at`, `merged_at` |

#### 3.1.3 Ticket Status Transition Config

New item pattern in `agent_workers` table:

| PK Pattern | SK Pattern | Purpose | Key Fields |
|------------|------------|---------|------------|
| `USER#{user_id}` | `FLOW#{flow_id}` | Status transition map | `flow_id`, `agent_type`, `on_claim`, `on_working`, `on_complete`, `on_pr_created`, `on_pr_merged`, `next_agent_type` |

### 3.2 Git State Detection

```python
# In app/services/agent_pr_integration.py

GIT_PATTERNS = {
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
    Returns structured git state data.
    """
    state = {
        "branch": "",
        "commit_count": 0,
        "files_changed": 0,
        "pr_url": "",
        "pushed": False,
    }

    for key, pattern in GIT_PATTERNS.items():
        match = re.search(pattern, terminal_output)
        if match:
            if key == "branch":
                state["branch"] = match.group(1)
            elif key == "commit_count":
                state["commit_count"] = int(match.group(1))
            elif key == "files_changed":
                state["files_changed"] = int(match.group(1))
            elif key in ("pr_created", "pr_url"):
                state["pr_url"] = match.group(1)
            elif key == "pushed":
                state["pushed"] = True

    return state
```

### 3.3 Ticket Status Lifecycle

```python
# In app/services/agent_pr_integration.py

DEFAULT_STATUS_FLOWS = {
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
        "on_pr_created": "",   # Reviewer doesn't create PRs
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
```

### 3.4 Backend Service

**New file**: `app/services/agent_pr_integration.py` (~500 lines)

```python
"""Agent PR & Ticket Integration service (AGENT-007).

Creates PRs from agent work, links PRs to tickets, manages
ticket status lifecycle, and handles cross-agent handoffs.
"""

from __future__ import annotations
import json
import logging
import re
from typing import Any, Dict, List, Optional
from uuid import uuid4

from app.core.tables import T
from app.core.time import now_ts
from app.services.tickets import TicketStore
from app.services.agent_orchestrator import complete_ticket as orchestrator_complete
from app.services.terminal_monitor import get_terminal_output
from app.services.agent_memory import add_memory
from app.services.alerts import audit_event, create_alert

logger = logging.getLogger(__name__)

_ticket_store = TicketStore()


def create_pr_from_agent(
    user_id: str,
    worker_id: str,
    ticket_id: str,
    *,
    repo_url: str = "",
    branch: str = "",
    title: str = "",
    description: str = "",
    files_changed: List[str] | None = None,
    method: str = "cli",  # "cli" or "api"
) -> Dict[str, Any]:
    """Create a PR from agent work.

    Two methods:
    - cli: Inject `gh pr create` command into agent terminal (AGENT-006)
    - api: Call GitHub API directly using stored GitHub token

    Steps:
    1. Detect git state from terminal output (branch, commits)
    2. Generate PR title and description from ticket + work summary
    3. Create PR (via CLI injection or API)
    4. Store PR record in DDB
    5. Link PR to ticket
    6. Transition ticket status
    """
    ts = now_ts()
    pr_id = uuid4().hex

    # Get terminal output for git state detection
    terminal_output = get_terminal_output(worker_id, chars=10000)
    git_state = detect_git_state(terminal_output)

    actual_branch = branch or git_state.get("branch", f"agent/{worker_id}/{ticket_id}")
    actual_files = files_changed or []

    # Get ticket for PR description context
    ticket = _ticket_store.get_ticket(ticket_id)
    ticket_title = ticket.get("title", "Untitled") if ticket else "Untitled"

    # Generate PR title and description
    pr_title = title or f"[{ticket_id}] {ticket_title}"
    pr_description = description or _generate_pr_description(
        ticket_id=ticket_id,
        ticket_title=ticket_title,
        ticket_description=ticket.get("description", "") if ticket else "",
        branch=actual_branch,
        files_changed=actual_files,
        terminal_output=terminal_output,
    )

    pr_url = ""
    pr_number = 0

    if method == "cli":
        # Inject gh pr create command into terminal
        from app.services.terminal_monitor import _inject_into_terminal
        cmd = _build_gh_pr_command(pr_title, pr_description, actual_branch)
        _inject_into_terminal(user_id, worker_id, cmd)
        # PR URL will be detected from terminal output by the monitor
        pr_url = git_state.get("pr_url", "")
    else:
        # Call GitHub API directly
        pr_result = _create_pr_via_api(
            repo_url=repo_url,
            branch=actual_branch,
            title=pr_title,
            description=pr_description,
            user_id=user_id,
        )
        pr_url = pr_result.get("html_url", "")
        pr_number = pr_result.get("number", 0)

    # Store PR record
    pr_record = {
        "pk": f"USER#{user_id}",
        "sk": f"PR#{pr_id}",
        "pr_id": pr_id,
        "worker_id": worker_id,
        "ticket_id": ticket_id,
        "repo_url": repo_url,
        "pr_url": pr_url,
        "pr_number": pr_number,
        "branch": actual_branch,
        "title": pr_title,
        "description": pr_description,
        "files_changed": actual_files,
        "commit_count": git_state.get("commit_count", 0),
        "status": "open",
        "created_at": ts,
        "merged_at": 0,
    }
    T.agent_workers.put_item(Item=pr_record)

    # Link PR to ticket
    _link_pr_to_ticket(ticket_id, pr_url, pr_number)

    # Transition ticket status
    _transition_ticket_on_pr_created(user_id, worker_id, ticket_id)

    audit_event(user_id, event="agent.pr_created", outcome="success",
                details={"worker_id": worker_id, "ticket_id": ticket_id, "pr_url": pr_url})

    return pr_record


def complete_agent_work(
    user_id: str,
    worker_id: str,
    ticket_id: str,
) -> Dict[str, Any]:
    """Complete agent work on a ticket.

    Called by AGENT-006 when completion signal is detected.
    1. Generate work summary from terminal output
    2. Update ticket with summary, files changed, decisions
    3. Create PR if applicable (coder agent)
    4. Record learnings in agent memory (AGENT-005)
    5. Transition ticket status
    6. Trigger cross-agent handoff if configured
    7. Call AGENT-003 complete_ticket to release claim
    """
    terminal_output = get_terminal_output(worker_id, chars=20000)

    # Get worker info
    worker = T.agent_workers.get_item(
        Key={"pk": f"USER#{user_id}", "sk": f"WORKER#{worker_id}"}
    ).get("Item")
    if not worker:
        raise ValueError("Worker not found")

    agent_type = worker.get("agent_type", "coder")

    # Generate work summary
    summary = generate_work_summary(terminal_output, ticket_id, agent_type)

    # Detect git state
    git_state = detect_git_state(terminal_output)

    # Update ticket with agent results
    ts = now_ts()
    update_expr = "SET agent_summary = :sum, agent_completed_at = :ts"
    expr_values = {":sum": summary["text"], ":ts": ts}

    if summary.get("files_changed"):
        update_expr += ", agent_files_changed = :files"
        expr_values[":files"] = summary["files_changed"]

    if summary.get("decisions"):
        update_expr += ", agent_decisions = :dec"
        expr_values[":dec"] = summary["decisions"]

    _ticket_store._table.update_item(
        Key={"pk": f"TICKET#{ticket_id}", "sk": "META"},
        UpdateExpression=update_expr,
        ExpressionAttributeValues=expr_values,
    )

    # Create PR if coder agent and changes were pushed
    pr_record = None
    if agent_type == "coder" and git_state.get("pushed"):
        pr_record = create_pr_from_agent(
            user_id, worker_id, ticket_id,
            repo_url=worker.get("repo_url", ""),
            branch=git_state.get("branch", ""),
            files_changed=summary.get("files_changed", []),
        )

    # Record learnings in memory
    add_memory(
        worker_id,
        category="learning",
        title=f"Completed: {ticket_id}",
        content=summary["text"],
        ticket_id=ticket_id,
        importance=3,
    )

    # Transition ticket status
    status_flow = _get_status_flow(user_id, agent_type)
    new_status = status_flow.get("on_complete", "done")
    _ticket_store.update_ticket_status(ticket_id, new_status)

    # Trigger cross-agent handoff
    next_agent = status_flow.get("next_agent_type", "")
    if next_agent:
        _trigger_cross_agent_handoff(ticket_id, next_agent)

    # Complete in orchestrator
    orchestrator_complete(
        user_id, worker_id, ticket_id,
        summary=summary["text"],
        pr_url=pr_record["pr_url"] if pr_record else "",
    )

    return {
        "ticket_id": ticket_id,
        "summary": summary,
        "pr": pr_record,
        "new_status": new_status,
        "next_agent_type": next_agent,
    }


def generate_work_summary(
    terminal_output: str,
    ticket_id: str,
    agent_type: str,
) -> Dict[str, Any]:
    """Generate a structured summary of the agent's work.

    Extracts from terminal output:
    - What was done (high-level description)
    - Files changed (from git diff/status output)
    - Test results (pass/fail counts)
    - Decisions made (from agent's own output)
    - Errors encountered and resolved
    """
    summary = {
        "text": "",
        "files_changed": [],
        "decisions": [],
        "test_results": {},
        "errors_resolved": [],
    }

    # Extract files changed from git status/diff output
    file_pattern = r"(?:modified|new file|deleted):\s+(.+)"
    files = re.findall(file_pattern, terminal_output)
    summary["files_changed"] = list(set(files))

    # Extract test results
    test_pattern = r"(\d+) (?:tests?|specs?) passed.*?(\d+) failed"
    test_match = re.search(test_pattern, terminal_output)
    if test_match:
        summary["test_results"] = {
            "passed": int(test_match.group(1)),
            "failed": int(test_match.group(2)),
        }

    # Extract decisions (agent outputs these as structured markers)
    decision_pattern = r"\[DECISION\]\s*(.+)"
    decisions = re.findall(decision_pattern, terminal_output)
    summary["decisions"] = decisions

    # Build summary text
    parts = [f"Ticket: {ticket_id}", f"Agent type: {agent_type}"]
    if summary["files_changed"]:
        parts.append(f"Files changed ({len(summary['files_changed'])}): " +
                     ", ".join(summary["files_changed"][:10]))
    if summary["test_results"]:
        parts.append(f"Tests: {summary['test_results'].get('passed', 0)} passed, "
                     f"{summary['test_results'].get('failed', 0)} failed")
    if decisions:
        parts.append("Decisions: " + "; ".join(decisions[:5]))

    summary["text"] = "\n".join(parts)
    return summary


def handle_github_webhook(
    payload: Dict[str, Any],
    event_type: str,
    signature: str,
) -> Dict[str, Any]:
    """Handle incoming GitHub webhook events.

    Supported events:
    - pull_request.merged: Update ticket status to "done"
    - pull_request.closed: Update ticket status to "closed" (if not merged)
    - pull_request_review.submitted: Record review on ticket
    """
    if event_type == "pull_request" and payload.get("action") == "closed":
        pr = payload.get("pull_request", {})
        pr_url = pr.get("html_url", "")

        if pr.get("merged"):
            return _handle_pr_merged(pr_url, pr)
        else:
            return _handle_pr_closed(pr_url, pr)

    elif event_type == "pull_request_review":
        pr = payload.get("pull_request", {})
        review = payload.get("review", {})
        pr_url = pr.get("html_url", "")
        return _handle_pr_review(pr_url, review)

    return {"handled": False, "reason": f"Unhandled event: {event_type}"}


def _handle_pr_merged(pr_url: str, pr_data: Dict) -> Dict[str, Any]:
    """Handle a merged PR: update ticket status and PR record."""
    # Find ticket linked to this PR URL
    # Update ticket status to "done" (from status flow on_pr_merged)
    # Update PR record status to "merged", merged_at
    # Send notification
    return {"handled": True, "action": "pr_merged", "pr_url": pr_url}


def _handle_pr_closed(pr_url: str, pr_data: Dict) -> Dict[str, Any]:
    """Handle a closed (not merged) PR."""
    return {"handled": True, "action": "pr_closed", "pr_url": pr_url}


def _handle_pr_review(pr_url: str, review: Dict) -> Dict[str, Any]:
    """Handle a PR review submission."""
    # Add review comment to ticket
    # If approved: update ticket status
    return {"handled": True, "action": "pr_reviewed", "pr_url": pr_url}


def list_agent_prs(
    user_id: str,
    *,
    worker_id: str | None = None,
    ticket_id: str | None = None,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """List agent-created PRs for a user."""
    resp = T.agent_workers.query(
        KeyConditionExpression="pk = :pk AND begins_with(sk, :prefix)",
        ExpressionAttributeValues={":pk": f"USER#{user_id}", ":prefix": "PR#"},
        Limit=limit,
        ScanIndexForward=False,
    )
    items = resp.get("Items", [])

    if worker_id:
        items = [i for i in items if i.get("worker_id") == worker_id]
    if ticket_id:
        items = [i for i in items if i.get("ticket_id") == ticket_id]

    return items


def get_status_flow_config(
    user_id: str,
    agent_type: str,
) -> Dict[str, Any]:
    """Get the status flow config for an agent type.

    Returns custom config if set, otherwise defaults.
    """
    resp = T.agent_workers.query(
        KeyConditionExpression="pk = :pk AND begins_with(sk, :prefix)",
        FilterExpression="agent_type = :at",
        ExpressionAttributeValues={
            ":pk": f"USER#{user_id}", ":prefix": "FLOW#", ":at": agent_type,
        },
    )
    items = resp.get("Items", [])
    if items:
        return items[0]
    return DEFAULT_STATUS_FLOWS.get(agent_type, DEFAULT_STATUS_FLOWS["coder"])


def set_status_flow_config(
    user_id: str,
    agent_type: str,
    flow: Dict[str, str],
) -> Dict[str, Any]:
    """Set custom status flow config for an agent type."""
    flow_id = uuid4().hex
    item = {
        "pk": f"USER#{user_id}",
        "sk": f"FLOW#{flow_id}",
        "flow_id": flow_id,
        "agent_type": agent_type,
        **flow,
        "created_at": now_ts(),
    }
    T.agent_workers.put_item(Item=item)
    return item


def _link_pr_to_ticket(ticket_id: str, pr_url: str, pr_number: int) -> None:
    """Link a PR to a ticket record."""
    update_expr = "SET pr_url = :url, pr_status = :st"
    values: Dict[str, Any] = {":url": pr_url, ":st": "open"}
    if pr_number:
        update_expr += ", pr_number = :num"
        values[":num"] = pr_number
    _ticket_store._table.update_item(
        Key={"pk": f"TICKET#{ticket_id}", "sk": "META"},
        UpdateExpression=update_expr,
        ExpressionAttributeValues=values,
    )


def _transition_ticket_on_pr_created(user_id: str, worker_id: str, ticket_id: str) -> None:
    """Transition ticket status when PR is created."""
    worker = T.agent_workers.get_item(
        Key={"pk": f"USER#{user_id}", "sk": f"WORKER#{worker_id}"}
    ).get("Item")
    agent_type = worker.get("agent_type", "coder") if worker else "coder"
    flow = _get_status_flow(user_id, agent_type)
    new_status = flow.get("on_pr_created")
    if new_status:
        _ticket_store.update_ticket_status(ticket_id, new_status)


def _get_status_flow(user_id: str, agent_type: str) -> Dict[str, str]:
    """Get the active status flow for an agent type."""
    return get_status_flow_config(user_id, agent_type)


def _trigger_cross_agent_handoff(ticket_id: str, next_agent_type: str) -> None:
    """Set ticket for pickup by the next agent type.

    Sets ticket.agent_eligible = "yes" and ticket.next_agent_type,
    then clears agent_worker_id so a new agent can claim it.
    """
    _ticket_store._table.update_item(
        Key={"pk": f"TICKET#{ticket_id}", "sk": "META"},
        UpdateExpression="SET agent_eligible = :yes, next_agent_type = :nat, "
                        "agent_worker_id = :empty, agent_state = :ready",
        ExpressionAttributeValues={
            ":yes": "yes", ":nat": next_agent_type,
            ":empty": "", ":ready": "ready_for_agent",
        },
    )
    logger.info("Cross-agent handoff: ticket %s queued for %s agent", ticket_id, next_agent_type)


def _build_gh_pr_command(title: str, description: str, branch: str) -> str:
    """Build a gh pr create command string."""
    # Escape quotes in title and description
    safe_title = title.replace('"', '\\"')
    safe_desc = description.replace('"', '\\"').replace("\n", "\\n")
    return f'gh pr create --title "{safe_title}" --body "{safe_desc}" --head "{branch}"\n'


def _generate_pr_description(
    *,
    ticket_id: str,
    ticket_title: str,
    ticket_description: str,
    branch: str,
    files_changed: List[str],
    terminal_output: str,
) -> str:
    """Generate a PR description from ticket and work context."""
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


def _create_pr_via_api(
    *,
    repo_url: str,
    branch: str,
    title: str,
    description: str,
    user_id: str,
) -> Dict[str, Any]:
    """Create a PR via GitHub API.

    In dev mode: returns a mock PR response.
    In prod: uses stored GitHub token to call GitHub REST API.
    """
    from app.core.settings import S
    if S.dev_mode:
        pr_number = hash(branch) % 10000
        return {
            "html_url": f"{repo_url}/pull/{pr_number}",
            "number": pr_number,
            "state": "open",
        }
    # Real implementation would use httpx/requests with GitHub token
    raise NotImplementedError("GitHub API integration requires GITHUB_TOKEN")
```

### 3.5 Backend Router

**New file**: `app/routers/agent_pr.py` (~300 lines)

Prefix: `/ui/agent/pr`

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/ui/agent/pr/{worker_id}/create` | `require_ui_session` | Manually trigger PR creation for current ticket |
| `GET` | `/ui/agent/pr` | `require_ui_session` | List agent-created PRs |
| `GET` | `/ui/agent/pr/{pr_id}` | `require_ui_session` | Get PR details |
| `GET` | `/ui/agent/pr/ticket/{ticket_id}` | `require_ui_session` | Get PR linked to a ticket |
| `POST` | `/ui/agent/pr/{worker_id}/complete` | `require_ui_session` | Manually trigger work completion |
| `GET` | `/ui/agent/pr/status-flow/{agent_type}` | `require_ui_session` | Get status flow config |
| `PUT` | `/ui/agent/pr/status-flow/{agent_type}` | `require_ui_session` | Set custom status flow config |
| `POST` | `/ui/agent/webhooks/github` | Webhook auth | Receive GitHub webhook events |
| `GET` | `/ui/admin/agent/prs` | `require_admin_session` | Admin: list all agent PRs |

### 3.6 Pydantic Models

**Add to `app/models.py`**:

```python
# -- Agent PR & Ticket Integration (AGENT-007) --

class AgentPrCreateIn(BaseModel):
    ticket_id: str = Field(..., min_length=1)
    repo_url: str = Field(default="", max_length=500)
    branch: str = Field(default="", max_length=200)
    title: str = Field(default="", max_length=200)
    description: str = Field(default="", max_length=10000)
    files_changed: Optional[List[str]] = None
    method: str = Field(default="cli", pattern="^(cli|api)$")

class AgentPrOut(BaseModel):
    pr_id: str
    worker_id: str
    ticket_id: str
    repo_url: str = ""
    pr_url: str = ""
    pr_number: int = 0
    branch: str = ""
    title: str = ""
    description: str = ""
    files_changed: List[str] = Field(default_factory=list)
    commit_count: int = 0
    status: str = "open"
    created_at: int = 0
    merged_at: int = 0

class AgentPrListOut(BaseModel):
    prs: List[AgentPrOut]
    count: int

class WorkSummaryOut(BaseModel):
    ticket_id: str
    text: str
    files_changed: List[str] = Field(default_factory=list)
    decisions: List[str] = Field(default_factory=list)
    test_results: Dict[str, int] = Field(default_factory=dict)

class AgentCompletionOut(BaseModel):
    ticket_id: str
    summary: WorkSummaryOut
    pr: Optional[AgentPrOut] = None
    new_status: str
    next_agent_type: str = ""

class StatusFlowConfig(BaseModel):
    agent_type: str
    on_claim: str = "in_progress"
    on_working: str = "in_progress"
    on_complete: str = "code_complete"
    on_pr_created: str = "in_review"
    on_pr_merged: str = "done"
    next_agent_type: str = ""

class StatusFlowUpdateIn(BaseModel):
    on_claim: Optional[str] = None
    on_working: Optional[str] = None
    on_complete: Optional[str] = None
    on_pr_created: Optional[str] = None
    on_pr_merged: Optional[str] = None
    next_agent_type: Optional[str] = None

class GithubWebhookPayload(BaseModel):
    action: str
    pull_request: Optional[Dict[str, Any]] = None
    review: Optional[Dict[str, Any]] = None
    repository: Optional[Dict[str, Any]] = None
```

### 3.7 Frontend Components

#### AgentPrList (`frontend/src/pages/agents/AgentPrList.tsx`)

Component (~250 lines):

- **PR table**: DataTable with columns: Ticket ID, PR Title, Branch, Status badge, Worker, Created, Actions
- **Status badges**: `open` (green), `merged` (purple), `closed` (gray)
- **Actions**: Open PR (external link), View Ticket, View Worker
- **Filter**: By worker, by ticket, by status

#### TicketAgentStatus (`frontend/src/pages/agents/TicketAgentStatus.tsx`)

Component (~150 lines):

- Embedded in ticket detail view showing: assigned agent, agent state, work summary, linked PR
- Progress indicator showing ticket lifecycle stages (Open -> In Progress -> Code Complete -> In Review -> Done)
- Manual "Create PR" and "Complete Work" buttons for intervention

#### StatusFlowEditor (`frontend/src/pages/agents/StatusFlowEditor.tsx`)

Component (~200 lines):

- Visual editor for ticket status flow per agent type
- Dropdown selectors for each transition point (on_claim, on_complete, etc.)
- Next agent type selector for cross-agent handoffs
- "Reset to Defaults" button

#### Route & Navigation

```tsx
<Route path="/agents/prs" element={<AgentPrList />} />
```

Sidebar: "Agent PRs" with `GitPullRequest` icon under "AI Agents" group.

---

## 4. Implementation Plan

### Phase 1: Git Detection + PR Creation (3-4 days)

| File | Change |
|------|--------|
| `app/services/agent_pr_integration.py` | New file: git detection, PR creation (CLI + API), summary generation |
| `app/models.py` | Add PR and status flow Pydantic models |

### Phase 2: Ticket Lifecycle + Cross-Agent Flow (2-3 days)

| File | Change |
|------|--------|
| `app/services/agent_pr_integration.py` | Add status flow config, cross-agent handoff, complete_agent_work |
| `app/services/tickets.py` | Add `update_ticket_status` support for agent-driven transitions |
| `scripts/local-ddb-init.py` | Extend agent_workers table for PR# and FLOW# items |

### Phase 3: Router + Webhooks (2 days)

| File | Change |
|------|--------|
| `app/routers/agent_pr.py` | New file: 9 endpoints including GitHub webhook |
| `app/main.py` | Register `agent_pr_router` |
| `app/core/settings.py` | Add `github_webhook_secret`, `github_token` settings |

### Phase 4: Frontend (2-3 days)

| File | Change |
|------|--------|
| `frontend/src/api/types.ts` | Add PR and status flow TypeScript types |
| `frontend/src/api/endpoints/agentPr.ts` | New file: API wrappers |
| `frontend/src/pages/agents/AgentPrList.tsx` | New file: PR list page |
| `frontend/src/pages/agents/TicketAgentStatus.tsx` | New file: ticket agent status component |
| `frontend/src/pages/agents/StatusFlowEditor.tsx` | New file: status flow editor |
| `frontend/src/App.tsx` | Add `/agents/prs` route |

### Phase 5: E2E Tests (1-2 days)

| File | Change |
|------|--------|
| `frontend/e2e/agent-pr-integration.spec.ts` | New file: ~16 tests in 4 sections |

---

## 5. E2E Test Plan (`frontend/e2e/agent-pr-integration.spec.ts`)

**Test setup**: Uses `e2e_admin_session_setup.py` sessions. `beforeAll` creates an LLM key (AGENT-001), a coder worker (AGENT-002), and a ticket. Claims the ticket for the worker via AGENT-003 API.

**Section 647: PR Creation API (4 tests)**

1. `Create PR from agent work (CLI method)` -- POST `/ui/agent/pr/{worker_id}/create` with `ticket_id`, `method: "cli"`. Verify 201 with `pr_id`, `ticket_id`, `branch` containing worker_id, `title` containing ticket title.
2. `Create PR from agent work (API method)` -- POST with `method: "api"`, `repo_url: "https://github.com/test/repo"`. Verify 201 with `pr_url` containing `github.com`, `pr_number > 0`.
3. `List agent PRs` -- GET `/ui/agent/pr`. Verify `count >= 2`, each PR has `pr_id`, `worker_id`, `ticket_id`, `status: "open"`.
4. `Get PR linked to ticket` -- GET `/ui/agent/pr/ticket/{ticket_id}`. Verify at least 1 PR linked with matching `ticket_id`.

**Section 648: Work Completion API (4 tests)**

5. `Complete agent work generates summary` -- POST `/ui/agent/pr/{worker_id}/complete` with `ticket_id`. Verify response has `summary` with `text`, `new_status` is non-empty.
6. `Ticket updated with agent summary` -- GET the ticket. Verify `agent_summary` is populated, `agent_completed_at > 0`.
7. `Worker returns to idle after completion` -- GET agent status. Verify `agent_state: "idle"`, `current_ticket_id: ""`, `tickets_completed` incremented.
8. `Work completion records memory` -- GET `/ui/agent/memory/{worker_id}/entries`. Verify at least 1 entry with `category: "learning"` and `ticket_id` matching the completed ticket.

**Section 649: Status Flow & Cross-Agent API (5 tests)**

9. `Get default status flow for coder` -- GET `/ui/agent/pr/status-flow/coder`. Verify `on_claim: "in_progress"`, `on_complete: "code_complete"`, `on_pr_merged: "done"`, `next_agent_type: "qa"`.
10. `Set custom status flow` -- PUT `/ui/agent/pr/status-flow/coder` with `on_complete: "ready_for_review"`. Verify 200. GET flow, verify updated value.
11. `Cross-agent handoff queues ticket for next agent` -- Create a ticket, assign to coder, complete work. Verify ticket has `next_agent_type: "qa"`, `agent_eligible: "yes"`, `agent_worker_id: ""`.
12. `QA agent picks up ticket after coder handoff` -- Create a QA worker with matching filter. Start agent loop. Poll until QA agent claims the ticket (max 15s). Verify QA worker's `current_ticket_id` matches.
13. `Status flow for QA agent` -- GET status flow for qa. Verify `on_complete: "qa_passed"`, `next_agent_type: ""` (end of chain).

**Section 650: Agent PR UI (5 tests)**

14. `Agent PRs page renders PR list` -- Navigate to `/agents/prs`. Verify heading "Agent PRs" visible. Verify table with columns: Ticket, PR Title, Branch, Status.
15. `PR row shows correct status badge` -- Verify at least 1 PR row with "open" status badge (green).
16. `PR row links to ticket` -- Verify "View Ticket" action/link on PR row.
17. `Status flow editor shows transitions` -- Navigate to status flow editor. Verify dropdowns for `on_claim`, `on_complete`, `on_pr_created`, `on_pr_merged`. Verify `next_agent_type` selector.
18. `Ticket detail shows agent status` -- Navigate to ticket detail. Verify agent status section showing assigned worker, work summary, and linked PR URL.

---

## 6. Security Considerations

### 6.1 GitHub Token Storage

GitHub tokens are stored in environment variables, not in DDB. They are never exposed via API responses. In dev mode, PR creation returns mock data without requiring a real token.

### 6.2 Webhook Signature Verification

GitHub webhook events are verified using HMAC-SHA256 signature validation against `GITHUB_WEBHOOK_SECRET`. Invalid signatures are rejected with 403.

### 6.3 PR Description Sanitization

PR titles and descriptions are sanitized to prevent injection attacks. Shell metacharacters are escaped when building `gh pr create` commands.

### 6.4 Cross-Agent Handoff Authorization

Cross-agent handoffs only work within the same user's workers and tickets. The system verifies user ownership at each transition point.

### 6.5 Status Flow Validation

Custom status flow configurations are validated against allowed status values. Invalid statuses are rejected.

---

## 7. Dependencies

| Dependency | Type | Description |
|------------|------|-------------|
| AGENT-003 | Upstream | `complete_ticket()` for releasing claims after work completion |
| AGENT-005 | Upstream | `add_memory()` for recording learnings |
| AGENT-006 | Upstream | Terminal output capture, completion signal detection, text injection |
| `app/services/tickets.py` | Upstream | Ticket CRUD and status transitions |
| AGENT-004 | Downstream | Fleet dashboard shows PR links and ticket status |

---

## 8. Acceptance Criteria

1. Agent-created PRs are linked to tickets with URL and PR number.
2. PR descriptions are auto-generated from ticket context and agent work summary.
3. PR creation works via both CLI injection (`gh pr create`) and GitHub API methods.
4. Ticket status transitions follow configurable agent-type-specific flows.
5. Cross-agent handoffs trigger next agent type to pick up the ticket.
6. Work summaries include files changed, test results, and decisions made.
7. GitHub webhook integration handles PR merge and review events.
8. Agent memory records learnings from each completed ticket.
9. Admin endpoint lists all agent-created PRs across users.
10. Custom status flow configurations can be set per user per agent type.
