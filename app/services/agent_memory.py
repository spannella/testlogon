"""Agent Memory & Context Injection service (AGENT-005).

Manages persistent agent identity, project context, and accumulated
memories. Assembles full context injection payloads for the agent loop.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from uuid import uuid4

from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

MAX_MEMORY_ENTRIES = 200
MAX_MEMORY_TOKEN_COUNT = 100_000  # Approximate context window budget for memories
SUMMARIZE_THRESHOLD = 80_000      # Trigger summarization when total tokens exceed this

# ---------------------------------------------------------------------------
# Default Identity Templates
# ---------------------------------------------------------------------------

IDENTITY_TEMPLATES: Dict[str, str] = {
    "coder": """You are a Coder Agent. Your primary responsibilities:
- Read ticket requirements carefully before writing any code
- Create a feature branch following the naming convention: {branch_convention}
- Write clean, well-documented code following the project's coding standards
- Add appropriate unit tests for new code
- Run the existing test suite to ensure no regressions
- Commit frequently with descriptive messages referencing the ticket ID
- When complete, output [AGENT_COMPLETE] to signal you are done

Code quality rules:
- Follow existing patterns in the codebase
- Add type hints (Python) or TypeScript types
- Write docstrings/comments for complex logic
- Keep functions focused and under 50 lines where possible
- Handle error cases explicitly
""",

    "qa": """You are a QA Agent. Your primary responsibilities:
- Read the ticket and any linked PR to understand what changed
- Write comprehensive E2E tests covering the acceptance criteria
- Test edge cases and error paths, not just happy paths
- Run the full test suite and report results
- If tests fail, investigate whether it's a test issue or a code bug
- Report bugs by outputting [AGENT_FEEDBACK_NEEDED] with details
- When all tests pass, output [AGENT_COMPLETE]

Testing rules:
- Use the project's test framework: {test_framework}
- Follow existing test patterns in the codebase
- Use descriptive test names that explain the scenario
- Clean up test data in afterAll/afterEach hooks
- Avoid flaky tests: use explicit waits, not timeouts
""",

    "reviewer": """You are a Code Review Agent. Your primary responsibilities:
- Review the PR diff for correctness, security, and code quality
- Check for common bugs: null references, off-by-one, race conditions
- Verify test coverage for new code paths
- Check for security issues: injection, auth bypass, data exposure
- Post review comments on the PR
- Approve if quality standards are met; request changes otherwise
- Output [AGENT_COMPLETE] when review is posted

Review checklist:
- Does the code match the ticket requirements?
- Are there adequate tests?
- Are error cases handled?
- Is the code readable and maintainable?
- Are there any security concerns?
""",

    "devops": """You are a DevOps Agent. Your primary responsibilities:
- Handle infrastructure-related tickets: CI/CD, deployment, monitoring
- Update configuration files, Dockerfiles, CI pipelines
- Ensure changes are backwards-compatible
- Test configuration changes in a staging-like environment
- Document infrastructure changes in the appropriate docs
- Output [AGENT_COMPLETE] when done

DevOps rules:
- Never modify production configuration directly
- Always test CI changes in a branch pipeline first
- Update documentation for any config changes
- Use infrastructure-as-code patterns
""",
}


# ---------------------------------------------------------------------------
# Identity operations
# ---------------------------------------------------------------------------


def initialize_memory(
    worker_id: str,
    agent_type: str,
    *,
    project_context: Dict[str, Any] | None = None,
    custom_instructions: str = "",
) -> None:
    """Initialize memory for a new worker from template.

    Called by AGENT-002 during worker creation.
    Creates IDENTITY and PROJECT records from defaults.
    """
    ts = now_ts()

    # Identity from template
    identity_text = IDENTITY_TEMPLATES.get(agent_type, IDENTITY_TEMPLATES.get("coder", ""))
    T.agent_memory.put_item(Item={
        "pk": f"WORKER#{worker_id}",
        "sk": "IDENTITY",
        "agent_type": agent_type,
        "identity_text": identity_text,
        "custom_instructions": custom_instructions,
        "updated_at": ts,
        "created_at": ts,
        "category": "identity",
    })

    # Project context
    ctx = project_context or {}
    T.agent_memory.put_item(Item={
        "pk": f"WORKER#{worker_id}",
        "sk": "PROJECT",
        "repo_url": ctx.get("repo_url", ""),
        "branch_convention": ctx.get("branch_convention", "agent/{worker_id}/{ticket_id}"),
        "coding_standards": ctx.get("coding_standards", ""),
        "pr_template": ctx.get("pr_template", ""),
        "test_framework": ctx.get("test_framework", ""),
        "ci_commands": ctx.get("ci_commands", ""),
        "file_structure_notes": ctx.get("file_structure_notes", ""),
        "updated_at": ts,
        "created_at": ts,
        "category": "project",
    })


def get_identity(worker_id: str) -> Dict[str, Any] | None:
    """Get the agent's identity record."""
    resp = T.agent_memory.get_item(
        Key={"pk": f"WORKER#{worker_id}", "sk": "IDENTITY"}
    )
    return resp.get("Item")


def set_identity(
    worker_id: str,
    *,
    agent_type: str | None = None,
    identity_text: str | None = None,
    custom_instructions: str | None = None,
) -> Dict[str, Any]:
    """Set or update the agent's identity.

    If no identity exists, creates one. Otherwise updates provided fields.
    """
    existing = get_identity(worker_id)
    ts = now_ts()

    if not existing:
        # Create new identity
        at = agent_type or "coder"
        it = identity_text if identity_text is not None else IDENTITY_TEMPLATES.get(at, "")
        ci = custom_instructions or ""
        item = {
            "pk": f"WORKER#{worker_id}",
            "sk": "IDENTITY",
            "agent_type": at,
            "identity_text": it,
            "custom_instructions": ci,
            "updated_at": ts,
            "created_at": ts,
            "category": "identity",
        }
        T.agent_memory.put_item(Item=item)
        return item

    updates = ["SET updated_at = :ts"]
    values: Dict[str, Any] = {":ts": ts}
    if identity_text is not None:
        updates.append("identity_text = :it")
        values[":it"] = identity_text
    if custom_instructions is not None:
        updates.append("custom_instructions = :ci")
        values[":ci"] = custom_instructions
    if agent_type is not None:
        updates.append("agent_type = :at")
        values[":at"] = agent_type

    T.agent_memory.update_item(
        Key={"pk": f"WORKER#{worker_id}", "sk": "IDENTITY"},
        UpdateExpression=", ".join(updates),
        ExpressionAttributeValues=values,
    )
    return get_identity(worker_id)  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Project context operations
# ---------------------------------------------------------------------------


def get_project_context(worker_id: str) -> Dict[str, Any] | None:
    """Get the agent's project context."""
    resp = T.agent_memory.get_item(
        Key={"pk": f"WORKER#{worker_id}", "sk": "PROJECT"}
    )
    return resp.get("Item")


def set_project_context(worker_id: str, **fields: Any) -> Dict[str, Any]:
    """Set or update project context fields.

    If no project context exists, creates one. Otherwise updates provided fields.
    """
    existing = get_project_context(worker_id)
    ts = now_ts()

    allowed_fields = {
        "repo_url", "branch_convention", "coding_standards",
        "pr_template", "test_framework", "ci_commands",
        "file_structure_notes",
    }

    if not existing:
        item: Dict[str, Any] = {
            "pk": f"WORKER#{worker_id}",
            "sk": "PROJECT",
            "repo_url": "",
            "branch_convention": "agent/{worker_id}/{ticket_id}",
            "coding_standards": "",
            "pr_template": "",
            "test_framework": "",
            "ci_commands": "",
            "file_structure_notes": "",
            "updated_at": ts,
            "created_at": ts,
            "category": "project",
        }
        for k, v in fields.items():
            if k in allowed_fields:
                item[k] = v
        T.agent_memory.put_item(Item=item)
        return item

    updates = ["SET updated_at = :ts"]
    values: Dict[str, Any] = {":ts": ts}
    for k, v in fields.items():
        if k in allowed_fields:
            updates.append(f"{k} = :{k}")
            values[f":{k}"] = v

    T.agent_memory.update_item(
        Key={"pk": f"WORKER#{worker_id}", "sk": "PROJECT"},
        UpdateExpression=", ".join(updates),
        ExpressionAttributeValues=values,
    )
    return get_project_context(worker_id)  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Memory entry operations
# ---------------------------------------------------------------------------


def add_memory(
    worker_id: str,
    *,
    category: str,
    title: str,
    content: str,
    ticket_id: str = "",
    importance: int = 3,
) -> Dict[str, Any]:
    """Add a new memory entry.

    Called by AGENT-003 after ticket completion to record learnings,
    or manually by the user through the UI.
    """
    memory_id = uuid4().hex
    ts = now_ts()

    # Estimate token count (rough: 1 token ~= 4 chars)
    token_count = len(content) // 4

    item = {
        "pk": f"WORKER#{worker_id}",
        "sk": f"MEM#{memory_id}",
        "memory_id": memory_id,
        "category": category,
        "title": title,
        "content": content,
        "ticket_id": ticket_id,
        "importance": importance,
        "token_count": token_count,
        "created_at": ts,
        "summarized": False,
        "summary": "",
    }
    T.agent_memory.put_item(Item=item)

    # Check if summarization is needed
    _maybe_trigger_summarization(worker_id)

    return item


def list_memories(
    worker_id: str,
    *,
    category: str | None = None,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """List memory entries, optionally filtered by category."""
    if category:
        resp = T.agent_memory.query(
            IndexName="ByCategory",
            KeyConditionExpression="pk = :pk AND category = :cat",
            ExpressionAttributeValues={
                ":pk": f"WORKER#{worker_id}", ":cat": category,
            },
            Limit=limit,
        )
    else:
        resp = T.agent_memory.query(
            KeyConditionExpression="pk = :pk AND begins_with(sk, :prefix)",
            ExpressionAttributeValues={
                ":pk": f"WORKER#{worker_id}", ":prefix": "MEM#",
            },
            Limit=limit,
        )
    return resp.get("Items", [])


def get_memory(worker_id: str, memory_id: str) -> Dict[str, Any] | None:
    """Get a single memory entry."""
    resp = T.agent_memory.get_item(
        Key={"pk": f"WORKER#{worker_id}", "sk": f"MEM#{memory_id}"}
    )
    return resp.get("Item")


def update_memory(
    worker_id: str,
    memory_id: str,
    *,
    title: str | None = None,
    content: str | None = None,
    importance: int | None = None,
) -> Dict[str, Any] | None:
    """Update an existing memory entry."""
    existing = get_memory(worker_id, memory_id)
    if not existing:
        return None

    updates: list[str] = []
    values: Dict[str, Any] = {}
    if title is not None:
        updates.append("title = :t")
        values[":t"] = title
    if content is not None:
        updates.append("content = :c")
        values[":c"] = content
        values[":tc"] = len(content) // 4
        updates.append("token_count = :tc")
    if importance is not None:
        updates.append("importance = :imp")
        values[":imp"] = importance

    if not updates:
        return existing

    T.agent_memory.update_item(
        Key={"pk": f"WORKER#{worker_id}", "sk": f"MEM#{memory_id}"},
        UpdateExpression="SET " + ", ".join(updates),
        ExpressionAttributeValues=values,
    )
    return get_memory(worker_id, memory_id)


def delete_memory(worker_id: str, memory_id: str) -> None:
    """Delete a memory entry."""
    T.agent_memory.delete_item(
        Key={"pk": f"WORKER#{worker_id}", "sk": f"MEM#{memory_id}"}
    )


# ---------------------------------------------------------------------------
# Context assembly
# ---------------------------------------------------------------------------


def assemble_full_context(
    worker_id: str,
    ticket_id: str | None = None,
) -> str:
    """Assemble the full context injection payload.

    Combines: identity + project context + relevant memories.
    This is injected into the agent's terminal at the start of each ticket.
    """
    sections = []

    # 1. Identity
    identity = get_identity(worker_id)
    if identity:
        text = identity.get("identity_text", "")
        custom = identity.get("custom_instructions", "")
        sections.append(f"=== AGENT IDENTITY ===\n{text}")
        if custom:
            sections.append(f"\n=== CUSTOM INSTRUCTIONS ===\n{custom}")

    # 2. Project context
    project = get_project_context(worker_id)
    if project:
        parts = []
        if project.get("repo_url"):
            parts.append(f"Repository: {project['repo_url']}")
        if project.get("branch_convention"):
            parts.append(f"Branch convention: {project['branch_convention']}")
        if project.get("coding_standards"):
            parts.append(f"Coding standards:\n{project['coding_standards']}")
        if project.get("test_framework"):
            parts.append(f"Test framework: {project['test_framework']}")
        if project.get("ci_commands"):
            parts.append(f"CI commands: {project['ci_commands']}")
        if parts:
            sections.append(f"\n=== PROJECT CONTEXT ===\n" + "\n".join(parts))

    # 3. Memories (sorted by importance, then recency)
    memories = list_memories(worker_id, limit=100)
    if memories:
        # Sort: highest importance first, then newest first
        memories.sort(key=lambda m: (-int(m.get("importance", 3)), -int(m.get("created_at", 0))))

        # Trim to token budget
        budget = MAX_MEMORY_TOKEN_COUNT
        included = []
        for mem in memories:
            cost = int(mem.get("token_count", 0))
            if budget - cost < 0:
                break
            # Use summary if available and original is large
            text = mem.get("summary") if mem.get("summarized") else mem.get("content", "")
            included.append(f"- [{mem.get('category', 'note')}] {mem.get('title', '')}: {text}")
            budget -= cost

        if included:
            sections.append(f"\n=== ACCUMULATED MEMORY ({len(included)} entries) ===\n" + "\n".join(included))

    return "\n\n".join(sections)


# ---------------------------------------------------------------------------
# Export / Import
# ---------------------------------------------------------------------------


def export_memory(worker_id: str) -> Dict[str, Any]:
    """Export all memory data as JSON for backup/transfer."""
    identity = get_identity(worker_id)
    project = get_project_context(worker_id)
    memories = list_memories(worker_id, limit=MAX_MEMORY_ENTRIES)

    return {
        "worker_id": worker_id,
        "exported_at": now_ts(),
        "identity": identity,
        "project_context": project,
        "memories": memories,
    }


def import_memory(worker_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
    """Import memory data from a JSON export."""
    imported: Dict[str, Any] = {"identity": False, "project": False, "memories": 0}

    if data.get("identity"):
        ident_data = data["identity"]
        set_identity(
            worker_id,
            identity_text=ident_data.get("identity_text", ""),
            custom_instructions=ident_data.get("custom_instructions", ""),
            agent_type=ident_data.get("agent_type"),
        )
        imported["identity"] = True

    if data.get("project_context"):
        ctx = data["project_context"]
        filtered = {
            k: v for k, v in ctx.items()
            if k not in ("pk", "sk", "created_at", "updated_at", "category")
        }
        set_project_context(worker_id, **filtered)
        imported["project"] = True

    for mem in data.get("memories", []):
        add_memory(
            worker_id,
            category=mem.get("category", "custom"),
            title=mem.get("title", "Imported"),
            content=mem.get("content", ""),
            ticket_id=mem.get("ticket_id", ""),
            importance=int(mem.get("importance", 3)),
        )
        imported["memories"] += 1

    return imported


def list_templates() -> List[Dict[str, str]]:
    """List available identity templates."""
    return [
        {
            "agent_type": agent_type,
            "identity_text": text,
            "description": f"Default identity template for {agent_type} agents",
        }
        for agent_type, text in IDENTITY_TEMPLATES.items()
    ]


# ---------------------------------------------------------------------------
# Summarization
# ---------------------------------------------------------------------------


def _maybe_trigger_summarization(worker_id: str) -> None:
    """Check if total memory tokens exceed threshold and summarize old entries.

    In dev mode: simple truncation instead of LLM-based summarization.
    """
    memories = list_memories(worker_id, limit=MAX_MEMORY_ENTRIES)
    total_tokens = sum(int(m.get("token_count", 0)) for m in memories)

    if total_tokens <= SUMMARIZE_THRESHOLD:
        return

    # Sort by importance (ascending) then age (oldest first)
    candidates = sorted(
        memories,
        key=lambda m: (int(m.get("importance", 3)), int(m.get("created_at", 0))),
    )

    for mem in candidates:
        if total_tokens <= SUMMARIZE_THRESHOLD:
            break
        if mem.get("summarized"):
            continue

        # Simple summarization: truncate to first 200 chars
        content = mem.get("content", "")
        summary = content[:200] + "..." if len(content) > 200 else content
        old_tokens = int(mem.get("token_count", 0))
        new_tokens = len(summary) // 4

        T.agent_memory.update_item(
            Key={"pk": f"WORKER#{worker_id}", "sk": f"MEM#{mem['memory_id']}"},
            UpdateExpression="SET summarized = :s, summary = :sm, token_count = :tc",
            ExpressionAttributeValues={":s": True, ":sm": summary, ":tc": new_tokens},
        )
        total_tokens -= (old_tokens - new_tokens)
