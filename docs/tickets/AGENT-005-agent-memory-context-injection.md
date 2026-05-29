# AGENT-005: Agent Memory & Context Injection

**Ticket**: AGENT-005
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: Medium
**Estimated effort**: 7-9 days
**Dependencies**: AGENT-002 (Worker Provisioning), AGENT-003 (Agent Framework)

---

## 1. Overview & Motivation

### 1.1 Purpose

AGENT-005 manages the persistent memory and identity context that shapes how each agent worker behaves. At worker startup, the system injects a structured identity prompt into the terminal that defines the agent's role (Coder, QA, Reviewer, DevOps), project context (repo conventions, coding standards, PR templates), and accumulated knowledge from previous ticket sessions. Memory persists across ticket sessions so the agent learns project patterns over time. Users can view and edit agent memory through the UI, and memory templates provide sensible defaults for each agent type.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| User | As a user, I want each agent to have a distinct identity so that coder agents write code and QA agents write tests. | Agent startup injects role-specific identity prompt; coder and QA agents behave differently given the same ticket. |
| User | As a user, I want to configure project context (repo URL, branch rules, coding standards) so that agents follow our conventions. | Project context injected at startup; agents create branches matching the naming convention. |
| User | As a user, I want agents to remember patterns from previous tickets so that they don't repeat mistakes. | Memory accumulates across sessions; agent context includes relevant past learnings. |
| User | As a user, I want to view and edit an agent's memory so that I can correct misconceptions or add knowledge. | Memory editor in worker detail drawer; changes take effect on next ticket. |
| User | As a user, I want default memory templates for each agent type so that new agents start with sensible instructions. | Template selector at worker creation; templates provide agent-type-specific prompts. |
| User | As a user, I want context window management so that old memories are summarized when approaching limits. | Auto-summarization when memory exceeds configurable threshold. |
| User | As a user, I want to export/import agent memory so that I can share configurations between agents. | Export as JSON; import to new agent. |

### 1.3 Why This Is Needed

Without persistent memory, every ticket starts from scratch. The agent doesn't know the project's coding style, test framework, CI requirements, or past decisions. Users would have to paste the same context into every terminal session. Memory injection transforms a generic AI tool into a specialized team member that understands the project and improves over time.

---

## 2. Current State Analysis

### 2.1 Existing Infrastructure

| Component | Location | Relevance |
|-----------|----------|-----------|
| Agent orchestrator | `app/services/agent_orchestrator.py` (AGENT-003) | `inject_ticket_context()` generates per-ticket context; memory augments this |
| Worker provisioner | `app/services/agent_worker_provisioner.py` (AGENT-002) | Worker creation; memory template applied at creation time |
| Agent workers DDB | `agent_workers` table | Worker records; will reference memory |
| Terminal infrastructure | `app/routers/terminal.py` | WebSocket SSH terminal; context injected as text via terminal |
| S3 mock | `app/core/dev_s3.py` | In-process moto S3 for file storage; can store large memory exports |
| Settings | `app/core/settings.py` | Configuration for memory limits, summarization thresholds |

### 2.2 Gaps

1. **No memory storage** -- no table or S3 structure for persisting agent memory entries.
2. **No identity templates** -- no pre-built role descriptions for coder, QA, reviewer, devops agent types.
3. **No project context model** -- no structured format for repo URL, branch rules, coding standards.
4. **No memory accumulation** -- no mechanism for the agent to add entries to its own memory after completing tickets.
5. **No summarization** -- no way to condense old memory entries when context window is full.
6. **No memory editor** -- no UI for viewing/editing agent memory.
7. **No context assembly** -- no function that combines identity + project + memory + ticket into a single injection payload.

---

## 3. Technical Design

### 3.1 DynamoDB Table: `agent_memory`

```python
# scripts/local-ddb-init.py
TableDef(
    _resolve_table_name(S.agent_memory_table_name, "agent_memory"),
    "pk",              # WORKER#{worker_id}
    "sk",              # MEM#{memory_id} or IDENTITY or PROJECT or TEMPLATE#{template_id}
    gsis=[
        {"index_name": "ByCreatedAt", "partition_key": "pk", "sort_key": "created_at"},
        {"index_name": "ByCategory", "partition_key": "pk", "sort_key": "category"},
    ],
    attr_types={"created_at": "N"},
)
```

**Item patterns**:

#### 3.1.1 Identity Record

| PK | SK | Purpose | Key Fields |
|----|------|---------|------------|
| `WORKER#{worker_id}` | `IDENTITY` | Agent role description | `agent_type`, `identity_text`, `custom_instructions`, `updated_at` |

#### 3.1.2 Project Context Record

| PK | SK | Purpose | Key Fields |
|----|------|---------|------------|
| `WORKER#{worker_id}` | `PROJECT` | Project-specific context | `repo_url`, `branch_convention`, `coding_standards`, `pr_template`, `test_framework`, `ci_commands`, `file_structure_notes`, `updated_at` |

#### 3.1.3 Memory Entries

| PK | SK | Purpose | Key Fields |
|----|------|---------|------------|
| `WORKER#{worker_id}` | `MEM#{memory_id}` | Individual memory entry | `memory_id`, `category` (learning/decision/pattern/error/custom), `title`, `content`, `ticket_id` (source ticket), `importance` (1-5), `token_count`, `created_at`, `summarized` (bool), `summary` |

#### 3.1.4 Memory Templates (Global)

| PK | SK | Purpose | Key Fields |
|----|------|---------|------------|
| `GLOBAL` | `TEMPLATE#{agent_type}` | Default memory template | `agent_type`, `identity_text`, `default_instructions`, `project_context_template`, `initial_memories` |

### 3.2 Default Identity Templates

```python
# In app/services/agent_memory.py

IDENTITY_TEMPLATES = {
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
```

### 3.3 Backend Service

**New file**: `app/services/agent_memory.py` (~450 lines)

```python
"""Agent Memory & Context Injection service (AGENT-005).

Manages persistent agent identity, project context, and accumulated
memories. Assembles full context injection payloads for the agent loop.
"""

from __future__ import annotations
import json
import logging
from typing import Any, Dict, List, Optional
from uuid import uuid4

from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

MAX_MEMORY_ENTRIES = 200
MAX_MEMORY_TOKEN_COUNT = 100_000  # Approximate context window budget for memories
SUMMARIZE_THRESHOLD = 80_000      # Trigger summarization when total tokens exceed this


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


def update_identity(
    worker_id: str,
    *,
    identity_text: str | None = None,
    custom_instructions: str | None = None,
) -> Dict[str, Any]:
    """Update the agent's identity or custom instructions."""
    updates = ["SET updated_at = :ts"]
    values = {":ts": now_ts()}
    if identity_text is not None:
        updates.append("identity_text = :it")
        values[":it"] = identity_text
    if custom_instructions is not None:
        updates.append("custom_instructions = :ci")
        values[":ci"] = custom_instructions
    
    T.agent_memory.update_item(
        Key={"pk": f"WORKER#{worker_id}", "sk": "IDENTITY"},
        UpdateExpression=", ".join(updates),
        ExpressionAttributeValues=values,
    )
    return get_identity(worker_id)


def get_project_context(worker_id: str) -> Dict[str, Any] | None:
    """Get the agent's project context."""
    resp = T.agent_memory.get_item(
        Key={"pk": f"WORKER#{worker_id}", "sk": "PROJECT"}
    )
    return resp.get("Item")


def update_project_context(worker_id: str, **fields) -> Dict[str, Any]:
    """Update project context fields."""
    updates = ["SET updated_at = :ts"]
    values = {":ts": now_ts()}
    for k, v in fields.items():
        updates.append(f"{k} = :{k}")
        values[f":{k}"] = v
    
    T.agent_memory.update_item(
        Key={"pk": f"WORKER#{worker_id}", "sk": "PROJECT"},
        UpdateExpression=", ".join(updates),
        ExpressionAttributeValues=values,
    )
    return get_project_context(worker_id)


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


def update_memory(
    worker_id: str,
    memory_id: str,
    *,
    title: str | None = None,
    content: str | None = None,
    importance: int | None = None,
) -> Dict[str, Any]:
    """Update an existing memory entry."""
    updates = []
    values = {}
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
        return get_memory(worker_id, memory_id)
    
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


def get_memory(worker_id: str, memory_id: str) -> Dict[str, Any] | None:
    """Get a single memory entry."""
    resp = T.agent_memory.get_item(
        Key={"pk": f"WORKER#{worker_id}", "sk": f"MEM#{memory_id}"}
    )
    return resp.get("Item")


def assemble_full_context(
    worker_id: str,
    ticket_id: str | None = None,
) -> str:
    """Assemble the full context injection payload.

    Combines: identity + project context + relevant memories + ticket context.
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
        memories.sort(key=lambda m: (-m.get("importance", 3), -m.get("created_at", 0)))
        
        # Trim to token budget
        budget = MAX_MEMORY_TOKEN_COUNT
        included = []
        for mem in memories:
            cost = mem.get("token_count", 0)
            if budget - cost < 0:
                break
            # Use summary if available and original is large
            text = mem.get("summary") if mem.get("summarized") else mem.get("content", "")
            included.append(f"- [{mem.get('category', 'note')}] {mem.get('title', '')}: {text}")
            budget -= cost
        
        if included:
            sections.append(f"\n=== ACCUMULATED MEMORY ({len(included)} entries) ===\n" + "\n".join(included))
    
    # 4. Ticket context (delegated to AGENT-003)
    if ticket_id:
        from app.services.agent_orchestrator import inject_ticket_context
        ticket_context = inject_ticket_context("", "", ticket_id)  # user/worker not needed for context text
        sections.append(f"\n{ticket_context}")
    
    return "\n\n".join(sections)


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
    imported = {"identity": False, "project": False, "memories": 0}
    
    if data.get("identity"):
        update_identity(worker_id, identity_text=data["identity"].get("identity_text", ""))
        imported["identity"] = True
    
    if data.get("project_context"):
        ctx = data["project_context"]
        update_project_context(worker_id, **{
            k: v for k, v in ctx.items()
            if k not in ("pk", "sk", "created_at", "updated_at", "category")
        })
        imported["project"] = True
    
    for mem in data.get("memories", []):
        add_memory(
            worker_id,
            category=mem.get("category", "custom"),
            title=mem.get("title", "Imported"),
            content=mem.get("content", ""),
            ticket_id=mem.get("ticket_id", ""),
            importance=mem.get("importance", 3),
        )
        imported["memories"] += 1
    
    return imported


def _maybe_trigger_summarization(worker_id: str) -> None:
    """Check if total memory tokens exceed threshold and summarize old entries.

    Summarization strategy:
    1. Calculate total token count across all memory entries
    2. If total > SUMMARIZE_THRESHOLD, find low-importance old entries
    3. Group related entries and generate summary text
    4. Replace content with summary, set summarized=True
    
    In dev mode: simple truncation instead of LLM-based summarization.
    """
    memories = list_memories(worker_id, limit=MAX_MEMORY_ENTRIES)
    total_tokens = sum(m.get("token_count", 0) for m in memories)
    
    if total_tokens <= SUMMARIZE_THRESHOLD:
        return
    
    # Sort by importance (ascending) then age (oldest first)
    candidates = sorted(memories, key=lambda m: (m.get("importance", 3), m.get("created_at", 0)))
    
    for mem in candidates:
        if total_tokens <= SUMMARIZE_THRESHOLD:
            break
        if mem.get("summarized"):
            continue
        
        # Simple summarization: truncate to first 200 chars
        content = mem.get("content", "")
        summary = content[:200] + "..." if len(content) > 200 else content
        old_tokens = mem.get("token_count", 0)
        new_tokens = len(summary) // 4
        
        T.agent_memory.update_item(
            Key={"pk": f"WORKER#{worker_id}", "sk": f"MEM#{mem['memory_id']}"},
            UpdateExpression="SET summarized = :s, summary = :sm, token_count = :tc",
            ExpressionAttributeValues={":s": True, ":sm": summary, ":tc": new_tokens},
        )
        total_tokens -= (old_tokens - new_tokens)
```

### 3.4 Backend Router

**New file**: `app/routers/agent_memory.py` (~250 lines)

Prefix: `/ui/agent/memory`

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/ui/agent/memory/{worker_id}/identity` | `require_ui_session` | Get agent identity |
| `PUT` | `/ui/agent/memory/{worker_id}/identity` | `require_ui_session` | Update agent identity |
| `GET` | `/ui/agent/memory/{worker_id}/project` | `require_ui_session` | Get project context |
| `PUT` | `/ui/agent/memory/{worker_id}/project` | `require_ui_session` | Update project context |
| `GET` | `/ui/agent/memory/{worker_id}/entries` | `require_ui_session` | List memory entries |
| `POST` | `/ui/agent/memory/{worker_id}/entries` | `require_ui_session` | Add memory entry |
| `PUT` | `/ui/agent/memory/{worker_id}/entries/{memory_id}` | `require_ui_session` | Update memory entry |
| `DELETE` | `/ui/agent/memory/{worker_id}/entries/{memory_id}` | `require_ui_session` | Delete memory entry |
| `GET` | `/ui/agent/memory/{worker_id}/full-context` | `require_ui_session` | Preview assembled full context |
| `GET` | `/ui/agent/memory/{worker_id}/export` | `require_ui_session` | Export all memory as JSON |
| `POST` | `/ui/agent/memory/{worker_id}/import` | `require_ui_session` | Import memory from JSON |
| `GET` | `/ui/agent/memory/templates` | `require_ui_session` | List available identity templates |

### 3.5 Pydantic Models

**Add to `app/models.py`**:

```python
# -- Agent Memory (AGENT-005) --

class AgentIdentityOut(BaseModel):
    agent_type: str
    identity_text: str
    custom_instructions: str = ""
    updated_at: int = 0

class AgentIdentityUpdateIn(BaseModel):
    identity_text: Optional[str] = None
    custom_instructions: Optional[str] = None

class ProjectContextOut(BaseModel):
    repo_url: str = ""
    branch_convention: str = ""
    coding_standards: str = ""
    pr_template: str = ""
    test_framework: str = ""
    ci_commands: str = ""
    file_structure_notes: str = ""
    updated_at: int = 0

class ProjectContextUpdateIn(BaseModel):
    repo_url: Optional[str] = Field(None, max_length=500)
    branch_convention: Optional[str] = Field(None, max_length=200)
    coding_standards: Optional[str] = Field(None, max_length=5000)
    pr_template: Optional[str] = Field(None, max_length=5000)
    test_framework: Optional[str] = Field(None, max_length=200)
    ci_commands: Optional[str] = Field(None, max_length=2000)
    file_structure_notes: Optional[str] = Field(None, max_length=5000)

class MemoryEntryIn(BaseModel):
    category: str = Field(..., pattern="^(learning|decision|pattern|error|custom)$")
    title: str = Field(..., min_length=1, max_length=200)
    content: str = Field(..., min_length=1, max_length=10000)
    ticket_id: str = Field(default="", max_length=100)
    importance: int = Field(default=3, ge=1, le=5)

class MemoryEntryUpdateIn(BaseModel):
    title: Optional[str] = Field(None, min_length=1, max_length=200)
    content: Optional[str] = Field(None, min_length=1, max_length=10000)
    importance: Optional[int] = Field(None, ge=1, le=5)

class MemoryEntryOut(BaseModel):
    memory_id: str
    category: str
    title: str
    content: str
    ticket_id: str = ""
    importance: int = 3
    token_count: int = 0
    created_at: int = 0
    summarized: bool = False
    summary: str = ""

class MemoryListOut(BaseModel):
    entries: List[MemoryEntryOut]
    count: int
    total_tokens: int

class FullContextOut(BaseModel):
    context_text: str
    total_tokens: int
    sections: List[str]

class MemoryExportOut(BaseModel):
    worker_id: str
    exported_at: int
    identity: Optional[AgentIdentityOut] = None
    project_context: Optional[ProjectContextOut] = None
    memories: List[MemoryEntryOut] = Field(default_factory=list)

class MemoryImportIn(BaseModel):
    identity: Optional[Dict[str, Any]] = None
    project_context: Optional[Dict[str, Any]] = None
    memories: List[Dict[str, Any]] = Field(default_factory=list)

class MemoryImportOut(BaseModel):
    identity: bool = False
    project: bool = False
    memories: int = 0

class MemoryTemplateOut(BaseModel):
    agent_type: str
    identity_text: str
    description: str = ""
```

### 3.6 Frontend Components

#### MemoryEditor (`frontend/src/pages/agents/MemoryEditor.tsx`)

Tab content in WorkerDetailDrawer (~350 lines):

- **Identity section**: Large textarea showing the identity prompt, with "Reset to Template" button
- **Custom instructions**: Textarea for additional user-provided instructions
- **Project context form**: Fields for repo URL, branch convention, coding standards, PR template, test framework, CI commands
- **Memory entries list**: Sortable/filterable list of memory entries with category badges, importance stars, expand/collapse content
- **Add memory button**: Dialog for adding new entries
- **Token budget bar**: Progress bar showing total tokens vs. budget (green/yellow/red)
- **Export/Import buttons**: Download JSON / upload JSON

#### ContextPreview (`frontend/src/pages/agents/ContextPreview.tsx`)

Component (~100 lines):

- Read-only view of the assembled full context
- Syntax-highlighted sections (identity, project, memories, ticket)
- Token count per section
- "Copy to Clipboard" button

#### Route Integration

Memory editor is a tab in the WorkerDetailDrawer (AGENT-004), not a separate route. The `/agents/llm-keys` and `/agents/workers` pages link to memory editing through the worker detail view.

---

## 4. Implementation Plan

### Phase 1: Memory Service + DDB (3-4 days)

| File | Change |
|------|--------|
| `app/core/settings.py` | Add `agent_memory_table_name`, `agent_memory_max_tokens` |
| `app/core/tables.py` | Add `agent_memory` table handle |
| `scripts/local-ddb-init.py` | Add `agent_memory` TableDef with 2 GSIs |
| `app/services/agent_memory.py` | New file: identity, project, memory CRUD, assembly, export/import, summarization |
| `app/models.py` | Add memory Pydantic models |

### Phase 2: Router + Templates (2 days)

| File | Change |
|------|--------|
| `app/routers/agent_memory.py` | New file: 12 endpoints |
| `app/main.py` | Register `agent_memory_router` |
| `app/services/agent_worker_provisioner.py` | Call `initialize_memory` during worker creation |

### Phase 3: Frontend (2-3 days)

| File | Change |
|------|--------|
| `frontend/src/api/types.ts` | Add memory TypeScript types |
| `frontend/src/api/endpoints/agentMemory.ts` | New file: API wrappers |
| `frontend/src/pages/agents/MemoryEditor.tsx` | New file: memory editor component |
| `frontend/src/pages/agents/ContextPreview.tsx` | New file: context preview |
| `frontend/src/pages/agents/WorkerDetailDrawer.tsx` | Add "Memory" tab with MemoryEditor |

### Phase 4: E2E Tests (1-2 days)

| File | Change |
|------|--------|
| `frontend/e2e/agent-memory.spec.ts` | New file: ~16 tests in 4 sections |

---

## 5. E2E Test Plan (`frontend/e2e/agent-memory.spec.ts`)

**Test setup**: Uses `e2e_admin_session_setup.py` sessions. `beforeAll` creates an LLM key (AGENT-001) and a worker (AGENT-002) to attach memory to.

**Section 639: Identity & Project Context API (4 tests)**

1. `New worker has identity from template` -- GET `/ui/agent/memory/{worker_id}/identity`. Verify `agent_type: "coder"`, `identity_text` contains "Coder Agent", `identity_text` is non-empty.
2. `Update identity text` -- PUT `/ui/agent/memory/{worker_id}/identity` with `identity_text: "You are a specialized Python agent..."`. Verify 200. GET identity, verify updated text.
3. `Update custom instructions` -- PUT identity with `custom_instructions: "Always use type hints"`. Verify 200. GET identity, verify `custom_instructions` contains "type hints".
4. `Update project context` -- PUT `/ui/agent/memory/{worker_id}/project` with `repo_url: "https://github.com/test/repo"`, `branch_convention: "feat/{ticket_id}"`, `test_framework: "pytest"`. Verify 200. GET project, verify all fields.

**Section 640: Memory Entry CRUD API (5 tests)**

5. `Add a memory entry` -- POST `/ui/agent/memory/{worker_id}/entries` with `category: "learning"`, `title: "DynamoDB pattern"`, `content: "Always use begins_with for SK queries"`, `importance: 4`. Verify 201 with `memory_id`, `token_count > 0`.
6. `Add multiple memories with categories` -- Add entries with categories `decision`, `pattern`, `error`. Verify each returns 201 with correct category.
7. `List memories` -- GET `/ui/agent/memory/{worker_id}/entries`. Verify `count >= 4`, entries have `memory_id`, `category`, `title`, `content`.
8. `Update memory importance` -- PUT `/ui/agent/memory/{worker_id}/entries/{memory_id}` with `importance: 5`. Verify 200. GET entry, verify `importance: 5`.
9. `Delete memory entry` -- DELETE `/ui/agent/memory/{worker_id}/entries/{memory_id}`. Verify 200. GET entry returns 404.

**Section 641: Context Assembly & Export API (4 tests)**

10. `Full context includes identity, project, and memories` -- GET `/ui/agent/memory/{worker_id}/full-context`. Verify `context_text` contains "AGENT IDENTITY", "PROJECT CONTEXT", "ACCUMULATED MEMORY". Verify `total_tokens > 0`.
11. `Export memory returns complete data` -- GET `/ui/agent/memory/{worker_id}/export`. Verify response has `identity`, `project_context`, `memories` array with at least 3 entries.
12. `Import memory to new worker` -- Create a second worker. POST `/ui/agent/memory/{worker2_id}/import` with exported data. Verify response `identity: true`, `project: true`, `memories >= 3`.
13. `List identity templates` -- GET `/ui/agent/memory/templates`. Verify at least 4 templates: `coder`, `qa`, `reviewer`, `devops`. Each has `identity_text`.

**Section 642: Memory UI (5 tests)**

14. `Worker detail drawer shows Memory tab` -- Navigate to `/agents`. Click worker card. Verify "Memory" tab is visible in drawer.
15. `Memory tab shows identity section` -- Click "Memory" tab. Verify identity textarea is visible with agent identity text.
16. `Memory entries list is visible` -- Verify list of memory entries with category badges (learning, decision, etc.) and importance indicators.
17. `Add memory dialog` -- Click "Add Memory" button. Verify dialog with category selector, title input, content textarea, importance slider. Submit and verify new entry appears in list.
18. `Context preview shows assembled text` -- Click "Preview Context" button or tab. Verify read-only view with sections (AGENT IDENTITY, PROJECT CONTEXT, ACCUMULATED MEMORY).

---

## 6. Security Considerations

### 6.1 Worker Ownership

All memory endpoints validate that the authenticated user owns the worker. Memory data is partitioned by `WORKER#{worker_id}` and the worker record is checked for `user_id` match.

### 6.2 Content Size Limits

Memory entry content is limited to 10KB per entry and 200 entries per worker. Summarization compresses old entries to stay within token budgets.

### 6.3 Import Validation

Imported memory data is validated against Pydantic models. Malformed entries are skipped. Import does not delete existing memories — it appends.

### 6.4 No Executable Code

Memory entries are plain text. The context injection payload is text pasted into a terminal. There is no mechanism for memory entries to execute arbitrary code outside the agent's terminal session.

---

## 7. Dependencies

| Dependency | Type | Description |
|------------|------|-------------|
| AGENT-002 | Upstream | Worker creation calls `initialize_memory()` |
| AGENT-003 | Upstream | Agent loop uses `assemble_full_context()` for ticket injection |
| AGENT-003 | Bidirectional | `complete_ticket` calls `add_memory()` to record learnings |
| AGENT-004 | Downstream | WorkerDetailDrawer integrates MemoryEditor tab |

---

## 8. Acceptance Criteria

1. New workers are initialized with role-specific identity prompts from templates.
2. Project context (repo URL, branch conventions, coding standards) is configurable per worker.
3. Memory entries accumulate across ticket sessions with category, title, content, and importance.
4. Full context assembly combines identity + project + memories into a single injection payload.
5. Context window management summarizes old entries when token budget is approached.
6. Users can view and edit agent memory through the UI.
7. Memory can be exported as JSON and imported to another worker.
8. Identity templates are available for coder, QA, reviewer, and devops agent types.
9. Memory entries support CRUD with category filtering.
10. Token count tracking is accurate and visible in the UI.
