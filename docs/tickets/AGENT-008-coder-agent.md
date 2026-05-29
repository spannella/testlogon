# AGENT-008: Coder Agent

**Ticket**: AGENT-008
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: High
**Estimated effort**: 10-12 days
**Dependencies**: AGENT-001 (LLM Provider Key Management), AGENT-002 (Terminal Worker Provisioning), AGENT-003 (Worker Agent Framework & Lifecycle), AGENT-004 (Worker Fleet Management UI), AGENT-005 (Agent Memory & Context Injection), AGENT-006 (Terminal Monitoring & Feedback Loop)

---

## 1. Overview & Motivation

### 1.1 Purpose

AGENT-008 defines the Coder Agent type -- an agent configuration profile that plugs into the Worker Agent Framework (AGENT-003) to autonomously implement code changes. The Coder Agent picks up tickets labeled `type:development` or `type:bugfix` from the existing ticket management system (`app/services/tickets.py`), clones the target repository into a provisioned terminal (AGENT-002), creates a feature branch, implements the required changes using Claude Code or Codex, runs the project test suite, iterates on failures, and produces a pull request referencing the original ticket. The agent updates ticket status throughout its lifecycle and escalates to a human via the feedback loop (AGENT-004) when it encounters blockers it cannot resolve autonomously.

Coder Agents are configurable with a skill level (junior, mid, senior) that gates ticket complexity, a maximum time budget per ticket, repository-specific conventions (branch naming, test commands, PR template), and retry limits for test failures. The agent type configuration is stored in the `agent_types` DynamoDB table and applied by the Worker Agent Framework when spawning a Coder Agent instance.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Platform Admin | As an admin, I want to register a Coder Agent type with repo-specific config. | Agent type created with repo URL, branch convention, test commands; appears in agent registry. |
| Platform Admin | As an admin, I want to set a skill level for a Coder Agent instance. | Skill level (junior/mid/senior) saved; agent only picks up tickets matching its complexity threshold. |
| Platform Admin | As an admin, I want to set a max time budget per ticket. | Timeout configured; agent escalates via feedback loop if exceeded. |
| Platform Admin | As an admin, I want the Coder Agent to follow our branch naming convention. | Branches created as `feat/{ticket-id}-{short-description}` (configurable pattern). |
| Platform Admin | As an admin, I want test failures to be retried before escalation. | Agent retries test fixes up to N times (configurable); escalates after exhaustion. |
| Ticket Author | As a ticket author, I want to see my development ticket picked up automatically. | Ticket transitions from `open` to `in_progress` when agent claims it. |
| Ticket Author | As a ticket author, I want the PR linked to my ticket. | Ticket updated with PR URL; PR description references ticket ID. |
| Ticket Author | As a ticket author, I want to know if the agent got stuck. | Feedback loop creates escalation; ticket status set to `blocked`. |
| QA Agent | As a downstream QA agent, I want to know when code is ready for testing. | Ticket status set to `code_complete` with PR URL in metadata; triggers QA agent pickup. |
| Project Manager | As a PM, I want to see Coder Agent throughput metrics. | Dashboard shows tickets completed, average time, failure rate per agent instance. |

### 1.3 Why This Is Needed

Manual development workflows create bottlenecks: developers context-switch between tickets, forget to run tests, produce inconsistent branch names, and leave tickets in ambiguous states. The Coder Agent automates the entire develop-test-PR cycle for well-defined tickets, freeing human developers to focus on complex architectural work. By enforcing consistent workflows (branch naming, test execution, PR templates), the Coder Agent also improves codebase hygiene. The skill level system ensures simple bug fixes and routine features are handled autonomously while complex refactors are routed to senior-configured agents or escalated to humans.

---

## 2. Current State Analysis

### 2.1 Existing Infrastructure

- **LLM Provider Key Management** (AGENT-001): API key storage and management for coding tools (Claude Code, Codex). Coder Agent registers as `agent_type=coder`.
- **Terminal Worker Provisioning** (AGENT-002): SSH/VNC terminal provisioning into EC2/K8s instances. Provides the compute environment where Claude Code or Codex runs.
- **Worker Agent Framework & Lifecycle** (AGENT-003): Generic worker loop that claims tickets, injects terminal commands, monitors output, and handles state transitions. Coder Agent plugs in as a type-specific behavior module.
- **Worker Fleet Management UI** (AGENT-004): Fleet overview and bulk operations for managing multiple agent instances.
- **Agent Memory & Context Injection** (AGENT-005): Injects project context (CLAUDE.md, ticket specs, codebase analysis) into agent terminal sessions.
- **Terminal Monitoring & Feedback Loop** (AGENT-006): Terminal output capture, pattern matching for completion/error signals, and escalation mechanism. Coder Agent uses this when tests fail repeatedly or implementation exceeds time budget.
- **Ticket System** (`app/services/tickets.py`): Existing `TicketStore` with `create_ticket`, `assign_ticket`, `update_status`, `add_message`. Status values: `open`, `in_progress`, `waiting_on_user`, `done`. Tickets have `subject`, `description`, `category`, `metadata` dict, `assigned_to_sub`, `space_id`.
- **Remote Terminals** (`app/services/`, `app/routers/`): SSH and VNC browser terminal infrastructure for executing commands on remote hosts.
- **EC2 Launcher** (INFRA-003): Instance provisioning with auto-inventory registration and SSH key injection.

### 2.2 Gaps

1. No agent type configuration schema for Coder Agent behavior (repo, branch naming, test commands, PR template).
2. No ticket label/tag filtering mechanism -- existing tickets use `category` and `metadata` but lack a structured `labels` list for agent-compatible filtering.
3. No skill level gating -- no way to assign complexity scores to tickets or filter by agent skill level.
4. No branch creation, git operations, or PR creation workflow orchestration.
5. No test execution monitoring or failure retry logic specific to code development.
6. No PR template injection or ticket-to-PR linking automation.
7. No time budget tracking or timeout-based escalation for development tasks.
8. No structured output schema for Coder Agent results (PR URL, files changed, test results).

---

## 3. Technical Design

### 3.1 Data Model

#### 3.1.1 AgentTypes Table Extension (Coder Config)

Additional fields on the `agent_types` table (AGENT-001) when `agent_type = "coder"`:

| Field | Type | Description |
|-------|------|-------------|
| `coder_config` | M (map) | Coder-specific configuration (see sub-fields below) |
| `coder_config.repo_url` | S | Git repository URL (HTTPS or SSH) |
| `coder_config.repo_branch_base` | S | Base branch for feature branches (default `main`) |
| `coder_config.branch_pattern` | S | Branch naming pattern, e.g. `feat/{ticket_id}-{slug}` |
| `coder_config.test_commands` | L (list of S) | Ordered list of test commands, e.g. `["just test", "just e2e"]` |
| `coder_config.test_timeout_seconds` | N | Max seconds for test suite execution (default 600) |
| `coder_config.test_retry_limit` | N | Max test-fix-retest cycles before escalation (default 3) |
| `coder_config.pr_template` | S | PR body template (Markdown with `{ticket_id}`, `{ticket_subject}`, `{summary}` placeholders) |
| `coder_config.pr_base_branch` | S | Target branch for PRs (default `main`) |
| `coder_config.skill_level` | S | `junior`, `mid`, or `senior` |
| `coder_config.max_ticket_time_seconds` | N | Time budget per ticket (default 3600 = 1 hour) |
| `coder_config.complexity_labels` | M (map) | Maps skill level to allowed ticket labels, e.g. `{"junior": ["complexity:low"], "mid": ["complexity:low", "complexity:medium"]}` |
| `coder_config.coding_tool` | S | `claude_code` or `codex` (default `claude_code`) |
| `coder_config.coding_tool_model` | S | Model override (e.g., `claude-sonnet-4-6`, `o3`) |
| `coder_config.pre_commands` | L (list of S) | Setup commands run before coding (e.g., `["nvm use 20", "source .venv/bin/activate"]`) |
| `coder_config.post_commands` | L (list of S) | Cleanup commands after PR creation |
| `coder_config.file_exclude_patterns` | L (list of S) | Glob patterns for files the agent should not modify |

#### 3.1.2 Ticket Labels Extension

Extend the existing `tickets` table META item with a `labels` string set:

| Field | Type | Description |
|-------|------|-------------|
| `labels` | SS (string set) | Set of labels, e.g. `{"type:development", "complexity:medium", "area:backend"}` |
| `complexity` | S | `low`, `medium`, `high`, `critical` -- derived from labels for quick filtering |
| `estimated_effort_hours` | N | Estimated effort in hours (set by Solution Architect Agent or human) |

#### 3.1.3 AgentRuns Table Extension (Coder Output)

Additional fields on the `agent_runs` table (AGENT-001) when the run is for a Coder Agent:

| Field | Type | Description |
|-------|------|-------------|
| `coder_output` | M (map) | Structured output from the Coder Agent run |
| `coder_output.branch_name` | S | Feature branch created |
| `coder_output.pr_url` | S | Pull request URL |
| `coder_output.pr_number` | N | PR number |
| `coder_output.files_changed` | L (list of S) | List of files modified |
| `coder_output.files_added` | L (list of S) | List of new files |
| `coder_output.files_deleted` | L (list of S) | List of deleted files |
| `coder_output.insertions` | N | Lines added |
| `coder_output.deletions` | N | Lines removed |
| `coder_output.test_results` | L (list of M) | Array of `{command, exit_code, duration_seconds, stdout_tail, stderr_tail}` |
| `coder_output.test_retry_count` | N | Number of test-fix-retest cycles executed |
| `coder_output.total_duration_seconds` | N | Wall-clock time from ticket claim to PR creation |
| `coder_output.escalated` | BOOL | Whether the agent escalated to a human |
| `coder_output.escalation_reason` | S | Reason for escalation (if any) |

### 3.2 Backend Service (`app/services/agent_coder.py`)

```python
# --- Configuration ---
def get_coder_config(*, agent_type_id: str) -> dict:
    """Fetch and validate coder_config from agent_types table."""

def update_coder_config(*, agent_type_id: str, owner_sub: str, config: dict) -> dict:
    """Validate and update coder_config fields. Validates repo URL accessibility."""

def validate_coder_config(config: dict) -> list[str]:
    """Return list of validation errors (empty = valid). Checks: repo_url format,
    branch_pattern has {ticket_id} placeholder, test_commands non-empty,
    skill_level in allowed values, timeouts positive."""

# --- Ticket Filtering ---
def find_eligible_tickets(*, agent_type_id: str, skill_level: str,
                          complexity_labels: dict, space_id: str | None = None,
                          limit: int = 10) -> list[dict]:
    """Query tickets table for tickets with labels matching type:development or type:bugfix
    AND complexity matching the agent's skill level. Returns oldest-first (FIFO).
    Skips tickets already assigned to another agent."""

def claim_ticket(*, agent_run_id: str, ticket_id: str, agent_sub: str) -> dict | None:
    """Atomically assign ticket to this agent (conditional update on assigned_to_sub=None).
    Sets status to in_progress. Returns ticket or None if already claimed."""

# --- Branch & Git Operations ---
def generate_branch_name(*, pattern: str, ticket_id: str, subject: str) -> str:
    """Render branch pattern with slugified subject. Max 80 chars.
    Example: 'feat/tkt_abc123-add-user-search'."""

def build_git_commands(*, repo_url: str, branch_name: str, base_branch: str,
                        pre_commands: list[str]) -> list[str]:
    """Return ordered list of terminal commands for repo setup:
    git clone, git checkout -b, pre_commands."""

# --- Coding Workflow ---
def build_coding_prompt(*, ticket: dict, coding_tool: str, model: str | None,
                         file_exclude_patterns: list[str]) -> str:
    """Construct the prompt injected into the terminal for Claude Code / Codex.
    Includes ticket subject, description, acceptance criteria from metadata,
    file exclusion instructions, and output format expectations."""

def build_test_commands(*, test_commands: list[str], test_timeout: int) -> list[str]:
    """Wrap each test command with timeout and exit-code capture."""

def build_fix_prompt(*, test_output: str, retry_number: int, max_retries: int) -> str:
    """Construct prompt for fixing test failures. Includes test output,
    remaining retry budget, and instructions to focus on the failing tests."""

# --- PR Creation ---
def build_pr_command(*, branch_name: str, base_branch: str, ticket_id: str,
                      ticket_subject: str, template: str, summary: str) -> str:
    """Return `gh pr create` command with rendered template body."""

def parse_pr_output(stdout: str) -> dict:
    """Extract PR URL and number from `gh pr create` stdout."""

# --- Output Assembly ---
def build_coder_output(*, branch_name: str, pr_url: str, pr_number: int,
                         git_diff_stat: str, test_results: list[dict],
                         retry_count: int, duration_seconds: int,
                         escalated: bool, escalation_reason: str | None) -> dict:
    """Parse git diff --stat output and assemble structured coder_output dict."""

# --- Status Updates ---
def mark_ticket_code_complete(*, ticket_id: str, agent_sub: str, pr_url: str) -> dict:
    """Update ticket status to code_complete (custom status added to ticket system).
    Add PR URL to ticket metadata. Add activity log entry."""

def mark_ticket_blocked(*, ticket_id: str, agent_sub: str, reason: str) -> dict:
    """Update ticket status to blocked. Trigger feedback loop escalation."""

# --- Workflow Orchestrator ---
def build_coder_workflow(*, agent_run_id: str, agent_type_id: str,
                           ticket: dict) -> list[dict]:
    """Return the ordered workflow steps for the Worker Agent Framework (AGENT-003):
    1. clone_repo: git clone + checkout base branch
    2. create_branch: git checkout -b feature branch
    3. run_pre_commands: environment setup
    4. inject_coding_prompt: send ticket prompt to Claude Code / Codex
    5. wait_for_coding: monitor terminal for completion signal
    6. run_tests: execute test commands
    7. evaluate_tests: check exit codes; if failures, go to fix_loop
    8. fix_loop: inject fix prompt, re-run tests (up to retry_limit)
    9. create_pr: gh pr create with template
    10. capture_output: git diff --stat, assemble coder_output
    11. update_ticket: mark code_complete with PR URL
    Each step is a dict with {step_id, type, command_or_prompt, timeout_seconds,
    on_failure: 'retry' | 'escalate' | 'next'}."""
```

### 3.3 Backend Router (`app/routers/agent_coder.py`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/ui/agents/types/coder/config-schema` | `require_admin_scope` | Return JSON schema for coder_config fields |
| PUT | `/ui/agents/types/{type_id}/coder-config` | `require_admin_scope` | Set or update coder_config |
| GET | `/ui/agents/types/{type_id}/coder-config` | `require_admin_scope` | Get current coder_config |
| POST | `/ui/agents/types/{type_id}/coder-config/validate` | `require_admin_scope` | Validate config without saving (test repo access, etc.) |
| GET | `/ui/agents/types/{type_id}/eligible-tickets` | `require_admin_scope` | Preview which tickets this agent would pick up |
| POST | `/ui/agents/runs/{run_id}/claim-ticket` | `require_admin_scope` | Manually trigger ticket claim for a specific run |
| GET | `/ui/agents/runs/{run_id}/coder-output` | `require_admin_scope` | Get structured output from a completed coder run |
| POST | `/ui/agents/types/{type_id}/test-workflow` | `require_admin_scope` | Dry-run: generate workflow steps for a given ticket without executing |
| GET | `/ui/agents/coder/metrics` | `require_admin_scope` | Aggregate metrics: tickets completed, avg time, failure rate |

<!-- NOTE: `require_admin_session` does not exist in the codebase. The correct admin auth dependency is `require_admin_scope(AdminScope.XXX)` from `app/auth/policy.py:84`. -->

**Key request models**:

```python
class CoderConfigIn(BaseModel):
    repo_url: str = Field(..., min_length=5, max_length=500)
    repo_branch_base: str = Field(default="main", max_length=100)
    branch_pattern: str = Field(default="feat/{ticket_id}-{slug}", max_length=200)
    test_commands: List[str] = Field(..., min_length=1, max_length=20)
    test_timeout_seconds: int = Field(default=600, ge=60, le=7200)
    test_retry_limit: int = Field(default=3, ge=0, le=10)
    pr_template: str = Field(default="Closes #{ticket_id}\n\n{summary}", max_length=5000)
    pr_base_branch: str = Field(default="main", max_length=100)
    skill_level: Literal["junior", "mid", "senior"] = "mid"
    max_ticket_time_seconds: int = Field(default=3600, ge=300, le=28800)
    complexity_labels: Optional[Dict[str, List[str]]] = None
    coding_tool: Literal["claude_code", "codex"] = "claude_code"
    coding_tool_model: Optional[str] = Field(default=None, max_length=100)
    pre_commands: Optional[List[str]] = Field(default=None, max_length=20)
    post_commands: Optional[List[str]] = Field(default=None, max_length=20)
    file_exclude_patterns: Optional[List[str]] = Field(default=None, max_length=50)

class TicketClaimIn(BaseModel):
    ticket_id: str = Field(..., min_length=1, max_length=100)

class TestWorkflowIn(BaseModel):
    ticket_id: str = Field(..., min_length=1, max_length=100)
```

Response models: `CoderConfigOut` (mirrors config with repo URL), `EligibleTicketOut` (ticket_id, subject, labels, complexity, estimated_effort), `CoderOutputOut` (full coder_output map), `CoderMetricsOut` (completed_count, avg_duration_seconds, failure_rate, escalation_rate, tickets_by_skill_level), `WorkflowPreviewOut` (list of workflow step previews).

Register in `app/main.py`:

```python
from app.routers.agent_coder import router as agent_coder_router
app.include_router(agent_coder_router, prefix="/ui")
```

### 3.4 Ticket Label Extension

Extend `TicketStore.create_ticket()` to accept an optional `labels: list[str]` parameter. Add `labels` (SS type) to the META item. Add a new GSI for label-based queries:

```python
# In local-ddb-init.py, extend tickets table GSIs:
# GSI: gsi_label -- partition_key: "gsi_label_pk" (S), sort_key: "gsi_label_sk" (S)
# gsi_label_pk = "LABEL#{label}" for each label in the set (fan-out writes)
# gsi_label_sk = updated_index_sk(ts, ticket_id)
```

For agent ticket filtering, write one index entry per label when creating or updating a ticket. Query `LABEL#type:development` or `LABEL#type:bugfix` to find eligible tickets.

### 3.5 Workflow Step Execution

The Worker Agent Framework (AGENT-003) executes the Coder workflow by injecting commands into the provisioned terminal (AGENT-002). Each step in the workflow list is processed sequentially:

1. **clone_repo**: `git clone {repo_url} /workspace && cd /workspace && git fetch origin`
2. **create_branch**: `git checkout -b {branch_name} origin/{base_branch}`
3. **run_pre_commands**: Execute each pre-command (e.g., `nvm use 20`, `source .venv/bin/activate`)
4. **inject_coding_prompt**: Pipe the constructed prompt to Claude Code or Codex via the terminal. For Claude Code: `claude --dangerously-skip-permissions -p "{prompt}"`. For Codex: `codex -q "{prompt}"`.
5. **wait_for_coding**: Monitor terminal output for completion signal (exit code 0 from the coding tool). Timeout after `max_ticket_time_seconds / 2` (leave time for tests and PR).
6. **run_tests**: Execute each test command in order. Capture exit code, stdout tail (last 200 lines), stderr tail (last 100 lines), and duration.
7. **evaluate_tests**: If all exit codes are 0, proceed to create_pr. If any failed, enter fix_loop.
8. **fix_loop**: Construct a fix prompt including the test failure output. Inject into coding tool. Re-run tests. Repeat up to `test_retry_limit` times. If exhausted, escalate.
9. **create_pr**: `gh pr create --title "{ticket_subject}" --body "{rendered_template}" --base {base_branch}`. Parse output for PR URL.
10. **capture_output**: `git diff --stat origin/{base_branch}...HEAD`. Parse insertions/deletions/files.
11. **update_ticket**: Call `mark_ticket_code_complete()` with PR URL.

### 3.6 Escalation Handling

When the Coder Agent cannot complete its task:

- **Test failures exhausted**: After `test_retry_limit` fix attempts, the agent calls `mark_ticket_blocked()` and creates a feedback request (AGENT-004) with: test command, exit code, last 200 lines of output, files changed, and a suggested next step.
- **Timeout exceeded**: If wall-clock time exceeds `max_ticket_time_seconds`, the agent saves its current state (branch name, files changed so far, partial test results) and escalates with a progress summary.
- **Git conflict**: If branch creation or push fails due to conflicts, the agent escalates with the conflict details.
- **Coding tool crash**: If Claude Code or Codex exits with a non-zero code (not from tests), the agent captures the error output and escalates.

### 3.7 Frontend Types (`frontend/src/api/types.ts`)

```typescript
export interface CoderConfig {
  repo_url: string;
  repo_branch_base: string;
  branch_pattern: string;
  test_commands: string[];
  test_timeout_seconds: number;
  test_retry_limit: number;
  pr_template: string;
  pr_base_branch: string;
  skill_level: "junior" | "mid" | "senior";
  max_ticket_time_seconds: number;
  complexity_labels?: Record<string, string[]>;
  coding_tool: "claude_code" | "codex";
  coding_tool_model?: string;
  pre_commands?: string[];
  post_commands?: string[];
  file_exclude_patterns?: string[];
}

export interface CoderOutput {
  branch_name: string;
  pr_url: string;
  pr_number: number;
  files_changed: string[];
  files_added: string[];
  files_deleted: string[];
  insertions: number;
  deletions: number;
  test_results: Array<{
    command: string;
    exit_code: number;
    duration_seconds: number;
    stdout_tail: string;
    stderr_tail: string;
  }>;
  test_retry_count: number;
  total_duration_seconds: number;
  escalated: boolean;
  escalation_reason?: string;
}

export interface CoderMetrics {
  completed_count: number;
  avg_duration_seconds: number;
  failure_rate: number;
  escalation_rate: number;
  tickets_by_skill_level: Record<string, number>;
  period_start: number;
  period_end: number;
}

export interface EligibleTicket {
  ticket_id: string;
  subject: string;
  labels: string[];
  complexity?: string;
  estimated_effort_hours?: number;
  created_at: number;
}
```

### 3.8 Frontend API (`frontend/src/api/endpoints/agents.ts`)

Standard CRUD wrappers for Coder Agent configuration, eligible ticket preview, coder output retrieval, and metrics. Key functions: `getCoderConfig`, `updateCoderConfig`, `validateCoderConfig`, `getEligibleTickets`, `claimTicket`, `getCoderOutput`, `testWorkflow`, `getCoderMetrics`.

### 3.9 Frontend Pages

- **CoderAgentConfigPage** (`frontend/src/pages/agents/CoderAgentConfigPage.tsx`): Route `/agents/types/:typeId/coder`. Tabbed layout: Config | Eligible Tickets | Metrics. `data-testid="coder-config-page"`.
  - **Config tab**: Repository URL input, base branch, branch pattern (with placeholder preview), test commands (sortable list), test timeout slider, retry limit slider, PR template editor (Markdown with placeholder syntax highlighting), skill level selector, time budget slider, coding tool radio (Claude Code / Codex), model override input, pre/post commands list editors, file exclusion patterns. "Validate" and "Save" buttons. `data-testid="coder-config-tab"`.
  - **Eligible Tickets tab**: Table showing tickets that match this agent's filter criteria. Columns: ticket ID, subject, labels, complexity, age. Refresh button. `data-testid="eligible-tickets-tab"`.
  - **Metrics tab**: Cards showing completed count, average duration, failure rate, escalation rate. Bar chart of tickets by skill level. Time-series chart of throughput over last 30 days. `data-testid="coder-metrics-tab"`.

- **CoderRunOutputPanel** (`frontend/src/pages/agents/CoderRunOutputPanel.tsx`): Embedded in Agent Run detail page (AGENT-005). Shows: branch name, PR link, files changed tree, diff stats, test results accordion (expand each command to see output), retry count, duration, escalation status. `data-testid="coder-output-panel"`.

---

## 4. Implementation Plan

### 4.1 Files to Create

| File | Purpose |
|------|---------|
| `app/services/agent_coder.py` | Coder Agent configuration, ticket filtering, workflow orchestration, output assembly |
| `app/routers/agent_coder.py` | Coder config CRUD, eligible tickets, output, metrics endpoints |
| `frontend/src/pages/agents/CoderAgentConfigPage.tsx` | Coder Agent configuration + metrics UI |
| `frontend/src/pages/agents/CoderRunOutputPanel.tsx` | Coder run output detail panel |

### 4.2 Files to Modify

| File | Changes |
|------|---------|
| `scripts/local-ddb-init.py` | Add `gsi_label` GSI to tickets table; add `labels` and `complexity` attr_types |
| `app/core/settings.py` | Add `tickets_label_index_name` setting |
| `app/core/tables.py` | No new tables (extends existing agent_types, agent_runs, tickets) |
| `app/services/tickets.py` | Add `labels` parameter to `create_ticket()`; add label GSI fan-out writes; add `code_complete` and `blocked` to `_TICKET_STATUSES` |
| `app/main.py` | Register `agent_coder_router` |
| `app/models.py` | Add `CoderConfigIn`, `CoderConfigOut`, `CoderOutputOut`, `CoderMetricsOut`, `EligibleTicketOut`, `TicketClaimIn`, `TestWorkflowIn` models |
| `frontend/src/api/types.ts` | Add `CoderConfig`, `CoderOutput`, `CoderMetrics`, `EligibleTicket` types |
| `frontend/src/api/endpoints/agents.ts` | Add Coder Agent API functions |
| `frontend/src/App.tsx` | Add `/agents/types/:typeId/coder` route |

---

## 5. E2E Test Plan

### 5.1 Test File

`frontend/e2e/agent-coder.spec.ts` -- 16 tests across 4 sections.

### 5.2 Test Setup

```typescript
const TS = Date.now();
let agentTypeId: string;
let ticketId: string;
let runId: string;
// Root = admin who configures agents
// Uses e2e_admin_session_setup.py sessions
```

### 5.3 Section 651: Coder Config API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 651.1 | Create Coder Agent type with config | POST agent type with `agent_type=coder`; PUT coder-config with repo_url, test_commands, skill_level; 200; config saved |
| 651.2 | Get coder config | GET `/ui/agents/types/{typeId}/coder-config`; 200; all fields match saved values |
| 651.3 | Validate coder config with invalid repo | POST validate with `repo_url="not-a-url"`; 200; `errors` array non-empty |
| 651.4 | Update skill level and time budget | PUT with `skill_level=senior`, `max_ticket_time_seconds=7200`; 200; values updated |

### 5.4 Section 652: Ticket Filtering & Claiming API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 652.1 | Create ticket with development label | Create ticket with `labels=["type:development", "complexity:medium"]`; ticket has labels in response |
| 652.2 | Eligible tickets returns matching ticket | GET eligible-tickets for mid-skill agent; array includes the created ticket |
| 652.3 | Claim ticket assigns to agent | POST claim-ticket with ticket_id; 200; ticket status = `in_progress`, assigned_to_sub = agent sub |
| 652.4 | Claimed ticket no longer eligible | GET eligible-tickets; array does not include the claimed ticket |

### 5.5 Section 653: Workflow & Output API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 653.1 | Test workflow generates steps | POST test-workflow with ticket_id; 200; `steps` array has 11 items; first step is `clone_repo` |
| 653.2 | Branch name follows pattern | Response includes `branch_name` matching `feat/{ticket_id}-*` pattern |
| 653.3 | PR command uses correct template | Response step for `create_pr` contains ticket ID in PR body |
| 653.4 | Get coder output from completed run | GET coder-output for a run; 200; `pr_url`, `files_changed`, `test_results` present |

### 5.6 Section 654: Coder Config UI (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 654.1 | Config page loads | Navigate `/agents/types/{typeId}/coder`; `[data-testid="coder-config-page"]` visible |
| 654.2 | Config tab shows saved values | Config tab active; repo URL input shows saved URL; skill level selector shows "mid" |
| 654.3 | Eligible tickets tab lists tickets | Click "Eligible Tickets" tab; `[data-testid="eligible-tickets-tab"]` visible; table shows at least 1 row |
| 654.4 | Metrics tab renders charts | Click "Metrics" tab; `[data-testid="coder-metrics-tab"]` visible; completed count card present |

---

## 6. Error Handling

| Scenario | Status | Detail |
|----------|--------|--------|
| Agent type not found | 404 | "Agent type not found" |
| Agent type is not a coder | 409 | "Agent type is not configured as a coder" |
| Invalid repo URL format | 422 | "Repository URL must be a valid git URL" |
| Branch pattern missing {ticket_id} | 422 | "Branch pattern must include {ticket_id} placeholder" |
| Empty test commands list | 422 | "At least one test command is required" |
| Invalid skill level | 422 | "Skill level must be junior, mid, or senior" |
| Ticket already claimed | 409 | "Ticket is already assigned to another agent" |
| Ticket not found | 404 | "Ticket not found" |
| No eligible tickets | 200 | Empty array (not an error) |
| Config validation failed | 200 | `{valid: false, errors: [...]}` (validation endpoint) |
| Run not found | 404 | "Agent run not found" |
| Run has no coder output | 404 | "No coder output available for this run" |
| Not admin | 403 | "Admin access required" |

---

## 7. Security Considerations

- **Admin-only access**: All Coder Agent configuration endpoints require `require_admin_scope()` (see `app/auth/policy.py:84`). Regular users cannot configure or trigger agents. <!-- NOTE: was `require_admin_session` which does not exist -->
- **Repository credential isolation**: Git credentials (SSH keys, personal access tokens) are stored in the agent secrets vault (AGENT-006), never in the coder_config. The terminal environment has credentials injected at provisioning time.
- **Command injection prevention**: Branch names and ticket subjects are sanitized (alphanumeric + hyphens only) before being interpolated into shell commands. The `build_git_commands()` and `build_pr_command()` functions use array-based command construction, not string interpolation.
- **File exclusion enforcement**: `file_exclude_patterns` are passed to the coding tool prompt. The agent's git diff output is checked post-hoc to verify no excluded files were modified; if they were, the PR is flagged for human review.
- **Time budget enforcement**: The Worker Agent Framework kills the terminal session if `max_ticket_time_seconds` is exceeded, preventing runaway resource consumption.
- **Ticket claim atomicity**: `claim_ticket()` uses a DynamoDB conditional update (`attribute_not_exists(assigned_to_sub) OR assigned_to_sub = :none`) to prevent double-claiming race conditions.
- **Output sanitization**: Stdout/stderr tails stored in `coder_output` are truncated to 10KB max to prevent storage abuse.

---

## 8. Performance Considerations

| Concern | Mitigation |
|---------|-----------|
| Ticket label fan-out writes | Max 10 labels per ticket; 10 additional GSI writes is acceptable |
| Eligible ticket query across labels | Query each label GSI partition separately and merge; typically 2 queries (type:development + type:bugfix) |
| Large test output capture | Tail last 200 lines of stdout, 100 lines of stderr; discard rest |
| Concurrent agent instances competing for tickets | Conditional update on claim prevents double-assignment; agents poll at staggered intervals |
| Workflow step timeouts | Each step has independent timeout; total bounded by max_ticket_time_seconds |
| Metrics aggregation | Pre-computed daily; dashboard queries last 30 daily snapshots |

---

## 9. Dependencies

| Dependency | Ticket | Status |
|------------|--------|--------|
| AGENT-001 (LLM Provider Key Management) | AGENT-001 | Required (API key management for coding tools) |
| AGENT-002 (Terminal Worker Provisioning) | AGENT-002 | Required (compute environment for coding) |
| AGENT-003 (Worker Agent Framework & Lifecycle) | AGENT-003 | Required (workflow execution engine, agent state machine) |
| AGENT-004 (Worker Fleet Management UI) | AGENT-004 | Required (fleet overview, bulk operations) |
| AGENT-005 (Agent Memory & Context Injection) | AGENT-005 | Required (context injection for coding tool prompts) |
| AGENT-006 (Terminal Monitoring & Feedback Loop) | AGENT-006 | Required (terminal output capture, escalation signals) |
| Ticket System | Existing | Available (`app/services/tickets.py`, needs label extension) |

### Downstream

| Ticket | Depends On |
|--------|-----------|
| AGENT-009 (QA Agent) | Uses `code_complete` status as trigger; reviews PRs created by Coder Agent |
| AGENT-011 (Solution Architect) | Creates tickets with labels and complexity that Coder Agent picks up |
| AGENT-012 (Project Manager) | Tracks Coder Agent throughput for project velocity |

---

## 10. Architecture & Data Flow

### 10.1 Coder Agent Workflow Pipeline

```
Ticket System                Worker Agent Framework (AGENT-003)
┌─────────────┐      ┌─────────────────────────────────────────────────────┐
│ Ticket Queue │      │  Coder Agent Workflow Orchestrator                  │
│ status=open  │      │                                                     │
│ labels:      │◄─────│  1. find_eligible_tickets(skill_level, labels)      │
│  type:dev    │ poll │  2. claim_ticket(ticket_id) ── conditional update   │
│  complexity: │      │     ↓                                               │
│  medium      │      │  3. build_git_commands(repo, branch)                │
└─────────────┘      │     └── Terminal: git clone → git checkout -b        │
                      │  4. run_pre_commands(["nvm use 20", ...])           │
                      │     └── Terminal: environment setup                  │
                      │  5. inject_coding_prompt(ticket, tool, model)       │
                      │     └── Terminal: claude --dangerously-skip-perms    │
                      │  6. wait_for_coding(timeout=max_time/2)             │
                      │     └── Monitor: exit code 0 = done                 │
                      │  7. run_tests(test_commands)                        │
                      │     └── Terminal: just test / just e2e              │
                      │  8. evaluate_tests → pass? → create_pr             │
                      │                    → fail? → fix_loop (retry N)     │
                      │  9. build_pr_command(template, ticket_id)           │
                      │     └── Terminal: gh pr create                      │
                      │  10. capture_output(git diff --stat)               │
                      │  11. update_ticket(status=code_complete, pr_url)   │
                      └─────────────────────────────────────────────────────┘
                                          │
                                          ▼
                      ┌─────────────────────────────────────────────────────┐
                      │  Escalation Path (on failure)                       │
                      │                                                     │
                      │  test retries exhausted ──► mark_ticket_blocked     │
                      │  timeout exceeded ─────────► save state + escalate  │
                      │  git conflict ─────────────► escalate with details  │
                      │  coding tool crash ────────► capture error + esc.   │
                      │                                                     │
                      │  All escalations → Feedback Loop (AGENT-006)        │
                      │                  → Ticket status = "blocked"        │
                      │                  → SSE: worker:error event          │
                      └─────────────────────────────────────────────────────┘
```

### 10.2 Test-Fix Loop Detail

```
┌──────────────────────────────────────────────────────┐
│  Test-Fix Loop (max test_retry_limit iterations)     │
│                                                      │
│  retry_count = 0                                     │
│  ┌────────────────────────────────────────────────┐  │
│  │  run_tests(test_commands)                      │  │
│  │    ↓                                           │  │
│  │  all pass? ──YES──► exit loop → create_pr      │  │
│  │    │                                           │  │
│  │   NO                                           │  │
│  │    ↓                                           │  │
│  │  retry_count += 1                              │  │
│  │  retry_count > limit? ──YES──► ESCALATE        │  │
│  │    │                                           │  │
│  │   NO                                           │  │
│  │    ↓                                           │  │
│  │  build_fix_prompt(test_output, retry_count)    │  │
│  │    ↓                                           │  │
│  │  inject into coding tool                       │  │
│  │    ↓                                           │  │
│  │  wait_for_coding(timeout)                      │  │
│  │    ↓                                           │  │
│  │  loop back to run_tests                        │  │
│  └────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────┘
```

---

## 11. Detailed DynamoDB Access Patterns

| # | Operation | Table | PK | SK / Key Condition | GSI | Notes |
|---|-----------|-------|----|--------------------|-----|-------|
| 1 | Get coder config | `agent_types` | `TYPE#{type_id}` | `CONFIG` | -- | GetItem; check `agent_type=coder` |
| 2 | Update coder config | `agent_types` | `TYPE#{type_id}` | `CONFIG` | -- | UpdateItem on `coder_config` map |
| 3 | Find tickets by label | `tickets` | -- | -- | `gsi_label` PK=`LABEL#type:development` | Query oldest-first |
| 4 | Claim ticket (conditional) | `tickets` | `SPACE#{space_id}` | `TICKET#{ticket_id}` | -- | ConditionExpression: `assigned_to_sub = :none OR attribute_not_exists(assigned_to_sub)` |
| 5 | Update ticket to code_complete | `tickets` | `SPACE#{space_id}` | `TICKET#{ticket_id}` | -- | UpdateItem: status, pr_url in metadata |
| 6 | Update ticket to blocked | `tickets` | `SPACE#{space_id}` | `TICKET#{ticket_id}` | -- | UpdateItem: status, escalation reason |
| 7 | Store coder output | `agent_runs` | `RUN#{run_id}` | `OUTPUT` | -- | PutItem with coder_output map |
| 8 | Get coder output | `agent_runs` | `RUN#{run_id}` | `OUTPUT` | -- | GetItem |
| 9 | Query metrics (daily snapshots) | `agent_runs` | -- | -- | `gsi_type_date` PK=`CODER#{type_id}`, SK=`DATE#{yyyy-mm-dd}` | Rollup records |
| 10 | Fan-out label index on ticket create | `tickets` | -- | -- | `gsi_label` | One PutItem per label in the set |

---

## 12. API Request/Response Examples

### 12.1 Set Coder Config

```bash
curl -s -X PUT "http://localhost:8000/ui/agents/types/type_abc123/coder-config" \
  -H "Cookie: ui_session=SESS_root; ui_access_token=JWT_root; ui_csrf=CSRF_root" \
  -H "x-csrf-token: CSRF_root" \
  -H "Content-Type: application/json" \
  -d '{
    "repo_url": "https://github.com/acme/backend.git",
    "repo_branch_base": "main",
    "branch_pattern": "feat/{ticket_id}-{slug}",
    "test_commands": ["just test", "just e2e"],
    "test_timeout_seconds": 600,
    "test_retry_limit": 3,
    "pr_template": "Closes #{ticket_id}\n\n## Summary\n{summary}\n\n## Test Results\nAll tests passing.",
    "pr_base_branch": "main",
    "skill_level": "mid",
    "max_ticket_time_seconds": 3600,
    "complexity_labels": {
      "junior": ["complexity:low"],
      "mid": ["complexity:low", "complexity:medium"],
      "senior": ["complexity:low", "complexity:medium", "complexity:high"]
    },
    "coding_tool": "claude_code",
    "coding_tool_model": "claude-sonnet-4-6",
    "pre_commands": ["source .venv/bin/activate", "nvm use 20"],
    "post_commands": ["just lint-fix"],
    "file_exclude_patterns": ["*.lock", "package-lock.json"]
  }'
```

```json
{
  "repo_url": "https://github.com/acme/backend.git",
  "repo_branch_base": "main",
  "branch_pattern": "feat/{ticket_id}-{slug}",
  "test_commands": ["just test", "just e2e"],
  "test_timeout_seconds": 600,
  "test_retry_limit": 3,
  "pr_template": "Closes #{ticket_id}\n\n## Summary\n{summary}\n\n## Test Results\nAll tests passing.",
  "pr_base_branch": "main",
  "skill_level": "mid",
  "max_ticket_time_seconds": 3600,
  "complexity_labels": {
    "junior": ["complexity:low"],
    "mid": ["complexity:low", "complexity:medium"],
    "senior": ["complexity:low", "complexity:medium", "complexity:high"]
  },
  "coding_tool": "claude_code",
  "coding_tool_model": "claude-sonnet-4-6",
  "pre_commands": ["source .venv/bin/activate", "nvm use 20"],
  "post_commands": ["just lint-fix"],
  "file_exclude_patterns": ["*.lock", "package-lock.json"],
  "updated_at": 1748520000
}
```

### 12.2 Get Coder Config

```bash
curl -s -X GET "http://localhost:8000/ui/agents/types/type_abc123/coder-config" \
  -H "Cookie: ui_session=SESS_root; ui_access_token=JWT_root; ui_csrf=CSRF_root"
```

```json
{
  "repo_url": "https://github.com/acme/backend.git",
  "repo_branch_base": "main",
  "branch_pattern": "feat/{ticket_id}-{slug}",
  "test_commands": ["just test", "just e2e"],
  "test_timeout_seconds": 600,
  "test_retry_limit": 3,
  "pr_template": "Closes #{ticket_id}\n\n## Summary\n{summary}",
  "pr_base_branch": "main",
  "skill_level": "mid",
  "max_ticket_time_seconds": 3600,
  "coding_tool": "claude_code",
  "coding_tool_model": "claude-sonnet-4-6",
  "pre_commands": ["source .venv/bin/activate", "nvm use 20"],
  "file_exclude_patterns": ["*.lock", "package-lock.json"]
}
```

### 12.3 Validate Config (with errors)

```bash
curl -s -X POST "http://localhost:8000/ui/agents/types/type_abc123/coder-config/validate" \
  -H "Cookie: ui_session=SESS_root; ui_access_token=JWT_root; ui_csrf=CSRF_root" \
  -H "x-csrf-token: CSRF_root" \
  -H "Content-Type: application/json" \
  -d '{"repo_url": "not-a-url", "branch_pattern": "my-branch", "test_commands": []}'
```

```json
{
  "valid": false,
  "errors": [
    "Repository URL must be a valid git URL (https:// or git@)",
    "Branch pattern must include {ticket_id} placeholder",
    "At least one test command is required"
  ]
}
```

### 12.4 Get Eligible Tickets

```bash
curl -s -X GET "http://localhost:8000/ui/agents/types/type_abc123/eligible-tickets?limit=5" \
  -H "Cookie: ui_session=SESS_root; ui_access_token=JWT_root; ui_csrf=CSRF_root"
```

```json
{
  "tickets": [
    {
      "ticket_id": "tkt_def456",
      "subject": "Add pagination to user list endpoint",
      "labels": ["type:development", "complexity:medium", "area:backend"],
      "complexity": "medium",
      "estimated_effort_hours": 2,
      "created_at": 1748430000
    },
    {
      "ticket_id": "tkt_ghi789",
      "subject": "Fix 500 error on empty search query",
      "labels": ["type:bugfix", "complexity:low", "area:backend"],
      "complexity": "low",
      "estimated_effort_hours": 1,
      "created_at": 1748440000
    }
  ],
  "count": 2
}
```

### 12.5 Claim Ticket

```bash
curl -s -X POST "http://localhost:8000/ui/agents/runs/run_xyz/claim-ticket" \
  -H "Cookie: ui_session=SESS_root; ui_access_token=JWT_root; ui_csrf=CSRF_root" \
  -H "x-csrf-token: CSRF_root" \
  -H "Content-Type: application/json" \
  -d '{"ticket_id": "tkt_def456"}'
```

```json
{
  "ok": true,
  "ticket_id": "tkt_def456",
  "status": "in_progress",
  "assigned_to_sub": "agent_run_xyz_sub",
  "claimed_at": 1748520100
}
```

### 12.6 Test Workflow (dry-run)

```bash
curl -s -X POST "http://localhost:8000/ui/agents/types/type_abc123/test-workflow" \
  -H "Cookie: ui_session=SESS_root; ui_access_token=JWT_root; ui_csrf=CSRF_root" \
  -H "x-csrf-token: CSRF_root" \
  -H "Content-Type: application/json" \
  -d '{"ticket_id": "tkt_def456"}'
```

```json
{
  "steps": [
    {"step_id": 1, "type": "clone_repo", "command": "git clone https://github.com/acme/backend.git /workspace && cd /workspace && git fetch origin", "timeout_seconds": 120, "on_failure": "escalate"},
    {"step_id": 2, "type": "create_branch", "command": "git checkout -b feat/tkt_def456-add-pagination-to-user-list origin/main", "timeout_seconds": 30, "on_failure": "escalate"},
    {"step_id": 3, "type": "run_pre_commands", "command": "source .venv/bin/activate && nvm use 20", "timeout_seconds": 60, "on_failure": "escalate"},
    {"step_id": 4, "type": "inject_coding_prompt", "command": "claude --dangerously-skip-permissions -p \"...\"", "timeout_seconds": 1800, "on_failure": "escalate"},
    {"step_id": 5, "type": "wait_for_coding", "command": null, "timeout_seconds": 1800, "on_failure": "escalate"},
    {"step_id": 6, "type": "run_tests", "command": "just test", "timeout_seconds": 600, "on_failure": "retry"},
    {"step_id": 7, "type": "run_tests", "command": "just e2e", "timeout_seconds": 600, "on_failure": "retry"},
    {"step_id": 8, "type": "evaluate_tests", "command": null, "timeout_seconds": 10, "on_failure": "escalate"},
    {"step_id": 9, "type": "create_pr", "command": "gh pr create --title \"Add pagination to user list endpoint\" --body \"Closes #tkt_def456\\n\\n## Summary\\n{summary}\"", "timeout_seconds": 60, "on_failure": "escalate"},
    {"step_id": 10, "type": "capture_output", "command": "git diff --stat origin/main...HEAD", "timeout_seconds": 30, "on_failure": "next"},
    {"step_id": 11, "type": "update_ticket", "command": null, "timeout_seconds": 30, "on_failure": "next"}
  ],
  "branch_name": "feat/tkt_def456-add-pagination-to-user-list",
  "total_timeout_seconds": 3600
}
```

### 12.7 Get Coder Output

```bash
curl -s -X GET "http://localhost:8000/ui/agents/runs/run_xyz/coder-output" \
  -H "Cookie: ui_session=SESS_root; ui_access_token=JWT_root; ui_csrf=CSRF_root"
```

```json
{
  "branch_name": "feat/tkt_def456-add-pagination-to-user-list",
  "pr_url": "https://github.com/acme/backend/pull/142",
  "pr_number": 142,
  "files_changed": ["app/routers/users.py", "app/services/users.py", "tests/test_users.py"],
  "files_added": [],
  "files_deleted": [],
  "insertions": 87,
  "deletions": 12,
  "test_results": [
    {"command": "just test", "exit_code": 0, "duration_seconds": 45, "stdout_tail": "42 passed", "stderr_tail": ""},
    {"command": "just e2e", "exit_code": 0, "duration_seconds": 312, "stdout_tail": "1070 passed", "stderr_tail": ""}
  ],
  "test_retry_count": 1,
  "total_duration_seconds": 1847,
  "escalated": false,
  "escalation_reason": null
}
```

### 12.8 Get Coder Metrics

```bash
curl -s -X GET "http://localhost:8000/ui/agents/coder/metrics?period_days=30" \
  -H "Cookie: ui_session=SESS_root; ui_access_token=JWT_root; ui_csrf=CSRF_root"
```

```json
{
  "completed_count": 47,
  "avg_duration_seconds": 2100,
  "failure_rate": 0.085,
  "escalation_rate": 0.064,
  "tickets_by_skill_level": {"junior": 12, "mid": 28, "senior": 7},
  "period_start": 1745928000,
  "period_end": 1748520000
}
```

---

## 13. Expanded Pydantic Models with Validators

```python
from pydantic import BaseModel, Field, field_validator
from typing import Dict, List, Literal, Optional

class CoderConfigIn(BaseModel):
    repo_url: str = Field(..., min_length=5, max_length=500)
    repo_branch_base: str = Field(default="main", max_length=100)
    branch_pattern: str = Field(default="feat/{ticket_id}-{slug}", max_length=200)
    test_commands: List[str] = Field(..., min_length=1, max_length=20)
    test_timeout_seconds: int = Field(default=600, ge=60, le=7200)
    test_retry_limit: int = Field(default=3, ge=0, le=10)
    pr_template: str = Field(
        default="Closes #{ticket_id}\n\n{summary}", max_length=5000
    )
    pr_base_branch: str = Field(default="main", max_length=100)
    skill_level: Literal["junior", "mid", "senior"] = "mid"
    max_ticket_time_seconds: int = Field(default=3600, ge=300, le=28800)
    complexity_labels: Optional[Dict[str, List[str]]] = None
    coding_tool: Literal["claude_code", "codex"] = "claude_code"
    coding_tool_model: Optional[str] = Field(default=None, max_length=100)
    pre_commands: Optional[List[str]] = Field(default=None, max_length=20)
    post_commands: Optional[List[str]] = Field(default=None, max_length=20)
    file_exclude_patterns: Optional[List[str]] = Field(default=None, max_length=50)

    @field_validator("repo_url")
    @classmethod
    def validate_repo_url(cls, v: str) -> str:
        if not (v.startswith("https://") or v.startswith("git@")):
            raise ValueError("Repository URL must start with https:// or git@")
        if " " in v:
            raise ValueError("Repository URL must not contain spaces")
        return v

    @field_validator("branch_pattern")
    @classmethod
    def validate_branch_pattern(cls, v: str) -> str:
        if "{ticket_id}" not in v:
            raise ValueError("Branch pattern must include {ticket_id} placeholder")
        import re
        if not re.match(r'^[a-zA-Z0-9_/{}\-]+$', v):
            raise ValueError("Branch pattern contains invalid characters")
        return v

    @field_validator("test_commands")
    @classmethod
    def validate_test_commands(cls, v: list) -> list:
        if not v:
            raise ValueError("At least one test command is required")
        for cmd in v:
            if not cmd.strip():
                raise ValueError("Test commands must not be empty strings")
            if len(cmd) > 500:
                raise ValueError("Individual test command must be <= 500 characters")
        return v

    @field_validator("pr_template")
    @classmethod
    def validate_pr_template(cls, v: str) -> str:
        if "{ticket_id}" not in v and "ticket_id" not in v:
            raise ValueError("PR template should reference the ticket ID")
        return v

    @field_validator("complexity_labels")
    @classmethod
    def validate_complexity_labels(cls, v: dict | None) -> dict | None:
        if v is None:
            return v
        allowed_levels = {"junior", "mid", "senior"}
        for level in v:
            if level not in allowed_levels:
                raise ValueError(f"Complexity label key must be one of {sorted(allowed_levels)}")
            if not isinstance(v[level], list):
                raise ValueError(f"Complexity labels for {level} must be a list")
        return v

    @field_validator("coding_tool_model")
    @classmethod
    def validate_coding_tool_model(cls, v: str | None) -> str | None:
        if v is not None and not v.strip():
            return None
        return v

    @field_validator("file_exclude_patterns")
    @classmethod
    def validate_file_exclude_patterns(cls, v: list | None) -> list | None:
        if v is None:
            return v
        for pattern in v:
            if not pattern.strip():
                raise ValueError("File exclude patterns must not be empty strings")
            if "/" in pattern and not pattern.startswith("**/"):
                pass  # Allow path-relative patterns
        return v


class CoderOutputOut(BaseModel):
    branch_name: str = ""
    pr_url: str = ""
    pr_number: int = 0
    files_changed: List[str] = Field(default_factory=list)
    files_added: List[str] = Field(default_factory=list)
    files_deleted: List[str] = Field(default_factory=list)
    insertions: int = Field(default=0, ge=0)
    deletions: int = Field(default=0, ge=0)
    test_results: List[Dict] = Field(default_factory=list)
    test_retry_count: int = Field(default=0, ge=0)
    total_duration_seconds: int = Field(default=0, ge=0)
    escalated: bool = False
    escalation_reason: Optional[str] = None

    @field_validator("test_results")
    @classmethod
    def validate_test_results(cls, v: list) -> list:
        for result in v:
            required = {"command", "exit_code", "duration_seconds"}
            missing = required - set(result.keys())
            if missing:
                raise ValueError(f"Test result missing fields: {missing}")
        return v


class CoderMetricsOut(BaseModel):
    completed_count: int = Field(ge=0)
    avg_duration_seconds: float = Field(ge=0)
    failure_rate: float = Field(ge=0, le=1)
    escalation_rate: float = Field(ge=0, le=1)
    tickets_by_skill_level: Dict[str, int] = Field(default_factory=dict)
    period_start: int
    period_end: int

    @field_validator("period_end")
    @classmethod
    def validate_period_end(cls, v: int, info) -> int:
        if "period_start" in info.data and v < info.data["period_start"]:
            raise ValueError("period_end must be >= period_start")
        return v
```

---

## 14. Frontend Component Tree

```
CoderAgentConfigPage
├── PageHeader
│   ├── Breadcrumb (Agents > Coder Config)
│   └── Heading ("Coder Agent Configuration")
├── Tabs
│   ├── Tab("Config") → CoderConfigTab
│   │   ├── Card("Repository")
│   │   │   ├── Input (repo_url)
│   │   │   ├── Input (repo_branch_base)
│   │   │   └── Input (branch_pattern) + PatternPreview
│   │   ├── Card("Test Suite")
│   │   │   ├── SortableList (test_commands)
│   │   │   ├── Slider (test_timeout_seconds, 60-7200)
│   │   │   └── Slider (test_retry_limit, 0-10)
│   │   ├── Card("PR Template")
│   │   │   └── MarkdownEditor (pr_template, with placeholder highlighting)
│   │   ├── Card("Agent Settings")
│   │   │   ├── RadioGroup (skill_level: junior/mid/senior)
│   │   │   ├── Slider (max_ticket_time_seconds, 300-28800)
│   │   │   ├── RadioGroup (coding_tool: claude_code/codex)
│   │   │   └── Input (coding_tool_model, optional)
│   │   ├── Card("Setup Commands")
│   │   │   ├── EditableList (pre_commands)
│   │   │   └── EditableList (post_commands)
│   │   ├── Card("File Exclusions")
│   │   │   └── EditableList (file_exclude_patterns)
│   │   └── ActionBar
│   │       ├── Button("Validate") → useMutation(validateConfig)
│   │       └── Button("Save")     → useMutation(updateConfig)
│   ├── Tab("Eligible Tickets") → EligibleTicketsTab
│   │   ├── Button("Refresh")
│   │   └── DataTable
│   │       ├── Column (Ticket ID)
│   │       ├── Column (Subject)
│   │       ├── Column (Labels) → BadgeGroup
│   │       ├── Column (Complexity) → Badge
│   │       ├── Column (Est. Effort)
│   │       └── Column (Age)
│   └── Tab("Metrics") → CoderMetricsTab
│       ├── StatCard (Completed)
│       ├── StatCard (Avg Duration)
│       ├── StatCard (Failure Rate %)
│       ├── StatCard (Escalation Rate %)
│       ├── BarChart (tickets_by_skill_level)
│       └── TimeSeriesChart (throughput, last 30d)
│
CoderRunOutputPanel (embedded in Agent Run detail)
├── Card("Branch & PR")
│   ├── CodeLink (branch_name)
│   └── ExternalLink (pr_url)
├── Card("Files Changed")
│   └── FileTree (files_changed + files_added + files_deleted, with +/- badges)
├── Card("Diff Stats")
│   ├── Stat (insertions, green)
│   └── Stat (deletions, red)
├── Card("Test Results")
│   └── Accordion
│       └── AccordionItem[] (one per test result)
│           ├── Header: command + exit_code badge + duration
│           └── Content: stdout_tail + stderr_tail (monospace)
├── Card("Retry Info")
│   └── Text (test_retry_count + escalated status)
└── Card("Duration")
    └── Text (total_duration_seconds, formatted)
```

### Component Props Interfaces

```typescript
interface CoderConfigTabProps {
  typeId: string;
  config: CoderConfig | undefined;
  isLoading: boolean;
  onSave: (config: CoderConfigIn) => void;
  onValidate: (config: CoderConfigIn) => void;
}

interface EligibleTicketsTabProps {
  typeId: string;
}

interface CoderMetricsTabProps {
  typeId: string;
  periodDays: number;
}

interface CoderRunOutputPanelProps {
  runId: string;
  output: CoderOutput | undefined;
  isLoading: boolean;
}

interface PatternPreviewProps {
  pattern: string;
  sampleTicketId: string;
  sampleSubject: string;
}
```

---

## 15. Observability

### 15.1 Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `coder_config_updates_total` | Counter | `type_id` | Config save operations |
| `coder_eligible_tickets_count` | Gauge | `type_id`, `skill_level` | Current eligible ticket count |
| `coder_ticket_claims_total` | Counter | `type_id`, `outcome=success\|conflict` | Ticket claim attempts |
| `coder_workflow_duration_seconds` | Histogram | `type_id`, `outcome=success\|escalated` | Total workflow wall-clock time |
| `coder_test_retry_count` | Histogram | `type_id` | Number of test-fix cycles per run |
| `coder_escalations_total` | Counter | `type_id`, `reason` | Escalation events by cause |
| `coder_pr_created_total` | Counter | `type_id` | Successful PR creations |
| `coder_lines_changed_total` | Counter | `type_id`, `direction=inserted\|deleted` | Code change volume |

### 15.2 Logging Events

| Event | Level | Fields | When |
|-------|-------|--------|------|
| `coder.config.updated` | INFO | `type_id`, `skill_level`, `coding_tool` | Config saved |
| `coder.config.validated` | INFO | `type_id`, `valid`, `error_count` | Config validation completed |
| `coder.ticket.claimed` | INFO | `type_id`, `run_id`, `ticket_id`, `complexity` | Ticket claimed by agent |
| `coder.ticket.claim_conflict` | WARN | `type_id`, `run_id`, `ticket_id` | Concurrent claim lost |
| `coder.workflow.started` | INFO | `run_id`, `ticket_id`, `branch_name` | Workflow execution begins |
| `coder.tests.passed` | INFO | `run_id`, `retry_count`, `duration_seconds` | All tests passed |
| `coder.tests.failed` | WARN | `run_id`, `retry_count`, `command`, `exit_code` | Test failure detected |
| `coder.fix.attempted` | INFO | `run_id`, `retry_number`, `max_retries` | Fix prompt injected |
| `coder.pr.created` | INFO | `run_id`, `pr_url`, `pr_number`, `insertions`, `deletions` | PR created successfully |
| `coder.escalated` | WARN | `run_id`, `ticket_id`, `reason` | Agent escalated to human |
| `coder.timeout` | ERROR | `run_id`, `ticket_id`, `elapsed_seconds`, `budget_seconds` | Time budget exceeded |

### 15.3 Alerting Rules

| Alert | Condition | Severity | Channel |
|-------|-----------|----------|---------|
| `CoderHighEscalationRate` | `rate(coder_escalations_total) / rate(coder_ticket_claims_total) > 0.25 over 1h` | Warning | Slack #agents |
| `CoderTestRetryExhaustion` | `coder_test_retry_count{quantile="0.95"} >= test_retry_limit` | Warning | Slack #agents |
| `CoderWorkflowTimeout` | `coder_workflow_duration_seconds{quantile="0.99"} > max_ticket_time_seconds * 0.9` | Critical | PagerDuty |

---

## 16. Rollout Plan

### 16.1 Feature Flags

| Flag | Scope | Default | Description |
|------|-------|---------|-------------|
| `AGENT_CODER_ENABLED` | Global | `false` | Gates all coder agent endpoints and workflow execution |
| `AGENT_CODER_AUTO_CLAIM` | Per-type | `false` | When true, coder agents auto-poll for eligible tickets; when false, manual claim only |

### 16.2 Phases

**Phase 1 -- Backend + manual claim (Week 1-2)**
- Deploy `agent_coder.py` service and router.
- `AGENT_CODER_ENABLED=true`, `AGENT_CODER_AUTO_CLAIM=false`.
- Admins manually claim tickets and trigger workflows via API.
- Monitor: workflow duration, test pass/fail rates, escalation causes.
- Validate: branch naming, PR template rendering, ticket status transitions.

**Phase 2 -- Auto-claim with guardrails (Week 3)**
- Enable `AGENT_CODER_AUTO_CLAIM=true` for 1-2 agent instances on internal repos.
- Agent polls every 60s for eligible tickets.
- Limit: 1 concurrent ticket per agent (no parallel workflows).
- Monitor: claim conflicts, timeout frequency, PR quality (manual review).

**Phase 3 -- General availability (Week 4+)**
- Enable auto-claim for all configured coder agent types.
- Allow parallel workflows (up to 3 per agent) for senior skill level.
- Frontend config page available to all admins.
- Publish runbook for troubleshooting stuck workflows.
- Monitor: throughput per agent, cost per ticket, human intervention rate.

---

## 17. Performance Considerations

### 17.1 Latency Targets

| Endpoint | Target P50 | Target P99 | Notes |
|----------|-----------|-----------|-------|
| `PUT coder-config` | 40ms | 150ms | Single DDB UpdateItem |
| `GET coder-config` | 20ms | 80ms | Single DDB GetItem |
| `POST validate` | 100ms | 500ms | May check repo URL accessibility (HTTP HEAD) |
| `GET eligible-tickets` | 80ms | 300ms | 2 GSI queries (dev + bugfix labels) + merge |
| `POST claim-ticket` | 30ms | 100ms | Single conditional UpdateItem |
| `GET coder-output` | 20ms | 80ms | Single DDB GetItem |
| `GET coder/metrics` | 100ms | 400ms | Query 30 daily rollup records |
| `POST test-workflow` | 50ms | 200ms | In-memory workflow generation, no I/O |

### 17.2 Caching Strategy

- **Coder config**: React Query `staleTime: 60_000`. Config rarely changes; invalidated on PUT.
- **Eligible tickets**: React Query `staleTime: 10_000`. Tickets claimed frequently; short stale window.
- **Metrics**: React Query `staleTime: 300_000`. Daily rollups; 5-minute cache acceptable.
- **Coder output**: React Query `staleTime: Infinity` once `escalated` or `pr_url` is set (output is final).

### 17.3 Workflow Execution Concerns

- **Terminal session isolation**: Each coder workflow runs in a dedicated terminal session (AGENT-002). No shared state between concurrent agent runs.
- **Git clone caching**: For repeated runs against the same repo, the agent can use `git fetch + reset` instead of fresh clone. Saves 10-30s per run.
- **Test output truncation**: Only last 200 lines of stdout and 100 lines of stderr are stored. Full output is available in the terminal session logs (AGENT-006) for 7 days.
- **Concurrent ticket claiming**: DDB conditional update ensures exactly one agent claims each ticket. Failed claims add ~30ms overhead; agents back off with jitter (1-5s).
- **Metrics rollup**: Daily snapshot computed by cron job (not real-time aggregation). Dashboard reads pre-computed records.

---

## 18. Expanded E2E Tests

### Section 655: Input Validation (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 655.1 | Empty repo URL rejected | PUT coder-config with `repo_url: ""` → 422 |
| 655.2 | Invalid repo URL rejected | PUT coder-config with `repo_url: "ftp://bad"` → 422 with "must start with https:// or git@" |
| 655.3 | Branch pattern without ticket_id rejected | PUT with `branch_pattern: "my-branch"` → 422 with "must include {ticket_id}" |
| 655.4 | Empty test_commands rejected | PUT with `test_commands: []` → 422 with "at least one test command" |
| 655.5 | test_timeout_seconds below 60 rejected | PUT with `test_timeout_seconds: 10` → 422 |

### Section 656: Authorization Boundary (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 656.1 | Non-admin cannot read coder config | Alice GET coder-config → 403 "Admin access required" |
| 656.2 | Non-admin cannot update coder config | Alice PUT coder-config → 403 |
| 656.3 | Non-admin cannot view eligible tickets | Alice GET eligible-tickets → 403 |
| 656.4 | CSRF required for config update | PUT coder-config without x-csrf-token → 403 |

### Section 657: Ticket Label Filtering (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 657.1 | Ticket without type:development label not eligible | Create ticket with labels `["area:backend"]` only; GET eligible-tickets; ticket not in list |
| 657.2 | Ticket with complexity above skill level not eligible | Junior agent; create ticket with `complexity:high`; GET eligible; not in list |
| 657.3 | Claimed ticket disappears from eligible list | Claim ticket; GET eligible; ticket no longer listed |
| 657.4 | Ticket in different space not eligible | Create ticket in space_B; agent configured for space_A; GET eligible; not in list |
| 657.5 | Bugfix label tickets also eligible | Create ticket with `type:bugfix`; GET eligible; ticket appears |

### Section 658: Workflow Edge Cases (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 658.1 | Test workflow for nonexistent ticket returns 404 | POST test-workflow with `ticket_id: "nonexistent"` → 404 |
| 658.2 | Claim already-claimed ticket returns 409 | Claim same ticket twice → second attempt returns 409 "already assigned" |
| 658.3 | Coder output for run without output returns 404 | GET coder-output for a run that has not completed → 404 "No coder output available" |
| 658.4 | Metrics endpoint returns zeros for new agent type | GET metrics for a type with no completed runs → `completed_count: 0`, `failure_rate: 0` |

---

## Codebase References

| Reference | File | Line(s) | Notes |
|-----------|------|---------|-------|
| TicketStore class | `app/services/tickets.py` | 110 | `create_ticket` (215), `get_ticket` (300), `assign_ticket` (577), `add_message` (621), `update_status` (683) |
| `require_admin_scope` | `app/auth/policy.py` | 84 | Correct admin auth (ticket originally said `require_admin_session` which does not exist) |
| `require_ui_session` | `app/services/sessions.py` | — | User auth dependency |
| `audit_event` | `app/services/alerts.py` | 695 | Signature: `(event, user_sub, request, **fields)` |
| Settings singleton | `app/core/settings.py` | 1-1494 | Frozen `Settings` dataclass; singleton `S` |
| Tables singleton | `app/core/tables.py` | — | `T` object; no `agent_types` or `agent_runs` table handles exist yet |
| `tickets` DDB table | `scripts/local-ddb-init.py` | 494-510 | Existing table — `labels` field extension proposed |
| `agent_types` DDB table | `scripts/local-ddb-init.py` | — | Does NOT exist yet — requires AGENT-001 |
| `agent_runs` DDB table | `scripts/local-ddb-init.py` | — | Does NOT exist yet — requires AGENT-001 |
| `agent_coder.py` | `app/services/` | — | Does NOT exist yet — new implementation in this ticket |
| `agent_coder.py` router | `app/routers/` | — | Does NOT exist yet — new implementation in this ticket |
| Router registration | `app/main.py` | 297-465 | No `agent_coder_router` registered yet |
| `now_ts` | `app/core/time.py` | — | Unix timestamp helper |

---

## Testing Strategy


### Unit Tests (pytest)


**Test file**: `tests/test_coder_agent.py`


**Mock setup**: moto for DynamoDB tables, `unittest.mock.patch` for external services (S3, Cognito, Stripe mock). All DDB tables created in-memory via moto `@mock_dynamodb` decorator.


| Test Function | Verifies |
|---|---|
| `test_create_coder_agent` | Creates record with correct fields and generated ID |
| `test_create_coder_agent_validation` | Rejects invalid input (missing required fields, out-of-range values) |
| `test_get_coder_agent_found` | Returns correct record by ID |
| `test_get_coder_agent_not_found` | Returns None for non-existent ID |
| `test_list_coder_agent` | Returns all records for the given scope/owner |
| `test_update_coder_agent` | Updates mutable fields and sets updated_at |
| `test_delete_coder_agent` | Removes record; subsequent get returns None |
| `test_coder_agent_owner_check` | Rejects operations from non-owner users |
| `test_coder_agent_admin_only` | Admin/root endpoints reject USER role with 403 |
| `test_coder_agent_concurrent_write` | Conditional update prevents stale overwrites |

### Integration Tests


Cross-service tests with real DDB (moto), verifying end-to-end flows:


1. Full CRUD lifecycle: create -> read -> update -> delete with real DDB (moto)
2. Authorization enforcement: non-owner access returns 403/404
3. Admin review/approval workflow with role-gated endpoints
4. Concurrent write safety: conditional updates prevent stale overwrites
5. Edge case: empty list returns `[]` not error; missing optional fields use defaults

### E2E Tests (Playwright)


**Test file**: `frontend/e2e/agent-coder.spec.ts`


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


**DDB seed data**: Uses existing tables; no new tables required. See DDB access patterns in technical design section.


### CI/Pipeline


- **Feature flags**: None required for dev/test
- **Execution**: E2E tests run serially (1 worker, Chromium only) per `playwright.config.ts`; pytest can run in parallel
- **Retry safety**: All tests are idempotent; unique `TS = Date.now()` suffixed identifiers prevent cross-run collisions
- **Prerequisite**: `just restart` to create DDB tables and seed E2E sessions before running

## Dependencies & Merge Safety


### Depends On


| Ticket | What's Needed | Status | Can Overlap? |
|--------|--------------|--------|-------------|
| AGENT-001 | LLM provider keys | Pending | No |
| AGENT-002 | Terminal worker provisioning | Pending | No |
| AGENT-003 | Worker agent framework | Pending | No |
| AGENT-004 | Fleet management UI | Pending | No |
| AGENT-005 | Memory & context injection | Pending | No |
| AGENT-006 | Terminal monitoring | Pending | No |

### Depended On By


| Ticket | What It Needs From This |
|--------|------------------------|
| AGENT-009 | Coder agent for code review |
| AGENT-012 | Coder agent for PM task delegation |

### Merge Strategy


**Sequential (after AGENT-006)**


- Must merge after: AGENT-001, AGENT-002, AGENT-003, AGENT-004, AGENT-005, AGENT-006
- Branch from `main` after dependencies are merged
- Can begin development in parallel but must rebase before merge
- DDB table creation is additive (no migration needed for new tables)

### Merge Checklist


- [ ] DDB tables verified (uses existing tables only)
- [ ] `.env.local` updated with any new environment variables
- [ ] Router registered in `app/main.py` (from `app/routers/agent_workers.py`)
- [ ] Frontend route(s) added to `App.tsx`: `/agents/coder`
- [ ] All E2E tests passing (`just e2e` or targeted spec file)
- [ ] No breaking changes to existing endpoints or UI components
- [ ] `just restart` succeeds with new table definitions
