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
| GET | `/ui/agents/types/coder/config-schema` | `require_admin_session` | Return JSON schema for coder_config fields |
| PUT | `/ui/agents/types/{type_id}/coder-config` | `require_admin_session` | Set or update coder_config |
| GET | `/ui/agents/types/{type_id}/coder-config` | `require_admin_session` | Get current coder_config |
| POST | `/ui/agents/types/{type_id}/coder-config/validate` | `require_admin_session` | Validate config without saving (test repo access, etc.) |
| GET | `/ui/agents/types/{type_id}/eligible-tickets` | `require_admin_session` | Preview which tickets this agent would pick up |
| POST | `/ui/agents/runs/{run_id}/claim-ticket` | `require_admin_session` | Manually trigger ticket claim for a specific run |
| GET | `/ui/agents/runs/{run_id}/coder-output` | `require_admin_session` | Get structured output from a completed coder run |
| POST | `/ui/agents/types/{type_id}/test-workflow` | `require_admin_session` | Dry-run: generate workflow steps for a given ticket without executing |
| GET | `/ui/agents/coder/metrics` | `require_admin_session` | Aggregate metrics: tickets completed, avg time, failure rate |

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

- **Admin-only access**: All Coder Agent configuration endpoints require `require_admin_session`. Regular users cannot configure or trigger agents.
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
