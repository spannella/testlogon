# AGENT-009: QA Agent

**Ticket**: AGENT-009
**Author**: Engineering
**Status**: Implemented
**Date**: 2026-05-29
**Priority**: High
**Estimated effort**: 10-12 days
**Dependencies**: AGENT-001 (LLM Provider Key Management), AGENT-002 (Terminal Worker Provisioning), AGENT-003 (Worker Agent Framework & Lifecycle), AGENT-004 (Worker Fleet Management UI), AGENT-005 (Agent Memory & Context Injection), AGENT-006 (Terminal Monitoring & Feedback Loop), AGENT-008 (Coder Agent)

---

## 1. Overview & Motivation

### 1.1 Purpose

AGENT-009 defines the QA Agent type -- an agent configuration profile that plugs into the Worker Agent Framework (AGENT-003) to autonomously verify code changes produced by the Coder Agent (AGENT-008) or human developers. The QA Agent picks up tickets labeled `type:qa` or those in `code_complete` status, checks out the associated PR branch, reads the ticket acceptance criteria, runs the existing test suite, writes additional E2E tests for new features, performs browser-automated visual verification for UI changes, and renders a pass/fail verdict. When issues are found, the QA Agent files bug tickets with reproduction steps, screenshots, and expected-vs-actual comparisons, then marks the PR as "changes requested". When all checks pass, the agent approves the PR and transitions the ticket to `qa_approved`.

QA Agents are configurable with the test framework to use (Playwright, Cypress, pytest), browser targets, test file naming conventions, screenshot comparison thresholds, and regression suite scope. The configuration is stored on the `agent_types` table and applied by the Worker Agent Framework when spawning a QA Agent instance.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Platform Admin | As an admin, I want to register a QA Agent type with testing config. | Agent type created with test framework, browser, conventions; appears in registry. |
| Platform Admin | As an admin, I want the QA Agent to automatically test PRs when code is complete. | Agent picks up tickets in `code_complete` status; checks out PR branch. |
| Platform Admin | As an admin, I want the QA Agent to write new E2E tests. | Agent generates test file following project conventions; tests cover acceptance criteria. |
| Platform Admin | As an admin, I want screenshots captured for UI changes. | Screenshots saved to S3; linked in QA report. |
| Platform Admin | As an admin, I want regression testing on every PR. | Full or scoped test suite runs after new tests pass. |
| Coder Agent | As a Coder Agent, I want my PR reviewed automatically. | QA Agent picks up `code_complete` ticket linked to my PR. |
| Ticket Author | As a ticket author, I want to see the QA results on my ticket. | Ticket updated with QA report: pass/fail, test count, coverage, screenshots. |
| Ticket Author | As a ticket author, I want bugs filed automatically. | Bug ticket created with reproduction steps, screenshots, expected vs actual. |
| Developer | As a developer, I want PR feedback from the QA Agent. | PR review posted via `gh pr review` with approve/request-changes. |
| Project Manager | As a PM, I want to see QA Agent throughput and defect detection rate. | Dashboard shows tickets tested, pass rate, bugs found, avg time. |

### 1.3 Why This Is Needed

Manual QA is the most common bottleneck in the development pipeline. PRs sit for hours or days waiting for human review. QA agents cannot catch every issue, but they eliminate the most common failures: missing tests, broken existing tests, visual regressions, and unmet acceptance criteria. By filing structured bug tickets with screenshots and reproduction steps, QA Agents also reduce the back-and-forth between developers and testers. The automated pass/fail verdict accelerates the merge pipeline and gives the Project Manager Agent (AGENT-012) accurate velocity data.

---

## 2. Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          QA Agent System Architecture                       │
└─────────────────────────────────────────────────────────────────────────────┘

                          ┌──────────────────┐
                          │  Ticket System   │
                          │  (DynamoDB)      │
                          │                  │
                          │ status=code_     │
                          │ complete tickets │
                          └────────┬─────────┘
                                   │ poll / SSE event
                                   ▼
┌─────────────────┐     ┌──────────────────────┐     ┌──────────────────────┐
│ Worker Agent    │────▶│    QA Agent Core      │────▶│  Terminal Worker    │
│ Framework       │     │  (agent_qa.py)        │     │  (SSH session)     │
│ (AGENT-003)     │     │                       │     │                     │
│                 │     │ ┌───────────────────┐ │     │ ┌─────────────────┐ │
│ lifecycle mgmt  │     │ │ 1. claim_ticket   │ │     │ │ git checkout    │ │
│ polling loop    │     │ │ 2. checkout_pr    │ │     │ │ npm install     │ │
│ heartbeat       │     │ │ 3. gen_tests      │ │     │ │ run tests       │ │
│ status tracking │     │ │ 4. run_tests      │ │     │ │ capture screens │ │
│                 │     │ │ 5. evaluate       │ │     │ └─────────────────┘ │
└─────────────────┘     │ │ 6. file_bugs      │ │     └──────────┬─────────┘
                        │ │ 7. review_pr      │ │                │
                        │ │ 8. update_ticket  │ │                │ terminal output
                        │ └───────────────────┘ │                ▼
                        └──────────┬────────────┘     ┌──────────────────────┐
                                   │                  │ Terminal Monitoring   │
                    ┌──────────────┼──────────────┐   │ (AGENT-006)          │
                    │              │              │    │                      │
                    ▼              ▼              ▼    │ stdout/stderr capture│
          ┌─────────────┐ ┌──────────────┐ ┌────────┐│ escalation triggers  │
          │ S3           │ │ GitHub API   │ │ LLM    ││ flaky detection      │
          │              │ │              │ │ Client │└──────────────────────┘
          │ screenshots/ │ │ gh pr review │ │        │
          │ artifacts/   │ │ gh pr list   │ │ Claude │
          │ test-results/│ │ check status │ │ Code / │
          └─────────────┘ └──────────────┘ │ Codex  │
                                           │        │
                                           │ test   │
                                           │ gen    │
                                           └────────┘

  ┌──────────────────────────────────────────────────────────────────────┐
  │                         Data Flow Summary                            │
  │                                                                      │
  │  1. Worker Framework polls for code_complete tickets                  │
  │  2. QA Agent claims ticket (conditional update → qa_in_progress)     │
  │  3. Terminal Worker checks out PR branch, installs dependencies       │
  │  4. LLM Client generates E2E tests from acceptance criteria + diff   │
  │  5. Terminal runs new tests → captures screenshots on pass/fail       │
  │  6. Terminal runs regression suite (full or affected scope)           │
  │  7. Results parsed; verdict determined (pass/fail/flaky/error)        │
  │  8. Bug tickets filed for real failures (not flaky)                   │
  │  9. gh pr review --approve or --request-changes posted                │
  │ 10. Ticket status → qa_approved (pass) or in_progress (fail)         │
  │ 11. Screenshots + artifacts uploaded to S3                            │
  │ 12. QA report rendered and attached to ticket as comment              │
  └──────────────────────────────────────────────────────────────────────┘

  ┌──────────────────────────────────────────────────────────────────────┐
  │                      Agent Run State Machine                         │
  │                                                                      │
  │  ┌─────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐       │
  │  │ pending │───▶│ claiming │───▶│ checkout │───▶│ gen_test │       │
  │  └─────────┘    └──────────┘    └──────────┘    └──────────┘       │
  │                                                       │             │
  │       ┌───────────────────────────────────────────────┘             │
  │       ▼                                                             │
  │  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐     │
  │  │ run_new  │───▶│ run_regr │───▶│ evaluate │───▶│ file_bug │     │
  │  └──────────┘    └──────────┘    └──────────┘    └──────────┘     │
  │                                                       │             │
  │       ┌───────────────────────────────────────────────┘             │
  │       ▼                                                             │
  │  ┌──────────┐    ┌──────────┐                                      │
  │  │ review   │───▶│ complete │                                      │
  │  └──────────┘    └──────────┘                                      │
  │                                                                      │
  │  Any step can transition to: ┌─────────┐ on unrecoverable error     │
  │                               │  error  │                           │
  │                               └─────────┘                           │
  └──────────────────────────────────────────────────────────────────────┘
```

---

## 3. Current State Analysis

### 3.1 Existing Infrastructure

- **LLM Provider Key Management** (AGENT-001): API key storage for coding tools used to generate tests. QA Agent registers as `agent_type=qa`.
- **Terminal Worker Provisioning** (AGENT-002): SSH terminal for running tests. Must have Node.js, browsers, and test frameworks installed.
- **Worker Agent Framework & Lifecycle** (AGENT-003): Generic worker loop. QA Agent plugs in as a type-specific behavior module.
- **Worker Fleet Management UI** (AGENT-004): Fleet overview for QA agent instances.
- **Agent Memory & Context Injection** (AGENT-005): Injects test conventions and project patterns into test generation prompts.
- **Terminal Monitoring & Feedback Loop** (AGENT-006): Terminal output capture and escalation for ambiguous test results or flaky tests.
- **Coder Agent** (AGENT-008): Produces PRs and sets tickets to `code_complete` -- the QA Agent's trigger.
- **Ticket System** (`app/services/tickets.py`): `TicketStore` with status management. AGENT-008 adds `code_complete` status.
- **Playwright Config** (`frontend/playwright.config.ts`): Existing E2E test framework. Workers: 1, retries: 1, Chromium only. Tests in `frontend/e2e/`.
- **pytest** (`tests/`): Backend unit test framework with in-memory DynamoDB mock.
- **S3 / File Storage**: Existing S3 infrastructure for storing screenshots and test artifacts.

### 3.2 Gaps

1. No agent type configuration schema for QA Agent behavior (test framework, browser, conventions).
2. No automated PR checkout and test execution workflow for QA purposes.
3. No E2E test generation based on ticket acceptance criteria.
4. No screenshot capture and comparison pipeline within the agent framework.
5. No automated bug ticket filing with structured reproduction data.
6. No PR review automation (approve/request-changes via `gh pr review`).
7. No QA report format or structured output schema.
8. No regression detection logic (comparing test results before/after the PR).
9. No flaky test detection or retry-aware verdict logic.

---

## 4. Technical Design

### 4.1 Data Model

#### 4.1.1 AgentTypes Table Extension (QA Config)

Additional fields on the `agent_types` table when `agent_type = "qa"`:

| Field | Type | Description |
|-------|------|-------------|
| `qa_config` | M (map) | QA-specific configuration |
| `qa_config.test_framework` | S | `playwright`, `cypress`, or `pytest` (default `playwright`) |
| `qa_config.browser` | S | `chromium`, `firefox`, `webkit` (default `chromium`) |
| `qa_config.test_dir` | S | Directory containing test files (default `frontend/e2e/`) |
| `qa_config.test_file_pattern` | S | Naming convention for new test files (default `{feature}.spec.ts`) |
| `qa_config.test_run_command` | S | Command to run tests (default `cd frontend && npx playwright test`) |
| `qa_config.test_run_specific_command` | S | Command to run a specific test file (default `cd frontend && npx playwright test e2e/{file}`) |
| `qa_config.regression_scope` | S | `full`, `affected`, or `none` (default `affected`) |
| `qa_config.regression_command` | S | Command for full regression (default `just e2e`) |
| `qa_config.screenshot_enabled` | BOOL | Whether to capture screenshots (default true) |
| `qa_config.screenshot_on_failure` | BOOL | Capture screenshots only on failure (default false; true = also on pass for visual record) |
| `qa_config.screenshot_s3_prefix` | S | S3 prefix for screenshot storage (default `qa-screenshots/`) |
| `qa_config.visual_diff_threshold` | N | Pixel difference threshold for visual comparison (default 0.01 = 1%) |
| `qa_config.max_test_time_seconds` | N | Time budget for entire QA pass (default 1800 = 30 min) |
| `qa_config.flaky_retry_count` | N | Retries for suspected flaky failures (default 2) |
| `qa_config.bug_ticket_space_id` | S (optional) | Ticket space for auto-filed bugs |
| `qa_config.pr_review_enabled` | BOOL | Whether to post `gh pr review` (default true) |
| `qa_config.coding_tool` | S | Tool for writing tests: `claude_code` or `codex` (default `claude_code`) |
| `qa_config.coding_tool_model` | S (optional) | Model override for test generation |

#### 4.1.2 AgentRuns Table Extension (QA Output)

Additional fields on the `agent_runs` table for QA Agent runs:

| Field | Type | Description |
|-------|------|-------------|
| `qa_output` | M (map) | Structured output from the QA Agent run |
| `qa_output.verdict` | S | `pass`, `fail`, `flaky`, `error` |
| `qa_output.pr_url` | S | PR under test |
| `qa_output.pr_branch` | S | Branch checked out |
| `qa_output.ticket_id` | S | Source ticket |
| `qa_output.acceptance_criteria_count` | N | Number of acceptance criteria extracted |
| `qa_output.new_tests_written` | N | Number of new E2E tests generated |
| `qa_output.new_test_file` | S | Path of generated test file |
| `qa_output.new_tests_pass_count` | N | New tests that passed |
| `qa_output.new_tests_fail_count` | N | New tests that failed |
| `qa_output.regression_tests_run` | N | Existing tests executed |
| `qa_output.regression_tests_pass` | N | Existing tests that passed |
| `qa_output.regression_tests_fail` | N | Existing tests that failed |
| `qa_output.regression_failures` | L (list of S) | Names of failing regression tests |
| `qa_output.screenshots` | L (list of M) | `{name, s3_key, step, status}` |
| `qa_output.bug_ticket_ids` | L (list of S) | Ticket IDs of auto-filed bugs |
| `qa_output.pr_review_action` | S | `approved`, `changes_requested`, or `none` |
| `qa_output.total_duration_seconds` | N | Wall-clock time for QA pass |
| `qa_output.flaky_tests` | L (list of S) | Tests that failed then passed on retry |

#### 4.1.3 Bug Ticket Template

Auto-filed bug tickets use the existing ticket system with structured `metadata`:

| Metadata Field | Type | Description |
|-------|------|-------------|
| `bug_source` | S | `qa_agent` |
| `source_ticket_id` | S | Original development ticket |
| `source_pr_url` | S | PR that introduced the bug |
| `agent_run_id` | S | QA Agent run that found the bug |
| `reproduction_steps` | S | Markdown-formatted reproduction steps |
| `expected_behavior` | S | What was expected |
| `actual_behavior` | S | What actually happened |
| `test_output` | S | Relevant test output (truncated) |
| `screenshot_urls` | L (list of S) | S3 URLs for failure screenshots |
| `severity` | S | `critical`, `major`, `minor` (auto-classified) |

### 4.2 DynamoDB Access Patterns

| Access Pattern | Table | PK | SK | GSI | Notes |
|----------------|-------|----|----|-----|-------|
| Get QA config for agent type | `agent_types` | `ATYPE#{type_id}` | `CONFIG` | -- | qa_config map stored on the config item |
| List QA-eligible tickets (code_complete) | `tickets` | -- | -- | `GSI2PK=SPACE#{space_id}, GSI2SK=STATUS#code_complete` | Sorted by created_at ascending (oldest first) |
| List QA-eligible tickets (type:qa label) | `tickets` | -- | -- | `GSI3PK=LABEL#type:qa` | Scan label GSI for qa-labeled tickets |
| Claim ticket (conditional update) | `tickets` | `TICKET#{ticket_id}` | `META` | -- | ConditionExpression: `status = :code_complete AND attribute_not_exists(qa_agent_run_id)` |
| Store QA output on run | `agent_runs` | `RUN#{run_id}` | `META` | -- | UpdateExpression: SET qa_output = :output |
| List QA runs by verdict | `agent_runs` | -- | -- | `GSI1PK=AGENT_TYPE#{type_id}, GSI1SK=COMPLETED#{ts}` | Filter on qa_output.verdict |
| Get bug tickets for a QA run | `tickets` | -- | -- | `GSI4PK=SOURCE_RUN#{run_id}` | All bugs filed by a specific QA run |
| QA metrics aggregation | `agent_runs` | -- | -- | `GSI1PK=AGENT_TYPE#{type_id}` | Scan all completed runs, aggregate in-service |

**Example DynamoDB item -- QA config on agent_types table:**

```json
{
  "pk": {"S": "ATYPE#qa-agent-001"},
  "sk": {"S": "CONFIG"},
  "agent_type": {"S": "qa"},
  "display_name": {"S": "QA Agent (Playwright)"},
  "qa_config": {"M": {
    "test_framework": {"S": "playwright"},
    "browser": {"S": "chromium"},
    "test_dir": {"S": "frontend/e2e/"},
    "test_file_pattern": {"S": "{feature}.spec.ts"},
    "test_run_command": {"S": "cd frontend && npx playwright test"},
    "test_run_specific_command": {"S": "cd frontend && npx playwright test e2e/{file}"},
    "regression_scope": {"S": "affected"},
    "regression_command": {"S": "just e2e"},
    "screenshot_enabled": {"BOOL": true},
    "screenshot_on_failure": {"BOOL": false},
    "screenshot_s3_prefix": {"S": "qa-screenshots/"},
    "visual_diff_threshold": {"N": "0.01"},
    "max_test_time_seconds": {"N": "1800"},
    "flaky_retry_count": {"N": "2"},
    "pr_review_enabled": {"BOOL": true},
    "coding_tool": {"S": "claude_code"},
    "coding_tool_model": {"S": "claude-opus-4-6"}
  }},
  "created_at": {"N": "1748534400"},
  "updated_at": {"N": "1748534400"}
}
```

**Example DynamoDB item -- QA output on agent_runs table:**

```json
{
  "pk": {"S": "RUN#run-abc-123"},
  "sk": {"S": "META"},
  "agent_type_id": {"S": "qa-agent-001"},
  "status": {"S": "completed"},
  "qa_output": {"M": {
    "verdict": {"S": "fail"},
    "pr_url": {"S": "https://github.com/org/repo/pull/42"},
    "pr_branch": {"S": "feat/messaging-reactions"},
    "ticket_id": {"S": "TICKET-789"},
    "acceptance_criteria_count": {"N": "5"},
    "new_tests_written": {"N": "8"},
    "new_test_file": {"S": "frontend/e2e/messaging-reactions.spec.ts"},
    "new_tests_pass_count": {"N": "6"},
    "new_tests_fail_count": {"N": "2"},
    "regression_tests_run": {"N": "1070"},
    "regression_tests_pass": {"N": "1069"},
    "regression_tests_fail": {"N": "1"},
    "regression_failures": {"L": [{"S": "messaging-features > section 11 > tip flow"}]},
    "screenshots": {"L": [
      {"M": {"name": {"S": "reaction-bar-visible.png"}, "s3_key": {"S": "qa-screenshots/run-abc-123/reaction-bar-visible.png"}, "step": {"S": "run_new_tests"}, "status": {"S": "pass"}}},
      {"M": {"name": {"S": "tip-flow-failure.png"}, "s3_key": {"S": "qa-screenshots/run-abc-123/tip-flow-failure.png"}, "step": {"S": "run_regression"}, "status": {"S": "fail"}}}
    ]},
    "bug_ticket_ids": {"L": [{"S": "TICKET-790"}, {"S": "TICKET-791"}]},
    "pr_review_action": {"S": "changes_requested"},
    "total_duration_seconds": {"N": "847"},
    "flaky_tests": {"L": []}
  }},
  "started_at": {"N": "1748534400"},
  "completed_at": {"N": "1748535247"}
}
```

### 4.3 Backend Service (`app/services/agent_qa.py`)

```python
# --- Configuration ---
def get_qa_config(*, agent_type_id: str) -> dict:
    """Fetch and validate qa_config from agent_types table."""

def update_qa_config(*, agent_type_id: str, owner_sub: str, config: dict) -> dict:
    """Validate and update qa_config fields."""

def validate_qa_config(config: dict) -> list[str]:
    """Return validation errors. Checks: test_framework valid, test_dir exists in repo,
    run commands non-empty, thresholds in range."""

# --- Ticket & PR Resolution ---
def find_qa_eligible_tickets(*, agent_type_id: str, space_id: str | None = None,
                              limit: int = 10) -> list[dict]:
    """Query tickets with status=code_complete or labels containing type:qa.
    Returns oldest-first. Skips tickets already assigned to a QA agent."""

def resolve_pr_from_ticket(*, ticket: dict) -> dict | None:
    """Extract PR URL from ticket metadata (set by Coder Agent).
    Returns {pr_url, pr_branch, pr_number} or None."""

def claim_qa_ticket(*, agent_run_id: str, ticket_id: str, agent_sub: str) -> dict | None:
    """Atomically assign ticket to QA agent. Sets status to qa_in_progress."""

# --- Test Generation ---
def extract_acceptance_criteria(*, ticket: dict) -> list[str]:
    """Parse ticket description and metadata for acceptance criteria.
    Looks for markdown checklists, 'Acceptance Criteria' headers, numbered lists."""

def build_test_generation_prompt(*, ticket: dict, acceptance_criteria: list[str],
                                   pr_diff: str, test_framework: str,
                                   test_file_pattern: str, existing_test_files: list[str]) -> str:
    """Construct prompt for Claude Code / Codex to write E2E tests.
    Includes: acceptance criteria, PR diff summary, existing test patterns,
    project conventions (from CLAUDE.md), and output format."""

# --- Test Execution ---
def build_test_run_commands(*, test_file: str, test_run_specific_command: str,
                             regression_scope: str, regression_command: str,
                             affected_files: list[str]) -> list[str]:
    """Return ordered commands: (1) run new tests, (2) run regression suite.
    For 'affected' scope, derive test files from changed source files."""

def parse_test_results(*, stdout: str, stderr: str, framework: str) -> dict:
    """Parse test framework output to extract pass/fail counts, test names,
    durations. Handles Playwright JSON reporter and pytest output."""

def detect_flaky_tests(*, initial_failures: list[str], retry_results: dict) -> list[str]:
    """Compare initial failures with retry results. Tests that failed then
    passed are classified as flaky."""

# --- Screenshot Management ---
def capture_screenshot_commands(*, test_file: str, screenshot_enabled: bool) -> list[str]:
    """Return Playwright screenshot commands or configure screenshot-on-failure."""

def upload_screenshots_to_s3(*, screenshots_dir: str, s3_prefix: str,
                               agent_run_id: str) -> list[dict]:
    """Upload screenshot PNGs to S3. Return [{name, s3_key, url}]."""

# --- Bug Filing ---
def build_bug_ticket(*, source_ticket: dict, pr_url: str, agent_run_id: str,
                      failure: dict, screenshots: list[dict]) -> dict:
    """Construct bug ticket data from test failure. Includes reproduction steps
    derived from test code, expected/actual from assertion error, severity from
    failure type (crash=critical, assertion=major, timeout=minor)."""

def file_bug_tickets(*, bugs: list[dict], space_id: str | None,
                      agent_sub: str) -> list[str]:
    """Create tickets in the ticket system. Return list of ticket IDs.
    Labels: type:bugfix, source:qa_agent, complexity:low."""

# --- PR Review ---
def build_pr_review_command(*, pr_number: int, verdict: str, report: str) -> str:
    """Return `gh pr review {pr_number} --approve` or
    `gh pr review {pr_number} --request-changes --body {report}`.
    Report includes: test counts, failures, bug ticket links, screenshots."""

# --- Verdict & Reporting ---
def determine_verdict(*, new_tests_pass: int, new_tests_fail: int,
                       regression_fail: int, flaky_tests: list[str]) -> str:
    """Return 'pass' (all green), 'fail' (real failures), 'flaky' (only flaky failures),
    or 'error' (infrastructure failure)."""

def build_qa_report(*, verdict: str, output: dict) -> str:
    """Render Markdown QA report for ticket comment and PR review body.
    Sections: Summary, New Tests, Regression Results, Screenshots, Bug Tickets."""

# --- Status Updates ---
def mark_ticket_qa_approved(*, ticket_id: str, agent_sub: str, report: str) -> dict:
    """Update ticket status to qa_approved. Add QA report as ticket message."""

def mark_ticket_qa_failed(*, ticket_id: str, agent_sub: str, report: str,
                           bug_ticket_ids: list[str]) -> dict:
    """Revert ticket status to in_progress. Add failure report + bug links."""

# --- Workflow Orchestrator ---
def build_qa_workflow(*, agent_run_id: str, agent_type_id: str,
                       ticket: dict, pr_info: dict) -> list[dict]:
    """Return ordered workflow steps for the Worker Agent Framework:
    1. checkout_pr: git clone + checkout PR branch
    2. install_deps: npm install, pip install, etc.
    3. read_ticket: extract acceptance criteria
    4. read_pr_diff: git diff for context
    5. generate_tests: inject test-writing prompt into coding tool
    6. run_new_tests: execute generated tests
    7. retry_failures: re-run failed new tests (flaky detection)
    8. run_regression: execute regression suite (full or affected)
    9. capture_screenshots: collect screenshots from test runs
    10. upload_artifacts: push screenshots to S3
    11. evaluate_results: determine verdict
    12. file_bugs: create bug tickets for real failures
    13. review_pr: gh pr review with verdict
    14. update_ticket: mark qa_approved or revert to in_progress
    15. generate_report: assemble QA report
    Each step: {step_id, type, command_or_prompt, timeout_seconds, on_failure}."""
```

### 4.4 Backend Router (`app/routers/agent_qa.py`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| PUT | `/ui/agents/types/{type_id}/qa-config` | `require_admin_scope` | Set or update qa_config |
| GET | `/ui/agents/types/{type_id}/qa-config` | `require_admin_scope` | Get current qa_config |
| POST | `/ui/agents/types/{type_id}/qa-config/validate` | `require_admin_scope` | Validate config without saving |
| GET | `/ui/agents/types/{type_id}/qa-eligible-tickets` | `require_admin_scope` | Preview tickets this QA agent would pick up |
| GET | `/ui/agents/runs/{run_id}/qa-output` | `require_admin_scope` | Get structured QA output |
| GET | `/ui/agents/runs/{run_id}/qa-report` | `require_admin_scope` | Get rendered Markdown QA report |
| GET | `/ui/agents/runs/{run_id}/qa-screenshots` | `require_admin_scope` | List screenshots with presigned S3 URLs |
| POST | `/ui/agents/types/{type_id}/test-qa-workflow` | `require_admin_scope` | Dry-run: preview workflow steps for a ticket |
| GET | `/ui/agents/qa/metrics` | `require_admin_scope` | QA metrics: tested count, pass rate, bugs found, avg time |

<!-- NOTE: `require_admin_session` does not exist in the codebase. The correct admin auth dependency is `require_admin_scope(AdminScope.XXX)` from `app/auth/policy.py:84`. -->

### 4.5 API Request/Response Examples

```bash
# --- PUT /ui/agents/types/{type_id}/qa-config ---
curl -X PUT http://localhost:8000/ui/agents/types/qa-agent-001/qa-config \
  -H "Cookie: ui_session=sess_abc; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_tok_123" \
  -H "Content-Type: application/json" \
  -d '{
    "test_framework": "playwright",
    "browser": "chromium",
    "test_dir": "frontend/e2e/",
    "test_file_pattern": "{feature}.spec.ts",
    "test_run_command": "cd frontend && npx playwright test",
    "test_run_specific_command": "cd frontend && npx playwright test e2e/{file}",
    "regression_scope": "affected",
    "regression_command": "just e2e",
    "screenshot_enabled": true,
    "screenshot_on_failure": false,
    "screenshot_s3_prefix": "qa-screenshots/",
    "visual_diff_threshold": 0.01,
    "max_test_time_seconds": 1800,
    "flaky_retry_count": 2,
    "bug_ticket_space_id": "space-bugs-001",
    "pr_review_enabled": true,
    "coding_tool": "claude_code",
    "coding_tool_model": "claude-opus-4-6"
  }'

# Response 200:
{
  "type_id": "qa-agent-001",
  "qa_config": {
    "test_framework": "playwright",
    "browser": "chromium",
    "test_dir": "frontend/e2e/",
    "test_file_pattern": "{feature}.spec.ts",
    "test_run_command": "cd frontend && npx playwright test",
    "test_run_specific_command": "cd frontend && npx playwright test e2e/{file}",
    "regression_scope": "affected",
    "regression_command": "just e2e",
    "screenshot_enabled": true,
    "screenshot_on_failure": false,
    "screenshot_s3_prefix": "qa-screenshots/",
    "visual_diff_threshold": 0.01,
    "max_test_time_seconds": 1800,
    "flaky_retry_count": 2,
    "bug_ticket_space_id": "space-bugs-001",
    "pr_review_enabled": true,
    "coding_tool": "claude_code",
    "coding_tool_model": "claude-opus-4-6"
  },
  "updated_at": 1748534400
}

# --- GET /ui/agents/types/{type_id}/qa-eligible-tickets ---
curl http://localhost:8000/ui/agents/types/qa-agent-001/qa-eligible-tickets \
  -H "Cookie: ui_session=sess_abc; ui_access_token=eyJ..."

# Response 200:
{
  "tickets": [
    {
      "ticket_id": "TICKET-789",
      "subject": "Add emoji reactions to messages",
      "status": "code_complete",
      "pr_url": "https://github.com/org/repo/pull/42",
      "pr_branch": "feat/messaging-reactions",
      "created_at": 1748520000,
      "labels": ["type:feature", "domain:messaging"]
    },
    {
      "ticket_id": "TICKET-801",
      "subject": "Fix sidebar preview for locked messages",
      "status": "code_complete",
      "pr_url": "https://github.com/org/repo/pull/45",
      "pr_branch": "fix/sidebar-locked-preview",
      "created_at": 1748524000,
      "labels": ["type:bugfix"]
    }
  ],
  "count": 2
}

# --- GET /ui/agents/runs/{run_id}/qa-output ---
curl http://localhost:8000/ui/agents/runs/run-abc-123/qa-output \
  -H "Cookie: ui_session=sess_abc; ui_access_token=eyJ..."

# Response 200:
{
  "verdict": "fail",
  "pr_url": "https://github.com/org/repo/pull/42",
  "pr_branch": "feat/messaging-reactions",
  "ticket_id": "TICKET-789",
  "acceptance_criteria_count": 5,
  "new_tests_written": 8,
  "new_test_file": "frontend/e2e/messaging-reactions.spec.ts",
  "new_tests_pass_count": 6,
  "new_tests_fail_count": 2,
  "regression_tests_run": 1070,
  "regression_tests_pass": 1069,
  "regression_tests_fail": 1,
  "regression_failures": ["messaging-features > section 11 > tip flow"],
  "screenshots": [
    {"name": "reaction-bar-visible.png", "s3_key": "qa-screenshots/run-abc-123/reaction-bar-visible.png", "step": "run_new_tests", "status": "pass"},
    {"name": "tip-flow-failure.png", "s3_key": "qa-screenshots/run-abc-123/tip-flow-failure.png", "step": "run_regression", "status": "fail"}
  ],
  "bug_ticket_ids": ["TICKET-790", "TICKET-791"],
  "pr_review_action": "changes_requested",
  "total_duration_seconds": 847,
  "flaky_tests": []
}

# --- GET /ui/agents/runs/{run_id}/qa-screenshots ---
curl http://localhost:8000/ui/agents/runs/run-abc-123/qa-screenshots \
  -H "Cookie: ui_session=sess_abc; ui_access_token=eyJ..."

# Response 200:
{
  "screenshots": [
    {
      "name": "reaction-bar-visible.png",
      "presigned_url": "https://s3.amazonaws.com/bucket/qa-screenshots/run-abc-123/reaction-bar-visible.png?X-Amz-Signature=...",
      "step": "run_new_tests",
      "status": "pass"
    },
    {
      "name": "tip-flow-failure.png",
      "presigned_url": "https://s3.amazonaws.com/bucket/qa-screenshots/run-abc-123/tip-flow-failure.png?X-Amz-Signature=...",
      "step": "run_regression",
      "status": "fail"
    }
  ]
}

# --- POST /ui/agents/types/{type_id}/qa-config/validate ---
curl -X POST http://localhost:8000/ui/agents/types/qa-agent-001/qa-config/validate \
  -H "Cookie: ui_session=sess_abc; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_tok_123" \
  -H "Content-Type: application/json" \
  -d '{"test_framework": "invalid_framework", "visual_diff_threshold": 2.0}'

# Response 200 (validation result, not HTTP error):
{
  "valid": false,
  "errors": [
    "test_framework must be one of: playwright, cypress, pytest",
    "visual_diff_threshold must be between 0.0 and 1.0"
  ]
}

# --- GET /ui/agents/qa/metrics ---
curl http://localhost:8000/ui/agents/qa/metrics?period_days=30 \
  -H "Cookie: ui_session=sess_abc; ui_access_token=eyJ..."

# Response 200:
{
  "tested_count": 47,
  "pass_rate": 0.787,
  "bugs_found_count": 23,
  "avg_duration_seconds": 612,
  "flaky_test_rate": 0.042,
  "period_start": 1745942400,
  "period_end": 1748534400
}
```

### 4.6 Pydantic Models

```python
from pydantic import BaseModel, Field
from typing import Literal, Optional
from enum import Enum


class TestFramework(str, Enum):
    PLAYWRIGHT = "playwright"
    CYPRESS = "cypress"
    PYTEST = "pytest"


class BrowserTarget(str, Enum):
    CHROMIUM = "chromium"
    FIREFOX = "firefox"
    WEBKIT = "webkit"


class RegressionScope(str, Enum):
    FULL = "full"
    AFFECTED = "affected"
    NONE = "none"


class CodingTool(str, Enum):
    CLAUDE_CODE = "claude_code"
    CODEX = "codex"


class QaVerdict(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    FLAKY = "flaky"
    ERROR = "error"


class PrReviewAction(str, Enum):
    APPROVED = "approved"
    CHANGES_REQUESTED = "changes_requested"
    NONE = "none"


class BugSeverity(str, Enum):
    CRITICAL = "critical"
    MAJOR = "major"
    MINOR = "minor"


class QaConfigIn(BaseModel):
    test_framework: TestFramework = TestFramework.PLAYWRIGHT
    browser: BrowserTarget = BrowserTarget.CHROMIUM
    test_dir: str = Field(default="frontend/e2e/", max_length=200)
    test_file_pattern: str = Field(default="{feature}.spec.ts", max_length=200)
    test_run_command: str = Field(default="cd frontend && npx playwright test", max_length=500)
    test_run_specific_command: str = Field(
        default="cd frontend && npx playwright test e2e/{file}", max_length=500
    )
    regression_scope: RegressionScope = RegressionScope.AFFECTED
    regression_command: str = Field(default="just e2e", max_length=500)
    screenshot_enabled: bool = True
    screenshot_on_failure: bool = False
    screenshot_s3_prefix: str = Field(default="qa-screenshots/", max_length=200)
    visual_diff_threshold: float = Field(default=0.01, ge=0.0, le=1.0)
    max_test_time_seconds: int = Field(default=1800, ge=300, le=14400)
    flaky_retry_count: int = Field(default=2, ge=0, le=5)
    bug_ticket_space_id: Optional[str] = None
    pr_review_enabled: bool = True
    coding_tool: CodingTool = CodingTool.CLAUDE_CODE
    coding_tool_model: Optional[str] = Field(default=None, max_length=100)

    class Config:
        json_schema_extra = {
            "example": {
                "test_framework": "playwright",
                "browser": "chromium",
                "test_dir": "frontend/e2e/",
                "regression_scope": "affected",
                "screenshot_enabled": True,
                "visual_diff_threshold": 0.01,
                "max_test_time_seconds": 1800,
                "flaky_retry_count": 2,
                "pr_review_enabled": True,
                "coding_tool": "claude_code"
            }
        }


class QaConfigOut(BaseModel):
    type_id: str
    qa_config: QaConfigIn
    updated_at: int


class ScreenshotItem(BaseModel):
    name: str
    s3_key: str
    step: str
    status: Literal["pass", "fail"]


class QaOutputOut(BaseModel):
    verdict: QaVerdict
    pr_url: str
    pr_branch: str
    ticket_id: str
    acceptance_criteria_count: int = Field(ge=0)
    new_tests_written: int = Field(ge=0)
    new_test_file: str
    new_tests_pass_count: int = Field(ge=0)
    new_tests_fail_count: int = Field(ge=0)
    regression_tests_run: int = Field(ge=0)
    regression_tests_pass: int = Field(ge=0)
    regression_tests_fail: int = Field(ge=0)
    regression_failures: list[str] = Field(default_factory=list)
    screenshots: list[ScreenshotItem] = Field(default_factory=list)
    bug_ticket_ids: list[str] = Field(default_factory=list)
    pr_review_action: PrReviewAction
    total_duration_seconds: int = Field(ge=0)
    flaky_tests: list[str] = Field(default_factory=list)


class QaReportOut(BaseModel):
    run_id: str
    verdict: QaVerdict
    report_markdown: str
    generated_at: int


class QaScreenshotOut(BaseModel):
    name: str
    presigned_url: str
    step: str
    status: Literal["pass", "fail"]


class QaMetricsOut(BaseModel):
    tested_count: int = Field(ge=0)
    pass_rate: float = Field(ge=0.0, le=1.0)
    bugs_found_count: int = Field(ge=0)
    avg_duration_seconds: float = Field(ge=0.0)
    flaky_test_rate: float = Field(ge=0.0, le=1.0)
    period_start: int
    period_end: int


class QaEligibleTicketOut(BaseModel):
    ticket_id: str
    subject: str
    status: str
    pr_url: Optional[str] = None
    pr_branch: Optional[str] = None
    created_at: int
    labels: list[str] = Field(default_factory=list)


class QaEligibleTicketsResponse(BaseModel):
    tickets: list[QaEligibleTicketOut]
    count: int


class QaValidationResult(BaseModel):
    valid: bool
    errors: list[str] = Field(default_factory=list)


class BugTicketMetadata(BaseModel):
    bug_source: Literal["qa_agent"] = "qa_agent"
    source_ticket_id: str
    source_pr_url: str
    agent_run_id: str
    reproduction_steps: str
    expected_behavior: str
    actual_behavior: str
    test_output: str = Field(max_length=5000)
    screenshot_urls: list[str] = Field(default_factory=list)
    severity: BugSeverity
```

**Key request models**:

```python
class QaConfigIn(BaseModel):
    test_framework: Literal["playwright", "cypress", "pytest"] = "playwright"
    browser: Literal["chromium", "firefox", "webkit"] = "chromium"
    test_dir: str = Field(default="frontend/e2e/", max_length=200)
    test_file_pattern: str = Field(default="{feature}.spec.ts", max_length=200)
    test_run_command: str = Field(default="cd frontend && npx playwright test", max_length=500)
    test_run_specific_command: str = Field(default="cd frontend && npx playwright test e2e/{file}", max_length=500)
    regression_scope: Literal["full", "affected", "none"] = "affected"
    regression_command: str = Field(default="just e2e", max_length=500)
    screenshot_enabled: bool = True
    screenshot_on_failure: bool = False
    screenshot_s3_prefix: str = Field(default="qa-screenshots/", max_length=200)
    visual_diff_threshold: float = Field(default=0.01, ge=0.0, le=1.0)
    max_test_time_seconds: int = Field(default=1800, ge=300, le=14400)
    flaky_retry_count: int = Field(default=2, ge=0, le=5)
    bug_ticket_space_id: Optional[str] = None
    pr_review_enabled: bool = True
    coding_tool: Literal["claude_code", "codex"] = "claude_code"
    coding_tool_model: Optional[str] = Field(default=None, max_length=100)
```

Response models: `QaConfigOut`, `QaOutputOut` (full qa_output map), `QaReportOut` (rendered Markdown), `QaScreenshotOut` (name, presigned_url, step, status), `QaMetricsOut` (tested_count, pass_rate, bugs_found_count, avg_duration_seconds, flaky_test_rate).

Register in `app/main.py`:

```python
from app.routers.agent_qa import router as agent_qa_router
app.include_router(agent_qa_router, prefix="/ui")
```

### 4.7 Test Generation Strategy

The QA Agent generates tests by:

1. **Extracting acceptance criteria** from the ticket description. Patterns recognized: markdown checklists (`- [ ] ...`), numbered acceptance criteria sections, "Given/When/Then" blocks, and structured tables.
2. **Reading the PR diff** (`git diff origin/main...HEAD`) to understand which files changed and what new endpoints/components were added.
3. **Scanning existing tests** in the test directory to learn project conventions (import patterns, helper functions, assertion styles, test organization).
4. **Constructing a prompt** that includes the acceptance criteria, diff summary, existing test examples, and CLAUDE.md conventions. The prompt asks the coding tool to produce a test file following the `{test_file_pattern}` naming convention.
5. **Writing the test file** via Claude Code or Codex in the terminal.
6. **Running the new tests** and iterating if they fail due to test code issues (not application bugs).

### 4.8 Regression Scope Selection

- **`full`**: Run the entire test suite (`just e2e` + `just test`). Most thorough but slowest.
- **`affected`**: Derive affected test files from changed source files using import graph analysis. If `app/services/tickets.py` changed, run `frontend/e2e/tickets.spec.ts` and `tests/test_tickets.py`. Uses a heuristic mapping: `app/services/{x}.py` -> `tests/test_{x}.py` + `frontend/e2e/{x}.spec.ts`.
- **`none`**: Skip regression testing. Only useful for QA of isolated documentation or configuration changes.

### 4.9 Flaky Test Handling

Tests that fail on the first run are retried `flaky_retry_count` times. If a test fails on the first run but passes on retry, it is classified as "flaky" and excluded from the verdict. Flaky tests are listed in the QA report for human attention. If ALL failures are flaky, the verdict is `flaky` (treated as a soft pass -- PR is approved but flaky tests are flagged).

### 4.10 Frontend Types (`frontend/src/api/types.ts`)

```typescript
export interface QaConfig {
  test_framework: "playwright" | "cypress" | "pytest";
  browser: "chromium" | "firefox" | "webkit";
  test_dir: string;
  test_file_pattern: string;
  test_run_command: string;
  test_run_specific_command: string;
  regression_scope: "full" | "affected" | "none";
  regression_command: string;
  screenshot_enabled: boolean;
  screenshot_on_failure: boolean;
  screenshot_s3_prefix: string;
  visual_diff_threshold: number;
  max_test_time_seconds: number;
  flaky_retry_count: number;
  bug_ticket_space_id?: string;
  pr_review_enabled: boolean;
  coding_tool: "claude_code" | "codex";
  coding_tool_model?: string;
}

export interface QaOutput {
  verdict: "pass" | "fail" | "flaky" | "error";
  pr_url: string;
  pr_branch: string;
  ticket_id: string;
  acceptance_criteria_count: number;
  new_tests_written: number;
  new_test_file: string;
  new_tests_pass_count: number;
  new_tests_fail_count: number;
  regression_tests_run: number;
  regression_tests_pass: number;
  regression_tests_fail: number;
  regression_failures: string[];
  screenshots: Array<{ name: string; s3_key: string; step: string; status: string }>;
  bug_ticket_ids: string[];
  pr_review_action: "approved" | "changes_requested" | "none";
  total_duration_seconds: number;
  flaky_tests: string[];
}

export interface QaMetrics {
  tested_count: number;
  pass_rate: number;
  bugs_found_count: number;
  avg_duration_seconds: number;
  flaky_test_rate: number;
  period_start: number;
  period_end: number;
}

export interface QaScreenshot {
  name: string;
  presigned_url: string;
  step: string;
  status: "pass" | "fail";
}
```

### 4.11 Frontend API (`frontend/src/api/endpoints/agents.ts`)

Add QA Agent API functions: `getQaConfig`, `updateQaConfig`, `validateQaConfig`, `getQaEligibleTickets`, `getQaOutput`, `getQaReport`, `getQaScreenshots`, `testQaWorkflow`, `getQaMetrics`.

### 4.12 Frontend Component Tree

```
QaAgentConfigPage                    data-testid="qa-config-page"
├── Tabs                             shadcn Tabs component
│   ├── TabsList
│   │   ├── TabsTrigger "Config"
│   │   ├── TabsTrigger "Eligible Tickets"
│   │   └── TabsTrigger "Metrics"
│   │
│   ├── TabsContent "config"         data-testid="qa-config-tab"
│   │   ├── Card
│   │   │   ├── CardHeader "Test Framework Settings"
│   │   │   └── CardContent
│   │   │       ├── Select (test_framework)       "playwright" | "cypress" | "pytest"
│   │   │       ├── Select (browser)              "chromium" | "firefox" | "webkit"
│   │   │       ├── Input (test_dir)              string, default "frontend/e2e/"
│   │   │       ├── Input (test_file_pattern)     string, default "{feature}.spec.ts"
│   │   │       ├── Input (test_run_command)       monospace font
│   │   │       └── Input (test_run_specific_command) monospace font
│   │   │
│   │   ├── Card
│   │   │   ├── CardHeader "Regression Settings"
│   │   │   └── CardContent
│   │   │       ├── Select (regression_scope)     "full" | "affected" | "none"
│   │   │       └── Input (regression_command)    monospace font
│   │   │
│   │   ├── Card
│   │   │   ├── CardHeader "Screenshot Settings"
│   │   │   └── CardContent
│   │   │       ├── Switch (screenshot_enabled)
│   │   │       ├── Switch (screenshot_on_failure)
│   │   │       ├── Input (screenshot_s3_prefix)
│   │   │       └── Slider (visual_diff_threshold) 0.00 - 1.00, step 0.01
│   │   │
│   │   ├── Card
│   │   │   ├── CardHeader "Execution Settings"
│   │   │   └── CardContent
│   │   │       ├── Input (max_test_time_seconds)  type="number", min=300, max=14400
│   │   │       ├── Input (flaky_retry_count)      type="number", min=0, max=5
│   │   │       ├── Select (coding_tool)           "claude_code" | "codex"
│   │   │       └── Input (coding_tool_model)      optional override
│   │   │
│   │   ├── Card
│   │   │   ├── CardHeader "Integration Settings"
│   │   │   └── CardContent
│   │   │       ├── Switch (pr_review_enabled)
│   │   │       └── Select (bug_ticket_space_id)   ticket space dropdown
│   │   │
│   │   └── div.flex.gap-2
│   │       ├── Button "Validate"     onClick → POST validate; shows toast
│   │       └── Button "Save"         onClick → PUT qa-config; shows toast
│   │
│   ├── TabsContent "eligible"       data-testid="qa-eligible-tab"
│   │   ├── Alert "These tickets are ready for QA"
│   │   └── DataTable
│   │       ├── columns: [ticket_id, subject, status, pr_url, created_at, labels]
│   │       ├── sortable by created_at
│   │       └── pr_url renders as clickable link
│   │
│   └── TabsContent "metrics"        data-testid="qa-metrics-tab"
│       ├── div.grid.grid-cols-2.lg:grid-cols-4
│       │   ├── StatCard "Tickets Tested" → tested_count
│       │   ├── StatCard "Pass Rate" → pass_rate as %
│       │   ├── StatCard "Bugs Found" → bugs_found_count
│       │   └── StatCard "Avg Duration" → avg_duration_seconds formatted
│       │
│       ├── Card "Flaky Test Rate"
│       │   └── Progress bar (flaky_test_rate as %)
│       │
│       └── Select "Period" → 7d / 30d / 90d (re-fetches metrics)

QaRunOutputPanel                     data-testid="qa-output-panel"
├── div.flex.items-center.gap-2
│   ├── Badge (verdict)              green=pass, red=fail, yellow=flaky, gray=error
│   ├── span "PR: {pr_url}"         clickable link
│   └── span "Ticket: {ticket_id}"  clickable link
│
├── Card "Test Results"
│   ├── div.grid.grid-cols-2
│   │   ├── div "New Tests"
│   │   │   ├── span "{new_tests_pass_count} passed"
│   │   │   └── span "{new_tests_fail_count} failed"
│   │   └── div "Regression Tests"
│   │       ├── span "{regression_tests_pass} passed"
│   │       └── span "{regression_tests_fail} failed"
│   │
│   └── Collapsible "Regression Failures" (if any)
│       └── ul → regression_failures.map(f => <li>{f}</li>)
│
├── Card "Screenshots"               expandable gallery
│   └── div.grid.grid-cols-3
│       └── screenshots.map(s =>
│           ├── img (thumbnail, onClick → lightbox)
│           ├── Badge (s.status)
│           └── span (s.step)
│       )
│
├── Card "Bug Tickets Filed"          (if bug_ticket_ids.length > 0)
│   └── ul → bug_ticket_ids.map(id =>
│       <li><Link to={`/tickets/${id}`}>{id}</Link></li>
│   )
│
├── Card "Flaky Tests"                (if flaky_tests.length > 0)
│   └── ul → flaky_tests.map(t => <li>{t}</li>)
│
└── div.text-sm.text-muted
    ├── span "Duration: {total_duration_seconds}s"
    └── span "PR Review: {pr_review_action}"
```

**State management:**

```typescript
// React Query hooks used by QaAgentConfigPage
const { data: config } = useQuery({
  queryKey: ["qa-config", typeId],
  queryFn: () => getQaConfig(typeId),
});

const { data: eligible } = useQuery({
  queryKey: ["qa-eligible", typeId],
  queryFn: () => getQaEligibleTickets(typeId),
  enabled: activeTab === "eligible",
});

const { data: metrics } = useQuery({
  queryKey: ["qa-metrics", periodDays],
  queryFn: () => getQaMetrics(periodDays),
  enabled: activeTab === "metrics",
});

const updateMut = useMutation({
  mutationFn: (data: QaConfigIn) => updateQaConfig(typeId, data),
  onSuccess: () => {
    queryClient.invalidateQueries({ queryKey: ["qa-config", typeId] });
    toast({ title: "QA config saved" });
  },
});

const validateMut = useMutation({
  mutationFn: (data: QaConfigIn) => validateQaConfig(typeId, data),
  onSuccess: (result) => {
    if (result.valid) toast({ title: "Config is valid" });
    else toast({ title: "Validation errors", description: result.errors.join(", "), variant: "destructive" });
  },
});
```

### 4.13 Frontend Pages

- **QaAgentConfigPage** (`frontend/src/pages/agents/QaAgentConfigPage.tsx`): Route `/agents/types/:typeId/qa`. Tabbed layout: Config | Eligible Tickets | Metrics. `data-testid="qa-config-page"`.
  - **Config tab**: Test framework selector, browser selector, test directory input, file pattern input, run commands, regression scope selector, screenshot toggles, visual diff threshold slider, time budget, flaky retry count, bug ticket space selector, PR review toggle, coding tool selector. "Validate" and "Save" buttons. `data-testid="qa-config-tab"`.
  - **Eligible Tickets tab**: Table of `code_complete` and `type:qa` tickets with PR links. `data-testid="qa-eligible-tab"`.
  - **Metrics tab**: Pass rate gauge, bugs found counter, avg duration, flaky test rate. `data-testid="qa-metrics-tab"`.

- **QaRunOutputPanel** (`frontend/src/pages/agents/QaRunOutputPanel.tsx`): Embedded in Agent Run detail page. Shows: verdict badge, test counts (new + regression), failure list, screenshot gallery (thumbnails with lightbox), bug ticket links, PR review status, flaky test list. `data-testid="qa-output-panel"`.

---

## 5. Implementation Plan

### 5.1 Files to Create

| File | Purpose |
|------|---------|
| `app/services/agent_qa.py` | QA Agent configuration, test generation, execution, bug filing, verdict logic |
| `app/routers/agent_qa.py` | QA config CRUD, output, report, screenshots, metrics endpoints |
| `frontend/src/pages/agents/QaAgentConfigPage.tsx` | QA Agent configuration + metrics UI |
| `frontend/src/pages/agents/QaRunOutputPanel.tsx` | QA run output detail panel with screenshot gallery |

### 5.2 Files to Modify

| File | Changes |
|------|---------|
| `app/services/tickets.py` | Add `qa_in_progress` and `qa_approved` to `_TICKET_STATUSES` |
| `app/main.py` | Register `agent_qa_router` |
| `app/models.py` | Add `QaConfigIn`, `QaConfigOut`, `QaOutputOut`, `QaReportOut`, `QaScreenshotOut`, `QaMetricsOut` models |
| `frontend/src/api/types.ts` | Add `QaConfig`, `QaOutput`, `QaMetrics`, `QaScreenshot` types |
| `frontend/src/api/endpoints/agents.ts` | Add QA Agent API functions |
| `frontend/src/App.tsx` | Add `/agents/types/:typeId/qa` route |

---

## 6. E2E Test Plan

### 6.1 Test File

`frontend/e2e/agent-qa.spec.ts` -- 16 tests across 4 sections.

### 6.2 Test Setup

```typescript
const TS = Date.now();
let agentTypeId: string;
let ticketId: string;
let runId: string;
let bugTicketId: string;
// Root = admin who configures agents
```

### 6.3 Section 655: QA Config API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 655.1 | Create QA Agent type with config | POST agent type with `agent_type=qa`; PUT qa-config with framework, browser, commands; 200 |
| 655.2 | Get QA config | GET qa-config; 200; all fields match (test_framework=playwright, browser=chromium) |
| 655.3 | Validate config with invalid framework | POST validate with `test_framework="invalid"`; 422 or validation errors returned |
| 655.4 | Update regression scope and screenshot settings | PUT with `regression_scope=full`, `screenshot_on_failure=true`; 200; values updated |

### 6.4 Section 656: Ticket Filtering & Acceptance Criteria (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 656.1 | Create ticket with code_complete status | Create development ticket; update status to `code_complete` with PR URL in metadata |
| 656.2 | QA eligible tickets returns code_complete ticket | GET qa-eligible-tickets; array includes the ticket with PR URL |
| 656.3 | Ticket with type:qa label is eligible | Create ticket with `labels=["type:qa"]`; GET eligible; ticket included |
| 656.4 | Claim QA ticket updates status | POST claim; ticket status = `qa_in_progress` |

### 6.5 Section 657: QA Output & Bug Filing API (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 657.1 | Get QA output from completed run | GET qa-output; 200; `verdict`, `new_tests_written`, `regression_tests_run` present |
| 657.2 | QA report renders Markdown | GET qa-report; 200; body contains "## Summary" and "## Test Results" |
| 657.3 | Screenshots listed with presigned URLs | GET qa-screenshots; 200; array of `{name, presigned_url, step, status}` |
| 657.4 | Bug tickets were auto-filed | QA output `bug_ticket_ids` non-empty; GET each ticket; subject contains "Bug:" |
| 657.5 | Bug ticket has reproduction metadata | Bug ticket metadata contains `reproduction_steps`, `expected_behavior`, `actual_behavior` |

### 6.6 Section 658: QA Config UI (3 tests)

| # | Test | Assertion |
|---|------|-----------|
| 658.1 | QA config page loads | Navigate `/agents/types/{typeId}/qa`; `[data-testid="qa-config-page"]` visible |
| 658.2 | Config tab shows saved framework | Config tab active; test framework selector shows "playwright" |
| 658.3 | Metrics tab renders pass rate | Click "Metrics" tab; `[data-testid="qa-metrics-tab"]` visible; pass rate gauge present |

### 6.7 Expanded E2E Test Details

#### Additional Edge Case Tests (Section 659: 8 tests)

| # | Test | Assertion |
|---|------|-----------|
| 659.1 | Concurrent QA claim race condition | Two agents try to claim same ticket simultaneously; only one succeeds (conditional update); the other gets 409 |
| 659.2 | QA config with empty test_run_command | PUT with `test_run_command=""`; 422 validation error |
| 659.3 | QA run with all tests flaky | Simulate run where all failures are flaky; verdict = `flaky`; PR approved |
| 659.4 | QA run with infrastructure error | Simulate run where terminal crashes; verdict = `error`; ticket stays in qa_in_progress |
| 659.5 | Bug deduplication | File bug for ticket A; run QA again on same ticket; no duplicate bug filed |
| 659.6 | Screenshot upload with >50 screenshots | Only first 50 screenshots stored; rest discarded with warning in report |
| 659.7 | QA config with max_test_time_seconds below minimum | PUT with `max_test_time_seconds=100`; 422 "must be >= 300" |
| 659.8 | QA eligible tickets excludes already-claimed tickets | Claim ticket X; GET eligible; ticket X not in list |

#### Negative Test Cases (Section 660: 6 tests)

| # | Test | Assertion |
|---|------|-----------|
| 660.1 | Non-admin cannot access QA config | Alice (USER role) GETs qa-config; 403 |
| 660.2 | QA output for non-existent run | GET qa-output with fake run_id; 404 |
| 660.3 | QA config on non-QA agent type | PUT qa-config on agent_type=coder; 409 "Agent type is not configured as qa" |
| 660.4 | Claim ticket not in code_complete status | Try to claim ticket in `open` status; 409 |
| 660.5 | Visual diff threshold out of range | PUT with `visual_diff_threshold=5.0`; 422 |
| 660.6 | QA screenshots for run with no screenshots | GET qa-screenshots; 200; empty array |

#### Concurrent Access Tests (Section 661: 4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 661.1 | Parallel QA config updates | Two admins update config simultaneously; last write wins; no data corruption |
| 661.2 | QA run completes while admin views output | Output panel refreshes; shows final verdict after completion |
| 661.3 | Ticket status changes during QA run | External status change to `closed` while QA in progress; QA agent detects and aborts gracefully |
| 661.4 | Multiple QA agents polling same ticket pool | Five agents poll; each claims different ticket; no ticket claimed twice |

---

## 7. Error Handling

### 7.1 Error Table

| Scenario | Status | Detail |
|----------|--------|--------|
| Agent type not found | 404 | "Agent type not found" |
| Agent type is not QA | 409 | "Agent type is not configured as qa" |
| Invalid test framework | 422 | "Test framework must be playwright, cypress, or pytest" |
| Invalid browser | 422 | "Browser must be chromium, firefox, or webkit" |
| PR URL not found in ticket metadata | 404 | "No PR URL found on this ticket" |
| Ticket not in code_complete status | 409 | "Ticket must be in code_complete status for QA" |
| Screenshot upload failed | 500 | "Failed to upload screenshot to S3" |
| Test generation timeout | 504 | "Test generation did not complete within time budget" |
| All tests errored (infra issue) | 200 | Verdict = `error`; escalation triggered |
| Run not found | 404 | "Agent run not found" |
| Not admin | 403 | "Admin access required" |

### 7.2 Error Handling Matrix

| Error Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|----------------|-------------|------------|---------------------|-----------------|
| Agent type not in DDB | 404 | `AGENT_TYPE_NOT_FOUND` | "The specified agent type does not exist." | Verify type_id is correct; check agent registry |
| qa_config missing on agent type | 404 | `QA_CONFIG_NOT_FOUND` | "No QA configuration found for this agent type." | PUT qa-config to create initial configuration |
| Agent type is not qa | 409 | `AGENT_TYPE_MISMATCH` | "This agent type is not configured as a QA agent." | Use PUT on a type with agent_type=qa |
| Invalid test_framework value | 422 | `INVALID_TEST_FRAMEWORK` | "Test framework must be playwright, cypress, or pytest." | Correct the value and retry |
| Invalid browser value | 422 | `INVALID_BROWSER` | "Browser must be chromium, firefox, or webkit." | Correct the value and retry |
| test_run_command empty | 422 | `EMPTY_RUN_COMMAND` | "Test run command cannot be empty." | Provide a valid shell command |
| visual_diff_threshold out of range | 422 | `THRESHOLD_OUT_OF_RANGE` | "Visual diff threshold must be between 0.0 and 1.0." | Use a value like 0.01 (1%) |
| max_test_time below 300s | 422 | `TIME_BUDGET_TOO_LOW` | "Test time budget must be at least 300 seconds." | Increase to >= 300 |
| flaky_retry_count > 5 | 422 | `RETRY_COUNT_TOO_HIGH` | "Flaky retry count cannot exceed 5." | Use a value between 0 and 5 |
| No PR URL on ticket | 404 | `PR_NOT_FOUND` | "No PR URL found in ticket metadata." | Ensure Coder Agent set pr_url on the ticket |
| Ticket not code_complete | 409 | `INVALID_TICKET_STATUS` | "Ticket must be in code_complete status." | Wait for Coder Agent to complete |
| Ticket already claimed | 409 | `TICKET_ALREADY_CLAIMED` | "This ticket is already being tested by another QA agent." | Pick a different ticket |
| Terminal not available | 503 | `TERMINAL_UNAVAILABLE` | "No terminal worker available for QA execution." | Wait for worker provisioning; check fleet status |
| Git checkout failed | 500 | `CHECKOUT_FAILED` | "Failed to check out PR branch." | Verify branch exists; check git credentials |
| npm install failed | 500 | `DEPS_INSTALL_FAILED` | "Dependency installation failed." | Check package.json; review install logs |
| Test generation LLM error | 502 | `LLM_GENERATION_ERROR` | "Test generation failed due to LLM provider error." | Check API key; retry after cooldown |
| Test generation timeout | 504 | `TEST_GEN_TIMEOUT` | "Test generation exceeded time budget." | Increase max_test_time_seconds or simplify acceptance criteria |
| Test execution timeout | 504 | `TEST_EXEC_TIMEOUT` | "Test execution exceeded time budget." | Increase max_test_time_seconds or reduce regression scope |
| S3 upload failed | 500 | `S3_UPLOAD_FAILED` | "Failed to upload screenshots to S3." | Check S3 credentials and bucket permissions |
| gh pr review failed | 502 | `PR_REVIEW_FAILED` | "Failed to post PR review on GitHub." | Check GitHub token permissions |
| Bug ticket creation failed | 500 | `BUG_FILING_FAILED` | "Failed to create bug ticket." | Check ticket system availability; verify space_id |
| Run not found | 404 | `RUN_NOT_FOUND` | "The specified agent run does not exist." | Verify run_id is correct |
| Not admin | 403 | `ADMIN_REQUIRED` | "Admin access is required for this operation." | Log in as admin or root |
| Infrastructure error (all tests crash) | 200 | (verdict=error) | "All tests failed due to infrastructure error." | Check terminal health; restart worker |

---

## 8. Observability & Monitoring

### 8.1 Metrics to Track

| Metric Name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `qa_agent_runs_total` | Counter | `verdict={pass,fail,flaky,error}` | Total QA runs by verdict |
| `qa_agent_run_duration_seconds` | Histogram | `agent_type_id` | Wall-clock time per QA run |
| `qa_agent_tests_generated_total` | Counter | `agent_type_id` | New E2E tests written |
| `qa_agent_tests_executed_total` | Counter | `type={new,regression}`, `result={pass,fail}` | Tests run by type and result |
| `qa_agent_bugs_filed_total` | Counter | `severity={critical,major,minor}` | Bug tickets auto-filed |
| `qa_agent_pr_reviews_total` | Counter | `action={approved,changes_requested,none}` | PR review actions posted |
| `qa_agent_flaky_tests_detected_total` | Counter | `agent_type_id` | Flaky tests caught |
| `qa_agent_screenshots_uploaded_total` | Counter | `status={pass,fail}` | Screenshots stored |
| `qa_agent_ticket_claim_conflicts_total` | Counter | -- | Concurrent claim failures |
| `qa_agent_llm_tokens_used_total` | Counter | `model` | LLM tokens consumed for test generation |
| `qa_agent_s3_upload_bytes_total` | Counter | -- | Total bytes uploaded to S3 |
| `qa_agent_eligible_tickets_gauge` | Gauge | -- | Current count of eligible tickets |

### 8.2 Log Events

| Event | Level | Fields | When |
|-------|-------|--------|------|
| `qa_run_started` | INFO | run_id, ticket_id, pr_url, agent_type_id | QA run begins |
| `qa_ticket_claimed` | INFO | run_id, ticket_id | Ticket claimed successfully |
| `qa_ticket_claim_conflict` | WARN | run_id, ticket_id | Concurrent claim failed |
| `qa_pr_checkout` | INFO | run_id, pr_branch, commit_sha | PR branch checked out |
| `qa_tests_generated` | INFO | run_id, test_count, test_file | New tests written |
| `qa_test_gen_failed` | ERROR | run_id, error | Test generation LLM error |
| `qa_new_tests_result` | INFO | run_id, pass_count, fail_count | New test results |
| `qa_regression_result` | INFO | run_id, pass_count, fail_count, failures | Regression results |
| `qa_flaky_detected` | WARN | run_id, test_names | Flaky tests found |
| `qa_screenshots_uploaded` | INFO | run_id, count, total_bytes | Screenshots pushed to S3 |
| `qa_bug_filed` | INFO | run_id, bug_ticket_id, severity | Bug ticket created |
| `qa_pr_reviewed` | INFO | run_id, pr_number, action | PR review posted |
| `qa_verdict` | INFO | run_id, verdict, duration_seconds | Final verdict |
| `qa_run_error` | ERROR | run_id, step, error | Infrastructure error during run |

### 8.3 Alert Thresholds

| Alert | Condition | Severity | Channel |
|-------|-----------|----------|---------|
| QA pass rate drop | pass_rate < 50% over 24h (rolling) | P2 | Slack #agents |
| QA run backlog | eligible_tickets_gauge > 20 | P3 | Slack #agents |
| QA run failure spike | > 5 verdict=error runs in 1h | P1 | PagerDuty |
| Flaky test rate high | flaky_test_rate > 15% over 7d | P3 | Slack #qa |
| QA run duration anomaly | p95 duration > 2x avg over 7d | P3 | Slack #agents |
| S3 upload failures | s3_upload_failed > 3 in 1h | P2 | Slack #infra |
| LLM token budget exceeded | daily tokens > budget threshold | P3 | Slack #agents |

### 8.4 Dashboard Queries (Prometheus/Grafana)

```promql
# QA pass rate (last 24h)
sum(rate(qa_agent_runs_total{verdict="pass"}[24h]))
/ sum(rate(qa_agent_runs_total[24h]))

# Average QA run duration
histogram_quantile(0.50, rate(qa_agent_run_duration_seconds_bucket[24h]))

# Bug filing rate
sum(rate(qa_agent_bugs_filed_total[24h])) by (severity)

# Flaky test rate
sum(rate(qa_agent_flaky_tests_detected_total[7d]))
/ sum(rate(qa_agent_tests_executed_total{type="regression"}[7d]))

# QA throughput (runs per hour)
sum(rate(qa_agent_runs_total[1h])) * 3600
```

---

## 9. Rollout Plan

### 9.1 Feature Flags

| Flag | Default | Description |
|------|---------|-------------|
| `QA_AGENT_ENABLED` | `false` | Master kill switch for QA Agent type registration |
| `QA_AGENT_TEST_GEN_ENABLED` | `true` | Enable LLM-based test generation (disable for dry-run mode) |
| `QA_AGENT_PR_REVIEW_ENABLED` | `false` | Enable automated PR reviews (start disabled, enable after confidence) |
| `QA_AGENT_BUG_FILING_ENABLED` | `false` | Enable automatic bug ticket creation (start disabled) |
| `QA_AGENT_REGRESSION_ENABLED` | `true` | Enable regression suite execution |
| `QA_AGENT_VISUAL_DIFF_ENABLED` | `false` | Enable pixel-level visual comparison (experimental) |

### 9.2 Migration Steps

1. **Schema migration**: No new DynamoDB tables required. The `qa_config` and `qa_output` maps are added to existing `agent_types` and `agent_runs` tables respectively. Add `qa_in_progress` and `qa_approved` to the ticket status enum.
2. **Ticket status backfill**: No backfill needed. New statuses only apply to future tickets.
3. **S3 bucket configuration**: Create `qa-screenshots/` prefix with lifecycle policy (90-day expiry). Configure CORS for presigned URL access from frontend.
4. **Agent type seed**: After deployment, admin creates the first QA Agent type via the UI or API.

### 9.3 Canary Deployment

1. **Week 1 (shadow mode)**: Deploy with `QA_AGENT_ENABLED=true`, `QA_AGENT_PR_REVIEW_ENABLED=false`, `QA_AGENT_BUG_FILING_ENABLED=false`. QA Agent runs tests and generates reports but does NOT post PR reviews or file bugs. Reports are visible only in the admin UI.
2. **Week 2 (limited PR review)**: Enable `QA_AGENT_PR_REVIEW_ENABLED=true` for a single agent type. Monitor false positive rate. Target: < 5% false approvals, < 10% false rejections.
3. **Week 3 (bug filing)**: Enable `QA_AGENT_BUG_FILING_ENABLED=true`. Monitor duplicate bug rate and severity accuracy.
4. **Week 4 (full rollout)**: Enable all flags. Monitor QA throughput and human override rate.

### 9.4 Rollback Procedure

1. **Immediate**: Set `QA_AGENT_ENABLED=false`. All QA agent instances stop picking up new tickets. In-progress runs complete but no new runs start.
2. **PR review rollback**: Set `QA_AGENT_PR_REVIEW_ENABLED=false`. Existing PR reviews remain but no new ones are posted.
3. **Bug filing rollback**: Set `QA_AGENT_BUG_FILING_ENABLED=false`. Already-filed bugs remain open for human triage.
4. **Data cleanup**: No data deletion needed. QA output on agent_runs and bug tickets can be archived.
5. **Ticket status reset**: Any tickets stuck in `qa_in_progress` can be manually reset to `code_complete` via admin API.

---

## 10. Security Considerations

- **Admin-only access**: All QA Agent configuration endpoints require `require_admin_scope()` (see `app/auth/policy.py:84`). <!-- NOTE: was `require_admin_session` which does not exist -->
- **Screenshot access control**: Presigned S3 URLs expire after 15 minutes. Screenshots are stored in a separate S3 prefix not accessible via the public file manager.
- **Test code injection prevention**: Generated test files are written to a sandboxed directory within the checked-out repo. The coding tool prompt explicitly instructs against modifying production source code.
- **Bug ticket attribution**: Auto-filed bugs have `metadata.bug_source = "qa_agent"` for auditability. The `agent_run_id` links back to the full QA run record.
- **PR review authentication**: `gh pr review` uses the agent's GitHub token from AGENT-006 secrets vault. Token permissions are scoped to the minimum required (repo read + PR review write).
- **Regression test isolation**: QA Agent runs in an isolated terminal instance. Test database is separate from production. No real user data is accessed.
- **Flaky test tracking**: Flaky test classifications are logged to prevent repeated false-positive bug filings for known flaky tests.

---

## 11. Performance Considerations

### 11.1 Query Cost Analysis

| Operation | Read/Write | Cost Estimate | Notes |
|-----------|-----------|---------------|-------|
| Get QA config | 1 RCU | Minimal | Single item read, eventually consistent |
| List eligible tickets (GSI scan) | 5-20 RCU | Moderate | Depends on ticket volume; filtered scan |
| Claim ticket (conditional write) | 5 WCU | Low | Single conditional update |
| Store QA output | 10-50 WCU | Moderate | Large map attribute; depends on screenshot count |
| Aggregate metrics | 50-200 RCU | High | Scans all completed runs for type; cache result |
| File bug ticket | 5 WCU per bug | Low | Typically 0-3 bugs per run |

### 11.2 Caching Strategy

| Data | TTL | Invalidation | Storage |
|------|-----|-------------|---------|
| QA config | 5 min | On PUT update | In-memory (service layer) |
| Eligible tickets list | 30 sec | On ticket status change | React Query |
| QA metrics | 5 min | On run completion | In-memory + React Query |
| Screenshot presigned URLs | 15 min | Regenerate on access | None (always fresh) |
| Regression test mapping (source -> test file) | 1 hour | On repo change | In-memory |

### 11.3 Pagination Limits

| Endpoint | Default Limit | Max Limit | Cursor |
|----------|--------------|-----------|--------|
| Eligible tickets | 10 | 50 | `last_evaluated_key` |
| QA screenshots | 50 (max stored) | 50 | None |
| QA metrics | N/A (aggregate) | N/A | N/A |
| Bug tickets for run | 20 | 100 | `last_evaluated_key` |

### 11.4 Rate Limiting

| Operation | Limit | Window | Scope |
|-----------|-------|--------|-------|
| QA config updates | 10 | 1 min | Per admin user |
| QA config validates | 30 | 1 min | Per admin user |
| QA eligible ticket queries | 60 | 1 min | Per admin user |
| QA workflow dry-run | 5 | 1 min | Per agent type |
| QA metric aggregation | 10 | 1 min | Global |

### 11.5 Performance Constraints

| Concern | Mitigation |
|---------|-----------|
| Full regression suite takes 30+ minutes | Default to `affected` scope; `full` only on explicit config |
| Screenshot uploads for large test suites | Batch upload; compress PNGs; cap at 50 screenshots per run |
| Test generation prompt size | PR diff truncated to 5000 lines; acceptance criteria capped at 20 items |
| Concurrent QA runs competing for tickets | Conditional update on ticket claim; staggered polling |
| S3 storage growth from screenshots | Lifecycle policy: delete screenshots older than 90 days |
| Bug ticket deduplication | Before filing, check existing open bugs with same `source_ticket_id` |
| Metrics aggregation on large run tables | Pre-compute daily aggregates; cache 5-min TTL |

---

## 12. Dependencies

| Dependency | Ticket | Status |
|------------|--------|--------|
| AGENT-001 (LLM Provider Key Management) | AGENT-001 | Required |
| AGENT-002 (Terminal Worker Provisioning) | AGENT-002 | Required |
| AGENT-003 (Worker Agent Framework & Lifecycle) | AGENT-003 | Required |
| AGENT-004 (Worker Fleet Management UI) | AGENT-004 | Required |
| AGENT-005 (Agent Memory & Context Injection) | AGENT-005 | Required |
| AGENT-006 (Terminal Monitoring & Feedback Loop) | AGENT-006 | Required (terminal output capture, escalation) |
| AGENT-008 (Coder Agent) | AGENT-008 | Required (produces code_complete tickets) |

### Downstream

| Ticket | Depends On |
|--------|-----------|
| AGENT-012 (Project Manager) | Uses QA pass rate and defect data for project reporting |

---

## Codebase References

| Reference | File | Line(s) | Notes |
|-----------|------|---------|-------|
| TicketStore class | `app/services/tickets.py` | 110 | `create_ticket` (215), `assign_ticket` (577), `add_message` (621), `update_status` (683) |
| `require_admin_scope` | `app/auth/policy.py` | 84 | Correct admin auth (ticket originally said `require_admin_session` which does not exist) |
| `require_ui_session` | `app/services/sessions.py` | — | User auth dependency |
| `audit_event` | `app/services/alerts.py` | 695 | Signature: `(event, user_sub, request, **fields)` |
| Settings singleton | `app/core/settings.py` | 1-1494 | Frozen `Settings` dataclass; singleton `S` |
| Tables singleton | `app/core/tables.py` | — | `T` object |
| Router registration | `app/main.py` | 297-465 | No `agent_qa_router` registered yet |
| `tickets` DDB table | `scripts/local-ddb-init.py` | 494-510 | Existing; ticket proposes extending with QA statuses |
| `agent_types` DDB table | `scripts/local-ddb-init.py` | — | Does NOT exist yet — requires AGENT-001 |
| `agent_runs` DDB table | `scripts/local-ddb-init.py` | — | Does NOT exist yet — requires AGENT-001 |
| `agent_qa.py` service | `app/services/` | — | Does NOT exist yet — new implementation in this ticket |
| `agent_qa.py` router | `app/routers/` | — | Does NOT exist yet — new implementation in this ticket |
| `now_ts` | `app/core/time.py` | — | Unix timestamp helper |

---

## Testing Strategy


### Unit Tests (pytest)


**Test file**: `tests/test_qa_agent.py`


**Mock setup**: moto for DynamoDB tables, `unittest.mock.patch` for external services (S3, Cognito, Stripe mock). All DDB tables created in-memory via moto `@mock_dynamodb` decorator.


| Test Function | Verifies |
|---|---|
| `test_create_qa_agent` | Creates record with correct fields and generated ID |
| `test_create_qa_agent_validation` | Rejects invalid input (missing required fields, out-of-range values) |
| `test_get_qa_agent_found` | Returns correct record by ID |
| `test_get_qa_agent_not_found` | Returns None for non-existent ID |
| `test_list_qa_agent` | Returns all records for the given scope/owner |
| `test_update_qa_agent` | Updates mutable fields and sets updated_at |
| `test_delete_qa_agent` | Removes record; subsequent get returns None |
| `test_qa_agent_owner_check` | Rejects operations from non-owner users |
| `test_qa_agent_admin_only` | Admin/root endpoints reject USER role with 403 |
| `test_qa_agent_concurrent_write` | Conditional update prevents stale overwrites |

### Integration Tests


Cross-service tests with real DDB (moto), verifying end-to-end flows:


1. Full CRUD lifecycle: create -> read -> update -> delete with real DDB (moto)
2. Authorization enforcement: non-owner access returns 403/404
3. Admin review/approval workflow with role-gated endpoints
4. Concurrent write safety: conditional updates prevent stale overwrites
5. Edge case: empty list returns `[]` not error; missing optional fields use defaults

### E2E Tests (Playwright)


**Test file**: `frontend/e2e/agent-qa.spec.ts`


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
| AGENT-002 | Terminal provisioning | Pending | No |
| AGENT-003 | Agent framework | Pending | No |
| AGENT-004 | Fleet UI | Pending | No |
| AGENT-005 | Context injection | Pending | No |
| AGENT-006 | Monitoring | Pending | No |
| AGENT-008 | Coder agent (code review) | Pending | No |

### Depended On By


| Ticket | What It Needs From This |
|--------|------------------------|
| AGENT-012 | QA agent for test verification |

### Merge Strategy


**Sequential (after AGENT-008)**


- Must merge after: AGENT-001, AGENT-002, AGENT-003, AGENT-004, AGENT-005, AGENT-006, AGENT-008
- Branch from `main` after dependencies are merged
- Can begin development in parallel but must rebase before merge
- DDB table creation is additive (no migration needed for new tables)

### Merge Checklist


- [ ] DDB tables verified (uses existing tables only)
- [ ] `.env.local` updated with any new environment variables
- [ ] Router registered in `app/main.py` (from `app/routers/agent_workers.py`)
- [ ] Frontend route(s) added to `App.tsx`: `/agents/qa`
- [ ] All E2E tests passing (`just e2e` or targeted spec file)
- [ ] No breaking changes to existing endpoints or UI components
- [ ] `just restart` succeeds with new table definitions
