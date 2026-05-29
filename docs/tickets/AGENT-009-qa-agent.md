# AGENT-009: QA Agent

**Ticket**: AGENT-009
**Author**: Engineering
**Status**: Design
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

## 2. Current State Analysis

### 2.1 Existing Infrastructure

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

### 2.2 Gaps

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

## 3. Technical Design

### 3.1 Data Model

#### 3.1.1 AgentTypes Table Extension (QA Config)

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

#### 3.1.2 AgentRuns Table Extension (QA Output)

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

#### 3.1.3 Bug Ticket Template

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

### 3.2 Backend Service (`app/services/agent_qa.py`)

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

### 3.3 Backend Router (`app/routers/agent_qa.py`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| PUT | `/ui/agents/types/{type_id}/qa-config` | `require_admin_session` | Set or update qa_config |
| GET | `/ui/agents/types/{type_id}/qa-config` | `require_admin_session` | Get current qa_config |
| POST | `/ui/agents/types/{type_id}/qa-config/validate` | `require_admin_session` | Validate config without saving |
| GET | `/ui/agents/types/{type_id}/qa-eligible-tickets` | `require_admin_session` | Preview tickets this QA agent would pick up |
| GET | `/ui/agents/runs/{run_id}/qa-output` | `require_admin_session` | Get structured QA output |
| GET | `/ui/agents/runs/{run_id}/qa-report` | `require_admin_session` | Get rendered Markdown QA report |
| GET | `/ui/agents/runs/{run_id}/qa-screenshots` | `require_admin_session` | List screenshots with presigned S3 URLs |
| POST | `/ui/agents/types/{type_id}/test-qa-workflow` | `require_admin_session` | Dry-run: preview workflow steps for a ticket |
| GET | `/ui/agents/qa/metrics` | `require_admin_session` | QA metrics: tested count, pass rate, bugs found, avg time |

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

### 3.4 Test Generation Strategy

The QA Agent generates tests by:

1. **Extracting acceptance criteria** from the ticket description. Patterns recognized: markdown checklists (`- [ ] ...`), numbered acceptance criteria sections, "Given/When/Then" blocks, and structured tables.
2. **Reading the PR diff** (`git diff origin/main...HEAD`) to understand which files changed and what new endpoints/components were added.
3. **Scanning existing tests** in the test directory to learn project conventions (import patterns, helper functions, assertion styles, test organization).
4. **Constructing a prompt** that includes the acceptance criteria, diff summary, existing test examples, and CLAUDE.md conventions. The prompt asks the coding tool to produce a test file following the `{test_file_pattern}` naming convention.
5. **Writing the test file** via Claude Code or Codex in the terminal.
6. **Running the new tests** and iterating if they fail due to test code issues (not application bugs).

### 3.5 Regression Scope Selection

- **`full`**: Run the entire test suite (`just e2e` + `just test`). Most thorough but slowest.
- **`affected`**: Derive affected test files from changed source files using import graph analysis. If `app/services/tickets.py` changed, run `frontend/e2e/tickets.spec.ts` and `tests/test_tickets.py`. Uses a heuristic mapping: `app/services/{x}.py` -> `tests/test_{x}.py` + `frontend/e2e/{x}.spec.ts`.
- **`none`**: Skip regression testing. Only useful for QA of isolated documentation or configuration changes.

### 3.6 Flaky Test Handling

Tests that fail on the first run are retried `flaky_retry_count` times. If a test fails on the first run but passes on retry, it is classified as "flaky" and excluded from the verdict. Flaky tests are listed in the QA report for human attention. If ALL failures are flaky, the verdict is `flaky` (treated as a soft pass -- PR is approved but flaky tests are flagged).

### 3.7 Frontend Types (`frontend/src/api/types.ts`)

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

### 3.8 Frontend API (`frontend/src/api/endpoints/agents.ts`)

Add QA Agent API functions: `getQaConfig`, `updateQaConfig`, `validateQaConfig`, `getQaEligibleTickets`, `getQaOutput`, `getQaReport`, `getQaScreenshots`, `testQaWorkflow`, `getQaMetrics`.

### 3.9 Frontend Pages

- **QaAgentConfigPage** (`frontend/src/pages/agents/QaAgentConfigPage.tsx`): Route `/agents/types/:typeId/qa`. Tabbed layout: Config | Eligible Tickets | Metrics. `data-testid="qa-config-page"`.
  - **Config tab**: Test framework selector, browser selector, test directory input, file pattern input, run commands, regression scope selector, screenshot toggles, visual diff threshold slider, time budget, flaky retry count, bug ticket space selector, PR review toggle, coding tool selector. "Validate" and "Save" buttons. `data-testid="qa-config-tab"`.
  - **Eligible Tickets tab**: Table of `code_complete` and `type:qa` tickets with PR links. `data-testid="qa-eligible-tab"`.
  - **Metrics tab**: Pass rate gauge, bugs found counter, avg duration, flaky test rate. `data-testid="qa-metrics-tab"`.

- **QaRunOutputPanel** (`frontend/src/pages/agents/QaRunOutputPanel.tsx`): Embedded in Agent Run detail page. Shows: verdict badge, test counts (new + regression), failure list, screenshot gallery (thumbnails with lightbox), bug ticket links, PR review status, flaky test list. `data-testid="qa-output-panel"`.

---

## 4. Implementation Plan

### 4.1 Files to Create

| File | Purpose |
|------|---------|
| `app/services/agent_qa.py` | QA Agent configuration, test generation, execution, bug filing, verdict logic |
| `app/routers/agent_qa.py` | QA config CRUD, output, report, screenshots, metrics endpoints |
| `frontend/src/pages/agents/QaAgentConfigPage.tsx` | QA Agent configuration + metrics UI |
| `frontend/src/pages/agents/QaRunOutputPanel.tsx` | QA run output detail panel with screenshot gallery |

### 4.2 Files to Modify

| File | Changes |
|------|---------|
| `app/services/tickets.py` | Add `qa_in_progress` and `qa_approved` to `_TICKET_STATUSES` |
| `app/main.py` | Register `agent_qa_router` |
| `app/models.py` | Add `QaConfigIn`, `QaConfigOut`, `QaOutputOut`, `QaReportOut`, `QaScreenshotOut`, `QaMetricsOut` models |
| `frontend/src/api/types.ts` | Add `QaConfig`, `QaOutput`, `QaMetrics`, `QaScreenshot` types |
| `frontend/src/api/endpoints/agents.ts` | Add QA Agent API functions |
| `frontend/src/App.tsx` | Add `/agents/types/:typeId/qa` route |

---

## 5. E2E Test Plan

### 5.1 Test File

`frontend/e2e/agent-qa.spec.ts` -- 16 tests across 4 sections.

### 5.2 Test Setup

```typescript
const TS = Date.now();
let agentTypeId: string;
let ticketId: string;
let runId: string;
let bugTicketId: string;
// Root = admin who configures agents
```

### 5.3 Section 655: QA Config API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 655.1 | Create QA Agent type with config | POST agent type with `agent_type=qa`; PUT qa-config with framework, browser, commands; 200 |
| 655.2 | Get QA config | GET qa-config; 200; all fields match (test_framework=playwright, browser=chromium) |
| 655.3 | Validate config with invalid framework | POST validate with `test_framework="invalid"`; 422 or validation errors returned |
| 655.4 | Update regression scope and screenshot settings | PUT with `regression_scope=full`, `screenshot_on_failure=true`; 200; values updated |

### 5.4 Section 656: Ticket Filtering & Acceptance Criteria (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 656.1 | Create ticket with code_complete status | Create development ticket; update status to `code_complete` with PR URL in metadata |
| 656.2 | QA eligible tickets returns code_complete ticket | GET qa-eligible-tickets; array includes the ticket with PR URL |
| 656.3 | Ticket with type:qa label is eligible | Create ticket with `labels=["type:qa"]`; GET eligible; ticket included |
| 656.4 | Claim QA ticket updates status | POST claim; ticket status = `qa_in_progress` |

### 5.5 Section 657: QA Output & Bug Filing API (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 657.1 | Get QA output from completed run | GET qa-output; 200; `verdict`, `new_tests_written`, `regression_tests_run` present |
| 657.2 | QA report renders Markdown | GET qa-report; 200; body contains "## Summary" and "## Test Results" |
| 657.3 | Screenshots listed with presigned URLs | GET qa-screenshots; 200; array of `{name, presigned_url, step, status}` |
| 657.4 | Bug tickets were auto-filed | QA output `bug_ticket_ids` non-empty; GET each ticket; subject contains "Bug:" |
| 657.5 | Bug ticket has reproduction metadata | Bug ticket metadata contains `reproduction_steps`, `expected_behavior`, `actual_behavior` |

### 5.6 Section 658: QA Config UI (3 tests)

| # | Test | Assertion |
|---|------|-----------|
| 658.1 | QA config page loads | Navigate `/agents/types/{typeId}/qa`; `[data-testid="qa-config-page"]` visible |
| 658.2 | Config tab shows saved framework | Config tab active; test framework selector shows "playwright" |
| 658.3 | Metrics tab renders pass rate | Click "Metrics" tab; `[data-testid="qa-metrics-tab"]` visible; pass rate gauge present |

---

## 6. Error Handling

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

---

## 7. Security Considerations

- **Admin-only access**: All QA Agent configuration endpoints require `require_admin_session`.
- **Screenshot access control**: Presigned S3 URLs expire after 15 minutes. Screenshots are stored in a separate S3 prefix not accessible via the public file manager.
- **Test code injection prevention**: Generated test files are written to a sandboxed directory within the checked-out repo. The coding tool prompt explicitly instructs against modifying production source code.
- **Bug ticket attribution**: Auto-filed bugs have `metadata.bug_source = "qa_agent"` for auditability. The `agent_run_id` links back to the full QA run record.
- **PR review authentication**: `gh pr review` uses the agent's GitHub token from AGENT-006 secrets vault. Token permissions are scoped to the minimum required (repo read + PR review write).
- **Regression test isolation**: QA Agent runs in an isolated terminal instance. Test database is separate from production. No real user data is accessed.
- **Flaky test tracking**: Flaky test classifications are logged to prevent repeated false-positive bug filings for known flaky tests.

---

## 8. Performance Considerations

| Concern | Mitigation |
|---------|-----------|
| Full regression suite takes 30+ minutes | Default to `affected` scope; `full` only on explicit config |
| Screenshot uploads for large test suites | Batch upload; compress PNGs; cap at 50 screenshots per run |
| Test generation prompt size | PR diff truncated to 5000 lines; acceptance criteria capped at 20 items |
| Concurrent QA runs competing for tickets | Conditional update on ticket claim; staggered polling |
| S3 storage growth from screenshots | Lifecycle policy: delete screenshots older than 90 days |
| Bug ticket deduplication | Before filing, check existing open bugs with same `source_ticket_id` |

---

## 9. Dependencies

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
