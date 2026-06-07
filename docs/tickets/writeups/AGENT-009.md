# AGENT-009: QA Agent — Investigation & Implementation Write-up

## 1. Summary & Classification

AGENT-009 defines the QA Agent type — a configuration profile that plugs into the Worker Agent Framework (AGENT-003) to autonomously test code changes produced by the Coder Agent (AGENT-008) or humans. The QA Agent polls for tickets in `code_complete` status (set by AGENT-008) or carrying a `type:qa` label, checks out the associated PR branch, generates E2E tests from acceptance criteria using a configured coding tool (Claude Code or Codex), runs the new tests, retries suspected flaky failures, runs a scoped regression suite, uploads screenshots to S3, files structured bug tickets for real failures, and posts a `gh pr review` verdict (approve or request-changes). The agent is fully deterministic in dev mode with `QA_AGENT_EXECUTE_COMMANDS=0` (the default) and operates in-memory for all E2E tests.

- **Type**: Feature (specialized agent type configuration)
- **Priority**: High
- **Status**: Implemented — `app/services/agent_qa.py` (1303 lines), `app/routers/agent_qa.py` (255 lines), frontend `QaAgentConfigPage.tsx` + `QaRunOutputPanel.tsx`, E2E spec `frontend/e2e/agent-qa.spec.ts` (sections 655–660)
- **Owning area**: Agent platform / autonomous QA pipeline
- **Who is affected**: Platform admins managing the automated QA pipeline; developers whose PRs are tested by the agent; AGENT-007 (which transitions tickets to `qa_approved` on QA pass); AGENT-008 (which waits for QA to clear before merging)
- **Cross-references**: SEC-021 (command injection in `gh pr review` and test run commands), SECOPS-007 (dev/prod parity via `QA_AGENT_EXECUTE_COMMANDS` flag), AGENT-007 (cross-agent handoff; coder sets `code_complete`), AGENT-008 (provides `code_complete` tickets and PR branches)

---

## 2. Current-State Investigation (what exists today)

### Service layer: `app/services/agent_qa.py` (1303 lines)

The service reuses the shared `agent_types` and `agent_runs` tables bootstrapped by `agent_coder.ensure_tables()` (`agent_qa.py:100`). It does not create its own tables.

**Config storage/validation** (`agent_qa.py:100–250`): `update_qa_config(agent_type_id, owner_sub, config)` normalizes the config dict against `_CONFIG_DEFAULTS` (line 73–90), then `put_item` at PK `TYPE#{type_id}` / SK `CONFIG` with a nested `qa_config` map. Validation covers framework (`playwright/cypress/pytest`), browser (`chromium/firefox/webkit`), regression scope (`full/affected/none`), float range for `visual_diff_threshold`, and integer range for timeouts.

**Eligible ticket discovery** (`agent_qa.py:300–380`): `find_qa_eligible_tickets()` queries both the `code_complete` status index (via `tickets_svc.STORE._table.query()` on the GSI that indexes by status) and the `type:qa` label index (via `tickets_svc.label_index_pk("type:qa")`). De-duplicates results, filters out tickets already assigned to a QA agent (checks `qa_agent_run_id` attribute), returns oldest-first.

**Atomic claiming** (`agent_qa.py:380–430`): `claim_qa_ticket(agent_run_id, ticket_id, agent_sub)` issues a conditional update: `ConditionExpression="attribute_not_exists(qa_agent_run_id)"` and sets `status=qa_in_progress` via `_apply_qa_status()`. Like the coder agent, `qa_in_progress` is an agent lifecycle status and is stored under `agent_status` on the ticket META item rather than going through the core `TicketStore.update_status()` guard.

**Test generation** (`agent_qa.py:430–560`): `extract_acceptance_criteria(ticket)` parses markdown checklists (`- [ ] …`), numbered lists under "Acceptance Criteria" headings, and "Given/When/Then" blocks from the ticket description. `build_test_generation_prompt()` constructs the full prompt including the acceptance criteria list, PR diff summary, and the project test conventions from CLAUDE.md injected via AGENT-005 memory context.

The coding command built at line ~560 follows the same pattern as AGENT-008:
```python
analyze_cmd = f'claude --dangerously-skip-permissions{model_flag} -p "{test_gen_prompt[:200]}..."'
```
This is the same SEC-021-relevant interpolation.

**Test execution and flaky detection** (`agent_qa.py:560–700`): `build_test_run_commands()` produces an ordered list: new test file first (`test_run_specific_command.format(file=new_test_file)`), then regression suite based on `regression_scope`. For `"affected"` scope, the mapping heuristic `app/services/{x}.py → tests/test_{x}.py + frontend/e2e/{x}.spec.ts` is applied to the PR's changed files.

`detect_flaky_tests(initial_failures, retry_results)` compares the set of initially failing test names with retry pass results. Tests that pass on the second attempt are classified flaky and excluded from the verdict. If all failures are flaky, `determine_verdict()` returns `"flaky"` — treated as a soft pass with PR approval but flagged.

**Screenshot management** (`agent_qa.py:700–780`): `upload_screenshots_to_s3(screenshots_dir, s3_prefix, agent_run_id)` iterates PNG files in a local directory and uploads via `boto3` S3 client (`app/core/aws`). In dev mode, S3 is the in-process moto mock started by `app/core/dev_s3.py`. `get_qa_screenshots(run_id)` generates presigned URLs via `s3_client.generate_presigned_url()` — presigned URLs work correctly with moto in dev.

**Bug ticket filing** (`agent_qa.py:780–890`): `build_bug_ticket()` structures reproduction data: test name, assertion error, last 5000 characters of test output (`_OUTPUT_TAIL_MAX = 5_000`), screenshot S3 keys, and auto-classified severity (`critical` for crashes, `major` for assertion failures, `minor` for timeouts). `file_bug_tickets()` calls `tickets_svc.STORE.create_ticket()` with labels `["type:bugfix", "source:qa_agent", "complexity:low"]` and stores the bug metadata in the ticket's `metadata` dict. Returns a list of created ticket IDs that are stored on the QA output.

**PR review command** (`agent_qa.py:890–940`): `build_pr_review_command(pr_number, verdict, report)` returns:
```python
f'gh pr review {pr_number} --approve'  # or
f'gh pr review {pr_number} --request-changes --body "{report}"'
```
The `report` string is truncated Markdown from `build_qa_report()`. Double-quote interpolation here has the same SEC-021 concern as the coder agent.

**QA output storage** (`agent_qa.py:940–1050`): `store_qa_output(run_id, qa_output)` does a `put_item` at `T.agent_runs` PK `RUN#{run_id}` / SK `META` with `qa_output` nested map. Supports Decimal coercion (`_coerce_numbers()`).

**Metrics** (`agent_qa.py:1200–1303`): `get_qa_metrics(agent_type_id)` scans completed runs on `agent_runs`, aggregates `tested_count`, `pass_rate`, `bugs_found_count`, `avg_duration_seconds`, `flaky_test_rate`. Like the coder agent, this is an in-memory aggregation scan — pre-computed snapshots are not yet implemented.

**Execution gate** (`app/core/settings.py:2205`): `S.agent_qa_execute_commands` defaults to `False`. When disabled, `build_qa_workflow()` generates the step list but no terminal injection or real test execution occurs — E2E tests drive the state machine in-memory.

### Router: `app/routers/agent_qa.py` (255 lines)

Registered in `app/main.py:767–768`. All endpoints under `/ui/agents`, gated by `require_admin_or_root` or `require_admin_or_root_csrf`. Key endpoints:
- `PUT /ui/agents/types/{type_id}/qa-config` — save config
- `POST /ui/agents/types/{type_id}/qa-config/validate` — `{valid, errors}` without saving
- `GET /ui/agents/types/{type_id}/qa-eligible-tickets` — preview eligible tickets
- `GET /ui/agents/runs/{run_id}/qa-output` — structured QA output
- `GET /ui/agents/runs/{run_id}/qa-report` — rendered Markdown report
- `GET /ui/agents/runs/{run_id}/qa-screenshots` — list with presigned URLs
- `POST /ui/agents/types/{type_id}/test-qa-workflow` — dry-run step generation
- `GET /ui/agents/qa/metrics` — aggregated throughput

### E2E spec: `frontend/e2e/agent-qa.spec.ts`

Six sections: 655 (QA Config API), 656 (Ticket filtering & claiming API), 657 (QA Output & Bug Filing API), 658 (QA Config UI), 659 (Edge cases), 660 (Negative cases). All run offline with execution disabled.

---

## 3. Gap / Threat Analysis

### SEC-021: PR review command injection

`build_pr_review_command()` interpolates `report` (Markdown string) into a double-quoted shell argument:
```python
f'gh pr review {pr_number} --request-changes --body "{report}"'
```
If `report` contains `"`, `\n`, or `$()`, the shell command breaks or executes injected code. The `pr_number` is typed as `int` in the router, so it is safe. The `report` is agent-generated, not user-provided directly, but ticket subjects and test output (which contain user-controlled text) flow into the report.

Mitigation: apply the same single-quote escaping used in AGENT-007's `_build_gh_pr_command()` before the real execution is enabled via `QA_AGENT_EXECUTE_COMMANDS=1`.

### Regression scope "affected" heuristic gaps

The `affected` scope maps `app/services/{x}.py` → `tests/test_{x}.py` + `frontend/e2e/{x}.spec.ts` by filename stem. This heuristic misses:
- Changes to routers (`app/routers/{x}.py`) that should trigger the same E2E spec
- Shared utilities (`app/core/*.py`) affecting multiple test files
- Frontend component changes not named after a single feature

In practice, most PRs that trigger the QA agent are coder agent PRs where the branch name encodes the ticket ID; the "affected" heuristic will catch file-name matches but not transitive dependencies. A `regression_scope="full"` config is the safe fallback for production.

### Bug ticket deduplication

`file_bug_tickets()` calls `create_ticket()` once per distinct failure — if the same PR is re-tested (e.g., after a fix-and-resubmit), duplicate bug tickets may be filed. There is no idempotency check on `source_pr_url` + `test_name`. This creates noise in the ticket queue for active PRs.

### Flaky test verdict soft-pass risk

When `determine_verdict()` returns `"flaky"`, the PR is approved (`gh pr review --approve`). If a genuinely breaking change flakes consistently (fails first run, passes on retry due to test infra issues), it is incorrectly approved. The `flaky_retry_count` (default 2) mitigates this but does not eliminate it.

---

## 4. Proposed Design / Fix

### SEC-021 fix for PR review command

Replace double-quote interpolation with single-quote escaping:

```python
def _sq(v: str) -> str:
    return "'" + str(v).replace("'", "'\\''") + "'"

def build_pr_review_command(*, pr_number: int, verdict: str, report: str) -> str:
    if verdict == "pass" or verdict == "flaky":
        return f"gh pr review {pr_number} --approve"
    return f"gh pr review {pr_number} --request-changes --body {_sq(report)}"
```

Apply the same fix to the test generation command in `build_qa_workflow()`.

### Bug ticket deduplication

Add a `source_run_fingerprint` field to bug tickets: `sha256(source_pr_url + test_name)[:16]`. Before `create_ticket()`, query the label index `LABELIDX#source:qa_agent` for tickets with matching `metadata.source_run_fingerprint`. If a match exists, skip creation and return the existing ticket ID.

### "Affected" scope enhancement

Store a simple static map `ROUTER_TO_SPEC = {"app/routers/{x}.py": "frontend/e2e/{x}.spec.ts"}` alongside the service map. Add `app/core/*.py` changes → `full` scope fallback. This is a low-cost enhancement that significantly improves coverage accuracy.

### Dev/Prod parity (SECOPS-007)

Current parity is correct:
- `S.agent_qa_execute_commands = False` (dev default): `build_qa_workflow()` generates steps; no real test execution, no subprocess, no S3 upload (S3 is moto in-process).
- Prod (`QA_AGENT_EXECUTE_COMMANDS=1`): real SSH terminal injection via AGENT-002; S3 uploads go to real AWS S3.
- Screenshot presigned URLs: moto generates syntactically valid but locally unreachable presigned URLs in dev. Tests assert URL format, not reachability.
- Bug ticket filing calls `tickets_svc.STORE.create_ticket()` — this uses DDB Local in dev and DDB in prod; no AWS-specific code in the filing path.

---

## 5. Testing, Verification & Rollout

### pytest unit tests (`tests/test_agent_qa.py`)

Concrete cases:
- `test_validate_qa_config_valid`: complete config dict → empty errors list
- `test_validate_qa_config_invalid_framework`: `test_framework="jest"` → errors contains "playwright, cypress, pytest"
- `test_validate_qa_config_threshold_range`: `visual_diff_threshold=1.5` → errors contains threshold range
- `test_extract_acceptance_criteria_checklist`: ticket description with `- [ ] …` markers → list of extracted strings
- `test_extract_acceptance_criteria_empty`: no structured criteria → empty list, no crash
- `test_detect_flaky_tests_all_flaky`: initial_failures = {"test_a"}; retry_results shows test_a passed → flaky_tests = ["test_a"]
- `test_detect_flaky_tests_real_failure`: initial_failures = {"test_a", "test_b"}; retry shows test_a passed, test_b still fails → flaky = ["test_a"], real failure = ["test_b"]
- `test_determine_verdict_pass`: no failures → "pass"
- `test_determine_verdict_fail`: real failures present → "fail"
- `test_determine_verdict_flaky`: only flaky failures → "flaky"
- `test_build_bug_ticket_severity_critical`: failure message contains "TypeError" → `severity="major"` or "critical"
- `test_pr_review_command_single_quotes`: `build_pr_review_command(pr_number=1, verdict="fail", report="body 'with' quotes")` → output contains `--body '` with escaped internal quote (after SEC-021 fix)
- `test_store_and_retrieve_qa_output`: put qa_output on agent_runs, get back with same verdict
- `test_claim_qa_ticket_double_claim`: two concurrent claims → second raises ValueError

### Playwright E2E

Existing `frontend/e2e/agent-qa.spec.ts` sections 655–660. Key:
- Section 657: `GET /qa-output` returns `verdict`, `pr_url`, `bug_ticket_ids`, `screenshots`
- Section 657: bug ticket created with `source:qa_agent` label, `source_ticket_id` in metadata
- Section 659: ticket with `qa_agent_run_id` already set → not returned in `qa-eligible-tickets`

Run: `cd frontend && npx playwright test e2e/agent-qa.spec.ts`

### Manual QA steps

1. `just restart` to seed sessions
2. Create a QA agent type; set `qa-config` with `test_framework="playwright"`, `pr_review_enabled=true`
3. Create a `code_complete`-status ticket (or one with `type:qa` label) → verify it appears in `qa-eligible-tickets`
4. Dry-run `test-qa-workflow` → verify 15 steps; step types include `checkout_pr`, `generate_tests`, `run_regression`
5. Navigate `/agents/types/{typeId}/qa` → confirm Config, Eligible Tickets, and Metrics tabs render

### Rollout

- Ship with `QA_AGENT_EXECUTE_COMMANDS=0` (current default). Zero prod impact.
- SEC-021 fix for PR review command must be merged before enabling execution in staging.
- Enable `QA_AGENT_EXECUTE_COMMANDS=1` only after: (a) AGENT-002 terminal provisioning confirmed, (b) S3 bucket for screenshots configured, (c) `PLAYWRIGHT_BROWSERS_PATH` set on agent worker image.

**Effort estimate**: M (service implemented; SEC-021 fix ~1 day; bug deduplication ~0.5 days; missing unit tests ~1 day).
