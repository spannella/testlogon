# AGENT-008: Coder Agent — Investigation & Implementation Write-up

## 1. Summary & Classification

AGENT-008 defines the Coder Agent type — a configuration profile that plugs into the Worker Agent Framework (AGENT-003) to autonomously implement code changes. The agent picks up tickets carrying `type:development` or `type:bugfix` labels, generates a fully ordered, deterministic workflow (clone repo → create branch → environment setup → inject coding prompt → run tests → fix loop → create PR → update ticket), and stores structured output on the shared `agent_runs` table. Skill-level gating (junior/mid/senior) filters eligible tickets by `complexity:*` label. When execution is enabled, the workflow drives real terminal sessions; when disabled (the default and always in E2E), it operates as an in-memory state machine.

- **Type**: Feature (specialized agent type configuration)
- **Priority**: High
- **Status**: Implemented — `app/services/agent_coder.py` (912 lines), `app/routers/agent_coder.py` (211 lines), frontend `CoderAgentConfigPage.tsx` + `CoderRunOutputPanel.tsx`, E2E spec `frontend/e2e/agent-coder.spec.ts` (sections 651–658)
- **Owning area**: Agent platform / autonomous development pipeline
- **Who is affected**: Platform admins configuring development automation; downstream AGENT-007 (PR integration), AGENT-009 (QA), AGENT-011 (Solution Architect produces tickets this agent consumes)
- **Cross-references**: SEC-021 (command injection — branch name, repo_url, coding_cmd), SECOPS-007 (execution gate; dev = in-memory mock; prod = real terminal), AGENT-003 (Worker Agent Framework lifecycle), AGENT-007 (PR creation on work completion)

---

## 2. Current-State Investigation (what exists today)

### Service layer: `app/services/agent_coder.py` (912 lines)

**Shared table bootstrap** (`agent_coder.py:70–140`): `ensure_tables()` idempotently creates `agent_types` (PK `pk`, SK `sk`) and `agent_runs` tables using `ddb.meta.client.create_table`. Catches `ResourceInUseException` for already-existing tables. These same tables are reused by AGENT-009, AGENT-010, and AGENT-011.

**Slug/branch sanitization** (`agent_coder.py:155–173`):
- `slugify(text, max_len=50)`: lowercases, replaces non-`[a-z0-9]` with hyphens, trims.
- `generate_branch_name(pattern, ticket_id, subject)`: renders `{ticket_id}` and `{slug}` in the pattern, then applies `re.sub(r"[^a-zA-Z0-9_/\-]", "-", name)` and a double-hyphen collapse. Max 80 chars with trailing `-/` stripped.

**Config storage** (`agent_coder.py:261–302`): `update_coder_config()` calls `_normalize_config()` then does a `put_item` on `T.agent_types` at PK `TYPE#{type_id}` / SK `CONFIG` with a nested `coder_config` map. A separate `update_item` on the META item (`sk="META"`) keeps `agent_type=coder` for discovery. Returns the normalized config dict.

**Ticket filtering** (`agent_coder.py:350–399`): `find_eligible_tickets()` queries the label index on the tickets table. It calls `tickets_svc.STORE._table.query(KeyConditionExpression="pk = :pk", ExpressionAttributeValues={":pk": tickets_svc.label_index_pk(label)})` — the label index uses PK = `LABELIDX#{label}`, a single-table pattern in the tickets table (`app/services/tickets.py:48`). Filters open, unassigned tickets; gates on complexity label vs. skill level; returns oldest-first (FIFO).

**Atomic ticket claim** (`agent_coder.py:402–441`): `claim_ticket()` issues a `ConditionExpression="attribute_not_exists(assigned_to_sub) OR assigned_to_sub = :none"` conditional update. Raises `ValueError("already_claimed")` on `ConditionalCheckFailedException`. This prevents double-claiming race conditions.

**Coding prompt construction** (`agent_coder.py:449–470`): `build_coding_prompt()` builds a plain text prompt from ticket subject, first message body, acceptance criteria from `ticket["metadata"]`, and file exclusion list. No LLM API call — the prompt is injected into the terminal session.

**Workflow generation** (`agent_coder.py:529–659`): `build_coder_workflow()` is pure (no I/O). Returns `{steps: [...], branch_name, total_timeout_seconds}`. The `coding_cmd` is built at line 559–563:

```python
if coding_tool == "codex":
    coding_cmd = f'codex -q "{prompt[:200]}..."'
else:
    model_flag = f" --model {model}" if model else ""
    coding_cmd = f'claude --dangerously-skip-permissions{model_flag} -p "{prompt[:200]}..."'
```

The truncated prompt (`[:200]`) is interpolated directly into a shell string using an f-string. Similarly, `build_pr_command()` at line 482–488 interpolates `title` and `body_escaped` into a double-quoted shell string using simple `replace('"', "'")`. This is the injection surface identified in SEC-021.

The git clone step at line 578:
```python
"command": f"git clone {repo_url} /workspace && cd /workspace && git fetch origin"
```
interpolates `repo_url` without additional sanitization beyond the format validator in `validate_coder_config()` (which checks `startswith("https://")` or `startswith("git@")`). `AGENT_CODER_EXECUTE_COMMANDS=0` (the default) keeps this dead code in dev/E2E.

**Execution gate** (`app/core/settings.py:2177`): `S.agent_coder_execute_commands` defaults to `False`. When `False`, `build_coder_workflow()` generates the step list but the actual terminal injection in the Worker Agent Framework is skipped; the state machine runs in-memory with mock step results. This is the SECOPS-007 dev/prod split for this agent type.

**Coder output** (`agent_coder.py:660–780`): `build_coder_output()` accepts `git_diff_stat` (string from `git diff --stat`), parses insertions/deletions, assembles a `coder_output` dict stored at `T.agent_runs` PK `RUN#{run_id}` / SK `OUTPUT`. Output tails are capped at `_OUTPUT_TAIL_MAX = 10_000` (line 43).

**Metrics** (`agent_coder.py:820–912`): `get_coder_metrics()` scans completed runs on `agent_runs`, filters by `agent_type_id`, aggregates `completed_count`, `avg_duration_seconds`, `failure_rate`, `escalation_rate`, and `tickets_by_skill_level`. Pre-computation via daily snapshots is not yet implemented; it currently does an in-memory aggregation.

### Router: `app/routers/agent_coder.py` (211 lines)

Registered in `app/main.py:765–766`. All endpoints under `/ui/agents`, protected by `require_admin_or_root` or `require_admin_or_root_csrf`. Notable endpoints:
- `GET /ui/agents/types/coder/config-schema` — returns `svc.config_schema()` dict
- `PUT /ui/agents/types/{type_id}/coder-config` — saves config, requires CSRF
- `POST /ui/agents/types/{type_id}/coder-config/validate` — returns `{valid, errors}` without saving
- `GET /ui/agents/types/{type_id}/eligible-tickets` — preview filter results
- `POST /ui/agents/runs/{run_id}/claim-ticket` — manual claim trigger
- `GET /ui/agents/runs/{run_id}/coder-output` — structured output retrieval
- `POST /ui/agents/types/{type_id}/test-workflow` — dry-run workflow generation
- `GET /ui/agents/coder/metrics` — aggregated throughput metrics

The ticket incorrectly listed `require_admin_session`; the actual dependency is `require_admin_or_root` from `app/auth/policy.py`.

### Ticket labels extension: `app/services/tickets.py`

`label_index_pk(label)` (tickets.py:48) returns `LABELIDX#{label}`. Label index items are written at create/update time (`tickets.py:318`). The coder agent queries these in `find_eligible_tickets()`. `create_ticket()` accepts a `labels` parameter that fans out index items. The statuses `code_complete` and `blocked` are stored as `agent_status` on the META item rather than through `TicketStore.update_status()` (which validates against the core status set), consistent with the AGENT-007 approach.

### E2E spec: `frontend/e2e/agent-coder.spec.ts`

Eight sections: 651 (Config API), 652 (Ticket filtering & claiming API), 653 (Workflow & output API), 654 (Config UI), 655 (Input validation), 656 (Authorization boundary), 657 (Ticket label filtering), 658 (Workflow edge cases). All run without real execution (`AGENT_CODER_EXECUTE_COMMANDS=0`).

---

## 3. Gap / Threat Analysis

### SEC-021: Command injection in build_coder_workflow

`build_coder_workflow()` at `agent_coder.py:559–563` f-strings `prompt[:200]` inside double-quoted shell arguments passed to `claude` or `codex`. A ticket subject or acceptance criteria containing `"` causes the shell command to break, and one containing `$(…)` or backtick command substitution would execute if passed to a shell. Currently gated by `S.agent_coder_execute_commands=False`.

Similarly, `build_pr_command()` at line 482–488 does `replace('"', "'")` on `title` and `body_escaped` — this is not shell-safe; a title containing `'` breaks the single-quote substitution and a title with `\n` creates a multiline argument.

`validate_coder_config()` checks that `repo_url` starts with `https://` or `git@` and has no spaces, but does not block `git@github.com:org/repo;evil_cmd` (semicolon after the git hostname). This blocks the most naive SSRF vectors but does not prevent advanced git transport attacks (`ext::`, `git+ssh://`).

**Impact when execution enabled**: arbitrary command execution on the worker SSH session. Risk rating per SEC-021: Medium (gated/latent).

### Metrics aggregation at scale

`get_coder_metrics()` does a full scan of `agent_runs` filtered in-memory. For >10K completed runs this is slow. The ticket design calls for daily snapshot pre-computation but the current implementation is the simple scan. Acceptable for early usage.

### Claim atomicity edge case

The `ConditionExpression` at `agent_coder.py:420` is `attribute_not_exists(assigned_to_sub) OR assigned_to_sub = :none` where `:none = None`. DynamoDB does not allow a `NULL` attribute value in expression attribute values. If `assigned_to_sub` is stored as an empty string `""` rather than absent, the condition will pass and a second agent could claim the same ticket. The `claim_ticket()` code sets `:none = None` — whether DDB Local and production DDB both treat `None` as the absence check depends on boto3 serialization. This should be tested explicitly.

---

## 4. Proposed Design / Fix

### SEC-021 fix for build_coder_workflow

Replace f-string shell command construction with a data structure that the Worker Agent Framework serializes to argv:

```python
# Instead of: coding_cmd = f'claude --dangerously-skip-permissions -p "{prompt[:200]}..."'
# Store as structured data:
coding_step = {
    "step_id": 4,
    "type": "inject_coding_prompt",
    "argv": ["claude", "--dangerously-skip-permissions", "-p", prompt],
    "timeout_seconds": coding_timeout,
    "on_failure": "escalate",
}
```

The Worker Agent Framework (AGENT-003) must execute argv via `subprocess(argv, shell=False)` rather than `subprocess(shell_string, shell=True)`. Until AGENT-003 is updated, mark the `command` field as display-only and document that real execution must use `argv`.

For `build_pr_command()`, use the same single-quote escaping pattern from AGENT-007's `_build_gh_pr_command()`:
```python
def _sq(v: str) -> str:
    return "'" + v.replace("'", "'\\''") + "'"

def build_pr_command(*, branch_name, base_branch, ticket_id, ticket_subject, template, summary):
    body = render_pr_template(...)
    return (
        f"gh pr create --title {_sq(ticket_subject)} "
        f"--body {_sq(body)} "
        f"--base {_sq(base_branch)} "
        f"--head {_sq(branch_name)}"
    )
```

For `repo_url`, add `ext::` and `file://` rejection to `validate_coder_config()`:
```python
if any(repo_url.startswith(p) for p in ("ext::", "file://", "git+", "http://")):
    errors.append("Repository URL must use https:// or git@ only")
```

### Daily metrics snapshots

Add a `POST /ui/agents/types/{type_id}/coder-metrics/snapshot` endpoint (admin-only) that writes `gsi_type_date_pk=CODER#{type_id}`, `gsi_type_date_sk=DATE#{yyyy-mm-dd}` rollup items to `agent_runs`. Query the snapshot GSI in `get_coder_metrics()` instead of scanning.

### Dev/Prod parity (SECOPS-007)

Currently correct:
- `S.agent_coder_execute_commands = False` (dev default): workflow is generated in-memory; the `command` fields are display strings only; no subprocess or SSH terminal injection occurs.
- Prod (`AGENT_CODER_EXECUTE_COMMANDS=1`): the Worker Agent Framework injects commands via the provisioned SSH session (AGENT-002).
- Same `build_coder_workflow()` code path in both envs; only the execution step differs.

---

## 5. Testing, Verification & Rollout

### pytest unit tests (`tests/test_agent_coder.py`)

Key test cases:
- `test_slugify_special_chars`: `slugify("Hello World! Fix it")` → `"hello-world-fix-it"`
- `test_generate_branch_name_long`: subject of 200 chars → branch name ≤ 80 chars; no trailing `-`
- `test_generate_branch_name_injection`: subject containing `"; rm -rf /"` → branch name contains only `[a-zA-Z0-9_/\-]`
- `test_validate_config_missing_repo`: empty `repo_url` → errors contains "Repository URL"
- `test_validate_config_ext_transport`: `repo_url="ext::ssh://evil"` → errors non-empty (after SEC-021 fix)
- `test_find_eligible_tickets_skill_gate`: ticket with `complexity:high` not returned for `skill_level=junior`
- `test_claim_ticket_atomic`: two concurrent claims → second raises `ValueError("already_claimed")`
- `test_build_coder_workflow_step_count`: workflow for a full config returns 10+ steps with correct types
- `test_build_coder_workflow_prompt_injection`: ticket with `"` in subject → `command` field safe to display
- `test_store_and_retrieve_coder_output`: store structured output, retrieve via `get_coder_output()`
- `test_get_coder_metrics_empty`: no runs → returns zeros without error
- `test_config_schema`: `config_schema()` includes required fields with expected types

### Playwright E2E

Existing `frontend/e2e/agent-coder.spec.ts` sections 651–658. All should pass offline. Key assertions:
- Section 651.3: validate with `repo_url="not-a-url"` → `errors` non-empty
- Section 653.1: `test-workflow` returns 11 steps; first step `type="clone_repo"`
- Section 657: ticket with `complexity:high` not in eligible list for `skill_level=junior` agent

### Manual QA steps

1. `just restart` to seed E2E sessions
2. Navigate `/agents/types/new` → create coder agent type → verify persisted
3. Set coder config with valid repo URL → "Validate" → green
4. Create a ticket with `labels=["type:development", "complexity:medium"]` → check "Eligible Tickets" tab shows it
5. Dry-run workflow → verify step list, branch name format

### Rollout plan

- Ship with `AGENT_CODER_EXECUTE_COMMANDS=0` (current default). No prod impact.
- SEC-021 fix (single-quote escaping in `build_pr_command`, argv refactor for `build_coder_workflow`) is a non-breaking change; ship before enabling execution in prod.
- Enable `AGENT_CODER_EXECUTE_COMMANDS=1` only after: (a) SEC-021 fix merged, (b) worker provisioning tested (AGENT-002), (c) a staging-only test run confirmed.

**Effort estimate**: M (service and tests largely done; SEC-021 fix, metrics snapshots, and claim atomicity hardening are the remaining work ~2 days).
