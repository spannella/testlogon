# AGENT-007: Agent PR & Ticket Integration — Investigation & Implementation Write-up

## 1. Summary & Classification

AGENT-007 closes the loop between autonomous agent work and the development workflow by automating pull-request creation, ticket lifecycle management, and cross-agent handoffs. When a coder agent finishes work on a ticket, this integration layer detects git state from terminal output, creates a PR (via `gh pr create` CLI injection or direct GitHub API call), links the PR record to the ticket item in DynamoDB, drives the ticket through agent-specific status transitions (open → in_progress → code_complete → in_review → done), records a structured work summary, and queues the ticket for the next agent type. A GitHub webhook receiver closes the loop on the CI side: merged/closed PR events update the ticket and PR record status.

- **Type**: Feature (integration layer)
- **Priority**: High
- **Status**: Implemented — service, router, models, frontend, and E2E spec all exist
- **Owning area**: Agent platform / DevOps workflow automation
- **Who is affected**: Platform admins and product teams using the autonomous agent pipeline; downstream agents (QA, DevOps) depend on the handoff mechanism
- **Cross-references**: SEC-021 (command injection risk in `_build_gh_pr_command`), SEC-022 (GitHub token handling), SECOPS-007 (dev/prod parity — mock PR API in `dev_mode`), AGENT-003 (orchestrator `complete_ticket`), AGENT-005 (memory `add_memory`), AGENT-006 (terminal monitor output)

---

## 2. Current-State Investigation (what exists today)

### Service layer: `app/services/agent_pr_integration.py` (770 lines)

The service is fully implemented. Key code paths:

**Git state detection** (`agent_pr_integration.py:46–88`): `detect_git_state(terminal_output)` applies six regex patterns from `GIT_PATTERNS` against the last 10–20KB of terminal buffer captured by `terminal_monitor.get_terminal_output(worker_id, chars=…)`. Extracts branch name, commit count, files-changed count, PR URL, and push confirmation.

**PR creation** (`agent_pr_integration.py:387–485`): `create_pr_from_agent(user_id, worker_id, ticket_id, …)` works in two modes:
- `method="cli"`: calls `_build_gh_pr_command()` (line 350), which single-quotes arguments via `"'" + value.replace("'", "'\\''") + "'"` for shell safety, then appends the command to the worker's terminal buffer via `terminal_monitor.get_or_create_buffer(worker_id)`.
- `method="api"`: calls `_create_pr_via_api()` (line 363). In `dev_mode` or when `S.github_token == ""`, returns a deterministic mock response (`{html_url, number, state}`); in prod with a real token, raises `NotImplementedError("Live GitHub API integration not enabled.")` — the real HTTP call to the GitHub REST API is stubbed but not wired.

PR records are stored on `T.agent_workers` table with PK `USER#{user_id}` / SK `PR#{pr_id}` (line 472).

**Status flow config** (`agent_pr_integration.py:95–261`): `DEFAULT_STATUS_FLOWS` maps agent types (`coder`, `qa`, `reviewer`, `devops`) to lifecycle transitions. Custom flows are stored as `FLOW#{flow_id}` items on `T.agent_workers` and retrieved by `get_status_flow_config()` (line 213), which queries a `begins_with(sk, "FLOW#")` + `FilterExpression=agent_type=:at` scan. Most-recent custom config wins.

`_apply_status()` (line 189) distinguishes the four core ticket statuses (`open`, `in_progress`, `waiting_on_user`, `done`) from agent lifecycle statuses. Core statuses go through `TicketStore.update_status()` (`app/services/tickets.py:683`); agent-specific statuses like `code_complete`, `in_review`, `qa_passed` are written directly to the META item under `agent_status` to avoid the TicketStore's transition guard.

**Cross-agent handoff** (`agent_pr_integration.py:508–523`): `_trigger_cross_agent_handoff()` sets `agent_eligible=yes`, `next_agent_type`, `agent_worker_id=""`, and `agent_state=ready_for_agent` on the ticket META item, then re-applies status `open` so the orchestrator's polling loop can see it.

**GitHub webhook receiver** (`agent_pr_integration.py:686–770`): `verify_webhook_signature()` (line 686) uses HMAC-SHA256 with `S.github_webhook_secret`. When the secret is empty (dev mode), verification passes unconditionally — this is intentional for local E2E testing. `handle_github_webhook()` routes `pull_request.closed` (merged or not) and `pull_request_review` events.

### Router: `app/routers/agent_pr_integration.py` (206 lines)

Registered in `app/main.py:757–764` under three separate routers:
- `router` (prefix `/ui/agent/pr`) — user-facing PR CRUD and completion endpoints
- `webhook_router` (prefix `/ui/agent/webhooks`) — GitHub webhook receiver at `POST /ui/agent/webhooks/github`
- `admin_router` (prefix `/ui/admin/agent`) — admin scan of all agent PRs

Auth uses `require_ui_session` (from `app/services/sessions.py`) for user endpoints and `require_admin_or_root` (from `app/auth/policy.py`) for the admin listing. The ticket notes `require_admin_session` which does not exist; the actual dependency is `require_admin_or_root` at router line 202.

### Models: `app/models.py`

Present: `AgentPrCreateIn`, `AgentPrListOut`, `AgentWorkCompleteIn`, `StatusFlowUpdateIn` (all imported in the router at lines 17–22).

### Frontend: `frontend/src/pages/agents/AgentPrList.tsx`

The file exists. Route `/agents/prs` is in `frontend/src/App.tsx`.

### Settings: `app/core/settings.py:910–911`

```
github_token: str = os.environ.get("GITHUB_TOKEN", "")
github_webhook_secret: str = os.environ.get("GITHUB_WEBHOOK_SECRET", "")
```

Both settings exist. In dev (default), both are empty strings; `_create_pr_via_api()` detects this and returns mock data.

### E2E spec: `frontend/e2e/agent-pr-integration.spec.ts`

Exists with four test sections: 647 (PR Creation API), 648 (Work Completion API), 649 (Status Flow & GitHub Webhook API), 650 (Agent PR UI).

---

## 3. Gap / Threat Analysis

### Remaining implementation gaps

1. **Live GitHub API not wired**: `_create_pr_via_api()` at line 380 raises `NotImplementedError("Live GitHub API integration not enabled.")` when `method="api"` and a token is configured. The ticket design assumed a real `httpx` call to `POST /repos/{owner}/{repo}/pulls`. The dev mock is sufficient for all E2E tests but production use requires finishing this path.

2. **`_find_pr_by_url()` uses full table scan** (line 664): The admin webhook handler finds a PR by its URL via `T.agent_workers.scan(FilterExpression="pr_url = :url")`. At scale this is expensive. A GSI on `pr_url` would be required for production efficiency; currently acceptable since the agent_workers table is small.

3. **Cross-agent handoff QA pickup not end-to-end tested**: Section 649 test 12 (`QA agent picks up ticket after coder handoff`) polls the QA agent's `current_ticket_id` for up to 15 seconds. The actual polling loop that drives `agent_eligible` re-queuing lives in the orchestrator (AGENT-003, `app/services/agent_orchestrator.py`) and must be running for the handoff to complete in a live test.

4. **`complete_agent_work()` does not call `agent_memory.add_memory()`** if the memory service raises — it is wrapped in a broad `except Exception` at line 569, which silently swallows the failure. This matches the ticket's "best effort" intent but means learnings may be silently lost.

### Security observations

**SEC-021 adjacency**: `_build_gh_pr_command()` (line 350) now correctly uses single-quote shell escaping rather than the ticket's original `"` + `\\n` approach, fixing the injection vector described in SEC-021 for this path. Branch names coming from terminal output go through `detect_git_state()` regex extraction, which does not additionally sanitize before interpolation into the gh command. If a branch name detected from the terminal contains a single quote, the escaping handles it; if it contains a null byte or other control character, the result is passed to the shell. Low risk since the gh CLI is well-hardened, but worth noting.

**SEC-022 adjacency**: `S.github_token` is read from the environment and never returned in any API response. The `get_agent_pr()` and list endpoints do not expose it. This is correct.

**Webhook HMAC**: When `GITHUB_WEBHOOK_SECRET` is empty in dev mode, the signature check at line 696 returns `True` without computing a MAC — this is the correct dev/prod parity design per SECOPS-007 (dev = no secret → accept; prod = secret required).

---

## 4. Proposed Design / Fix

### Remaining work: live GitHub API

Complete `_create_pr_via_api()` in `app/services/agent_pr_integration.py`:

```python
import httpx

def _create_pr_via_api(*, repo_url, branch, title, description, user_id):
    token = getattr(S, "github_token", "")
    if S.dev_mode or not token:
        # ... existing mock path ...
    # Parse owner/repo from repo_url
    match = re.search(r"github\.com[:/](.+?)/.+?(\.git)?$", repo_url)
    if not match:
        raise ValueError("Cannot parse owner/repo from repo_url")
    owner_repo = match.group(1) + "/" + ...
    resp = httpx.post(
        f"https://api.github.com/repos/{owner_repo}/pulls",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
        json={"title": title, "body": description, "head": branch, "base": "main"},
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()
```

### DDB efficiency: add GSI for PR URL lookup

Add to `scripts/local-ddb-init.py` under the `agent_workers` table a GSI: PK = `pr_url_gsi_pk` (S, value `PR_URL#{pr_url}`), SK = `created_at` (N). Fan-out write in `create_pr_from_agent()` when `pr_url` is non-empty. Replace the scan in `_find_pr_by_url()` with a GSI query. Per SECOPS-007, this table lives in DDB Local in dev and AWS DynamoDB in prod — no extra abstraction needed.

### Dev/Prod parity (SECOPS-007)

Current parity is correct:
- Dev: `S.dev_mode=True` or `github_token=""` → mock PR API, no outbound HTTP.
- Prod: `GITHUB_TOKEN` set, `DEV_MODE=0` → live GitHub API call.
- Same code path; branch selected by `if S.dev_mode or not token:`.

No changes to the flag structure are needed.

---

## 5. Testing, Verification & Rollout

### pytest unit tests (`tests/test_agent_pr_integration.py`)

Concrete cases to cover (moto for DDB, `unittest.mock.patch` for external calls):
- `test_detect_git_state_branch_and_pr_url`: feed multiline git output, assert `state["branch"]` and `state["pr_url"]` extracted correctly
- `test_detect_git_state_empty_output`: assert all defaults returned without error
- `test_create_pr_cli_mode_dev`: call `create_pr_from_agent(method="cli")` with `dev_mode=True`; assert PR record in DDB with `method="cli"`, `gh_command` containing the ticket title, ticket META updated with `pr_status="open"`
- `test_create_pr_api_mode_dev`: call `create_pr_from_agent(method="api")`; assert mock `pr_url` with `/pull/` and `pr_number > 0`
- `test_build_gh_pr_command_single_quote_injection`: title and body containing `'` → assert single-quote is escaped; no shell metacharacter in the flat string representation
- `test_apply_status_core`: `_apply_status(ticket_id, "system", "in_progress")` calls `TicketStore.update_status`
- `test_apply_status_agent_lifecycle`: `_apply_status(ticket_id, "system", "code_complete")` writes `agent_status` on META item without calling `update_status`
- `test_cross_agent_handoff`: after `_trigger_cross_agent_handoff(ticket_id, "qa")`, ticket META has `agent_eligible=yes`, `next_agent_type=qa`, `agent_worker_id=""`
- `test_webhook_signature_no_secret_dev`: with empty `github_webhook_secret`, `verify_webhook_signature(b"x", "anything")` returns True
- `test_webhook_signature_valid`: with a secret, correct HMAC passes; tampered signature fails
- `test_handle_pr_merged`: put a PR record in DDB; fire webhook event; assert PR item has `status=merged`, ticket META has `pr_status=merged` and `agent_status=done`
- `test_list_agent_prs_filtered_by_worker`: create two PRs for different workers; filter by worker_id returns only one

### Playwright E2E

Existing spec `frontend/e2e/agent-pr-integration.spec.ts` covers sections 647–650. Run with:
```
cd frontend && npx playwright test e2e/agent-pr-integration.spec.ts
```
All four sections should pass offline (mock GitHub in dev mode). Manual check: navigate `/agents/prs`, confirm PR table renders, "open" status badge is visible, "View Ticket" link present.

### Observability

`audit_event("agent.pr_created", …)` is called at `agent_pr_integration.py:478`. Ensure the alert store writes successfully (a unit test for this). Consider adding `audit_event("agent.work_completed", …)` in `complete_agent_work()` after the orchestrator call.

### Rollout

- Deploy with `GITHUB_TOKEN=""` and `GITHUB_WEBHOOK_SECRET=""` in dev (current default). All E2E tests run offline.
- To enable live GitHub integration: set `GITHUB_TOKEN` and `GITHUB_WEBHOOK_SECRET` in prod `.env`, configure a GitHub webhook pointing to `POST /ui/agent/webhooks/github`.
- No DDB migration needed — PR records and FLOW records are additive to the existing `agent_workers` table.

**Effort estimate**: S (core done; remaining gap is the ~20-line live GitHub API call and an optional GSI). **Suggested order**: (1) write the live `httpx` call for `method="api"`, (2) add webhook GSI, (3) add missing unit tests.
