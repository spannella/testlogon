# AGENT-015: Compliance & Security Agent — Investigation & Implementation Write-up

## 1. Summary & Classification

AGENT-015 defines the Compliance & Security Agent, a continuously running agent type that reviews pull requests and the full codebase for security vulnerabilities and compliance violations. It classifies findings against OWASP Top 10 categories, GDPR data handling requirements, PCI DSS payment flow controls, and WCAG accessibility standards. Critical and high-severity findings trigger automatic remediation ticket creation. Periodic full-codebase audits run on a configurable schedule. The agent maintains a finding status workflow (open → acknowledged → remediated / false_positive / accepted_risk) and provides trend dashboards with per-framework compliance status.

**Type**: Feature (new agent type + security finding / audit tracking system). **Priority**: High. **Status**: Implemented (service + router + frontend + DDB tables all present). **Persona**: Platform owner / security reviewer.

Cross-references: **SEC-021** (command injection — real scanning via `compliance_agent_execute_commands` gates shell exec of git clone / dependency scanners). **SEC-022** (credential exposure — `security_config` on `agent_types` table must not store plaintext GitHub tokens; PR review service account tokens should be in secrets manager). **SECOPS-007** (dev/prod parity — all scanning execution gated; mock audit lifecycle deterministic).

---

## 2. Current-State Investigation (what exists today)

### 2.1 Backend Service

`app/services/agent_compliance.py` (1082 lines). Module docstring (lines 1–18) identifies this as AGENT-015.

- **Table bootstrap** (`ensure_tables`, line 149): Creates `agent_types` (reused), `compliance_security_findings`, and `compliance_security_audits` tables in-process. The `compliance_security_findings` table has three GSIs: GSI1 on severity (`USER#{id}#SEVERITY#{sev}`), GSI2 on status (`USER#{id}#STATUS#{status}`), GSI3 on source_ref (`USER#{id}#SOURCE#{ref}`). Table names at `settings.py:2260–2264`. Table handles at `app/core/tables.py:517–518` (`compliance_findings`, `compliance_audits`).

- **Security config** (`validate_security_config`, `_normalize_config`, `get_security_config`, `update_security_config`, lines 299–430): Config stored on `agent_types` table as `SECURITY_CONFIG` item. Validation checks: `periodic_audit_frequency` in allowed values, `periodic_audit_day` is a weekday, `hour_utc` in 0–23, `wcag_level` in A/AA/AAA, `compliance_frameworks` is a subset of allowed frameworks, `remediation_ticket_min_severity` is a valid severity. Effective config (`get_effective_config`, line 432) merges stored config with defaults.

- **Finding CRUD** (`create_finding`, `get_finding`, `list_findings`, lines 510–691): `create_finding` (line 510) validates `severity` and `category` enums. Writes to `compliance_security_findings` with three GSI projections. Auto-creates remediation tickets when `auto_create_remediation_tickets=True` and `severity_rank(severity) >= severity_rank(remediation_ticket_min_severity)` (lines 557–583). `_remediation_ticket_body` (line 591) formats a detailed ticket body with file path, line range, code snippet, and remediation text. `list_findings` (line 619) routes to the appropriate GSI based on the filter combination: severity→GSI1, status→GSI2, source_ref→GSI3, or PK scan for no filter.

- **Finding status workflow** (`update_finding_status`, line 692): Validates status transitions — `open → acknowledged | false_positive | accepted_risk`, `acknowledged → remediated | false_positive | accepted_risk`, `remediated → open` (reopens). Sets `resolved_at` on terminal statuses. Raises `FindingValidationError("INVALID_STATUS_TRANSITION", ...)` on invalid moves.

- **Verification** (`verify_remediation`, line 742): Returns context (finding + remediation ticket content) for the agent to re-examine. Agent updates status via the normal `update_finding_status` path.

- **Audit lifecycle** (`start_audit`, `complete_audit`, `get_running_audit`, `list_audits`, `run_mock_audit`, lines 788–940): `start_audit` writes audit record with `status=running`. `get_running_audit` (line 788) queries `compliance_audits` for any item with `status=running` for a user (PK scan — could miss concurrent audits on a busy table; see gaps). `run_mock_audit` (line 909) is the deterministic mock path: aggregates current open findings into `finding_counts`, computes `compliance_summary`, calls `complete_audit`. Real scanning gated by `S.compliance_agent_execute_commands` (`settings.py:2271`).

- **Finding trends** (`get_finding_trends`, `_all_findings`, lines 942–996): `_all_findings` does a full PK scan of `compliance_security_findings` for the user, optionally filtered by `since_ts` using a DDB `FilterExpression`. Groups findings into weekly buckets. Returns trend data for charting.

- **Compliance status** (`_compute_compliance_summary`, `get_compliance_status`, lines 996–1040): Maps OWASP/GDPR/PCI/WCAG categories to framework membership. Returns per-framework `passed`/`failed`/`open_findings` counts. `status` = `failing` if `open_findings > 0`, else `passing`.

- **PR review mock** (`review_pr_mock`, line 1041): Deterministic mock that creates a fixed set of synthetic findings for a PR. Real PR scanning (cloning, running tools) gated by `S.compliance_agent_execute_commands`.

### 2.2 Backend Router

`app/routers/agent_compliance.py` (263 lines). Router prefixes: `/ui/agents/security` (renamed from `/ui/agents/compliance` for the findings endpoints) and config endpoints. Router variable: `agent_compliance_router`. Registered in `app/main.py:783`.

Auth split:
- Most read endpoints (`list_findings`, `get_finding`, `list_audits`, `get_trends`, `get_compliance`, `get_config`) use `require_ui_session` — scoped to authenticated `user_sub`.
- Write endpoints that trigger audits (`trigger_audit` at line 174, `update_security_config` at line 230) use both `require_ui_session` AND `require_admin_or_root` (double-dependency). This is correct — users can read their own findings but only admins can run audits or change config.

Routes implemented (matching ticket §3.3):
- `GET /ui/agents/security/findings` → list with `?severity=`, `?status=`, `?source_ref=`
- `GET /ui/agents/security/findings/{finding_id}` → single finding
- `PATCH /ui/agents/security/findings/{finding_id}/status` → update status
- `GET /ui/agents/security/audits` → list audits
- `GET /ui/agents/security/audits/{audit_id}` → audit detail
- `POST /ui/agents/security/audits/trigger` → admin-gated, triggers `run_mock_audit`
- `GET /ui/agents/security/trends` → finding trends
- `GET /ui/agents/security/compliance` → compliance status
- `PUT /ui/agents/security/config` → admin-gated config update
- `GET /ui/agents/security/config` → read config

Note: The ticket §3.3 specifies `POST /ui/agents/security/audits/trigger` but the router also exposes a `GET /ui/agents/security/config/schema` endpoint (line 50) not in the original spec — this returns the `config_schema()` dict for frontend validation.

### 2.3 Frontend

Routes in `frontend/src/App.tsx`:
- `agents/compliance` → `ComplianceAgentConfigPage` (lazy, line 234, 493)
- `agents/security` → `ComplianceAgentConfigPage` (line 494, same component as `/compliance`)
- `agents/security/findings` → `ComplianceAgentConfigPage` (line 495)
- `agents/security/audits` → `ComplianceAgentConfigPage` (line 496)

Frontend pages at:
- `frontend/src/pages/agents/ComplianceAgentConfigPage.tsx`

Note: The ticket spec called for separate `SecurityDashboardPage`, `FindingsListPage`, `AuditHistoryPage`, and `CompliancePanel` components. The implementation consolidates these into a single tabbed `ComplianceAgentConfigPage`. The individual component files named in the ticket (`SecurityDashboardPage.tsx`, etc.) do not exist separately — all functionality is in `ComplianceAgentConfigPage.tsx`.

### 2.4 Dev/Prod Parity

Feature flags in `app/core/settings.py`:

| Flag | Setting key | Default | Purpose |
|------|-------------|---------|---------|
| `SECURITY_AGENT_ENABLED` | (no standalone flag; included in agent block) | controlled by `agent_workers_enabled` | Router registration |
| `COMPLIANCE_AGENT_EXECUTE_COMMANDS` | `compliance_agent_execute_commands` (line 2271) | `"0"` (off) | Real scanning vs mock |

Real scanning execution (`compliance_agent_execute_commands=True`) would dispatch git clone, dependency scanners, and SAST tools via the Worker Agent Framework. Current implementation (`False`) uses `run_mock_audit` (line 909) — aggregates existing findings deterministically, no subprocess/shell calls. DDB uses DynamoDB Local in dev. Satisfies SECOPS-007.

SEC-022 note: the `security_config.severity_thresholds` map is stored in plain DDB as part of `SECURITY_CONFIG`. No secrets are in `security_config` directly. The ticket spec §7 mentions "GitHub review service account token stored in secrets manager" — this is not yet wired in the current implementation (no `github_token_secret` field exists in the config schema or the service code).

---

## 3. Gap / Threat Analysis

### 3.1 What Is Implemented

All core service functions are present: finding CRUD, status workflow, audit lifecycle (start/complete/mock), trends, compliance status, PR review mock. Router endpoints match the spec. DDB tables with correct GSI definitions are created via `ensure_tables` and `scripts/local-ddb-init.py:2083–2098`. Settings flags and table name settings are wired.

### 3.2 Gaps and Risks

1. **`get_running_audit` uses PK scan, not indexed lookup** (line 788): Queries `compliance_audits` with `begins_with(sk, 'AUDIT#')` and Python-level filter for `status=running`. For users with many audit records, this scans the full partition. The ticket spec §3.1.2 defines GSI1 on `USER#{user_id}#AUDITS` with `started_at` sort key — but does not define a GSI for `status=running`. A dedicated `running_audit` lock item (e.g., `sk=RUNNING`) would be more efficient.

2. **Concurrent audit trigger race condition** (409 not guaranteed): `trigger_audit` (router line ~174) calls `get_running_audit` (read) then `start_audit` (write). Between these two operations a second concurrent request could also pass `get_running_audit` and both would write `status=running`. A DDB conditional expression on `start_audit` would prevent this: `ConditionExpression="attribute_not_exists(pk)"` on a `RUNNING_LOCK` item.

3. **SEC-021 (command injection) — latent**: When `compliance_agent_execute_commands=True`, the Worker Agent Framework would execute git operations with PR diffs and repo URLs from the ticket/PR system. The service currently has no `repo_url` validation in `review_pr_mock` (line 1041). Before enabling real execution, PR source URLs must be validated against allowed repositories (same fix as SEC-021 for coder/architect agents).

4. **SEC-022 (credential exposure)**: `GET /ui/agents/security/config` returns the full `security_config` dict. If a future config extension adds a `github_service_token` field (for PR blocking), it must be stripped from API responses — expose only a `has_github_token: bool`. The Pydantic model `UpdateSecurityConfigIn` should never accept plaintext tokens.

5. **Finding trend aggregation scans all findings** (`_all_findings`, line 942): Full PK scan with optional `FilterExpression` on `created_at`. For users with thousands of findings, this is O(all findings). The `since_ts` filter is applied after fetching (DDB FilterExpression doesn't reduce pages scanned). Should use the GSI1/GSI2 scan with `ScanIndexForward` and a timestamp range if available.

6. **Frontend consolidation deviation**: The ticket spec called for four separate component files. The implementation uses one consolidated `ComplianceAgentConfigPage`. While functionally equivalent, the `data-testid` values referenced in E2E tests (`security-dashboard-page`, `findings-list`, `audit-history`, `compliance-panel`) must be present inside the consolidated page to ensure E2E specs pass.

---

## 4. Proposed Design / Fix

### 4.1 Concurrent Audit Prevention

Add a conditional DDB write in `start_audit` (line 801):

```python
def start_audit(*, user_id: str, agent_id: str, worker_id: str = "") -> dict:
    # First, check for running audit with a conditional write lock
    try:
        T.compliance_audits.put_item(
            Item={"pk": _user_pk(user_id), "sk": "RUNNING_LOCK",
                  "agent_id": agent_id, "started_at": now_ts()},
            ConditionExpression="attribute_not_exists(pk)",
        )
    except ClientError as exc:
        if "ConditionalCheckFailed" in str(exc):
            raise FindingValidationError("AUDIT_IN_PROGRESS", "A security audit is already in progress")
        raise
    # Proceed with normal audit record creation...
```

Delete `RUNNING_LOCK` item in `complete_audit` and on audit failure.

### 4.2 SEC-021 Pre-checks for Real Execution

When `compliance_agent_execute_commands=True`, add a repo URL allowlist check before dispatching to the Worker Agent Framework. Accept only URLs from configured `allowed_repo_hosts` (e.g., `github.com`, `gitlab.com`). Reject `file://`, `ext::`, and private-network URLs.

### 4.3 GitHub Token Isolation (SEC-022)

Do not add `github_token` to `security_config` DDB record. Instead, reference a secrets manager key name: `github_token_secret_name: str` in config. At execution time, the Worker Agent Framework resolves this to the actual token from AWS Secrets Manager (prod) or mock KMS (dev) via `app/core/crypto.py`. This follows the existing SSH key and LLM key patterns from AGENT-001.

### 4.4 Dev/Prod Parity (SECOPS-007)

Current implementation satisfies SECOPS-007:
- `compliance_agent_execute_commands=False` → `run_mock_audit` only; no subprocess, no outbound calls.
- DDB via `app/core/aws.py` → DynamoDB Local in dev, real DDB in prod.
- Remediation ticket creation uses `tickets_svc.STORE.create_ticket` → DDB-backed in both environments.
- No scattered `if dev:` in business logic; flag-selected at the `trigger_audit` dispatch point.

---

## 5. Testing, Verification & Rollout

### 5.1 E2E Tests

Ticket spec: `frontend/e2e/agent-compliance.spec.ts` (the spec also references `agent-security.spec.ts`). Sections 679–682 (16 tests).

Key scenarios:
- **679.1**: `POST /ui/agents/security/findings` (simulates agent output) with `severity="critical"`, `category="injection"`; 201; `status="open"`, `finding_id` present.
- **680.1**: `PATCH .../findings/{id}/status` with `status="acknowledged"`; 200; `status="acknowledged"`.
- **680.3**: `PATCH .../findings/{id}/status` with `status="remediated"`; 200; `resolved_at` is non-null.
- **681.1**: `POST /ui/agents/security/audits/trigger` (admin); 200; `audit_id`, `status="running"` → mock completes → `status="completed"`.
- **681.2**: Double-trigger audit; second returns 409 `AUDIT_IN_PROGRESS`.
- **681.3**: `GET /ui/agents/security/trends?days=30`; `weeks` array present.
- **682.1**: Navigate `/agents/security`; `ComplianceAgentConfigPage` renders with `[data-testid="security-dashboard-page"]` or equivalent visible.

Auth: `trigger_audit` requires admin (root session). Findings read requires only `require_ui_session`.

### 5.2 Unit Tests

File: `tests/test_compliance_agent.py`. Key cases:
- `test_create_finding_valid_severity`: All five severities accepted; stored correctly with all three GSI projections set.
- `test_create_finding_invalid_category`: `FindingValidationError("INVALID_CATEGORY", ...)`.
- `test_status_transition_open_to_remediated`: Direct `open → remediated` transition accepted; `resolved_at` timestamp is set.
- `test_status_transition_invalid`: `remediated → acknowledged` raises `INVALID_STATUS_TRANSITION`.
- `test_auto_remediation_ticket_creation`: With `auto_create_remediation_tickets=True` and `remediation_ticket_min_severity="high"`, creating a `critical` finding calls `tickets_svc.STORE.create_ticket` with a body containing the `file_path` and `code_snippet`.
- `test_auto_remediation_ticket_skipped_for_low`: Creating a `low` severity finding when `remediation_ticket_min_severity="high"` does NOT call `create_ticket`.
- `test_run_mock_audit_aggregates_findings`: Seed 2 critical + 1 high + 3 medium open findings; `run_mock_audit` produces `finding_counts={"critical": 2, "high": 1, "medium": 3, "low": 0, "info": 0}`.
- `test_run_mock_audit_completes`: `start_audit` → `run_mock_audit` → `get_audit` returns `status="completed"` and `completed_at` is non-null.
- `test_concurrent_audit_prevention`: Two `start_audit` calls; second raises `AUDIT_IN_PROGRESS` on the second (after §4.1 fix is applied).
- `test_get_compliance_status_failing`: With `injection` category finding in `open` status, `owasp_top_10` framework shows `status="failing"`, `open_findings > 0`.
- `test_list_findings_by_severity`: Create 2 critical + 1 medium findings; `list_findings(severity="critical")` returns exactly 2.
- `test_finding_trend_weekly_buckets`: Create findings over 4 weeks; `get_finding_trends(days=30)` returns `weeks` array with 4 entries.

### 5.3 Rollout

Incremental rollout (ticket §17.2):
- **Week 1**: `SECURITY_AGENT_ENABLED=1`, `compliance_agent_execute_commands=0`. Audit-only (mock). No PR blocking, no ticket creation.
- **Week 2**: `SECURITY_REMEDIATION_TICKETS_ENABLED=1` (equivalent to `auto_create_remediation_tickets`). Monitor ticket creation rate and false-positive rate.
- **Week 3**: `compliance_agent_execute_commands=1`. Real scanning. Monitor performance and false positives.
- **Week 4**: `SECURITY_PR_BLOCK_ENABLED=1` (equivalent to `block_merge_on_critical`). Only after verifying low false-positive rate.

Tables (`compliance_security_findings`, `compliance_security_audits`) defined in `scripts/local-ddb-init.py:2083–2098`. Additive.

**Effort**: M (service complete; concurrent audit race condition and SEC-021/022 hardening are targeted fixes).

**Risks**: 
- Finding trend aggregation performance at scale (>10K findings).
- SEC-021 command injection when real scanning is enabled.
- SEC-022 GitHub token must not be stored in DDB config.
- `get_running_audit` PK scan is a correctness risk for concurrent audit prevention before the conditional write fix is applied.
