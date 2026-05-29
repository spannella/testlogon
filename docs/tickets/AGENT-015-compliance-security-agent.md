# AGENT-015: Compliance & Security Agent

**Ticket**: AGENT-015
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: High
**Estimated effort**: 12-14 days
**Dependencies**: AGENT-001 (Agent Registry), AGENT-002 (Terminal Provisioning), AGENT-003 (Worker Agent Framework), AGENT-004 (Ticket Lifecycle Bridge), AGENT-005 (Context Injection & Output Parsing), AGENT-006 (Agent Monitoring & Health), AGENT-007 (Orchestration Dashboard)

---

## 1. Overview & Motivation

### 1.1 Purpose

AGENT-015 defines the Compliance & Security Agent type -- a continuously running agent that monitors all tickets and pull requests for security vulnerabilities and compliance violations. The agent reviews every PR diff against OWASP Top 10 categories (SQL injection, XSS, hardcoded secrets, insecure authentication), checks compliance requirements (GDPR data handling, PCI for payment flows, WCAG accessibility), and adds severity-rated comments on tickets and PRs flagging concerns. When critical or high-severity issues are found, the agent creates remediation tickets and can optionally block PR merge via review status. It also performs periodic full-codebase security audits on a configurable schedule (weekly or monthly), producing comprehensive vulnerability reports.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Owner | As a platform owner, I want every PR automatically reviewed for security issues. | Agent posts security review comments on every PR with severity ratings. |
| Owner | As a platform owner, I want to enforce GDPR compliance in code changes. | Agent flags data handling patterns that violate GDPR (missing consent, improper PII storage). |
| Owner | As a platform owner, I want PCI compliance checked for payment code. | Agent identifies insecure payment data handling and flags PCI DSS violations. |
| Owner | As a platform owner, I want critical security issues to block deployments. | Configurable: critical findings set PR review to "changes requested". |
| Owner | As a platform owner, I want remediation tickets created for findings. | Agent creates `type:security` tickets with reproduction steps and fix guidance. |
| Developer | As a developer, I want clear security guidance on my PRs. | Comments include specific line references, vulnerability description, and remediation suggestion. |
| Owner | As a platform owner, I want periodic full codebase security audits. | Scheduled audit produces a comprehensive vulnerability report. |
| Owner | As a platform owner, I want to track security finding trends over time. | Dashboard shows finding counts by severity over time, resolution rates. |

### 1.3 Why This Is Needed

Security vulnerabilities in production code are the most costly defects to fix -- exponentially more expensive than catching them during code review. Manual security reviews are inconsistent, depend on reviewer expertise, and cannot scale to cover every PR. An autonomous Compliance & Security Agent provides consistent, comprehensive security analysis on every code change, catches common vulnerability patterns that human reviewers miss under time pressure, and enforces compliance framework requirements automatically. The periodic audit capability provides a safety net for vulnerabilities that slip through individual PR reviews.

---

## 2. Current State Analysis

### 2.1 Existing Infrastructure

- **Agent Registry** (AGENT-001): Agent type definitions, configuration schemas.
- **Worker Agent Framework** (AGENT-003): Task execution, context injection, output parsing.
- **Ticket Lifecycle Bridge** (AGENT-004): Agent-to-ticket integration for creating remediation tickets.
- **Security hardening docs** (`docs/security-hardening-runbook.md`): Existing security configuration reference.
- **Auth system** (`app/auth/deps.py`): Cookie auth, CSRF, JWT verification -- patterns the agent should validate.
- **Billing integrations** (`app/routers/billing.py`): Stripe/PayPal/CCBill -- PCI-relevant code.
- **Ticketing system** (`app/services/tickets.py`): Ticket CRUD for creating security remediation tickets.

### 2.2 Gaps

1. No agent type profile for security review workflows.
2. No automated PR security review integration.
3. No security finding model with severity, category, and remediation tracking.
4. No compliance framework rule definitions (GDPR, PCI, WCAG).
5. No mechanism to block PR merge based on security findings.
6. No periodic codebase audit scheduler.
7. No security finding trend dashboard.

---

## 3. Technical Design

### 3.1 Data Model

#### 3.1.1 SecurityFindings Table

Stores individual security findings from PR reviews and periodic audits.

| Field | Type | Description |
|-------|------|-------------|
| `pk` | S | `USER#{user_id}` |
| `sk` | S | `FINDING#{finding_id}` |
| `finding_id` | S | UUID hex |
| `user_id` | S | Platform owner |
| `agent_id` | S | Security Agent instance |
| `source` | S | `pr_review`, `ticket_review`, `periodic_audit`, `manual_scan` |
| `source_ref` | S | PR number, ticket ID, or audit ID |
| `severity` | S | `critical`, `high`, `medium`, `low`, `info` |
| `category` | S | OWASP or compliance category (see below) |
| `title` | S | Short finding title (max 200 chars) |
| `description` | S | Detailed description with evidence (max 5000 chars) |
| `file_path` | S (optional) | Affected source file |
| `line_range` | S (optional) | `start_line-end_line` |
| `code_snippet` | S (optional) | Relevant code excerpt (max 1000 chars) |
| `remediation` | S | Suggested fix (max 2000 chars) |
| `status` | S | `open`, `acknowledged`, `remediated`, `false_positive`, `accepted_risk` |
| `remediation_ticket_id` | S (optional) | Ticket created for remediation |
| `resolved_at` | N (optional) | Unix timestamp when resolved |
| `created_at` | N | Unix timestamp |
| `GSI1PK` | S | `USER#{user_id}#SEVERITY#{severity}` |
| `GSI1SK` | N | `created_at` |
| `GSI2PK` | S | `USER#{user_id}#STATUS#{status}` |
| `GSI2SK` | N | `created_at` |
| `GSI3PK` | S | `USER#{user_id}#SOURCE#{source_ref}` |
| `GSI3SK` | N | `created_at` |

```python
TableDef(
    "agent_security_findings", "pk", "sk",
    gsi=[
        {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
        {"index_name": "GSI2", "partition_key": "GSI2PK", "sort_key": "GSI2SK"},
        {"index_name": "GSI3", "partition_key": "GSI3PK", "sort_key": "GSI3SK"},
    ],
    attr_types={
        "created_at": "N", "resolved_at": "N",
        "GSI1SK": "N", "GSI2SK": "N", "GSI3SK": "N",
    },
),
```

#### 3.1.2 SecurityAudits Table

Tracks periodic full-codebase audit runs and their results.

| Field | Type | Description |
|-------|------|-------------|
| `pk` | S | `USER#{user_id}` |
| `sk` | S | `AUDIT#{audit_id}` |
| `audit_id` | S | UUID hex |
| `agent_id` | S | Agent that performed the audit |
| `worker_id` | S | Worker that executed the audit |
| `status` | S | `running`, `completed`, `failed` |
| `started_at` | N | Unix timestamp |
| `completed_at` | N (optional) | Unix timestamp |
| `finding_counts` | S | JSON map `{"critical": 0, "high": 2, "medium": 5, "low": 8, "info": 3}` |
| `files_scanned` | N | Number of files analyzed |
| `compliance_summary` | S | JSON map of compliance framework pass/fail counts |
| `report_s3_key` | S (optional) | S3 key for full audit report |
| `GSI1PK` | S | `USER#{user_id}#AUDITS` |
| `GSI1SK` | N | `started_at` |

```python
TableDef(
    "agent_security_audits", "pk", "sk",
    gsi=[
        {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
    ],
    attr_types={
        "started_at": "N", "completed_at": "N",
        "files_scanned": "N", "GSI1SK": "N",
    },
),
```

#### 3.1.3 Compliance Rules Configuration (on Agent Registry Record)

Stored as a DDB map on the agent registry entry (`security_config` field):

```json
{
  "scan_on_pr": true,
  "scan_on_ticket_update": true,
  "block_merge_on_critical": true,
  "block_merge_on_high": false,
  "periodic_audit_frequency": "weekly",
  "periodic_audit_day": "sunday",
  "periodic_audit_hour_utc": 2,
  "compliance_frameworks": ["owasp_top_10", "gdpr", "pci_dss"],
  "wcag_level": "AA",
  "severity_thresholds": {
    "hardcoded_secret": "critical",
    "sql_injection": "critical",
    "xss": "high",
    "insecure_auth": "high",
    "missing_csrf": "high",
    "pii_logging": "high",
    "missing_input_validation": "medium",
    "insecure_dependency": "medium",
    "missing_rate_limit": "low"
  },
  "ignored_paths": ["node_modules/", ".venv/", "tests/", "frontend/e2e/"],
  "auto_create_remediation_tickets": true,
  "remediation_ticket_min_severity": "high"
}
```

#### 3.1.4 Finding Categories

| Category | Framework | Description |
|----------|-----------|-------------|
| `injection` | OWASP A03 | SQL injection, NoSQL injection, command injection |
| `broken_auth` | OWASP A07 | Insecure authentication, missing session management |
| `xss` | OWASP A03 | Cross-site scripting (stored, reflected, DOM-based) |
| `insecure_design` | OWASP A04 | Missing security controls, insecure defaults |
| `security_misconfig` | OWASP A05 | Hardcoded secrets, debug mode in prod, permissive CORS |
| `vulnerable_components` | OWASP A06 | Known vulnerable dependencies |
| `crypto_failure` | OWASP A02 | Weak encryption, missing TLS, insecure hashing |
| `access_control` | OWASP A01 | Broken access control, IDOR, privilege escalation |
| `logging_monitoring` | OWASP A09 | Missing audit logs, insufficient monitoring |
| `ssrf` | OWASP A10 | Server-side request forgery |
| `gdpr_pii` | GDPR | PII in logs, missing consent, improper data retention |
| `gdpr_rights` | GDPR | Missing data export/deletion, no consent withdrawal |
| `pci_card_data` | PCI DSS | Card data in logs, unencrypted storage, missing masking |
| `pci_transmission` | PCI DSS | Insecure transmission of payment data |
| `wcag_contrast` | WCAG | Insufficient color contrast ratio |
| `wcag_keyboard` | WCAG | Missing keyboard navigation |
| `wcag_aria` | WCAG | Missing ARIA labels, roles |

### 3.2 Backend Service (`app/services/agent_security.py`)

```python
def create_finding(*, user_id: str, agent_id: str, source: str,
                    source_ref: str, severity: str, category: str,
                    title: str, description: str, file_path: str | None = None,
                    line_range: str | None = None, code_snippet: str | None = None,
                    remediation: str = "") -> dict:
    """Create a security finding from an agent review."""
    # 1. Validate severity and category enums
    # 2. Generate finding_id
    # 3. Write to SecurityFindings table
    # 4. If auto_create_remediation_tickets and severity >= threshold, create ticket
    # 5. Return finding dict

def list_findings(*, user_id: str, severity: str | None = None,
                   status: str | None = None, source_ref: str | None = None,
                   limit: int = 50, cursor: str | None = None) -> dict:
    """List findings filtered by severity, status, or source."""
    # Query appropriate GSI based on filter
    # Return {"findings": [...], "next_cursor": ...}

def update_finding_status(*, user_id: str, finding_id: str,
                            status: str, note: str | None = None) -> dict:
    """Update finding status (acknowledge, mark remediated, false positive, accepted risk)."""
    # 1. Validate status transition
    # 2. Update record
    # 3. If status=remediated, set resolved_at
    # 4. Return updated finding

def verify_remediation(*, user_id: str, finding_id: str,
                         agent_id: str) -> dict:
    """Agent verifies that a remediation ticket fix actually resolves the finding."""
    # 1. Fetch finding and remediation ticket
    # 2. Return context for agent to re-check the code
    # 3. Agent updates status to remediated or reopens

def start_audit(*, user_id: str, agent_id: str, worker_id: str) -> dict:
    """Start a periodic security audit."""
    # 1. Create audit record with status=running
    # 2. Return audit context for injection into agent terminal

def complete_audit(*, user_id: str, audit_id: str,
                     finding_counts: dict, files_scanned: int,
                     compliance_summary: dict,
                     report_s3_key: str | None = None) -> dict:
    """Mark an audit as completed with results."""

def list_audits(*, user_id: str, limit: int = 20,
                 cursor: str | None = None) -> dict:
    """List past security audits."""

def get_finding_trends(*, user_id: str, days: int = 90) -> dict:
    """Aggregate finding counts by severity and category over time."""
    # 1. Query findings from last N days
    # 2. Group by week, severity, category
    # 3. Return trend data for charting

def get_compliance_status(*, user_id: str) -> dict:
    """Get current compliance status per framework."""
    # 1. Fetch latest audit compliance_summary
    # 2. Fetch open findings by compliance category
    # 3. Return per-framework pass/fail/open counts
```

### 3.3 Backend Router (`app/routers/agent_security.py`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/ui/agents/security/findings` | `require_ui_session` | List findings (filters: `?severity=`, `?status=`, `?source_ref=`) |
| GET | `/ui/agents/security/findings/{finding_id}` | `require_ui_session` | Get finding detail |
| PATCH | `/ui/agents/security/findings/{finding_id}/status` | `require_ui_session` | Update finding status |
| GET | `/ui/agents/security/audits` | `require_ui_session` | List past audits |
| GET | `/ui/agents/security/audits/{audit_id}` | `require_ui_session` | Get audit detail with finding counts |
| POST | `/ui/agents/security/audits/trigger` | `require_ui_session` | Manually trigger a security audit |
| GET | `/ui/agents/security/trends` | `require_ui_session` | Get finding trend data (optional `?days=`) |
| GET | `/ui/agents/security/compliance` | `require_ui_session` | Get compliance status per framework |
| PUT | `/ui/agents/security/config` | `require_ui_session` | Update Security Agent config |
| GET | `/ui/agents/security/config` | `require_ui_session` | Get current Security Agent config |

**Key request models**:

```python
class UpdateFindingStatusIn(BaseModel):
    status: Literal["acknowledged", "remediated", "false_positive", "accepted_risk"]
    note: Optional[str] = Field(default=None, max_length=1000)

class UpdateSecurityConfigIn(BaseModel):
    scan_on_pr: Optional[bool] = None
    scan_on_ticket_update: Optional[bool] = None
    block_merge_on_critical: Optional[bool] = None
    block_merge_on_high: Optional[bool] = None
    periodic_audit_frequency: Optional[Literal["daily", "weekly", "biweekly", "monthly"]] = None
    periodic_audit_day: Optional[str] = None
    periodic_audit_hour_utc: Optional[int] = Field(default=None, ge=0, le=23)
    compliance_frameworks: Optional[List[Literal["owasp_top_10", "gdpr", "pci_dss", "wcag"]]] = None
    wcag_level: Optional[Literal["A", "AA", "AAA"]] = None
    severity_thresholds: Optional[Dict[str, Literal["critical", "high", "medium", "low", "info"]]] = None
    ignored_paths: Optional[List[str]] = None
    auto_create_remediation_tickets: Optional[bool] = None
    remediation_ticket_min_severity: Optional[Literal["critical", "high", "medium", "low"]] = None
```

Register in `app/main.py`:

```python
from app.routers.agent_security import router as agent_security_router
app.include_router(agent_security_router, prefix="/ui")
```

### 3.4 Frontend Types (`frontend/src/api/types.ts`)

```typescript
export interface SecurityFinding {
  finding_id: string;
  agent_id: string;
  source: "pr_review" | "ticket_review" | "periodic_audit" | "manual_scan";
  source_ref: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  category: string;
  title: string;
  description: string;
  file_path?: string;
  line_range?: string;
  code_snippet?: string;
  remediation: string;
  status: "open" | "acknowledged" | "remediated" | "false_positive" | "accepted_risk";
  remediation_ticket_id?: string;
  resolved_at?: number;
  created_at: number;
}

export interface SecurityAudit {
  audit_id: string;
  agent_id: string;
  status: "running" | "completed" | "failed";
  started_at: number;
  completed_at?: number;
  finding_counts: Record<string, number>;
  files_scanned: number;
  compliance_summary: Record<string, { passed: number; failed: number; open: number }>;
  report_s3_key?: string;
}

export interface SecurityTrends {
  weeks: Array<{
    week_start: string;
    by_severity: Record<string, number>;
    by_category: Record<string, number>;
    total: number;
  }>;
}

export interface ComplianceStatus {
  frameworks: Record<string, {
    name: string;
    passed: number;
    failed: number;
    open_findings: number;
    status: "passing" | "failing" | "unknown";
  }>;
}

export interface SecurityAgentConfig {
  scan_on_pr: boolean;
  scan_on_ticket_update: boolean;
  block_merge_on_critical: boolean;
  block_merge_on_high: boolean;
  periodic_audit_frequency: string;
  compliance_frameworks: string[];
  auto_create_remediation_tickets: boolean;
  remediation_ticket_min_severity: string;
}
```

### 3.5 Frontend API (`frontend/src/api/endpoints/agents.ts`)

Standard wrappers: `listFindings(filters?)`, `getFinding(findingId)`, `updateFindingStatus(findingId, status, note?)`, `listAudits()`, `getAudit(auditId)`, `triggerAudit()`, `getFindingTrends(days?)`, `getComplianceStatus()`, `getSecurityConfig()`, `updateSecurityConfig(config)`.

### 3.6 Frontend Pages

- **SecurityDashboardPage** (`frontend/src/pages/agents/SecurityDashboardPage.tsx`): Route `/agents/security`. Summary cards: open criticals (red), open highs (orange), total findings, compliance status. Trend chart showing findings over time. Quick-access tabs: Findings, Audits, Compliance, Config. `data-testid="security-dashboard-page"`.
- **FindingsListPage** (`frontend/src/pages/agents/FindingsListPage.tsx`): Table of findings with severity badges (color-coded), category, status, source ref. Filters: severity, status, source. Click row to expand detail inline. Bulk actions: acknowledge, mark false positive. `data-testid="findings-list"`.
- **AuditHistoryPage** (`frontend/src/pages/agents/AuditHistoryPage.tsx`): List of audit runs with status, date, finding counts bar. Click to view audit detail with per-category breakdown. "Run Audit Now" button. `data-testid="audit-history"`.
- **CompliancePanel** (`frontend/src/pages/agents/CompliancePanel.tsx`): Per-framework compliance cards (OWASP, GDPR, PCI, WCAG). Each shows passed/failed counts with progress bar. Drill-down to related findings. `data-testid="compliance-panel"`.

---

## 4. Implementation Plan

### 4.1 Files to Create

| File | Purpose |
|------|---------|
| `app/services/agent_security.py` | Finding CRUD, audit management, trend aggregation, compliance status |
| `app/routers/agent_security.py` | Security Agent API endpoints |
| `frontend/src/pages/agents/SecurityDashboardPage.tsx` | Security overview dashboard |
| `frontend/src/pages/agents/FindingsListPage.tsx` | Findings list with filters |
| `frontend/src/pages/agents/AuditHistoryPage.tsx` | Audit run history |
| `frontend/src/pages/agents/CompliancePanel.tsx` | Compliance framework status |

### 4.2 Files to Modify

| File | Changes |
|------|---------|
| `scripts/local-ddb-init.py` | Add `agent_security_findings`, `agent_security_audits` TableDefs |
| `app/core/settings.py` | Add table name settings |
| `app/core/tables.py` | Add table handles |
| `app/main.py` | Register `agent_security_router` |
| `app/models.py` | Add `SecurityFindingOut`, `SecurityAuditOut`, `ComplianceStatusOut` models |
| `frontend/src/api/types.ts` | Add security finding, audit, compliance types |
| `frontend/src/api/endpoints/agents.ts` | Add Security Agent API functions |
| `frontend/src/App.tsx` | Add `/agents/security`, `/agents/security/findings`, `/agents/security/audits` routes |

---

## 5. E2E Test Plan

### 5.1 Test File

`frontend/e2e/agent-security.spec.ts` -- 16 tests across 4 sections.

### 5.2 Test Setup

```typescript
const TS = Date.now();
let findingId1: string;
let findingId2: string;
let findingId3: string;
let auditId: string;
// Alice = platform owner
```

### 5.3 Section 679: Security Findings CRUD API (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 679.1 | Create critical finding | POST finding with `severity=critical`, `category=injection`, `source=pr_review`; 201; returns `finding_id`, `status=open` |
| 679.2 | Create high finding with remediation | POST finding with `severity=high`, `category=xss`, `remediation="Escape output..."`; 201; `remediation` stored |
| 679.3 | Create medium compliance finding | POST finding with `severity=medium`, `category=gdpr_pii`; 201; `category` matches |
| 679.4 | List findings by severity | GET `/ui/agents/security/findings?severity=critical`; 200; all results have `severity=critical` |
| 679.5 | Get single finding detail | GET `/ui/agents/security/findings/{findingId1}`; 200; full object with `description`, `code_snippet`, `remediation` |

### 5.4 Section 680: Finding Status Workflow API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 680.1 | Acknowledge finding | PATCH `findings/{findingId2}/status` with `status=acknowledged`; 200; `status=acknowledged` |
| 680.2 | Mark finding as false positive | PATCH `findings/{findingId3}/status` with `status=false_positive`, `note="This is test code"`; 200; `status=false_positive` |
| 680.3 | Mark finding as remediated | PATCH `findings/{findingId1}/status` with `status=remediated`; 200; `resolved_at` is set |
| 680.4 | List open findings only | GET `findings?status=open`; 200; result does not include acknowledged/remediated/false_positive findings |

### 5.5 Section 681: Audit & Compliance API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 681.1 | Trigger security audit | POST `/ui/agents/security/audits/trigger`; 200; returns `audit_id`, `status=running` |
| 681.2 | List audits | GET `/ui/agents/security/audits`; 200; array includes triggered audit |
| 681.3 | Get finding trends | GET `/ui/agents/security/trends?days=30`; 200; `weeks` array present with `by_severity` data |
| 681.4 | Get compliance status | GET `/ui/agents/security/compliance`; 200; `frameworks` object with at least one framework status |

### 5.6 Section 682: Security Dashboard UI (3 tests)

| # | Test | Assertion |
|---|------|-----------|
| 682.1 | Security dashboard loads | Navigate `/agents/security`; `[data-testid="security-dashboard-page"]` visible; summary cards present |
| 682.2 | Findings list with severity badges | Navigate to findings tab; `[data-testid="findings-list"]` visible; severity badges color-coded |
| 682.3 | Update finding status via UI | Click finding row; change status to "Acknowledged"; status badge updates |

---

## 6. Error Handling

| Scenario | Status | Detail |
|----------|--------|--------|
| Finding not found | 404 | "Security finding not found" |
| Invalid severity | 422 | "Invalid severity: {value}" |
| Invalid category | 422 | "Invalid category: {value}" |
| Invalid status transition | 409 | "Cannot transition finding from {current} to {target}" |
| Audit already running | 409 | "A security audit is already in progress" |
| Audit not found | 404 | "Audit not found" |
| Config validation error | 422 | Specific field error message |
| Agent not configured | 404 | "No Security Agent configured for this user" |
| Trend days out of range | 422 | "days must be between 1 and 365" |

---

## 7. Security Considerations

- **Ownership enforcement**: All findings and audits scoped to authenticated `user_id`. Cross-tenant access blocked.
- **Code snippet sanitization**: `code_snippet` field is rendered as preformatted text (not HTML). XSS prevention in frontend display.
- **Finding sensitivity**: Security findings may describe exploitable vulnerabilities. Access is restricted to the platform owner (not shared with other users). No public API for findings.
- **Audit report storage**: Full audit reports stored in S3 with per-user prefix isolation. Presigned URLs for download (15-minute expiry). Reports encrypted at rest (S3 SSE-S3).
- **Agent isolation**: Security Agent terminal runs with read-only access to the codebase (no write access to production systems). Can only create findings and tickets via the API.
- **Rate limiting**: `audits/trigger` endpoint rate-limited to 1 per day per user to prevent resource abuse.
- **Compliance data handling**: The agent itself must follow the same compliance rules it enforces -- no PII in finding descriptions, code snippets truncated to avoid storing full sensitive files.
- **PR review permissions**: If `block_merge_on_critical` is enabled, the agent's GitHub review uses a service account with repository collaborator access. The token is stored in secrets manager, not in DDB config.

---

## 8. Performance Considerations

| Concern | Mitigation |
|---------|-----------|
| Full codebase audit duration | File count and size limits configurable; ignored_paths reduces scope; 60-minute timeout |
| Finding accumulation over time | GSI queries with status filter; closed findings TTL-expired after 365 days |
| Trend aggregation | Pre-computed weekly buckets on audit completion; cached in summary records |
| PR review speed | Agent reviews diff only (not full codebase); target < 5 minutes per PR |
| Concurrent PR reviews | Multiple worker instances can review PRs in parallel; finding writes are idempotent |

---

## 9. Dependencies

| Dependency | Ticket | Status |
|------------|--------|--------|
| AGENT-001 (Agent Registry) | AGENT-001 | Required (agent type definitions, config storage) |
| AGENT-002 (Terminal Provisioning) | AGENT-002 | Required (terminal with codebase access for scanning) |
| AGENT-003 (Worker Agent Framework) | AGENT-003 | Required (continuous execution mode, PR-trigger support) |
| AGENT-004 (Ticket Lifecycle Bridge) | AGENT-004 | Required (creating remediation tickets) |
| AGENT-005 (Context Injection) | AGENT-005 | Required (injecting PR diffs, codebase context) |
| AGENT-006 (Agent Monitoring) | AGENT-006 | Required (monitoring audit runs, alerting on agent failures) |
| AGENT-007 (Orchestration Dashboard) | AGENT-007 | Required (viewing agent activity, audit history) |
| Ticketing system | Existing | Available (remediation ticket creation) |
| GitHub integration | External | Required for PR review comments and merge blocking |

### Downstream

| Ticket | Depends On |
|--------|-----------|
| AGENT-014 (Documentation Agent) | Compliance docs may be triggered by security findings |
| AGENT-018 (Accountant Agent) | Security audit compute costs tracked per audit run |

---

## 10. Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│              Compliance & Security Agent Architecture               │
└─────────────────────────────────────────────────────────────────────┘

  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
  │ PR Webhook   │   │ Schedule     │   │ Manual Scan  │
  │ (GitHub)     │   │ (weekly/     │   │ Trigger      │
  │              │   │  monthly)    │   │              │
  └──────┬───────┘   └──────┬───────┘   └──────┬───────┘
         └──────────────────┼──────────────────┘
                            ▼
  ┌──────────────────────────────────────────────┐
  │     Security Agent Core (agent_security.py)  │
  │                                              │
  │  ┌────────────────┐  ┌───────────────────┐  │
  │  │ PR Review      │  │ Full Audit        │  │
  │  │ - OWASP scan   │  │ - dependency scan │  │
  │  │ - secrets scan │  │ - code scan       │  │
  │  │ - compliance   │  │ - compliance      │  │
  │  │ - XSS/SQLi     │  │ - GDPR/PCI/WCAG  │  │
  │  └────────────────┘  └───────────────────┘  │
  └──────┬──────────────────┬──────────────────┬┘
         │                  │                  │
         ▼                  ▼                  ▼
  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
  │ Findings     │ │ Audit Log    │ │ Ticket System│
  │ Table (DDB)  │ │ Table (DDB)  │ │ remediation  │
  │ 3 GSIs       │ │              │ │ tickets      │
  └──────────────┘ └──────────────┘ └──────────────┘
```

---

## 11. DynamoDB Access Patterns

| Access Pattern | Table | PK | SK | GSI | Notes |
|----------------|-------|----|----|-----|-------|
| Get finding | `security_findings` | `USER#{user_id}` | `FINDING#{id}` | -- | Single item |
| List by severity | `security_findings` | -- | -- | `GSI1PK=USER#{id}#SEV#{sev}` | Critical/High first |
| List by category | `security_findings` | -- | -- | `GSI2PK=USER#{id}#CAT#{cat}` | OWASP categories |
| List open findings | `security_findings` | -- | -- | `GSI3PK=USER#{id}#STATUS#open` | Unresolved items |
| Get audit record | `security_audits` | `USER#{user_id}` | `AUDIT#{id}` | -- | Single item |
| List audits | `security_audits` | `USER#{user_id}` | begins_with `AUDIT#` | -- | All audits |

---

## 12. API Request/Response Examples

```bash
# --- GET /ui/agents/security/findings?severity=critical ---
curl http://localhost:8000/ui/agents/security/findings?severity=critical \
  -H "Cookie: ui_session=sess_abc; ui_access_token=eyJ..."

# Response 200:
{
  "findings": [
    {
      "finding_id": "find-001",
      "category": "hardcoded_secret",
      "severity": "critical",
      "title": "AWS secret key found in source",
      "file_path": "app/services/legacy.py",
      "line_number": 42,
      "description": "Hardcoded AWS_SECRET_ACCESS_KEY detected",
      "remediation": "Move to environment variable or secrets manager",
      "status": "open",
      "created_at": 1748534400
    }
  ],
  "count": 1
}

# --- POST /ui/agents/security/audit ---
curl -X POST http://localhost:8000/ui/agents/security/audit \
  -H "Cookie: ui_session=sess_abc; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_tok_123"

# Response 202:
{
  "audit_id": "audit-abc-123",
  "status": "in_progress",
  "started_at": 1748534400
}
```

---

## 13. Error Handling Matrix

| Error Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|----------------|-------------|------------|---------------------|-----------------|
| Finding not found | 404 | `FINDING_NOT_FOUND` | "Security finding not found." | Verify finding_id |
| Audit not found | 404 | `AUDIT_NOT_FOUND` | "Audit record not found." | Verify audit_id |
| Audit already running | 409 | `AUDIT_IN_PROGRESS` | "An audit is already in progress." | Wait for completion |
| Invalid severity filter | 422 | `INVALID_SEVERITY` | "Severity must be critical, high, medium, or low." | Fix query parameter |
| Invalid category filter | 422 | `INVALID_CATEGORY` | "Invalid OWASP category." | Use valid category |
| Finding already resolved | 409 | `ALREADY_RESOLVED` | "Finding is already resolved." | No action needed |
| Agent not configured | 404 | `AGENT_NOT_CONFIGURED` | "No Security Agent configured." | Create agent |
| Not admin | 403 | `ADMIN_REQUIRED` | "Admin access required." | Use admin account |

---

## 14. Pydantic Models

```python
from pydantic import BaseModel, Field
from typing import Literal, Optional, List
from enum import Enum

class FindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

class FindingStatus(str, Enum):
    OPEN = "open"
    RESOLVED = "resolved"
    ACCEPTED_RISK = "accepted_risk"
    FALSE_POSITIVE = "false_positive"

class SecurityFindingOut(BaseModel):
    finding_id: str
    category: str
    severity: FindingSeverity
    title: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    description: str
    remediation: str
    status: FindingStatus
    pr_url: Optional[str] = None
    remediation_ticket_id: Optional[str] = None
    created_at: int
    resolved_at: Optional[int] = None

class SecurityAuditOut(BaseModel):
    audit_id: str
    status: Literal["in_progress", "completed", "failed"]
    findings_count: int = Field(ge=0)
    critical_count: int = Field(ge=0)
    high_count: int = Field(ge=0)
    started_at: int
    completed_at: Optional[int] = None
    duration_seconds: Optional[int] = None

class ResolveFindingIn(BaseModel):
    resolution: Literal["resolved", "accepted_risk", "false_positive"]
    notes: Optional[str] = Field(default=None, max_length=2000)
```

---

## 15. Frontend Component Tree

```
SecurityDashboard                     data-testid="security-dashboard"
├── div.grid.grid-cols-4
│   ├── StatCard "Critical" → count (red)
│   ├── StatCard "High" → count (orange)
│   ├── StatCard "Medium" → count (yellow)
│   └── StatCard "Low" → count (blue)
├── Card "Findings by Category"
│   └── BarChart (OWASP categories)
├── Tabs
│   ├── TabsTrigger "Open"
│   ├── TabsTrigger "Resolved"
│   └── TabsTrigger "Audits"
├── DataTable (findings)
│   ├── columns: [severity, category, title, file, status, created_at]
│   └── row click → FindingDetail dialog
└── Button "Run Full Audit"
```

---

## 16. Observability & Monitoring

### 16.1 Metrics

| Metric Name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `security_findings_total` | Counter | `severity`, `category` | Findings detected |
| `security_findings_open_gauge` | Gauge | `severity` | Currently open findings |
| `security_audits_total` | Counter | `result` | Audit runs |
| `security_audit_duration_seconds` | Histogram | -- | Audit execution time |
| `security_pr_reviews_total` | Counter | `result={clean,issues_found}` | PR reviews |

### 16.2 Alerts

| Alert | Condition | Severity |
|-------|-----------|----------|
| Critical finding detected | critical findings > 0 | P0 |
| High findings growing | open high findings > 10 | P1 |
| Audit failed | audit status=failed | P2 |

---

## 17. Rollout Plan

### 17.1 Feature Flags

| Flag | Default | Description |
|------|---------|-------------|
| `SECURITY_AGENT_ENABLED` | `false` | Master kill switch |
| `SECURITY_PR_REVIEW_ENABLED` | `false` | Auto-review PRs |
| `SECURITY_PR_BLOCK_ENABLED` | `false` | Block PR merge on critical findings |
| `SECURITY_REMEDIATION_TICKETS_ENABLED` | `false` | Auto-file remediation tickets |

### 17.2 Canary

1. **Week 1**: Enable audit-only mode. No PR blocking, no ticket creation.
2. **Week 2**: Enable `SECURITY_PR_REVIEW_ENABLED`. Review comments only.
3. **Week 3**: Enable `SECURITY_REMEDIATION_TICKETS_ENABLED`.
4. **Week 4**: Enable `SECURITY_PR_BLOCK_ENABLED` after verifying low false-positive rate.

---

## 18. Expanded E2E Test Details

### Section (additional): Edge Cases (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| E1 | Resolve finding as false positive | POST resolve with resolution="false_positive"; status updated |
| E2 | Concurrent audit trigger | POST audit while one is running; 409 |
| E3 | Finding with no file path (dependency issue) | Finding has null file_path; renders without error |
| E4 | Audit with zero findings | Completed audit with findings_count=0; dashboard shows "All clear" |

### Section (additional): Negative Tests (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| N1 | Non-admin cannot trigger audit | Alice (USER) POSTs audit; 403 |
| N2 | Invalid resolution type | POST resolve with resolution="ignore"; 422 |
| N3 | Resolve non-existent finding | POST resolve with fake finding_id; 404 |
| N4 | List findings with invalid severity | GET findings?severity=mega; 422 |

---

## Codebase References

| Reference | File | Line(s) | Notes |
|-----------|------|---------|-------|
| TicketStore class | `app/services/tickets.py` | 110 | For creating remediation tickets |
| Auth system | `app/auth/deps.py` | — | Cookie auth, CSRF, JWT patterns the agent validates |
| `require_admin_scope` | `app/auth/policy.py` | 84 | Admin auth dependency for audit trigger endpoints |
| `require_ui_session` | `app/services/sessions.py` | — | User auth dependency |
| Billing router | `app/routers/billing.py` | — | Confirmed exists; PCI-relevant code for compliance checks |
| Security hardening runbook | `docs/security-hardening-runbook.md` | — | Confirmed exists; existing security reference |
| `audit_event` | `app/services/alerts.py` | 695 | Signature: `(event, user_sub, request, **fields)` |
| Settings singleton | `app/core/settings.py` | 1-1494 | Frozen `Settings` dataclass; singleton `S` |
| Tables singleton | `app/core/tables.py` | — | `T` object |
| Router registration | `app/main.py` | 297-465 | No `agent_security_router` registered yet |
| `agent_security_findings` DDB table | `scripts/local-ddb-init.py` | — | Does NOT exist yet — new table proposed in this ticket |
| `agent_security.py` service | `app/services/` | — | Does NOT exist yet — new implementation in this ticket |
| `agent_security.py` router | `app/routers/` | — | Does NOT exist yet — new implementation in this ticket |
| `tickets` DDB table | `scripts/local-ddb-init.py` | 494-510 | Existing table |
| `now_ts` | `app/core/time.py` | — | Unix timestamp helper |
