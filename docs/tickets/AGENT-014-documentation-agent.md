# AGENT-014: Documentation Agent

**Ticket**: AGENT-014
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: Medium
**Estimated effort**: 10-12 days
**Dependencies**: AGENT-001 (Agent Registry), AGENT-002 (Terminal Provisioning), AGENT-003 (Worker Agent Framework), AGENT-004 (Ticket Lifecycle Bridge), AGENT-005 (Context Injection & Output Parsing), AGENT-006 (Agent Monitoring & Health), AGENT-007 (Orchestration Dashboard)

---

## 1. Overview & Motivation

### 1.1 Purpose

AGENT-014 defines the Documentation Agent type -- a hybrid-triggered agent that maintains comprehensive, accurate documentation for the platform. It picks up tickets labeled `type:documentation` and also activates automatically when PRs are merged or new features are deployed. The agent reads the codebase, recent pull requests, and existing documentation to identify gaps (missing READMEs, undocumented APIs, stale docs referencing renamed functions or deleted files). It writes documentation directly (API docs, architecture docs, user guides) and creates tickets requesting inline documentation from coder agents. A freshness monitoring system flags documents that reference source files which have changed since the doc was last updated, ensuring documentation never silently drifts from the implementation.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Owner | As a platform owner, I want documentation to stay current automatically. | Doc Agent detects stale docs and updates or flags them. |
| Owner | As a platform owner, I want API documentation generated from code. | Agent produces OpenAPI-aligned docs for all endpoints. |
| Owner | As a platform owner, I want user guides written when features ship. | PR merge triggers doc agent to assess if user-facing docs are needed. |
| Developer | As a developer, I want architecture decision records maintained. | Agent creates ADRs when significant design changes are merged. |
| Developer | As a developer, I want inline code documentation requested where missing. | Agent creates `type:documentation` tickets for code files lacking docstrings. |
| Owner | As a platform owner, I want documentation coverage metrics. | Dashboard shows coverage percentage per module. |
| Owner | As a platform owner, I want documentation to follow consistent standards. | Agent enforces configured templates and format guidelines. |
| Owner | As a platform owner, I want to know which docs are stale. | Freshness monitor compares doc references against file modification timestamps. |

### 1.3 Why This Is Needed

Documentation is the most universally neglected aspect of software projects. Code changes daily, but documentation updates are deferred indefinitely. An autonomous Documentation Agent solves this by treating documentation as a first-class deliverable: every merged PR is checked for documentation impact, gaps are systematically identified, and freshness is continuously monitored. The agent writes documentation itself when possible and delegates to specialized coder agents when inline code documentation is needed. This eliminates the common failure mode where documentation exists but describes a version of the system that no longer exists.

---

## 2. Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                  Documentation Agent System Architecture                    │
└─────────────────────────────────────────────────────────────────────────────┘

  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
  │ PR Merge     │  │ Schedule     │  │ Manual       │
  │ Webhook      │  │ Trigger      │  │ Trigger      │
  │ (GitHub)     │  │ (cron/daily) │  │ (UI click)   │
  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘
         │                 │                  │
         └─────────────────┼──────────────────┘
                           ▼
  ┌──────────────────────────────────────────────────────────┐
  │             Doc Agent Core (agent_docs.py)               │
  │                                                          │
  │  ┌─────────────────┐  ┌─────────────────────────────┐  │
  │  │ Freshness Check │  │ PR Impact Assessment        │  │
  │  │ - git log hashes│  │ - changed_files → source_refs│  │
  │  │ - compare stored│  │ - identify gaps              │  │
  │  │ - flag stale    │  │ - create update tickets      │  │
  │  └─────────────────┘  └─────────────────────────────┘  │
  │                                                          │
  │  ┌─────────────────┐  ┌─────────────────────────────┐  │
  │  │ Doc Generation  │  │ Coverage Tracking           │  │
  │  │ - read codebase │  │ - register artifacts        │  │
  │  │ - apply template│  │ - compute scores            │  │
  │  │ - write docs    │  │ - aggregate summary         │  │
  │  └─────────────────┘  └─────────────────────────────┘  │
  └──────────┬──────────────────┬──────────────────┬────────┘
             │                  │                  │
             ▼                  ▼                  ▼
  ┌──────────────────┐ ┌──────────────┐ ┌──────────────────┐
  │ DocCoverage      │ │ DocTemplates │ │ Ticket System    │
  │ Table (DDB)      │ │ Table (DDB)  │ │                  │
  │ pk=USER#id       │ │ pk=USER#id   │ │ type:documentation│
  │ sk=DOC#path      │ │ sk=TMPL#id   │ │ inline doc       │
  └──────────────────┘ └──────────────┘ │ requests         │
                                        └──────────────────┘
```

---

## 3. Current State Analysis

### 2.1 Existing Infrastructure

- **Agent Registry** (AGENT-001): Agent type definitions, configuration schemas.
- **Worker Agent Framework** (AGENT-003): Task execution, context injection.
- **Ticket Lifecycle Bridge** (AGENT-004): Agent-to-ticket integration for creating documentation requests.
- **Documentation files**: Existing `docs/` directory with `architecture.md`, `dynamodb.md`, `local-dev-stack.md`, `file-reference.md`, `CLAUDE.md`.
- **OpenAPI**: Backend exposes `/openapi.json` for auto-generated API spec.
- **Ticketing system** (`app/services/tickets.py`): Ticket CRUD, labels, status tracking.
- **Git integration**: PR metadata available via GitHub API or git log parsing.

### 2.2 Gaps

1. No agent type profile for documentation maintenance workflows.
2. No PR-merge trigger for documentation review.
3. No documentation coverage model tracking which modules/endpoints are documented.
4. No freshness monitoring system comparing docs against source file changes.
5. No documentation template system enforcing consistent format.
6. No mechanism for agents to create inline documentation tickets for other agents.
7. No documentation coverage dashboard.

---

## 3. Technical Design

### 3.1 Data Model

#### 3.1.1 DocCoverage Table

Tracks documentation coverage and freshness per source file and documentation artifact.

| Field | Type | Description |
|-------|------|-------------|
| `pk` | S | `USER#{user_id}` |
| `sk` | S | `DOC#{doc_path}` (e.g., `DOC#docs/architecture.md`) |
| `doc_path` | S | Relative path to documentation file |
| `doc_type` | S | `api`, `architecture`, `user_guide`, `adr`, `readme`, `inline` |
| `source_refs` | S | JSON array of source file paths this doc references |
| `source_hashes` | S | JSON map of `{source_path: git_hash}` at time of last doc update |
| `coverage_score` | N | 0.0-1.0 completeness estimate |
| `is_stale` | BOOL | Whether any referenced source has changed |
| `stale_since` | N (optional) | Unix timestamp when staleness first detected |
| `last_verified` | N | Unix timestamp of last freshness check |
| `last_updated` | N | Unix timestamp of last documentation update |
| `created_at` | N | Unix timestamp |
| `agent_id` | S (optional) | Agent that last updated this doc |
| `GSI1PK` | S | `USER#{user_id}#TYPE#{doc_type}` |
| `GSI1SK` | N | `last_updated` |
| `GSI2PK` | S | `USER#{user_id}#STALE#{is_stale}` |
| `GSI2SK` | N | `stale_since` or `last_updated` |

```python
TableDef(
    "agent_doc_coverage", "pk", "sk",
    gsi=[
        {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
        {"index_name": "GSI2", "partition_key": "GSI2PK", "sort_key": "GSI2SK"},
    ],
    attr_types={
        "coverage_score": "N", "last_verified": "N", "last_updated": "N",
        "created_at": "N", "stale_since": "N", "GSI1SK": "N", "GSI2SK": "N",
    },
),
```

#### 3.1.2 DocTemplates Table

Stores documentation templates the agent uses to generate consistent docs.

| Field | Type | Description |
|-------|------|-------------|
| `pk` | S | `USER#{user_id}` |
| `sk` | S | `TMPL#{template_id}` |
| `template_id` | S | UUID hex |
| `name` | S | Template name (e.g., "API Endpoint Doc", "Architecture Decision Record") |
| `doc_type` | S | `api`, `architecture`, `user_guide`, `adr`, `readme` |
| `template_body` | S | Markdown template with `{{placeholders}}` |
| `required_sections` | S | JSON array of required section headings |
| `created_at` | N | Unix timestamp |

```python
TableDef(
    "agent_doc_templates", "pk", "sk",
    attr_types={"created_at": "N"},
),
```

#### 3.1.3 Documentation Agent Configuration (on Agent Registry Record)

Stored as a DDB map on the agent registry entry (`doc_config` field):

```json
{
  "trigger_on_pr_merge": true,
  "freshness_check_frequency": "daily",
  "freshness_check_hour_utc": 6,
  "doc_format": "markdown",
  "doc_root": "docs/",
  "api_doc_root": "docs/api/",
  "adr_root": "docs/adr/",
  "user_guide_root": "docs/guides/",
  "min_coverage_threshold": 0.7,
  "create_tickets_for_inline_docs": true,
  "inline_doc_target_agent_type": "coder",
  "ignored_paths": ["node_modules/", ".venv/", "dist/"]
}
```

### 3.2 DynamoDB Access Patterns

| Access Pattern | Table | PK | SK | GSI | Notes |
|----------------|-------|----|----|-----|-------|
| Get doc record | `agent_doc_coverage` | `USER#{user_id}` | `DOC#{doc_path}` | -- | Single item |
| List all docs for user | `agent_doc_coverage` | `USER#{user_id}` | begins_with `DOC#` | -- | All tracked docs |
| List docs by type | `agent_doc_coverage` | -- | -- | `GSI1PK=USER#{id}#TYPE#{type}, GSI1SK=last_updated` | Filter by doc_type |
| List stale docs | `agent_doc_coverage` | -- | -- | `GSI2PK=USER#{id}#STALE#true, GSI2SK=stale_since` | Oldest-stale first |
| Update freshness | `agent_doc_coverage` | `USER#{user_id}` | `DOC#{doc_path}` | -- | SET is_stale, source_hashes |
| Get template | `agent_doc_templates` | `USER#{user_id}` | `TMPL#{template_id}` | -- | Single item |
| List templates | `agent_doc_templates` | `USER#{user_id}` | begins_with `TMPL#` | -- | All templates |

**Example DynamoDB item -- doc coverage record:**

```json
{
  "pk": {"S": "USER#alice-sub-001"},
  "sk": {"S": "DOC#docs/api/messaging.md"},
  "doc_path": {"S": "docs/api/messaging.md"},
  "doc_type": {"S": "api"},
  "source_refs": {"S": "[\"app/routers/messaging.py\", \"app/services/messaging.py\"]"},
  "source_hashes": {"S": "{\"app/routers/messaging.py\": \"abc123\", \"app/services/messaging.py\": \"def456\"}"},
  "coverage_score": {"N": "0.85"},
  "is_stale": {"BOOL": false},
  "last_verified": {"N": "1748534400"},
  "last_updated": {"N": "1748520000"},
  "created_at": {"N": "1748400000"},
  "GSI1PK": {"S": "USER#alice-sub-001#TYPE#api"},
  "GSI1SK": {"N": "1748520000"},
  "GSI2PK": {"S": "USER#alice-sub-001#STALE#false"},
  "GSI2SK": {"N": "1748520000"}
}
```

### 3.3 Backend Service (`app/services/agent_docs.py`)

```python
def check_freshness(*, user_id: str) -> dict:
    """Run freshness check on all tracked documentation."""
    # 1. Query all DOC# records for user
    # 2. For each doc, compare source_hashes against current git hashes
    # 3. Mark stale docs with is_stale=True, stale_since=now
    # 4. Return {"total": N, "stale": M, "fresh": K, "stale_docs": [...]}

def get_coverage_summary(*, user_id: str) -> dict:
    """Return documentation coverage summary per module/type."""
    # 1. Query all DOC# records
    # 2. Group by doc_type
    # 3. Compute average coverage_score per type
    # 4. Return {"overall_coverage": 0.82, "by_type": {...}, "total_docs": N}

def register_doc(*, user_id: str, doc_path: str, doc_type: str,
                  source_refs: list[str], coverage_score: float,
                  agent_id: str | None = None) -> dict:
    """Register a documentation artifact in the coverage tracker."""
    # 1. Compute current git hashes for source_refs
    # 2. Write to DocCoverage table
    # 3. Return doc record

def update_doc_record(*, user_id: str, doc_path: str,
                       source_refs: list[str] | None = None,
                       coverage_score: float | None = None) -> dict:
    """Update a documentation record after doc has been refreshed."""
    # 1. Recompute source_hashes
    # 2. Set is_stale=False, last_updated=now
    # 3. Return updated record

def list_stale_docs(*, user_id: str, limit: int = 50) -> list[dict]:
    """List documents flagged as stale, ordered by staleness duration."""
    # Query GSI2 with STALE#True partition

def assess_pr_impact(*, user_id: str, changed_files: list[str]) -> dict:
    """Given a list of changed files from a PR, assess documentation impact."""
    # 1. Find all DOC# records whose source_refs overlap with changed_files
    # 2. Identify new source files with no doc coverage
    # 3. Return {"docs_to_update": [...], "uncovered_files": [...], "impact_level": "high"}

def create_doc_template(*, user_id: str, name: str, doc_type: str,
                         template_body: str, required_sections: list[str]) -> dict:
    """Create a documentation template."""

def list_doc_templates(*, user_id: str, doc_type: str | None = None) -> list[dict]:
    """List documentation templates."""

def create_inline_doc_ticket(*, user_id: str, source_file: str,
                               description: str) -> dict:
    """Create a type:documentation ticket requesting inline docs for a source file."""
    # 1. Create ticket via TicketStore with type=documentation
    # 2. Set label to source file path
    # 3. Return ticket dict
```

### 3.3 Backend Router (`app/routers/agent_docs.py`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/ui/agents/docs/coverage` | `require_ui_session` | Get documentation coverage summary |
| GET | `/ui/agents/docs/coverage/details` | `require_ui_session` | List all tracked docs with coverage scores |
| GET | `/ui/agents/docs/stale` | `require_ui_session` | List stale documentation |
| POST | `/ui/agents/docs/freshness-check` | `require_ui_session` | Trigger manual freshness check |
| POST | `/ui/agents/docs/register` | `require_ui_session` | Register a doc artifact |
| PUT | `/ui/agents/docs/coverage/{doc_path}` | `require_ui_session` | Update doc coverage record |
| POST | `/ui/agents/docs/assess-pr` | `require_ui_session` | Assess PR impact on documentation |
| GET | `/ui/agents/docs/templates` | `require_ui_session` | List doc templates |
| POST | `/ui/agents/docs/templates` | `require_ui_session` | Create doc template |
| PUT | `/ui/agents/docs/templates/{template_id}` | `require_ui_session` | Update doc template |
| DELETE | `/ui/agents/docs/templates/{template_id}` | `require_ui_session` | Delete doc template |
| PUT | `/ui/agents/docs/config` | `require_ui_session` | Update Documentation Agent config |

**Key request models**:

```python
class RegisterDocIn(BaseModel):
    doc_path: str = Field(..., min_length=1, max_length=500)
    doc_type: Literal["api", "architecture", "user_guide", "adr", "readme", "inline"]
    source_refs: List[str] = Field(default_factory=list)
    coverage_score: float = Field(default=1.0, ge=0.0, le=1.0)

class AssessPrIn(BaseModel):
    changed_files: List[str] = Field(..., min_length=1)

class CreateDocTemplateIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    doc_type: Literal["api", "architecture", "user_guide", "adr", "readme"]
    template_body: str = Field(..., min_length=1, max_length=10000)
    required_sections: List[str] = Field(default_factory=list)

class UpdateDocConfigIn(BaseModel):
    trigger_on_pr_merge: Optional[bool] = None
    freshness_check_frequency: Optional[Literal["hourly", "daily", "weekly"]] = None
    freshness_check_hour_utc: Optional[int] = Field(default=None, ge=0, le=23)
    min_coverage_threshold: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    create_tickets_for_inline_docs: Optional[bool] = None
    ignored_paths: Optional[List[str]] = None
```

Register in `app/main.py`:

```python
from app.routers.agent_docs import router as agent_docs_router
app.include_router(agent_docs_router, prefix="/ui")
```

### 3.4 Frontend Types (`frontend/src/api/types.ts`)

```typescript
export interface DocCoverageRecord {
  doc_path: string;
  doc_type: "api" | "architecture" | "user_guide" | "adr" | "readme" | "inline";
  source_refs: string[];
  coverage_score: number;
  is_stale: boolean;
  stale_since?: number;
  last_verified: number;
  last_updated: number;
}

export interface DocCoverageSummary {
  overall_coverage: number;
  by_type: Record<string, { count: number; avg_coverage: number; stale_count: number }>;
  total_docs: number;
  stale_docs: number;
}

export interface DocTemplate {
  template_id: string;
  name: string;
  doc_type: string;
  template_body: string;
  required_sections: string[];
  created_at: number;
}

export interface DocAgentConfig {
  trigger_on_pr_merge: boolean;
  freshness_check_frequency: "hourly" | "daily" | "weekly";
  freshness_check_hour_utc: number;
  min_coverage_threshold: number;
  create_tickets_for_inline_docs: boolean;
  ignored_paths: string[];
}

export interface PrImpactAssessment {
  docs_to_update: DocCoverageRecord[];
  uncovered_files: string[];
  impact_level: "none" | "low" | "medium" | "high";
}
```

### 3.5 API Request/Response Examples

```bash
# --- GET /ui/agents/docs/coverage ---
curl http://localhost:8000/ui/agents/docs/coverage \
  -H "Cookie: ui_session=sess_abc; ui_access_token=eyJ..."

# Response 200:
{
  "overall_coverage": 0.82,
  "total_docs": 15,
  "stale_docs": 3,
  "by_type": {
    "api": {"count": 8, "avg_coverage": 0.90, "stale_count": 1},
    "architecture": {"count": 3, "avg_coverage": 0.75, "stale_count": 2},
    "user_guide": {"count": 2, "avg_coverage": 0.70, "stale_count": 0},
    "readme": {"count": 2, "avg_coverage": 0.85, "stale_count": 0}
  }
}

# --- POST /ui/agents/docs/assess-pr ---
curl -X POST http://localhost:8000/ui/agents/docs/assess-pr \
  -H "Cookie: ui_session=sess_abc; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_tok_123" \
  -H "Content-Type: application/json" \
  -d '{"changed_files": ["app/routers/messaging.py", "app/services/messaging.py"]}'

# Response 200:
{
  "docs_to_update": [
    {"doc_path": "docs/api/messaging.md", "doc_type": "api", "is_stale": true}
  ],
  "uncovered_files": [],
  "impact_level": "medium"
}

# --- POST /ui/agents/docs/register ---
curl -X POST http://localhost:8000/ui/agents/docs/register \
  -H "Cookie: ui_session=sess_abc; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_tok_123" \
  -H "Content-Type: application/json" \
  -d '{
    "doc_path": "docs/api/billing.md",
    "doc_type": "api",
    "source_refs": ["app/routers/billing.py", "app/services/billing.py"],
    "coverage_score": 0.95
  }'

# Response 201:
{
  "doc_path": "docs/api/billing.md",
  "doc_type": "api",
  "source_refs": ["app/routers/billing.py", "app/services/billing.py"],
  "coverage_score": 0.95,
  "is_stale": false,
  "last_verified": 1748534400,
  "last_updated": 1748534400,
  "created_at": 1748534400
}
```

### 3.6 Pydantic Models

```python
from pydantic import BaseModel, Field
from typing import Literal, Optional, List, Dict


class RegisterDocIn(BaseModel):
    doc_path: str = Field(..., min_length=1, max_length=500)
    doc_type: Literal["api", "architecture", "user_guide", "adr", "readme", "inline"]
    source_refs: List[str] = Field(default_factory=list, max_length=50)
    coverage_score: float = Field(default=1.0, ge=0.0, le=1.0)


class UpdateDocIn(BaseModel):
    source_refs: Optional[List[str]] = Field(default=None, max_length=50)
    coverage_score: Optional[float] = Field(default=None, ge=0.0, le=1.0)


class AssessPrIn(BaseModel):
    changed_files: List[str] = Field(..., min_length=1, max_length=200)


class DocCoverageOut(BaseModel):
    doc_path: str
    doc_type: str
    source_refs: List[str]
    coverage_score: float
    is_stale: bool
    stale_since: Optional[int] = None
    last_verified: int
    last_updated: int
    created_at: int


class DocCoverageSummaryOut(BaseModel):
    overall_coverage: float = Field(ge=0.0, le=1.0)
    total_docs: int = Field(ge=0)
    stale_docs: int = Field(ge=0)
    by_type: Dict[str, dict]


class PrImpactOut(BaseModel):
    docs_to_update: List[DocCoverageOut]
    uncovered_files: List[str]
    impact_level: Literal["none", "low", "medium", "high"]


class CreateDocTemplateIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    doc_type: Literal["api", "architecture", "user_guide", "adr", "readme"]
    template_body: str = Field(..., min_length=1, max_length=10000)
    required_sections: List[str] = Field(default_factory=list, max_length=20)


class DocTemplateOut(BaseModel):
    template_id: str
    name: str
    doc_type: str
    template_body: str
    required_sections: List[str]
    created_at: int


class UpdateDocConfigIn(BaseModel):
    trigger_on_pr_merge: Optional[bool] = None
    freshness_check_frequency: Optional[Literal["hourly", "daily", "weekly"]] = None
    freshness_check_hour_utc: Optional[int] = Field(default=None, ge=0, le=23)
    min_coverage_threshold: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    create_tickets_for_inline_docs: Optional[bool] = None
    ignored_paths: Optional[List[str]] = None
```

### 3.7 Frontend Component Tree

```
DocCoveragePage                        data-testid="doc-coverage-page"
├── div.grid.grid-cols-2.lg:grid-cols-4
│   ├── StatCard "Overall Coverage" → overall_coverage as %
│   ├── StatCard "Total Docs" → total_docs
│   ├── StatCard "Stale Docs" → stale_docs (red if > 0)
│   └── StatCard "Fresh Docs" → total - stale (green)
├── Card "Coverage by Type"
│   └── BarChart (by_type keys vs avg_coverage)
├── Tabs
│   ├── TabsTrigger "All Docs"
│   ├── TabsTrigger "Stale Only"
│   └── TabsTrigger "By Type"
├── DataTable (all docs)
│   ├── columns: [doc_path, doc_type, coverage_score, is_stale, last_updated]
│   ├── coverage_score → Progress bar
│   ├── is_stale → Badge (red "Stale" / green "Fresh")
│   └── sortable by coverage_score, last_updated
└── Button "Run Freshness Check" → POST freshness-check

StaleDocsPanel                         data-testid="stale-docs-panel"
├── Alert "These docs need attention"
└── ul
    └── staleDocs.map(doc =>
        ├── li
        │   ├── span.font-mono (doc.doc_path)
        │   ├── span "stale for {duration}" in red
        │   ├── span "changed source: {files}"
        │   └── Button "Refresh" → triggers agent update
    )

DocTemplatesPage                       data-testid="doc-templates-page"
├── Button "New Template"
├── DataTable
│   ├── columns: [name, doc_type, required_sections count, created_at]
│   └── row click → edit dialog
└── Dialog "Create/Edit Template"
    ├── Input (name)
    ├── Select (doc_type)
    ├── Textarea (template_body) with markdown preview
    ├── Input[] (required_sections) add/remove
    └── Button "Save"
```

### 3.8 Frontend API (`frontend/src/api/endpoints/agents.ts`)

Standard wrappers: `getDocCoverage()`, `listDocCoverageDetails()`, `listStaleDocs()`, `triggerFreshnessCheck()`, `registerDoc(data)`, `updateDocRecord(docPath, data)`, `assessPrImpact(changedFiles)`, `listDocTemplates(docType?)`, `createDocTemplate(data)`, `updateDocTemplate(id, data)`, `deleteDocTemplate(id)`, `updateDocConfig(config)`.

### 3.6 Frontend Pages

- **DocCoveragePage** (`frontend/src/pages/agents/DocCoveragePage.tsx`): Route `/agents/docs`. Top summary cards: overall coverage %, total docs, stale count. Bar chart of coverage by doc type. Table of all tracked docs with status indicators (green=fresh, yellow=stale). Filter by type and staleness. `data-testid="doc-coverage-page"`.
- **StaleDocsPanel** (`frontend/src/pages/agents/StaleDocsPanel.tsx`): Lists stale docs sorted by staleness duration. Each entry shows doc path, referenced source files that changed, staleness duration. "Refresh Now" button triggers agent to update the doc. `data-testid="stale-docs-panel"`.
- **DocTemplatesPage** (`frontend/src/pages/agents/DocTemplatesPage.tsx`): Route `/agents/docs/templates`. CRUD for documentation templates. Template editor with markdown preview. `data-testid="doc-templates-page"`.

---

## 4. Implementation Plan

### 4.1 Files to Create

| File | Purpose |
|------|---------|
| `app/services/agent_docs.py` | Doc coverage tracking, freshness checks, template management |
| `app/routers/agent_docs.py` | Documentation Agent API endpoints |
| `frontend/src/pages/agents/DocCoveragePage.tsx` | Coverage dashboard |
| `frontend/src/pages/agents/StaleDocsPanel.tsx` | Stale docs list |
| `frontend/src/pages/agents/DocTemplatesPage.tsx` | Template management |

### 4.2 Files to Modify

| File | Changes |
|------|---------|
| `scripts/local-ddb-init.py` | Add `agent_doc_coverage`, `agent_doc_templates` TableDefs |
| `app/core/settings.py` | Add table name settings |
| `app/core/tables.py` | Add table handles |
| `app/main.py` | Register `agent_docs_router` |
| `app/models.py` | Add `DocCoverageOut`, `DocCoverageSummaryOut`, `DocTemplateOut` models |
| `frontend/src/api/types.ts` | Add documentation coverage types |
| `frontend/src/api/endpoints/agents.ts` | Add Documentation Agent API functions |
| `frontend/src/App.tsx` | Add `/agents/docs` and `/agents/docs/templates` routes |

---

## 5. E2E Test Plan

### 5.1 Test File

`frontend/e2e/agent-docs.spec.ts` -- 16 tests across 4 sections.

### 5.2 Test Setup

```typescript
const TS = Date.now();
let templateId: string;
// Alice = platform owner
```

### 5.3 Section 675: Doc Coverage Registration API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 675.1 | Register a documentation artifact | POST `/ui/agents/docs/register` with `doc_path="docs/api/messaging.md"`, `doc_type="api"`, `source_refs=["app/routers/messaging.py"]`; 201; returns record with `coverage_score`, `is_stale=false` |
| 675.2 | Register multiple docs of different types | POST 2 more registrations (architecture, user_guide); 201; coverage details list length >= 3 |
| 675.3 | Get coverage summary | GET `/ui/agents/docs/coverage`; 200; `overall_coverage` is numeric, `total_docs >= 3`, `by_type` has entries |
| 675.4 | List coverage details with type filter | GET `/ui/agents/docs/coverage/details?doc_type=api`; 200; all results have `doc_type="api"` |

### 5.4 Section 676: Freshness & Staleness API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 676.1 | Trigger freshness check | POST `/ui/agents/docs/freshness-check`; 200; returns `total`, `stale`, `fresh` counts |
| 676.2 | List stale docs | GET `/ui/agents/docs/stale`; 200; array returned (may be empty if no files changed) |
| 676.3 | Update doc record clears staleness | PUT `/ui/agents/docs/coverage/{doc_path}` with updated `source_refs`; 200; `is_stale=false`, `last_updated` is recent |
| 676.4 | Assess PR impact | POST `/ui/agents/docs/assess-pr` with `changed_files=["app/routers/messaging.py"]`; 200; `docs_to_update` includes the messaging API doc; `impact_level` returned |

### 5.5 Section 677: Doc Templates API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 677.1 | Create doc template | POST `/ui/agents/docs/templates` with `name="API Endpoint Template"`, `doc_type="api"`, `template_body="# {{endpoint}}..."`; 201; returns `template_id` |
| 677.2 | List templates | GET `/ui/agents/docs/templates`; array includes created template with `name`, `doc_type` |
| 677.3 | Update template | PUT `/ui/agents/docs/templates/{templateId}` with new `template_body`; 200; body updated |
| 677.4 | Delete template | DELETE `/ui/agents/docs/templates/{templateId}`; 200; list no longer includes template |

### 5.6 Section 678: Doc Coverage UI (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 678.1 | Coverage page loads | Navigate `/agents/docs`; `[data-testid="doc-coverage-page"]` visible; summary cards show coverage % |
| 678.2 | Coverage table lists tracked docs | Table rows visible with doc paths, coverage scores, staleness indicators |
| 678.3 | Stale docs panel shows flagged docs | Click "Stale" filter or tab; `[data-testid="stale-docs-panel"]` visible (may show "No stale docs") |
| 678.4 | Templates page CRUD | Navigate `/agents/docs/templates`; `[data-testid="doc-templates-page"]` visible; create template via form; template appears in list |

### 5.7 Expanded E2E Test Details

#### Section 679: Edge Cases (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 679.1 | Register duplicate doc path | POST register same doc_path twice; 409 |
| 679.2 | Coverage summary with no docs | DELETE all docs; GET coverage; overall_coverage=0, total_docs=0 |
| 679.3 | Assess PR with no matching docs | POST assess-pr with unrelated files; docs_to_update=[], impact_level="none" |
| 679.4 | Template with empty required_sections | POST template with empty required_sections; 201; accepted |

#### Section 680: Negative Tests (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 680.1 | Other user cannot access docs | Bob GETs Alice's coverage; 403 or empty |
| 680.2 | Invalid doc_type | POST register with doc_type="invalid"; 422 |
| 680.3 | Coverage score out of range | POST register with coverage_score=1.5; 422 |
| 680.4 | Delete nonexistent template | DELETE template with bad ID; 404 |

---

## 6. Error Handling

| Scenario | Status | Detail |
|----------|--------|--------|
| Doc path not found | 404 | "Documentation record not found: {doc_path}" |
| Duplicate doc registration | 409 | "Documentation already registered: {doc_path}" |
| Template not found | 404 | "Template not found" |
| Invalid doc_type | 422 | "Invalid doc_type: {value}" |
| Empty changed_files | 422 | "At least one changed file is required" |
| Coverage score out of range | 422 | "coverage_score must be between 0.0 and 1.0" |
| Template body too long | 422 | "template_body must not exceed 10000 characters" |
| Agent not configured | 404 | "No Documentation Agent configured for this user" |

### 6.2 Error Handling Matrix

| Error Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|----------------|-------------|------------|---------------------|-----------------|
| Doc not found | 404 | `DOC_NOT_FOUND` | "Documentation record not found." | Verify doc_path |
| Duplicate registration | 409 | `DOC_ALREADY_EXISTS` | "Already registered." | Update existing record instead |
| Template not found | 404 | `TEMPLATE_NOT_FOUND` | "Template not found." | Verify template_id |
| Invalid doc_type | 422 | `INVALID_DOC_TYPE` | "Invalid doc_type: {value}." | Use valid enum |
| Coverage out of range | 422 | `SCORE_OUT_OF_RANGE` | "coverage_score must be 0.0-1.0." | Fix value |
| Empty changed_files | 422 | `NO_CHANGED_FILES` | "Provide at least one changed file." | Add file paths |
| Template body too long | 422 | `BODY_TOO_LONG` | "Max 10000 characters." | Shorten template |
| Path traversal | 422 | `INVALID_PATH` | "Path must be relative, no ../." | Use relative paths |
| Agent not configured | 404 | `DOC_AGENT_NOT_CONFIGURED` | "No Documentation Agent configured." | Create agent first |

---

## 7. Observability & Monitoring

### 7.1 Metrics

| Metric Name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `doc_freshness_checks_total` | Counter | -- | Freshness check runs |
| `doc_stale_count_gauge` | Gauge | -- | Currently stale docs |
| `doc_coverage_gauge` | Gauge | `doc_type` | Average coverage by type |
| `doc_templates_total` | Gauge | -- | Active templates count |
| `doc_pr_assessments_total` | Counter | `impact_level` | PR impact assessments |
| `doc_inline_tickets_created_total` | Counter | -- | Inline doc tickets created |

### 7.2 Alerts

| Alert | Condition | Severity |
|-------|-----------|----------|
| Stale doc count > 50% | stale/total > 0.5 | P2 |
| Coverage below threshold | overall_coverage < min_threshold | P3 |
| Freshness check failed | No check in 48h | P3 |

---

## 8. Rollout Plan

### 8.1 Feature Flags

| Flag | Default | Description |
|------|---------|-------------|
| `DOC_AGENT_ENABLED` | `false` | Master kill switch |
| `DOC_PR_TRIGGER_ENABLED` | `false` | Auto-trigger on PR merge |
| `DOC_INLINE_TICKETS_ENABLED` | `false` | Create tickets for missing inline docs |

### 8.2 Canary

1. **Week 1**: Enable freshness checking only. No doc writing or ticket creation.
2. **Week 2**: Enable `DOC_INLINE_TICKETS_ENABLED`. Monitor ticket creation rate.
3. **Week 3**: Enable `DOC_PR_TRIGGER_ENABLED`. Full automation.

### 8.3 Rollback

Set `DOC_AGENT_ENABLED=false`. Existing coverage records remain.

---

## 9. Security Considerations

- **Ownership enforcement**: All doc coverage and template operations scoped to the authenticated user's `user_id`. Cross-tenant access is blocked.
- **Source file path validation**: `source_refs` paths are validated to ensure they are relative paths within the repository root. Absolute paths and path traversal (`../`) are rejected to prevent information leakage.
- **Template body sanitization**: Template bodies stored as-is (markdown), but rendered with XSS protection in the frontend. No executable code blocks are evaluated.
- **Git hash computation**: Source hashes are computed by the agent in its terminal session (not by the backend). The backend stores hashes as opaque strings and compares them for staleness detection.
- **PR impact assessment**: `changed_files` list validated to contain only relative paths. Backend does not access the filesystem -- it only compares against stored `source_refs` in DDB.
- **Doc content access**: Documentation files themselves are stored in the git repository, not in DDB. The backend only tracks metadata (paths, hashes, coverage). The agent writes files via its terminal session.

---

## 8. Performance Considerations

| Concern | Mitigation |
|---------|-----------|
| Freshness check scans all docs | Paginated query; capped at 1000 docs per user; parallelized hash comparison |
| PR impact assessment with many changed files | Index lookup on source_refs; O(N*M) where N=docs, M=changed_files; practical limit ~100 changed files |
| Template body storage | 10KB max per template; 50 templates per user limit |
| Coverage summary aggregation | Pre-computed on freshness check runs; cached in summary record |
| Stale doc list growth | Stale docs naturally resolve when updated; no unbounded growth |

---

## 9. Dependencies

| Dependency | Ticket | Status |
|------------|--------|--------|
| AGENT-001 (Agent Registry) | AGENT-001 | Required (agent type definitions, config storage) |
| AGENT-002 (Terminal Provisioning) | AGENT-002 | Required (terminal for git operations and doc writing) |
| AGENT-003 (Worker Agent Framework) | AGENT-003 | Required (task execution, PR-merge trigger support) |
| AGENT-004 (Ticket Lifecycle Bridge) | AGENT-004 | Required (creating inline documentation tickets) |
| AGENT-005 (Context Injection) | AGENT-005 | Required (injecting codebase context and PR diffs) |
| AGENT-006 (Agent Monitoring) | AGENT-006 | Required (monitoring freshness check runs) |
| AGENT-007 (Orchestration Dashboard) | AGENT-007 | Required (viewing doc agent activity) |
| Ticketing system | Existing | Available (creating documentation tickets) |
| Git/GitHub integration | Existing | Available (PR merge events, file change detection) |

### Downstream

| Ticket | Depends On |
|--------|-----------|
| AGENT-015 (Compliance Agent) | May audit documentation for compliance requirements |
| AGENT-017 (Marketing Agent) | Reads documentation to generate marketing content |
