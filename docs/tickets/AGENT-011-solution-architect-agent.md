# AGENT-011: Solution Architect Agent

**Ticket**: AGENT-011
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: High
**Estimated effort**: 10-12 days
**Dependencies**: AGENT-001 (LLM Provider Key Management), AGENT-002 (Terminal Worker Provisioning), AGENT-003 (Worker Agent Framework & Lifecycle), AGENT-004 (Worker Fleet Management UI), AGENT-005 (Agent Memory & Context Injection), AGENT-006 (Terminal Monitoring & Feedback Loop)

---

## 1. Overview & Motivation

### 1.1 Purpose

AGENT-011 defines the Solution Architect Agent type -- an agent configuration profile that plugs into the Worker Agent Framework (AGENT-003) to autonomously decompose feature requests into actionable development tickets. The Solution Architect Agent picks up tickets labeled `type:feature_request`, analyzes the existing codebase to understand current architecture and patterns, designs a technical solution (data model, API endpoints, frontend components), breaks the feature down into discrete development tickets with acceptance criteria, assigns complexity labels and effort estimates, establishes a dependency graph between tickets, and links everything back to the original feature request.

The agent is configured with architecture guidelines (naming conventions, tech stack constraints, DynamoDB patterns), reference documentation (CLAUDE.md, docs/), and ticket templates that match the project's established format. By reading the actual codebase -- not just documentation -- the agent ensures its designs align with existing patterns rather than introducing inconsistencies.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Platform Admin | As an admin, I want to register a Solution Architect Agent with architecture guidelines. | Agent type created with guidelines, conventions, constraints; appears in registry. |
| Platform Admin | As an admin, I want the agent to read the actual codebase before designing. | Agent clones repo and scans relevant files (services, routers, models, frontend). |
| Platform Admin | As an admin, I want generated tickets to follow our project format. | Tickets use configured template; include data model, API design, frontend plan, E2E tests. |
| Product Manager | As a PM, I want feature requests decomposed automatically. | Feature request ticket transitions to `tickets_created`; linked dev tickets appear in space. |
| Product Manager | As a PM, I want effort estimates on each dev ticket. | Each ticket has `estimated_effort_hours` and `complexity` label. |
| Product Manager | As a PM, I want a dependency graph so I know build order. | Tickets have `depends_on` metadata listing prerequisite ticket IDs. |
| Coder Agent | As a Coder Agent, I want tickets with clear acceptance criteria. | Each dev ticket has structured acceptance criteria, data model, API spec, test expectations. |
| Ticket Author | As a feature requester, I want to see the technical plan. | Feature request ticket updated with architecture summary and links to dev tickets. |
| Solution Architect | As a human architect, I want to review designs before dev starts. | Agent can request feedback on ambiguous design decisions before creating tickets. |
| Project Manager | As a PM, I want to see how many feature requests have been decomposed. | Dashboard shows decomposition count, avg tickets per feature, avg estimation accuracy. |

### 1.3 Why This Is Needed

Feature requests are the most unstructured input in the development pipeline. They describe desired outcomes ("I want users to share videos in messages") without specifying implementation details. Converting a feature request into development tickets requires understanding the existing codebase, identifying what already exists, designing new components that fit the architecture, and breaking the work into testable increments. This is typically done by senior engineers in planning meetings -- a time-intensive process that scales poorly. The Solution Architect Agent automates this decomposition, producing tickets that are directly actionable by the Coder Agent (AGENT-008). The agent's designs are grounded in the actual codebase, not abstract patterns, ensuring consistency with existing implementation.

---

## 2. Current State Analysis

### 2.1 Existing Infrastructure

- **LLM Provider Key Management** (AGENT-001): API key management for coding tools used in codebase analysis. Solution Architect registers as `agent_type=architect`.
- **Terminal Worker Provisioning** (AGENT-002): SSH terminal for cloning and reading the codebase.
- **Worker Agent Framework & Lifecycle** (AGENT-003): Generic worker loop. Solution Architect plugs in with analysis-specific behavior.
- **Worker Fleet Management UI** (AGENT-004): Fleet overview for architect agent instances.
- **Agent Memory & Context Injection** (AGENT-005): Injects architecture guidelines and project documentation into analysis prompts.
- **Terminal Monitoring & Feedback Loop** (AGENT-006): Terminal output capture and feedback mechanism for requesting human input on ambiguous design decisions.
- **Ticket System** (`app/services/tickets.py`): `TicketStore` with `create_ticket()` accepting `subject`, `description`, `category`, `metadata`, `space_id`, `labels` (AGENT-008 extension).
- **CLAUDE.md**: Project architecture documentation with file structure, conventions, patterns, and checklist for adding new features.
- **Existing ticket specs** (`docs/tickets/`): 200+ ticket spec files following a consistent format (Overview, Current State, Technical Design, Implementation Plan, E2E Test Plan, Error Handling, Security, Performance, Dependencies).
- **File reference** (`docs/file-reference.md`): Full repository file map.
- **DynamoDB docs** (`docs/dynamodb.md`): Table schema reference.

### 2.2 Gaps

1. No agent type configuration for architecture analysis (guidelines, conventions, reference docs).
2. No codebase scanning and pattern extraction workflow.
3. No ticket decomposition logic -- breaking a feature into ordered, dependent development tickets.
4. No complexity estimation based on codebase analysis.
5. No dependency graph generation between tickets.
6. No ticket template system for generating structured development tickets with data model, API design, and test plans.
7. No architecture summary generation for feature request ticket updates.
8. No design review / feedback request mechanism for ambiguous decisions.
9. No metrics for decomposition quality (tickets per feature, estimation accuracy).

---

## 3. Technical Design

### 3.1 Data Model

#### 3.1.1 AgentTypes Table Extension (Architect Config)

Additional fields on the `agent_types` table when `agent_type = "architect"`:

| Field | Type | Description |
|-------|------|-------------|
| `architect_config` | M (map) | Architect-specific configuration |
| `architect_config.repo_url` | S | Git repository URL for codebase analysis |
| `architect_config.repo_branch` | S | Branch to analyze (default `main`) |
| `architect_config.reference_docs` | L (list of S) | Paths to reference documents to read (e.g., `["CLAUDE.md", "docs/dynamodb.md", "docs/file-reference.md"]`) |
| `architect_config.scan_paths` | L (list of S) | Directories to scan for existing patterns (e.g., `["app/services/", "app/routers/", "app/models.py", "frontend/src/"]`) |
| `architect_config.ticket_template` | S | Markdown template for generated dev tickets (with placeholders) |
| `architect_config.architecture_guidelines` | S | Free-text guidelines (max 10000 chars): naming conventions, DDB patterns, etc. |
| `architect_config.tech_stack_constraints` | M (map) | `{backend: "Python/FastAPI", frontend: "React/TypeScript", database: "DynamoDB", ...}` |
| `architect_config.naming_conventions` | M (map) | `{tables: "snake_case", routes: "/ui/{resource}", services: "{feature}_store.py", ...}` |
| `architect_config.max_tickets_per_feature` | N | Maximum dev tickets to generate per feature (default 8, max 20) |
| `architect_config.target_ticket_space_id` | S (optional) | Space for generated tickets |
| `architect_config.complexity_estimation` | M (map) | Heuristics: `{new_table: 2, new_endpoint: 0.5, new_page: 1.5, ...}` in days |
| `architect_config.coding_tool` | S | `claude_code` or `codex` (default `claude_code`) |
| `architect_config.coding_tool_model` | S (optional) | Model override |
| `architect_config.max_analysis_time_seconds` | N | Time budget for codebase analysis (default 900) |
| `architect_config.require_design_review` | BOOL | Whether to request human review before creating tickets (default false) |
| `architect_config.ticket_spec_style` | S | `full` (350-550 lines like docs/tickets/) or `compact` (50-100 lines summary) |

#### 3.1.2 FeatureDecompositions Table

Tracks the relationship between feature requests and generated development tickets.

| Field | Type | Description |
|-------|------|-------------|
| `pk` | S | `FEATURE#{feature_ticket_id}` |
| `sk` | S | `DEV#{dev_ticket_id}` or `META` |
| `feature_ticket_id` | S | Source feature request ticket |
| `dev_ticket_id` | S (optional) | Generated development ticket (null for META) |
| `agent_run_id` | S | Agent run that performed decomposition |
| `decomposition_summary` | S | Architecture summary (META item only, max 10000 chars) |
| `total_tickets_created` | N | Count of dev tickets (META item only) |
| `total_estimated_hours` | N | Sum of effort estimates (META item only) |
| `dependency_graph` | S | JSON string of `{ticket_id: [depends_on_ticket_id, ...]}` (META item only) |
| `order` | N | Build order index (dev ticket items only, 1-based) |
| `complexity` | S | `low`, `medium`, `high`, `critical` (dev ticket items only) |
| `estimated_hours` | N | Effort estimate (dev ticket items only) |
| `ticket_type` | S | `development`, `bugfix`, `infrastructure` (dev ticket items only) |
| `created_at` | N | Unix timestamp |
| `GSI1PK` | S | `AGENT_RUN#{agent_run_id}` (to find all decompositions by run) |
| `GSI1SK` | N | `created_at` |

```python
TableDef(
    "feature_decompositions", "pk", "sk",
    gsi=[
        {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
    ],
    attr_types={"order": "N", "estimated_hours": "N", "total_tickets_created": "N",
                "total_estimated_hours": "N", "created_at": "N", "GSI1SK": "N"},
),
```

#### 3.1.3 AgentRuns Table Extension (Architect Output)

| Field | Type | Description |
|-------|------|-------------|
| `architect_output` | M (map) | Structured output |
| `architect_output.feature_ticket_id` | S | Source feature request |
| `architect_output.decomposition_summary` | S | Architecture summary |
| `architect_output.tickets_created` | L (list of M) | `{ticket_id, subject, complexity, estimated_hours, order, depends_on}` |
| `architect_output.total_tickets` | N | Count |
| `architect_output.total_estimated_hours` | N | Sum of estimates |
| `architect_output.dependency_graph` | M | `{ticket_id: [depends_on_ids]}` |
| `architect_output.codebase_analysis` | M | `{files_scanned, patterns_found, existing_related_files}` |
| `architect_output.design_decisions` | L (list of M) | `{decision, rationale, alternatives_considered}` |
| `architect_output.feedback_requested` | BOOL | Whether design review was requested |
| `architect_output.feedback_response` | S (optional) | Human feedback received |
| `architect_output.total_duration_seconds` | N | Wall-clock time |

### 3.2 Backend Service (`app/services/agent_architect.py`)

```python
# --- Configuration ---
def get_architect_config(*, agent_type_id: str) -> dict:
def update_architect_config(*, agent_type_id: str, owner_sub: str, config: dict) -> dict:
def validate_architect_config(config: dict) -> list[str]:
    """Validate: repo_url valid, reference_docs paths valid, scan_paths valid,
    ticket_template has required placeholders, guidelines non-empty."""

# --- Ticket Filtering ---
def find_architect_eligible_tickets(*, agent_type_id: str, limit: int = 10) -> list[dict]:
    """Query tickets with labels containing type:feature_request and status=open.
    Skip tickets already decomposed (check feature_decompositions table)."""

def claim_architect_ticket(*, agent_run_id: str, ticket_id: str, agent_sub: str) -> dict | None:
    """Assign ticket. Set status to analyzing."""

# --- Codebase Analysis ---
def build_analysis_prompt(*, ticket: dict, reference_docs: list[str],
                            scan_paths: list[str], guidelines: str,
                            tech_constraints: dict, naming_conventions: dict) -> str:
    """Construct prompt for the coding tool to analyze the codebase.
    Instructs the tool to:
    1. Read reference docs (CLAUDE.md, docs/)
    2. Scan existing services, routers, models for patterns
    3. Identify existing code related to the feature request
    4. List files that would need modification vs creation
    5. Output structured analysis as JSON."""

def parse_codebase_analysis(*, tool_output: str) -> dict:
    """Extract structured analysis: files_scanned, patterns_found,
    existing_related_files, suggested_approach."""

# --- Solution Design ---
def build_design_prompt(*, ticket: dict, analysis: dict, guidelines: str,
                         tech_constraints: dict, naming_conventions: dict,
                         complexity_estimation: dict, max_tickets: int,
                         ticket_spec_style: str) -> str:
    """Construct prompt for the coding tool to design the solution.
    Instructs the tool to:
    1. Design data model (DDB tables/extensions with TableDef)
    2. Design API endpoints (method, path, auth, request/response models)
    3. Design frontend components (pages, routes, types)
    4. Break into ordered development tickets
    5. Set complexity and effort estimate for each
    6. Establish dependency graph
    7. Output structured design as JSON."""

def parse_solution_design(*, tool_output: str) -> dict:
    """Extract: tickets list, dependency_graph, design_decisions, summary."""

# --- Ticket Generation ---
def generate_ticket_content(*, ticket_data: dict, template: str,
                              ticket_spec_style: str, feature_ticket: dict) -> str:
    """Render ticket template with placeholders filled from design data.
    For 'full' style: produce 350-550 line spec matching docs/tickets/ format.
    For 'compact' style: produce 50-100 line summary."""

def create_dev_tickets(*, feature_ticket_id: str, agent_run_id: str,
                        tickets_data: list[dict], template: str,
                        ticket_spec_style: str, space_id: str | None,
                        agent_sub: str) -> list[dict]:
    """Create tickets in the ticket system. For each:
    1. Render content from template
    2. Create ticket with labels (type:development + complexity:{level})
    3. Set metadata (depends_on, estimated_effort_hours, feature_request_id)
    4. Write decomposition record to feature_decompositions table
    Return list of created ticket summaries."""

def build_dependency_graph(*, tickets: list[dict]) -> dict:
    """Construct {ticket_id: [depends_on_ids]} from ticket dependency metadata.
    Validate: no circular dependencies, all references resolve."""

# --- Complexity Estimation ---
def estimate_complexity(*, ticket_data: dict, heuristics: dict) -> dict:
    """Estimate effort using configured heuristics.
    Inputs: new tables count, new endpoints count, new pages count,
    files to modify count, test count.
    Returns {complexity: str, estimated_hours: float, breakdown: dict}."""

# --- Design Review ---
def request_design_review(*, agent_run_id: str, feature_ticket_id: str,
                            summary: str, design_decisions: list[dict],
                            tickets_preview: list[dict]) -> str:
    """Create feedback request (AGENT-004) with design summary and
    ticket preview. Return feedback_request_id."""

def apply_design_feedback(*, feedback: str, original_design: dict) -> dict:
    """Construct prompt to revise design based on human feedback.
    Re-run design generation with feedback context."""

# --- Status Updates ---
def mark_feature_tickets_created(*, feature_ticket_id: str, agent_sub: str,
                                   summary: str, dev_ticket_ids: list[str]) -> dict:
    """Update feature request ticket status to tickets_created.
    Add architecture summary and ticket links as ticket message."""

def write_decomposition_meta(*, feature_ticket_id: str, agent_run_id: str,
                               summary: str, total_tickets: int,
                               total_hours: float, dependency_graph: dict) -> None:
    """Write META record to feature_decompositions table."""

# --- Workflow Orchestrator ---
def build_architect_workflow(*, agent_run_id: str, agent_type_id: str,
                               ticket: dict) -> list[dict]:
    """Return ordered workflow steps:
    1. clone_repo: clone and checkout analysis branch
    2. read_reference_docs: read CLAUDE.md, docs/ via the coding tool
    3. scan_codebase: analyze existing code in scan_paths
    4. analyze_feature: map feature request to existing architecture
    5. design_solution: produce technical design with data model, API, frontend
    6. estimate_effort: assign complexity and hours to each ticket
    7. build_dependency_graph: establish build order
    8. request_review: if require_design_review, pause for human feedback
    9. apply_feedback: revise design if feedback received
    10. generate_tickets: create dev tickets in ticket system
    11. write_decomposition: record decomposition metadata
    12. update_feature_ticket: mark tickets_created with summary"""

# --- Metrics ---
def get_architect_metrics(*, period_days: int = 30) -> dict:
    """Aggregate: features decomposed, avg tickets per feature,
    avg estimated hours per feature, decomposition rate."""
```

### 3.3 Backend Router (`app/routers/agent_architect.py`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| PUT | `/ui/agents/types/{type_id}/architect-config` | `require_admin_session` | Set or update architect_config |
| GET | `/ui/agents/types/{type_id}/architect-config` | `require_admin_session` | Get current architect_config |
| POST | `/ui/agents/types/{type_id}/architect-config/validate` | `require_admin_session` | Validate config |
| GET | `/ui/agents/types/{type_id}/architect-eligible-tickets` | `require_admin_session` | Preview eligible feature requests |
| GET | `/ui/agents/runs/{run_id}/architect-output` | `require_admin_session` | Get decomposition output |
| GET | `/ui/agents/features/{feature_ticket_id}/decomposition` | `require_admin_session` | Get decomposition for a feature request |
| GET | `/ui/agents/features/{feature_ticket_id}/dependency-graph` | `require_admin_session` | Get dependency graph visualization data |
| GET | `/ui/agents/features/{feature_ticket_id}/dev-tickets` | `require_admin_session` | List dev tickets generated from a feature |
| POST | `/ui/agents/types/{type_id}/test-architect-workflow` | `require_admin_session` | Dry-run: preview workflow for a feature request |
| GET | `/ui/agents/architect/metrics` | `require_admin_session` | Decomposition metrics |

**Key request models**:

```python
class ArchitectConfigIn(BaseModel):
    repo_url: str = Field(..., min_length=5, max_length=500)
    repo_branch: str = Field(default="main", max_length=100)
    reference_docs: List[str] = Field(default=["CLAUDE.md"], max_length=20)
    scan_paths: List[str] = Field(default=["app/services/", "app/routers/", "frontend/src/"], max_length=20)
    ticket_template: str = Field(default="", max_length=20000)
    architecture_guidelines: str = Field(default="", max_length=10000)
    tech_stack_constraints: Optional[Dict[str, str]] = None
    naming_conventions: Optional[Dict[str, str]] = None
    max_tickets_per_feature: int = Field(default=8, ge=1, le=20)
    target_ticket_space_id: Optional[str] = None
    complexity_estimation: Optional[Dict[str, float]] = None
    coding_tool: Literal["claude_code", "codex"] = "claude_code"
    coding_tool_model: Optional[str] = Field(default=None, max_length=100)
    max_analysis_time_seconds: int = Field(default=900, ge=120, le=3600)
    require_design_review: bool = False
    ticket_spec_style: Literal["full", "compact"] = "compact"
```

Response models: `ArchitectConfigOut`, `ArchitectOutputOut` (full architect_output map), `DecompositionOut` (summary, tickets, graph, analysis), `DependencyGraphOut` (nodes and edges for visualization), `DevTicketListOut` (list of generated tickets with order/complexity/effort), `ArchitectMetricsOut` (features_decomposed, avg_tickets_per_feature, avg_hours_per_feature).

Register in `app/main.py`:

```python
from app.routers.agent_architect import router as agent_architect_router
app.include_router(agent_architect_router, prefix="/ui")
```

### 3.4 Codebase Analysis Strategy

The Solution Architect Agent reads the codebase in two phases:

**Phase 1 -- Reference Documents**: Read `CLAUDE.md`, `docs/dynamodb.md`, `docs/file-reference.md`, and any additional configured reference docs. These provide the high-level architecture, conventions, and gotchas.

**Phase 2 -- Targeted Scanning**: Based on the feature request description, identify relevant domains (e.g., "video sharing" -> scan `app/services/vod_*`, `app/routers/vod_*`, `frontend/src/pages/vod/`). The prompt instructs the coding tool to:
- List existing files in `scan_paths` (using `find` or `ls -R`)
- Read files related to the feature domain (grep for keywords)
- Identify existing patterns: DynamoDB table structure, router organization, service layer patterns, frontend page structure
- Note which existing components can be reused vs. what needs to be created

### 3.5 Ticket Template Placeholders

The `ticket_template` supports these placeholders:

| Placeholder | Description |
|-------------|-------------|
| `{ticket_id}` | Generated ticket ID |
| `{subject}` | Ticket subject line |
| `{feature_ticket_id}` | Parent feature request ticket |
| `{overview}` | Feature overview and motivation |
| `{current_state}` | Existing infrastructure and gaps |
| `{data_model}` | DynamoDB table design with TableDef |
| `{api_design}` | Backend service and router spec |
| `{frontend_design}` | Frontend types, API, pages spec |
| `{e2e_test_plan}` | E2E test sections and test cases |
| `{error_handling}` | Error handling table |
| `{security}` | Security considerations |
| `{dependencies}` | Dependency list |
| `{complexity}` | Complexity label |
| `{estimated_hours}` | Effort estimate |
| `{depends_on}` | List of prerequisite ticket IDs |
| `{build_order}` | Position in the dependency chain |

### 3.6 Dependency Graph Generation

The agent produces a dependency graph as a DAG (directed acyclic graph):

```json
{
  "nodes": [
    {"id": "tkt_abc123", "subject": "Add video_shares DDB table", "complexity": "low", "order": 1},
    {"id": "tkt_def456", "subject": "Implement video sharing service", "complexity": "medium", "order": 2},
    {"id": "tkt_ghi789", "subject": "Add video share API endpoints", "complexity": "medium", "order": 3}
  ],
  "edges": [
    {"from": "tkt_abc123", "to": "tkt_def456"},
    {"from": "tkt_def456", "to": "tkt_ghi789"}
  ]
}
```

The agent validates: no cycles, all referenced IDs exist, root nodes (no dependencies) come first in build order. The frontend renders this as an interactive dependency graph visualization.

### 3.7 Frontend Types (`frontend/src/api/types.ts`)

```typescript
export interface ArchitectConfig {
  repo_url: string;
  repo_branch: string;
  reference_docs: string[];
  scan_paths: string[];
  ticket_template: string;
  architecture_guidelines: string;
  tech_stack_constraints?: Record<string, string>;
  naming_conventions?: Record<string, string>;
  max_tickets_per_feature: number;
  target_ticket_space_id?: string;
  complexity_estimation?: Record<string, number>;
  coding_tool: "claude_code" | "codex";
  coding_tool_model?: string;
  max_analysis_time_seconds: number;
  require_design_review: boolean;
  ticket_spec_style: "full" | "compact";
}

export interface ArchitectOutput {
  feature_ticket_id: string;
  decomposition_summary: string;
  tickets_created: Array<{
    ticket_id: string;
    subject: string;
    complexity: string;
    estimated_hours: number;
    order: number;
    depends_on: string[];
  }>;
  total_tickets: number;
  total_estimated_hours: number;
  dependency_graph: Record<string, string[]>;
  codebase_analysis: {
    files_scanned: number;
    patterns_found: string[];
    existing_related_files: string[];
  };
  design_decisions: Array<{
    decision: string;
    rationale: string;
    alternatives_considered: string[];
  }>;
  feedback_requested: boolean;
  feedback_response?: string;
  total_duration_seconds: number;
}

export interface DependencyGraphNode {
  id: string;
  subject: string;
  complexity: string;
  order: number;
  status?: string;
}

export interface DependencyGraphEdge {
  from: string;
  to: string;
}

export interface ArchitectMetrics {
  features_decomposed: number;
  avg_tickets_per_feature: number;
  avg_hours_per_feature: number;
  decomposition_rate: number;
  period_start: number;
  period_end: number;
}
```

### 3.8 Frontend API (`frontend/src/api/endpoints/agents.ts`)

Add Solution Architect Agent API functions: `getArchitectConfig`, `updateArchitectConfig`, `validateArchitectConfig`, `getArchitectEligibleTickets`, `getArchitectOutput`, `getDecomposition`, `getDependencyGraph`, `getDevTicketsForFeature`, `testArchitectWorkflow`, `getArchitectMetrics`.

### 3.9 Frontend Pages

- **ArchitectAgentConfigPage** (`frontend/src/pages/agents/ArchitectAgentConfigPage.tsx`): Route `/agents/types/:typeId/architect`. Tabbed layout: Config | Features | Metrics. `data-testid="architect-config-page"`.
  - **Config tab**: Repository URL, branch, reference docs list, scan paths list, ticket template editor (with placeholder syntax highlighting and preview), architecture guidelines textarea, tech stack constraints key-value editor, naming conventions key-value editor, max tickets slider, ticket spec style selector, complexity estimation heuristics editor, coding tool selector, analysis time budget, design review toggle. `data-testid="architect-config-tab"`.
  - **Features tab**: Table of feature requests (open + decomposed). For decomposed: click to see architecture summary, generated ticket list with dependency graph visualization, effort breakdown. `data-testid="architect-features-tab"`.
  - **Metrics tab**: Features decomposed count, avg tickets per feature, avg hours per feature, decomposition rate over time. `data-testid="architect-metrics-tab"`.

- **DependencyGraphView** (`frontend/src/pages/agents/DependencyGraphView.tsx`): Interactive DAG visualization of ticket dependencies. Nodes colored by complexity (green=low, yellow=medium, red=high). Edges show build order. Click node to navigate to ticket. Used in ArchitectAgentConfigPage Features tab and standalone. `data-testid="dependency-graph-view"`.

- **ArchitectRunOutputPanel** (`frontend/src/pages/agents/ArchitectRunOutputPanel.tsx`): Embedded in Agent Run detail page. Shows: feature request summary, codebase analysis (files scanned, patterns found), design decisions with rationale, generated tickets list with dependency graph, effort breakdown, feedback status. `data-testid="architect-output-panel"`.

---

## 4. Implementation Plan

### 4.1 Files to Create

| File | Purpose |
|------|---------|
| `app/services/agent_architect.py` | Architect Agent config, codebase analysis, solution design, ticket generation |
| `app/routers/agent_architect.py` | Architect config CRUD, decomposition, dependency graph, metrics endpoints |
| `frontend/src/pages/agents/ArchitectAgentConfigPage.tsx` | Architect Agent configuration + features + metrics UI |
| `frontend/src/pages/agents/DependencyGraphView.tsx` | Interactive ticket dependency graph visualization |
| `frontend/src/pages/agents/ArchitectRunOutputPanel.tsx` | Architect run output detail panel |

### 4.2 Files to Modify

| File | Changes |
|------|---------|
| `scripts/local-ddb-init.py` | Add `feature_decompositions` TableDef with GSI1 |
| `app/core/settings.py` | Add `feature_decompositions_table_name` setting |
| `app/core/tables.py` | Add `feature_decompositions` table handle |
| `app/services/tickets.py` | Add `analyzing`, `tickets_created` to `_TICKET_STATUSES` |
| `app/main.py` | Register `agent_architect_router` |
| `app/models.py` | Add `ArchitectConfigIn`, `ArchitectOutputOut`, `DecompositionOut`, `DependencyGraphOut`, `ArchitectMetricsOut` models |
| `frontend/src/api/types.ts` | Add `ArchitectConfig`, `ArchitectOutput`, `DependencyGraphNode`, `DependencyGraphEdge`, `ArchitectMetrics` types |
| `frontend/src/api/endpoints/agents.ts` | Add Architect Agent API functions |
| `frontend/src/App.tsx` | Add `/agents/types/:typeId/architect` route |

---

## 5. E2E Test Plan

### 5.1 Test File

`frontend/e2e/agent-architect.spec.ts` -- 14 tests across 4 sections.

### 5.2 Test Setup

```typescript
const TS = Date.now();
let agentTypeId: string;
let featureTicketId: string;
let runId: string;
let devTicketIds: string[];
// Root = admin who configures agents
```

### 5.3 Section 663: Architect Config API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 663.1 | Create Architect Agent type with config | POST agent type `agent_type=architect`; PUT architect-config with repo_url, reference_docs, scan_paths, guidelines; 200 |
| 663.2 | Get architect config | GET architect-config; 200; all fields match; reference_docs includes "CLAUDE.md" |
| 663.3 | Update ticket template and guidelines | PUT with new `ticket_template` and `architecture_guidelines`; 200; values updated |
| 663.4 | Validate config with invalid repo | POST validate with `repo_url=""`; errors array non-empty |

### 5.4 Section 664: Feature Decomposition API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 664.1 | Create feature request ticket | Create ticket with `labels=["type:feature_request"]`; status = `open` |
| 664.2 | Eligible tickets returns feature request | GET architect-eligible-tickets; array includes the feature ticket |
| 664.3 | Get decomposition for feature | GET decomposition; 200; `decomposition_summary` non-empty; `total_tickets_created >= 1` |
| 664.4 | Get dev tickets for feature | GET dev-tickets; 200; array of tickets with `complexity`, `estimated_hours`, `order` |

### 5.5 Section 665: Dependency Graph & Output API (3 tests)

| # | Test | Assertion |
|---|------|-----------|
| 665.1 | Get dependency graph | GET dependency-graph; 200; `nodes` array has entries; `edges` array present |
| 665.2 | Graph has no circular dependencies | Each node's `order` is greater than all its dependencies' orders |
| 665.3 | Architect output includes design decisions | GET architect-output; 200; `design_decisions` array non-empty; each has `decision`, `rationale` |

### 5.6 Section 666: Architect Config UI (3 tests)

| # | Test | Assertion |
|---|------|-----------|
| 666.1 | Architect config page loads | Navigate `/agents/types/{typeId}/architect`; `[data-testid="architect-config-page"]` visible |
| 666.2 | Features tab shows decomposed features | Click "Features" tab; `[data-testid="architect-features-tab"]` visible; table has rows |
| 666.3 | Dependency graph renders | Click on a decomposed feature; `[data-testid="dependency-graph-view"]` visible; nodes rendered |

---

## 6. Error Handling

| Scenario | Status | Detail |
|----------|--------|--------|
| Agent type not found | 404 | "Agent type not found" |
| Agent type is not architect | 409 | "Agent type is not configured as architect" |
| Empty reference docs | 422 | "At least one reference document path is required" |
| Empty scan paths | 422 | "At least one scan path is required" |
| Feature ticket not found | 404 | "Feature request ticket not found" |
| Feature already decomposed | 409 | "This feature request has already been decomposed" |
| Circular dependency detected | 422 | "Circular dependency detected in ticket graph" |
| Max tickets exceeded | 422 | "Decomposition exceeds maximum ticket limit" |
| Codebase analysis timeout | 504 | "Codebase analysis did not complete within time budget" |
| Template placeholder missing | 422 | "Ticket template missing required placeholder: {placeholder}" |
| Run not found | 404 | "Agent run not found" |
| Not admin | 403 | "Admin access required" |

---

## 7. Security Considerations

- **Admin-only access**: All Architect Agent endpoints require `require_admin_session`.
- **Repository read-only**: The Architect Agent only reads the codebase. It does not create branches, modify files, or push changes. The terminal is provisioned with read-only repository access.
- **Ticket content sanitization**: Generated ticket descriptions are sanitized to prevent XSS when rendered in the frontend. Markdown output from the coding tool is validated against an allowlist of safe HTML elements.
- **Reference doc access control**: Reference document paths are validated against the repository tree. Paths outside the repository root are rejected (`../` traversal prevention).
- **Design decision auditability**: All design decisions (rationale, alternatives considered) are logged in the architect_output for review. The human can override any design choice.
- **Ticket creation rate limiting**: Max `max_tickets_per_feature` tickets per decomposition prevents resource exhaustion from a single feature request.
- **Codebase analysis isolation**: The terminal session has read-only filesystem access. No outbound network access except to the configured repository.

---

## 8. Performance Considerations

| Concern | Mitigation |
|---------|-----------|
| Codebase analysis for large repos | Scan only configured paths; cap file count at 500; skip binary files |
| Large ticket template rendering | Template rendering is string substitution; negligible cost |
| Feature decompositions table growth | TTL not needed; decompositions are permanent reference data |
| Dependency graph validation | O(V+E) topological sort; max 20 nodes |
| Concurrent decomposition of same feature | Conditional check on feature_decompositions META before starting |
| Coding tool response parsing | JSON extraction with fallback regex parsing; timeout at max_analysis_time_seconds |

---

## 9. Dependencies

| Dependency | Ticket | Status |
|------------|--------|--------|
| AGENT-001 (LLM Provider Key Management) | AGENT-001 | Required |
| AGENT-002 (Terminal Worker Provisioning) | AGENT-002 | Required |
| AGENT-003 (Worker Agent Framework & Lifecycle) | AGENT-003 | Required |
| AGENT-004 (Worker Fleet Management UI) | AGENT-004 | Required |
| AGENT-005 (Agent Memory & Context Injection) | AGENT-005 | Required |
| AGENT-006 (Terminal Monitoring & Feedback Loop) | AGENT-006 | Required (design review feedback, terminal output) |
| Ticket System | Existing | Available (needs label + status extensions from AGENT-008) |

### Downstream

| Ticket | Depends On |
|--------|-----------|
| AGENT-008 (Coder Agent) | Picks up development tickets created by Architect Agent |
| AGENT-012 (Project Manager) | Uses decomposition data for project planning and velocity tracking |
