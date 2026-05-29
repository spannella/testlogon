# AGENT-012: Project Manager Agent

**Ticket**: AGENT-012
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: High
**Estimated effort**: 12-14 days
**Dependencies**: AGENT-001 (LLM Provider Key Management), AGENT-002 (Terminal Worker Provisioning), AGENT-003 (Worker Agent Framework & Lifecycle), AGENT-004 (Worker Fleet Management UI), AGENT-005 (Agent Memory & Context Injection), AGENT-006 (Terminal Monitoring & Feedback Loop), AGENT-008 (Coder Agent), AGENT-009 (QA Agent), AGENT-010 (DevOps/SRE Agent), AGENT-011 (Solution Architect Agent)

---

## 1. Overview & Motivation

### 1.1 Purpose

AGENT-012 defines the Project Manager Agent type -- an agent configuration profile that plugs into the Worker Agent Framework (AGENT-003) to autonomously manage the full project lifecycle from idea intake through delivery. The PM Agent accepts ideas directly from users or picks up tickets labeled `type:product_request`, validates scope and feasibility, creates structured feature request tickets, prioritizes the development backlog using an impact/effort matrix, tracks project velocity across all agent types, identifies and escalates blockers, and produces daily/weekly progress reports.

The PM Agent sits at the top of the agent pipeline: it converts raw ideas into feature requests that the Solution Architect Agent (AGENT-011) decomposes, which the Coder Agent (AGENT-008) implements, which the QA Agent (AGENT-009) verifies, and which the DevOps Agent (AGENT-010) deploys. The PM Agent tracks progress across this entire pipeline and reports aggregate project health.

The agent is configured with a priority framework (P0-P3), sprint/cycle duration, capacity per agent type, and reporting cadence. It can escalate to users when priorities conflict, scope is unclear, or capacity is insufficient for planned work.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Platform Admin | As an admin, I want to register a PM Agent with project management config. | Agent type created with priority framework, capacity, reporting cadence; appears in registry. |
| User | As a user, I want to submit a product idea and have it triaged automatically. | Idea submitted; PM Agent creates feature request ticket with user stories and success criteria. |
| Product Manager | As a PM, I want the agent to prioritize the backlog automatically. | Backlog ordered by impact/effort score; priority labels (P0-P3) assigned. |
| Product Manager | As a PM, I want to see which tickets are blocked and why. | Dashboard shows blocked tickets with blocker type and assigned agent. |
| Product Manager | As a PM, I want daily and weekly progress reports. | Reports generated on schedule with: completed, in-progress, blocked, velocity trend. |
| Platform Admin | As an admin, I want the agent to escalate priority conflicts. | When two P0 tickets compete for limited agent capacity, feedback loop requests human decision. |
| Platform Admin | As an admin, I want project velocity tracked over time. | Velocity measured as story points (estimated hours) completed per sprint. |
| Coder Agent | As a Coder Agent, I want a prioritized backlog. | Backlog tickets ordered by priority; agent picks highest-priority eligible ticket first. |
| Stakeholder | As a stakeholder, I want a project status overview. | Dashboard shows overall progress, burndown chart, agent utilization, ETA for features. |
| Solution Architect | As a Solution Architect, I want feature requests to have clear scope. | Feature request tickets created by PM Agent have description, user stories, success criteria, priority. |

### 1.3 Why This Is Needed

Without a PM Agent, the agent pipeline has no orchestration layer. Individual agents operate independently: the Coder Agent picks the oldest ticket, the QA Agent processes whatever is code_complete, and nobody tracks overall progress or identifies bottlenecks. The PM Agent provides:

1. **Intake funnel**: Converts raw ideas into structured, prioritized feature requests -- the entry point for the entire agent pipeline.
2. **Backlog prioritization**: Ensures the most valuable work is done first, not just the oldest work.
3. **Velocity tracking**: Measures how fast the agent team delivers, enabling capacity planning and sprint forecasting.
4. **Blocker detection**: Identifies stuck tickets before they cascade into project delays.
5. **Reporting**: Provides stakeholders with accurate, up-to-date project status without manual status meetings.
6. **Capacity management**: Matches work volume to available agent capacity, preventing overload and identifying when more agents are needed.

---

## 2. Current State Analysis

### 2.1 Existing Infrastructure

- **LLM Provider Key Management** (AGENT-001): API key management for coding tools used in idea triage. PM Agent registers as `agent_type=pm`.
- **Terminal Worker Provisioning** (AGENT-002): Terminal environment for idea analysis with coding tools.
- **Worker Agent Framework & Lifecycle** (AGENT-003): Generic worker loop with periodic/event-driven execution modes.
- **Worker Fleet Management UI** (AGENT-004): Fleet overview and agent utilization data.
- **Agent Memory & Context Injection** (AGENT-005): Injects project context for idea analysis and feasibility assessment.
- **Terminal Monitoring & Feedback Loop** (AGENT-006): Escalation for priority conflicts and scope ambiguity.
- **Coder Agent** (AGENT-008): Picks up `type:development` tickets; tracks completion time and output.
- **QA Agent** (AGENT-009): Picks up `code_complete` tickets; tracks pass/fail rate.
- **DevOps Agent** (AGENT-010): Picks up `type:deployment` tickets; tracks deployment frequency.
- **Solution Architect Agent** (AGENT-011): Picks up `type:feature_request` tickets; produces dev tickets.
- **Ticket System** (`app/services/tickets.py`): `TicketStore` with status management, labels (AGENT-008), spaces, assignment.
- **Project Management** (`app/services/projects_store.py`): Existing project CRUD with tracked files and events.

### 2.2 Gaps

1. No idea intake endpoint for users to submit product ideas to the agent pipeline.
2. No feature request ticket generation from unstructured ideas (user stories, success criteria).
3. No backlog prioritization engine (impact/effort scoring, P0-P3 classification).
4. No velocity tracking across agent types (story points completed per time period).
5. No blocker detection and escalation for stuck tickets.
6. No automated progress reporting (daily/weekly summaries).
7. No capacity planning (matching work volume to agent availability).
8. No project dashboard aggregating status across all agent types.
9. No sprint/cycle management (start/end dates, scope, burndown).
10. No priority conflict resolution mechanism.

---

## 3. Technical Design

### 3.1 Data Model

#### 3.1.1 AgentTypes Table Extension (PM Config)

Additional fields on the `agent_types` table when `agent_type = "pm"`:

| Field | Type | Description |
|-------|------|-------------|
| `pm_config` | M (map) | PM-specific configuration |
| `pm_config.priority_framework` | M (map) | `{P0: "Critical/blocking", P1: "High/next sprint", P2: "Medium/backlog", P3: "Low/nice-to-have"}` |
| `pm_config.priority_weights` | M (map) | Impact/effort scoring weights: `{user_impact: 0.4, revenue_impact: 0.3, technical_debt: 0.15, effort_inverse: 0.15}` |
| `pm_config.sprint_duration_days` | N | Sprint length in days (default 14) |
| `pm_config.capacity_per_agent_type` | M (map) | Available hours per sprint per agent type: `{coder: 80, qa: 40, devops: 20, architect: 20}` |
| `pm_config.reporting_cadence` | S | `daily`, `weekly`, or `both` (default `both`) |
| `pm_config.report_time_utc` | S | Time to generate reports (default `09:00`) |
| `pm_config.idea_intake_enabled` | BOOL | Whether users can submit ideas directly (default true) |
| `pm_config.auto_prioritize` | BOOL | Whether agent auto-assigns priorities (default true; false = suggest only) |
| `pm_config.auto_create_feature_requests` | BOOL | Whether ideas are auto-converted to feature requests (default false -- requires human approval) |
| `pm_config.blocker_stale_hours` | N | Hours before a ticket is flagged as stale/blocked (default 48) |
| `pm_config.escalation_on_conflict` | BOOL | Escalate to user when priorities conflict (default true) |
| `pm_config.coding_tool` | S | `claude_code` or `codex` (for idea analysis) |
| `pm_config.coding_tool_model` | S (optional) | Model override |
| `pm_config.project_space_id` | S (optional) | Ticket space for project management |
| `pm_config.stakeholder_subs` | L (list of S) | User subs to receive reports |

#### 3.1.2 ProductIdeas Table

Stores raw ideas submitted by users before conversion to feature requests.

| Field | Type | Description |
|-------|------|-------------|
| `pk` | S | `IDEA#{idea_id}` |
| `sk` | S | `META` |
| `idea_id` | S | UUID hex |
| `submitted_by` | S | User sub who submitted the idea |
| `title` | S | Short title (max 200 chars) |
| `description` | S | Detailed description (max 5000 chars) |
| `status` | S | `submitted`, `triaging`, `accepted`, `rejected`, `converted` |
| `priority_suggestion` | S (optional) | PM Agent's suggested priority (P0-P3) |
| `impact_score` | N (optional) | Calculated impact score (0-100) |
| `effort_score` | N (optional) | Estimated effort score (0-100) |
| `priority_rationale` | S (optional) | Why this priority was assigned |
| `feature_ticket_id` | S (optional) | Created feature request ticket (when converted) |
| `agent_run_id` | S (optional) | Agent run that processed this idea |
| `rejection_reason` | S (optional) | Why idea was rejected |
| `created_at` | N | Unix timestamp |
| `updated_at` | N | Unix timestamp |
| `GSI1PK` | S | `STATUS#{status}` |
| `GSI1SK` | N | `created_at` |
| `GSI2PK` | S | `USER#{submitted_by}` |
| `GSI2SK` | N | `created_at` |

```python
TableDef(
    "product_ideas", "pk", "sk",
    gsi=[
        {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
        {"index_name": "GSI2", "partition_key": "GSI2PK", "sort_key": "GSI2SK"},
    ],
    attr_types={"impact_score": "N", "effort_score": "N", "created_at": "N",
                "updated_at": "N", "GSI1SK": "N", "GSI2SK": "N"},
),
```

#### 3.1.3 ProjectSprints Table

Tracks sprint/cycle boundaries and metrics.

| Field | Type | Description |
|-------|------|-------------|
| `pk` | S | `PROJECT#{project_space_id}` |
| `sk` | S | `SPRINT#{sprint_id}` |
| `sprint_id` | S | UUID hex |
| `sprint_number` | N | Sequential sprint number |
| `start_date` | S | ISO date (YYYY-MM-DD) |
| `end_date` | S | ISO date |
| `status` | S | `planned`, `active`, `completed` |
| `planned_hours` | N | Total planned effort hours |
| `completed_hours` | N | Completed effort hours |
| `tickets_planned` | N | Tickets in scope at sprint start |
| `tickets_completed` | N | Tickets completed during sprint |
| `tickets_carried_over` | N | Tickets not completed (carried to next sprint) |
| `velocity` | N | Story points (hours) completed |
| `blockers_count` | N | Tickets blocked during sprint |
| `created_at` | N | Unix timestamp |
| `updated_at` | N | Unix timestamp |

```python
TableDef(
    "project_sprints", "pk", "sk",
    attr_types={"sprint_number": "N", "planned_hours": "N", "completed_hours": "N",
                "tickets_planned": "N", "tickets_completed": "N",
                "tickets_carried_over": "N", "velocity": "N", "blockers_count": "N",
                "created_at": "N", "updated_at": "N"},
),
```

#### 3.1.4 ProjectReports Table

Stores generated progress reports.

| Field | Type | Description |
|-------|------|-------------|
| `pk` | S | `PROJECT#{project_space_id}` |
| `sk` | S | `REPORT#{created_at}#{report_id}` |
| `report_id` | S | UUID hex |
| `report_type` | S | `daily`, `weekly`, `sprint_summary` |
| `agent_run_id` | S | Agent run that generated the report |
| `content` | S | Markdown report content |
| `metrics_snapshot` | M | Key metrics at report time |
| `created_at` | N | Unix timestamp |

```python
TableDef(
    "project_reports", "pk", "sk",
    attr_types={"created_at": "N"},
),
```

#### 3.1.5 AgentRuns Table Extension (PM Output)

| Field | Type | Description |
|-------|------|-------------|
| `pm_output` | M (map) | Structured output |
| `pm_output.operation_type` | S | `idea_triage`, `backlog_prioritize`, `report_generate`, `blocker_detect`, `sprint_plan` |
| `pm_output.ideas_processed` | N | Ideas triaged (idea_triage operation) |
| `pm_output.ideas_accepted` | N | Ideas accepted |
| `pm_output.ideas_rejected` | N | Ideas rejected |
| `pm_output.feature_tickets_created` | L (list of S) | Feature request ticket IDs created |
| `pm_output.tickets_reprioritized` | N | Tickets whose priority changed (backlog operation) |
| `pm_output.blockers_found` | N | Blocked tickets identified |
| `pm_output.escalations_created` | N | Escalations sent to humans |
| `pm_output.report_id` | S (optional) | Generated report ID |
| `pm_output.sprint_id` | S (optional) | Sprint ID (sprint operations) |
| `pm_output.velocity_current` | N (optional) | Current sprint velocity |
| `pm_output.velocity_trend` | S (optional) | `increasing`, `stable`, `decreasing` |
| `pm_output.total_duration_seconds` | N | Wall-clock time |

### 3.2 Backend Service (`app/services/agent_pm.py`)

```python
# --- Configuration ---
def get_pm_config(*, agent_type_id: str) -> dict:
def update_pm_config(*, agent_type_id: str, owner_sub: str, config: dict) -> dict:
def validate_pm_config(config: dict) -> list[str]:
    """Validate: priority_framework has P0-P3, weights sum to 1.0,
    sprint_duration > 0, capacity values > 0."""

# --- Idea Intake ---
def submit_idea(*, user_sub: str, title: str, description: str) -> dict:
    """Create product idea record. Status = submitted. Return idea with idea_id."""

def list_ideas(*, status: str | None = None, user_sub: str | None = None,
               limit: int = 25, cursor: str | None = None) -> dict:
    """List ideas filtered by status or submitter. Paginated."""

def get_idea(*, idea_id: str) -> dict | None:

def update_idea_status(*, idea_id: str, status: str, agent_sub: str | None = None,
                        rejection_reason: str | None = None,
                        feature_ticket_id: str | None = None) -> dict:

# --- Idea Triage ---
def triage_idea(*, idea: dict, coding_tool: str, model: str | None,
                 priority_framework: dict, priority_weights: dict) -> dict:
    """Use coding tool to analyze idea:
    1. Assess user impact (how many users benefit, how much pain it solves)
    2. Assess revenue impact (does it drive subscriptions, reduce churn)
    3. Assess technical debt reduction (does it improve architecture)
    4. Estimate effort (high-level T-shirt sizing)
    5. Assign impact_score (0-100), effort_score (0-100)
    6. Calculate priority using weighted formula
    7. Generate user stories and success criteria
    Return {priority, impact_score, effort_score, rationale, user_stories, success_criteria}."""

def build_feature_request_from_idea(*, idea: dict, triage_result: dict,
                                      priority: str) -> dict:
    """Construct feature request ticket data:
    subject, description (with user stories + success criteria),
    labels (type:feature_request, priority:{P0-P3}),
    metadata (idea_id, impact_score, effort_score, user_stories)."""

def convert_idea_to_feature_request(*, idea_id: str, agent_sub: str,
                                      triage_result: dict,
                                      space_id: str | None) -> dict:
    """Create feature request ticket in ticket system.
    Update idea status to converted with feature_ticket_id.
    Return {idea, feature_ticket}."""

# --- Backlog Prioritization ---
def get_backlog(*, space_id: str | None, statuses: list[str] | None = None,
                 limit: int = 100) -> list[dict]:
    """Fetch all open, in_progress, and code_complete tickets.
    Include labels, metadata, estimated_effort_hours."""

def calculate_priority_score(*, ticket: dict, weights: dict) -> float:
    """Score = weights.user_impact * user_impact_score +
              weights.revenue_impact * revenue_impact_score +
              weights.technical_debt * tech_debt_score +
              weights.effort_inverse * (100 - effort_score).
    Scores from 0-100. Higher = higher priority."""

def prioritize_backlog(*, backlog: list[dict], weights: dict,
                        capacity: dict) -> list[dict]:
    """Sort tickets by priority score descending.
    Assign P0/P1/P2/P3 based on score thresholds:
    P0: score >= 80, P1: score >= 60, P2: score >= 40, P3: score < 40.
    Cap P0 count to available capacity in current sprint.
    Return ordered list with priority assignments."""

def apply_priorities(*, prioritized: list[dict], agent_sub: str,
                      auto_prioritize: bool) -> int:
    """Update ticket labels with priority. If auto_prioritize=False,
    create suggestions instead of applying directly. Return count updated."""

# --- Blocker Detection ---
def detect_blockers(*, space_id: str | None, stale_hours: int) -> list[dict]:
    """Scan tickets for blockers:
    1. Tickets in 'in_progress' for > stale_hours without status change
    2. Tickets in 'blocked' status
    3. Tickets assigned to agents that are in 'error' or 'terminated' state
    4. Tickets with unresolved dependencies (depends_on tickets not done)
    Return [{ticket_id, blocker_type, stale_since, assigned_agent, details}]."""

def escalate_blockers(*, blockers: list[dict], agent_sub: str) -> int:
    """Create feedback requests for critical blockers (P0/P1 stale > stale_hours).
    Add ticket message noting the blocker. Return count escalated."""

# --- Velocity Tracking ---
def calculate_velocity(*, sprint: dict, completed_tickets: list[dict]) -> dict:
    """Sum estimated_effort_hours for tickets completed in sprint.
    Return {velocity_hours, tickets_completed, avg_hours_per_ticket}."""

def get_velocity_trend(*, sprints: list[dict], periods: int = 5) -> dict:
    """Compare velocity across recent sprints.
    Return {trend: 'increasing'|'stable'|'decreasing', velocities: [...],
    avg_velocity, prediction_next}."""

# --- Sprint Management ---
def create_sprint(*, space_id: str, sprint_number: int, start_date: str,
                   end_date: str, planned_tickets: list[str]) -> dict:
    """Create sprint record. Calculate planned_hours from ticket estimates."""

def close_sprint(*, sprint_id: str, space_id: str) -> dict:
    """Calculate completed vs planned. Carry over incomplete tickets.
    Update sprint metrics. Return sprint summary."""

def get_current_sprint(*, space_id: str) -> dict | None:
    """Return the active sprint (status=active)."""

def get_sprint_burndown(*, sprint_id: str, space_id: str) -> list[dict]:
    """Daily snapshot of remaining hours for burndown chart.
    Return [{date, remaining_hours, ideal_hours}]."""

# --- Capacity Planning ---
def get_agent_utilization(*, agent_types: list[str]) -> dict:
    """Query agent runs to calculate current utilization per agent type.
    Return {agent_type: {total_capacity_hours, used_hours, available_hours, utilization_pct}}."""

def check_capacity_fit(*, backlog: list[dict], capacity: dict) -> dict:
    """Compare total estimated effort in P0+P1 tickets against available capacity.
    Return {fits: bool, overflow_hours, overflow_tickets, recommendation}."""

# --- Reporting ---
def generate_daily_report(*, space_id: str, sprints: list[dict],
                           backlog: list[dict], blockers: list[dict],
                           agent_utilization: dict) -> str:
    """Render Markdown daily report with:
    - Today's completions (tickets that moved to done/deployed)
    - In-progress tickets with agent assignments
    - Blockers and escalations
    - Agent utilization summary
    Return Markdown string."""

def generate_weekly_report(*, space_id: str, sprint: dict | None,
                            velocity_trend: dict, backlog_summary: dict,
                            agent_metrics: dict) -> str:
    """Render Markdown weekly report with:
    - Sprint progress (if active sprint)
    - Velocity trend and forecast
    - Backlog health (total tickets by priority)
    - Agent performance (completion rate, avg time by type)
    - Blockers resolved vs new
    - Capacity utilization
    - Recommendations
    Return Markdown string."""

def save_report(*, space_id: str, report_type: str, content: str,
                 metrics_snapshot: dict, agent_run_id: str) -> str:
    """Write report to project_reports table. Return report_id."""

def send_report_notifications(*, report_id: str, stakeholder_subs: list[str],
                                report_type: str) -> None:
    """Send notification (via existing notification system) to stakeholders
    with report link."""

# --- Priority Conflict Resolution ---
def detect_priority_conflicts(*, backlog: list[dict], capacity: dict) -> list[dict]:
    """Identify cases where:
    1. Multiple P0 tickets exceed agent capacity
    2. Two features have similar scores but different stakeholder urgency
    3. A dependency chain has mismatched priorities (P2 blocks P0)
    Return [{conflict_type, tickets, description, recommended_resolution}]."""

def escalate_conflict(*, conflict: dict, agent_sub: str) -> str:
    """Create feedback request describing the conflict and asking for
    human resolution. Return feedback_request_id."""

# --- Workflow Orchestrator ---
def build_pm_workflow(*, agent_run_id: str, agent_type_id: str,
                       operation_type: str) -> list[dict]:
    """Return ordered workflow steps based on operation type:

    For 'idea_triage' (triggered by new ideas):
    1. fetch_ideas: get submitted ideas
    2. triage_each: analyze with coding tool
    3. assign_priority: calculate scores and priority
    4. create_feature_requests: convert accepted ideas to tickets (if auto)
    5. update_idea_status: mark triaged/accepted/rejected

    For 'backlog_prioritize' (periodic):
    1. fetch_backlog: get all open tickets
    2. score_tickets: calculate priority scores
    3. reorder_backlog: sort and assign P0-P3
    4. apply_labels: update ticket labels
    5. detect_conflicts: find priority conflicts
    6. escalate_conflicts: request human resolution if needed

    For 'report_generate' (scheduled):
    1. fetch_sprint: get current sprint data
    2. calculate_velocity: compute sprint velocity
    3. detect_blockers: find stale/blocked tickets
    4. get_utilization: agent utilization metrics
    5. generate_report: render daily or weekly report
    6. save_report: persist to project_reports
    7. send_notifications: notify stakeholders

    For 'blocker_detect' (periodic):
    1. scan_tickets: find stale and blocked tickets
    2. classify_blockers: determine blocker type
    3. escalate: create feedback requests for critical blockers
    4. update_tickets: add blocker notes to affected tickets

    For 'sprint_plan' (at sprint boundaries):
    1. close_current: close active sprint, calculate metrics
    2. carry_over: move incomplete tickets to new sprint
    3. plan_next: create next sprint, select scope from prioritized backlog
    4. calculate_forecast: predict completion based on velocity trend
    """

# --- Metrics ---
def get_pm_metrics(*, space_id: str | None, period_days: int = 30) -> dict:
    """Aggregate: ideas processed, feature requests created, velocity trend,
    backlog health, blocker rate, agent utilization, priority distribution."""
```

### 3.3 Backend Router (`app/routers/agent_pm.py`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| PUT | `/ui/agents/types/{type_id}/pm-config` | `require_admin_scope` | Set or update pm_config |
| GET | `/ui/agents/types/{type_id}/pm-config` | `require_admin_scope` | Get current pm_config |
| POST | `/ui/agents/types/{type_id}/pm-config/validate` | `require_admin_scope` | Validate config |
| POST | `/ui/agents/ideas` | `require_ui_session` | Submit a product idea (any authenticated user) |
| GET | `/ui/agents/ideas` | `require_ui_session` | List ideas (own ideas for users; all for admins) |
| GET | `/ui/agents/ideas/{idea_id}` | `require_ui_session` | Get idea details |
| PATCH | `/ui/agents/ideas/{idea_id}` | `require_admin_scope` | Update idea status (accept/reject) |
| GET | `/ui/agents/backlog` | `require_admin_scope` | Get prioritized backlog |
| POST | `/ui/agents/backlog/reprioritize` | `require_admin_scope` | Trigger backlog reprioritization |
| GET | `/ui/agents/sprints` | `require_admin_scope` | List sprints |
| GET | `/ui/agents/sprints/{sprint_id}` | `require_admin_scope` | Get sprint details with burndown |
| POST | `/ui/agents/sprints` | `require_admin_scope` | Create new sprint |
| PATCH | `/ui/agents/sprints/{sprint_id}` | `require_admin_scope` | Close sprint |
| GET | `/ui/agents/reports` | `require_admin_scope` | List generated reports |
| GET | `/ui/agents/reports/{report_id}` | `require_admin_scope` | Get report content |
| GET | `/ui/agents/blockers` | `require_admin_scope` | Get current blockers |
| GET | `/ui/agents/capacity` | `require_admin_scope` | Get agent capacity and utilization |
| GET | `/ui/agents/runs/{run_id}/pm-output` | `require_admin_scope` | Get PM run output |
| GET | `/ui/agents/pm/metrics` | `require_admin_scope` | PM metrics dashboard data |
| GET | `/ui/agents/pm/dashboard` | `require_admin_scope` | Aggregated project dashboard data |

<!-- NOTE: `require_admin_session` does not exist in the codebase. The correct admin auth dependency is `require_admin_scope(AdminScope.XXX)` from `app/auth/policy.py:84`. -->

**Key request models**:

```python
class PmConfigIn(BaseModel):
    priority_framework: Dict[str, str] = Field(
        default={"P0": "Critical/blocking", "P1": "High/next sprint",
                 "P2": "Medium/backlog", "P3": "Low/nice-to-have"})
    priority_weights: Dict[str, float] = Field(
        default={"user_impact": 0.4, "revenue_impact": 0.3,
                 "technical_debt": 0.15, "effort_inverse": 0.15})
    sprint_duration_days: int = Field(default=14, ge=1, le=90)
    capacity_per_agent_type: Dict[str, int] = Field(
        default={"coder": 80, "qa": 40, "devops": 20, "architect": 20})
    reporting_cadence: Literal["daily", "weekly", "both"] = "both"
    report_time_utc: str = Field(default="09:00", pattern=r"^\d{2}:\d{2}$")
    idea_intake_enabled: bool = True
    auto_prioritize: bool = True
    auto_create_feature_requests: bool = False
    blocker_stale_hours: int = Field(default=48, ge=1, le=720)
    escalation_on_conflict: bool = True
    coding_tool: Literal["claude_code", "codex"] = "claude_code"
    coding_tool_model: Optional[str] = Field(default=None, max_length=100)
    project_space_id: Optional[str] = None
    stakeholder_subs: Optional[List[str]] = Field(default=None, max_length=20)

class SubmitIdeaIn(BaseModel):
    title: str = Field(..., min_length=3, max_length=200)
    description: str = Field(..., min_length=10, max_length=5000)

class UpdateIdeaIn(BaseModel):
    status: Literal["accepted", "rejected"]
    rejection_reason: Optional[str] = Field(default=None, max_length=1000)

class CreateSprintIn(BaseModel):
    start_date: str = Field(..., pattern=r"^\d{4}-\d{2}-\d{2}$")
    end_date: str = Field(..., pattern=r"^\d{4}-\d{2}-\d{2}$")
    planned_ticket_ids: Optional[List[str]] = None
```

Response models: `PmConfigOut`, `IdeaOut` (idea details with priority suggestion), `IdeaListOut` (paginated ideas), `BacklogOut` (ordered list of tickets with priority scores), `SprintOut` (sprint details with metrics), `SprintBurndownOut` (daily remaining hours), `ReportOut` (report content and metrics), `BlockerOut` (ticket_id, blocker_type, details), `CapacityOut` (per-agent-type utilization), `PmOutputOut`, `PmMetricsOut`, `ProjectDashboardOut`.

Register in `app/main.py`:

```python
from app.routers.agent_pm import router as agent_pm_router
app.include_router(agent_pm_router, prefix="/ui")
```

### 3.4 Idea Intake Flow

1. **User submits idea**: POST to `/ui/agents/ideas` with title and description. No admin required -- any authenticated user can submit.
2. **PM Agent triages**: Periodic sweep picks up `submitted` ideas. Uses coding tool to analyze impact, effort, and generate user stories.
3. **Priority assignment**: Impact/effort scores feed into priority formula. Result: P0-P3 suggestion.
4. **If `auto_create_feature_requests = true`**: Automatically create feature request ticket and mark idea as `converted`.
5. **If `auto_create_feature_requests = false`**: Mark idea as `accepted` with priority suggestion. Human reviews and approves conversion via PATCH endpoint. This is the default -- humans stay in the loop for scope decisions.
6. **Rejection**: If idea is out of scope, infeasible, or duplicate, mark as `rejected` with reason.

### 3.5 Backlog Prioritization Algorithm

```
For each ticket in backlog:
    impact_scores = extract from metadata (user_impact, revenue_impact, tech_debt)
    effort_score = estimated_effort_hours normalized to 0-100 scale
    
    weighted_score = (
        weights.user_impact * impact_scores.user_impact +
        weights.revenue_impact * impact_scores.revenue_impact +
        weights.technical_debt * impact_scores.tech_debt +
        weights.effort_inverse * (100 - effort_score)
    )
    
    priority = P0 if weighted_score >= 80
               P1 if weighted_score >= 60
               P2 if weighted_score >= 40
               P3 otherwise

Sort tickets by weighted_score descending.
Cap P0 count to capacity.coder * 0.3 (max 30% of sprint capacity on critical items).
```

### 3.6 Reporting Content

**Daily Report Sections**:
- Completed today: tickets that reached `done`, `deployed`, or `qa_approved`
- In progress: tickets with active agent runs
- Blocked: stale or blocked tickets with blocker details
- Agent utilization: hours used / available per agent type
- Key metrics: velocity (trailing 7 days), open P0 count, backlog size

**Weekly Report Sections**:
- Sprint progress: planned vs completed hours, burndown chart data
- Velocity trend: last 5 sprints with trend direction
- Feature pipeline: ideas submitted / triaged / converted / in development / deployed
- Backlog health: ticket count by priority, age distribution
- Agent performance: per-type completion rate, average duration, error rate
- Blockers: resolved vs new, longest-standing blockers
- Capacity: utilization heat map, bottleneck identification
- Recommendations: scaling suggestions, process improvements

### 3.7 Frontend Types (`frontend/src/api/types.ts`)

```typescript
export interface PmConfig {
  priority_framework: Record<string, string>;
  priority_weights: Record<string, number>;
  sprint_duration_days: number;
  capacity_per_agent_type: Record<string, number>;
  reporting_cadence: "daily" | "weekly" | "both";
  report_time_utc: string;
  idea_intake_enabled: boolean;
  auto_prioritize: boolean;
  auto_create_feature_requests: boolean;
  blocker_stale_hours: number;
  escalation_on_conflict: boolean;
  coding_tool: "claude_code" | "codex";
  coding_tool_model?: string;
  project_space_id?: string;
  stakeholder_subs?: string[];
}

export interface ProductIdea {
  idea_id: string;
  submitted_by: string;
  title: string;
  description: string;
  status: "submitted" | "triaging" | "accepted" | "rejected" | "converted";
  priority_suggestion?: string;
  impact_score?: number;
  effort_score?: number;
  priority_rationale?: string;
  feature_ticket_id?: string;
  rejection_reason?: string;
  created_at: number;
  updated_at: number;
}

export interface BacklogItem {
  ticket_id: string;
  subject: string;
  labels: string[];
  priority: string;
  priority_score: number;
  complexity?: string;
  estimated_hours?: number;
  status: string;
  assigned_to?: string;
  age_hours: number;
}

export interface Sprint {
  sprint_id: string;
  sprint_number: number;
  start_date: string;
  end_date: string;
  status: "planned" | "active" | "completed";
  planned_hours: number;
  completed_hours: number;
  tickets_planned: number;
  tickets_completed: number;
  tickets_carried_over: number;
  velocity: number;
}

export interface SprintBurndown {
  date: string;
  remaining_hours: number;
  ideal_hours: number;
}

export interface ProjectReport {
  report_id: string;
  report_type: "daily" | "weekly" | "sprint_summary";
  content: string;
  metrics_snapshot: Record<string, any>;
  created_at: number;
}

export interface Blocker {
  ticket_id: string;
  ticket_subject: string;
  blocker_type: "stale" | "blocked" | "agent_error" | "dependency";
  stale_since?: number;
  assigned_agent?: string;
  details: string;
  priority: string;
}

export interface AgentCapacity {
  agent_type: string;
  total_capacity_hours: number;
  used_hours: number;
  available_hours: number;
  utilization_pct: number;
}

export interface PmMetrics {
  ideas_submitted: number;
  ideas_converted: number;
  features_in_pipeline: number;
  velocity_current: number;
  velocity_trend: "increasing" | "stable" | "decreasing";
  backlog_size: number;
  p0_count: number;
  blockers_count: number;
  avg_cycle_time_hours: number;
  period_start: number;
  period_end: number;
}

export interface ProjectDashboard {
  sprint: Sprint | null;
  velocity_trend: { sprint_number: number; velocity: number }[];
  backlog_by_priority: Record<string, number>;
  pipeline_funnel: { stage: string; count: number }[];
  agent_utilization: AgentCapacity[];
  blockers: Blocker[];
  recent_completions: Array<{ ticket_id: string; subject: string; completed_at: number }>;
}
```

### 3.8 Frontend API (`frontend/src/api/endpoints/agents.ts`)

Add PM Agent API functions: `getPmConfig`, `updatePmConfig`, `validatePmConfig`, `submitIdea`, `listIdeas`, `getIdea`, `updateIdeaStatus`, `getBacklog`, `reprioritizeBacklog`, `listSprints`, `getSprint`, `createSprint`, `closeSprint`, `listReports`, `getReport`, `getBlockers`, `getCapacity`, `getPmOutput`, `getPmMetrics`, `getProjectDashboard`.

### 3.9 Frontend Pages

- **PmAgentConfigPage** (`frontend/src/pages/agents/PmAgentConfigPage.tsx`): Route `/agents/types/:typeId/pm`. Tabbed layout: Config | Ideas | Sprints | Reports. `data-testid="pm-config-page"`.
  - **Config tab**: Priority framework editor (4 rows for P0-P3 with descriptions), priority weights sliders (must sum to 1.0), sprint duration, capacity per agent type inputs, reporting cadence, report time, toggles (idea intake, auto-prioritize, auto-create features, escalation), blocker stale hours, stakeholder list. `data-testid="pm-config-tab"`.
  - **Ideas tab**: Table of submitted ideas with status badge, priority suggestion, impact/effort scores. Actions: accept, reject, convert to feature request. Submission form for new ideas (admin quick-entry). `data-testid="pm-ideas-tab"`.
  - **Sprints tab**: Sprint cards with progress bars, velocity, dates. Active sprint expanded with ticket list and burndown chart. Create/close sprint buttons. `data-testid="pm-sprints-tab"`.
  - **Reports tab**: List of generated reports with type badge and date. Click to expand and read full Markdown report. `data-testid="pm-reports-tab"`.

- **ProjectDashboardPage** (`frontend/src/pages/agents/ProjectDashboardPage.tsx`): Route `/agents/dashboard`. Top-level project health view. `data-testid="project-dashboard-page"`.
  - **Sprint Progress**: Current sprint burndown chart, planned vs completed hours.
  - **Velocity Trend**: Line chart of velocity across last 5-10 sprints.
  - **Pipeline Funnel**: Horizontal bar chart: Ideas -> Feature Requests -> Dev Tickets -> In Progress -> Code Complete -> QA -> Deployed.
  - **Backlog Health**: Stacked bar chart by priority (P0/P1/P2/P3).
  - **Agent Utilization**: Per-agent-type utilization bars (coder, qa, devops, architect).
  - **Blockers**: Alert cards for blocked tickets with escalation buttons.
  - **Recent Completions**: Timeline of recently completed/deployed tickets.

- **IdeaSubmissionPage** (`frontend/src/pages/agents/IdeaSubmissionPage.tsx`): Route `/ideas/submit`. Public-facing (any authenticated user). Simple form with title and description. Confirmation message with idea ID. Status tracker showing idea progression. `data-testid="idea-submission-page"`.

- **PmRunOutputPanel** (`frontend/src/pages/agents/PmRunOutputPanel.tsx`): Embedded in Agent Run detail page. Shows: operation type, ideas processed, tickets created/reprioritized, blockers found, escalations, report link, velocity snapshot. `data-testid="pm-output-panel"`.

---

## 4. Implementation Plan

### 4.1 Files to Create

| File | Purpose |
|------|---------|
| `app/services/agent_pm.py` | PM Agent config, idea intake, prioritization, velocity, reporting, sprint management |
| `app/routers/agent_pm.py` | PM config, ideas, backlog, sprints, reports, dashboard endpoints |
| `frontend/src/pages/agents/PmAgentConfigPage.tsx` | PM Agent configuration + ideas + sprints + reports UI |
| `frontend/src/pages/agents/ProjectDashboardPage.tsx` | Top-level project health dashboard |
| `frontend/src/pages/agents/IdeaSubmissionPage.tsx` | User-facing idea submission form |
| `frontend/src/pages/agents/PmRunOutputPanel.tsx` | PM run output detail panel |

### 4.2 Files to Modify

| File | Changes |
|------|---------|
| `scripts/local-ddb-init.py` | Add `product_ideas`, `project_sprints`, `project_reports` TableDefs |
| `app/core/settings.py` | Add table name settings for new tables |
| `app/core/tables.py` | Add table handles for new tables |
| `app/main.py` | Register `agent_pm_router` |
| `app/models.py` | Add all PM request/response models |
| `frontend/src/api/types.ts` | Add `PmConfig`, `ProductIdea`, `BacklogItem`, `Sprint`, `SprintBurndown`, `ProjectReport`, `Blocker`, `AgentCapacity`, `PmMetrics`, `ProjectDashboard` types |
| `frontend/src/api/endpoints/agents.ts` | Add PM Agent API functions |
| `frontend/src/App.tsx` | Add `/agents/types/:typeId/pm`, `/agents/dashboard`, `/ideas/submit` routes |
| `frontend/src/components/layout/Sidebar.tsx` | Add "Project Dashboard" link in agent management section |
| `frontend/src/components/layout/AppShell.tsx` | Add "Project Dashboard" to mobile sidebar |

---

## 5. E2E Test Plan

### 5.1 Test File

`frontend/e2e/agent-pm.spec.ts` -- 18 tests across 4 sections.

### 5.2 Test Setup

```typescript
const TS = Date.now();
let agentTypeId: string;
let ideaId: string;
let featureTicketId: string;
let sprintId: string;
let reportId: string;
// Root = admin; Alice = regular user submitting ideas
```

### 5.3 Section 667: PM Config & Idea Intake API (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 667.1 | Create PM Agent type with config | POST agent type `agent_type=pm`; PUT pm-config with priority framework, weights, capacity; 200 |
| 667.2 | Get PM config | GET pm-config; 200; `priority_framework` has P0-P3; `sprint_duration_days=14` |
| 667.3 | Submit product idea (as user) | POST `/ui/agents/ideas` as Alice with title + description; 201; `idea_id`, `status=submitted` |
| 667.4 | List ideas shows submitted idea | GET ideas; array includes idea with `status=submitted` |
| 667.5 | Update idea status to accepted | PATCH idea with `status=accepted`; 200; idea status = `accepted` |

### 5.4 Section 668: Backlog & Prioritization API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 668.1 | Get backlog returns tickets ordered by priority | GET backlog; 200; array of tickets with `priority_score` descending |
| 668.2 | Reprioritize backlog updates labels | POST reprioritize; 200; `tickets_reprioritized >= 0` |
| 668.3 | Get blockers detects stale tickets | GET blockers; 200; array of `{ticket_id, blocker_type, details}` |
| 668.4 | Get capacity shows agent utilization | GET capacity; 200; array with entries for each agent type; each has `utilization_pct` |

### 5.5 Section 669: Sprint & Reporting API (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 669.1 | Create sprint | POST sprint with start/end dates; 201; `sprint_id`, `status=planned` |
| 669.2 | Get sprint details | GET sprint; 200; `sprint_number`, `planned_hours`, `status` present |
| 669.3 | List reports | GET reports; 200; array returned (may be empty initially) |
| 669.4 | Get PM output from run | GET pm-output; 200; `operation_type` present |
| 669.5 | Get PM metrics | GET pm/metrics; 200; `velocity_current`, `backlog_size`, `p0_count` present |

### 5.6 Section 670: PM Config & Dashboard UI (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 670.1 | PM config page loads | Navigate `/agents/types/{typeId}/pm`; `[data-testid="pm-config-page"]` visible |
| 670.2 | Ideas tab shows submitted ideas | Click "Ideas" tab; `[data-testid="pm-ideas-tab"]` visible; table has rows |
| 670.3 | Project dashboard loads | Navigate `/agents/dashboard`; `[data-testid="project-dashboard-page"]` visible |
| 670.4 | Idea submission page works | Navigate `/ideas/submit` as Alice; `[data-testid="idea-submission-page"]` visible; submit form present |

---

## 6. Error Handling

| Scenario | Status | Detail |
|----------|--------|--------|
| Agent type not found | 404 | "Agent type not found" |
| Agent type is not PM | 409 | "Agent type is not configured as pm" |
| Priority weights don't sum to 1.0 | 422 | "Priority weights must sum to 1.0" |
| Sprint dates invalid | 422 | "End date must be after start date" |
| Sprint overlap with existing | 409 | "Sprint dates overlap with an existing sprint" |
| Idea not found | 404 | "Product idea not found" |
| Idea already converted | 409 | "This idea has already been converted to a feature request" |
| Idea title too short | 422 | "Title must be at least 3 characters" |
| Description too short | 422 | "Description must be at least 10 characters" |
| Idea intake disabled | 403 | "Idea submission is not enabled" |
| No active sprint | 404 | "No active sprint found" |
| Report not found | 404 | "Report not found" |
| Not admin (config endpoints) | 403 | "Admin access required" |
| Not authenticated (idea submission) | 401 | Standard auth error |
| Capacity config missing agent type | 422 | "Capacity must include at least 'coder' agent type" |

---

## 7. Security Considerations

- **Admin-only for configuration**: PM config, backlog management, sprint management, and reporting endpoints require `require_admin_scope()` (see `app/auth/policy.py:84`). <!-- NOTE: was `require_admin_session` which does not exist -->
- **User-accessible idea submission**: The `/ui/agents/ideas` POST endpoint uses `require_ui_session` (any authenticated user), not admin. Users can only see their own ideas; admins see all.
- **Priority manipulation prevention**: Only the PM Agent or admins can change ticket priorities. Regular users cannot modify their own tickets' priority labels.
- **Report access control**: Reports contain sensitive project data (velocity, blockers, agent utilization). Restricted to admin and configured stakeholder_subs.
- **Idea content sanitization**: Idea titles and descriptions are sanitized against XSS before storage and rendering.
- **Stakeholder validation**: `stakeholder_subs` must reference existing users. Invalid subs are rejected at config save time.
- **Sprint scope immutability**: Once a sprint is active, its scope (planned tickets) cannot be changed -- only tickets can be added or removed individually via backlog management. This prevents retroactive scope adjustment that would distort velocity metrics.
- **Velocity data integrity**: Velocity is calculated from ticket estimated_effort_hours, which are set by the Solution Architect Agent. Manual overrides are logged for audit.

---

## 8. Performance Considerations

| Concern | Mitigation |
|---------|-----------|
| Backlog query for large ticket spaces | Paginated query with limit; GSI on status for filtered access |
| Priority scoring for 1000+ tickets | Batch scoring in memory; no LLM call per ticket (formula-based) |
| Velocity calculation across sprints | Pre-computed on sprint close; cached in sprint record |
| Report generation with multiple data sources | Parallel data fetching (sprints, backlog, blockers, utilization) |
| Ideas table growth | GSI1 on status for filtered queries; no TTL needed (ideas are permanent) |
| Daily/weekly report scheduling | Worker Agent Framework handles scheduling; report generation is lightweight |
| Dashboard data aggregation | Pre-computed metrics in pm_metrics; dashboard reads cached data |

---

## 9. Dependencies

| Dependency | Ticket | Status |
|------------|--------|--------|
| AGENT-001 (LLM Provider Key Management) | AGENT-001 | Required |
| AGENT-002 (Terminal Worker Provisioning) | AGENT-002 | Required (for idea triage with coding tool) |
| AGENT-003 (Worker Agent Framework & Lifecycle) | AGENT-003 | Required |
| AGENT-004 (Worker Fleet Management UI) | AGENT-004 | Required (fleet utilization data) |
| AGENT-005 (Agent Memory & Context Injection) | AGENT-005 | Required (context for idea analysis) |
| AGENT-006 (Terminal Monitoring & Feedback Loop) | AGENT-006 | Required (priority conflict escalation, terminal output) |
| AGENT-008 (Coder Agent) | AGENT-008 | Required (velocity data from coder runs) |
| AGENT-009 (QA Agent) | AGENT-009 | Required (pass rate data for project health) |
| AGENT-010 (DevOps Agent) | AGENT-010 | Required (deployment metrics for pipeline tracking) |
| AGENT-011 (Solution Architect) | AGENT-011 | Required (decomposition data, effort estimates) |
| Ticket System | Existing | Available (needs label extensions from AGENT-008) |
| Notification System | Existing | Available (for report delivery) |

### Downstream

| Ticket | Depends On |
|--------|-----------|
| All agent types | PM Agent prioritizes their backlogs |

---

## Codebase References

| Reference | File | Line(s) | Notes |
|-----------|------|---------|-------|
| TicketStore class | `app/services/tickets.py` | 110 | `create_ticket` (215), `update_status` (683), `add_message` (621) |
| Projects store | `app/services/projects_store.py` | — | Existing project CRUD (confirmed exists) |
| `require_admin_scope` | `app/auth/policy.py` | 84 | Correct admin auth (ticket originally said `require_admin_session` which does not exist) |
| `require_ui_session` | `app/services/sessions.py` | — | User auth dependency |
| `audit_event` | `app/services/alerts.py` | 695 | Signature: `(event, user_sub, request, **fields)` |
| Settings singleton | `app/core/settings.py` | 1-1494 | Frozen `Settings` dataclass; singleton `S` |
| Tables singleton | `app/core/tables.py` | — | `T` object |
| Router registration | `app/main.py` | 297-465 | No `agent_pm_router` registered yet |
| `agent_types` DDB table | `scripts/local-ddb-init.py` | — | Does NOT exist yet — requires AGENT-001 |
| `agent_runs` DDB table | `scripts/local-ddb-init.py` | — | Does NOT exist yet — requires AGENT-001 |
| `agent_pm.py` service | `app/services/` | — | Does NOT exist yet — new implementation in this ticket |
| `agent_pm.py` router | `app/routers/` | — | Does NOT exist yet — new implementation in this ticket |
| `tickets` DDB table | `scripts/local-ddb-init.py` | 494-510 | Existing table |
| `now_ts` | `app/core/time.py` | — | Unix timestamp helper |

---

## Testing Strategy


### Unit Tests (pytest)


**Test file**: `tests/test_pm_agent.py`


**Mock setup**: moto for DynamoDB tables, `unittest.mock.patch` for external services (S3, Cognito, Stripe mock). All DDB tables created in-memory via moto `@mock_dynamodb` decorator.


| Test Function | Verifies |
|---|---|
| `test_create_pm_agent` | Creates record with correct fields and generated ID |
| `test_create_pm_agent_validation` | Rejects invalid input (missing required fields, out-of-range values) |
| `test_get_pm_agent_found` | Returns correct record by ID |
| `test_get_pm_agent_not_found` | Returns None for non-existent ID |
| `test_list_pm_agent` | Returns all records for the given scope/owner |
| `test_update_pm_agent` | Updates mutable fields and sets updated_at |
| `test_delete_pm_agent` | Removes record; subsequent get returns None |
| `test_pm_agent_owner_check` | Rejects operations from non-owner users |
| `test_pm_agent_admin_only` | Admin/root endpoints reject USER role with 403 |
| `test_pm_agent_concurrent_write` | Conditional update prevents stale overwrites |

### Integration Tests


Cross-service tests with real DDB (moto), verifying end-to-end flows:


1. Full CRUD lifecycle: create -> read -> update -> delete with real DDB (moto)
2. Authorization enforcement: non-owner access returns 403/404
3. Admin review/approval workflow with role-gated endpoints
4. Concurrent write safety: conditional updates prevent stale overwrites
5. Edge case: empty list returns `[]` not error; missing optional fields use defaults

### E2E Tests (Playwright)


**Test file**: `frontend/e2e/agent-pm.spec.ts`


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
| AGENT-008 | Coder agent | Pending | No |
| AGENT-009 | QA agent | Pending | No |
| AGENT-010 | DevOps agent | Pending | No |
| AGENT-011 | Architect agent | Pending | No |

### Depended On By


| Ticket | What It Needs From This |
|--------|------------------------|
| (none currently identified) | -- |

### Merge Strategy


**Sequential (after AGENT-011)**


- Must merge after: AGENT-001, AGENT-002, AGENT-003, AGENT-004, AGENT-005, AGENT-006, AGENT-008, AGENT-009, AGENT-010, AGENT-011
- Branch from `main` after dependencies are merged
- Can begin development in parallel but must rebase before merge
- DDB table creation is additive (no migration needed for new tables)

### Merge Checklist


- [ ] DDB tables verified (uses existing tables only)
- [ ] `.env.local` updated with any new environment variables
- [ ] Router registered in `app/main.py` (from `app/routers/agent_workers.py`)
- [ ] Frontend route(s) added to `App.tsx`: `/agents/pm`
- [ ] All E2E tests passing (`just e2e` or targeted spec file)
- [ ] No breaking changes to existing endpoints or UI components
- [ ] `just restart` succeeds with new table definitions
