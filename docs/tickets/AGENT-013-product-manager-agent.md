# AGENT-013: Product Manager Agent

**Ticket**: AGENT-013
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: Medium
**Estimated effort**: 10-12 days
**Dependencies**: AGENT-001 (Agent Registry), AGENT-002 (Terminal Provisioning), AGENT-003 (Worker Agent Framework), AGENT-004 (Ticket Lifecycle Bridge), AGENT-005 (Context Injection & Output Parsing), AGENT-006 (Agent Monitoring & Health), AGENT-007 (Orchestration Dashboard)

---

## 1. Overview & Motivation

### 1.1 Purpose

AGENT-013 defines the Product Manager Agent type -- a schedule-driven autonomous agent that continuously reviews the live application, analyzes UX flows and feature gaps, and generates feature ideas for the platform owner to approve or reject. Unlike ticket-driven agent types, the PM Agent operates on a configurable cadence (daily or weekly), browsing the live application via Playwright in its terminal session, comparing against competitor patterns, and synthesizing feature proposals with rationale and expected user impact. Approved ideas are automatically converted into `type:product_request` tickets that the Project Manager Agent can pick up for planning and decomposition. Rejected ideas are archived with the user's reasoning, and the agent learns from approval/rejection patterns to improve future suggestions over time.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Owner | As a platform owner, I want an AI agent to periodically review my app and suggest features. | PM Agent runs on schedule, produces feature ideas with rationale. |
| Owner | As a platform owner, I want to approve or reject feature ideas with feedback. | Feedback UI shows ideas with approve/reject buttons; rejected ideas store reason. |
| Owner | As a platform owner, I want approved ideas to become actionable tickets automatically. | Approved idea creates a `type:product_request` ticket in the ticketing system. |
| Owner | As a platform owner, I want the agent to learn from my preferences over time. | Agent tracks approval rates per category; adjusts future suggestion weighting. |
| Owner | As a platform owner, I want the agent to analyze competitor applications. | Agent accepts competitor URLs and includes comparative analysis in suggestions. |
| Owner | As a platform owner, I want the agent to identify pain points from support tickets. | Agent reads recent support tickets and correlates common complaints to feature gaps. |
| Owner | As a platform owner, I want to configure which areas of my app the agent focuses on. | Focus areas configurable (messaging, billing, UX, performance, etc.). |
| Owner | As a platform owner, I want to see the agent's browsing session recordings. | Terminal output includes Playwright traces; screenshots stored in S3. |

### 1.3 Why This Is Needed

Product management requires continuous attention to the evolving needs of users, competitive landscape, and platform capabilities. Most small teams lack dedicated product managers, leading to reactive development driven by urgent bugs rather than strategic feature planning. An autonomous PM Agent fills this gap by systematically reviewing the application on a schedule, analyzing user feedback from support tickets, and generating prioritized feature ideas. The approval/rejection feedback loop ensures the agent's suggestions align with the owner's vision while reducing the cognitive burden of feature ideation.

---

## 2. Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                  Product Manager Agent System Architecture                   │
└─────────────────────────────────────────────────────────────────────────────┘

  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
  │ Schedule      │   │ Manual       │   │ Support      │
  │ Trigger       │   │ Trigger      │   │ Tickets      │
  │ (cron/daily/  │   │ (owner click │   │ (helpdesk    │
  │  weekly)      │   │  in UI)      │   │  analysis)   │
  └──────┬────────┘   └──────┬───────┘   └──────┬───────┘
         │                   │                   │
         └───────────────────┼───────────────────┘
                             ▼
  ┌──────────────────────────────────────────────────────┐
  │           PM Agent Core (agent_pm.py)                │
  │                                                      │
  │  1. Gather context (preferences, recent rejections)  │
  │  2. Browse live app via Playwright                   │
  │  3. Analyze competitor URLs                          │
  │  4. Analyze support ticket pain points               │
  │  5. Generate feature ideas with evidence             │
  │  6. Store ideas as pending for owner review          │
  └────────┬──────────────┬──────────────┬───────────────┘
           │              │              │
           ▼              ▼              ▼
  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
  │ Feature Ideas│ │ Preference   │ │ S3           │
  │ Table (DDB)  │ │ Learning     │ │ Screenshots  │
  │              │ │ Table (DDB)  │ │ & Traces     │
  │ pk=USER#id   │ │              │ │              │
  │ sk=IDEA#id   │ │ pk=USER#id   │ └──────────────┘
  └──────┬───────┘ │ sk=PREF#cat  │
         │         └──────────────┘
         │
         ▼  (on approve)
  ┌──────────────┐
  │ Ticket System│
  │              │
  │ type:product │
  │ _request     │
  └──────────────┘

  ┌──────────────────────────────────────────────────────┐
  │              Idea Lifecycle State Machine             │
  │                                                      │
  │  ┌─────────┐  approve  ┌──────────┐                │
  │  │ pending │──────────▶│ approved │                │
  │  └────┬────┘           └────┬─────┘                │
  │       │ reject              │ archive              │
  │       ▼                     ▼                      │
  │  ┌──────────┐         ┌──────────┐                │
  │  │ rejected │────────▶│ archived │                │
  │  └──────────┘ archive └──────────┘                │
  └──────────────────────────────────────────────────────┘
```

---

## 3. Current State Analysis

### 2.1 Existing Infrastructure

- **Agent Registry** (AGENT-001): Agent type definitions, configuration schemas, lifecycle management.
- **Terminal Provisioning** (AGENT-002): EC2/K8s instances with Claude Code, Playwright, and browser automation tools.
- **Worker Agent Framework** (AGENT-003): Task execution loop, context injection, output parsing, health reporting.
- **Ticket Lifecycle Bridge** (AGENT-004): Agent-to-ticket integration; agents can create, update, and close tickets.
- **Context Injection** (AGENT-005): Injects codebase context, project state, and configuration into agent sessions.
- **Ticketing system** (`app/services/tickets.py`): Ticket CRUD, spaces, messaging, status transitions.
- **Helpdesk** (`app/routers/messaging.py`): Support ticket conversations with routing.
- **Newsfeed** (`app/routers/newsfeed.py`): User feedback via posts and comments.

### 2.2 Gaps

1. No agent type profile for product management workflows.
2. No schedule-driven agent execution model (existing agents are ticket-triggered).
3. No feature idea model with approval/rejection workflow and feedback capture.
4. No competitor analysis configuration or URL management.
5. No preference learning system that tracks owner approval patterns.
6. No integration between support ticket analysis and feature ideation.
7. No screenshot/trace storage for agent browsing sessions.

---

## 3. Technical Design

### 3.1 Data Model

#### 3.1.1 AgentFeatureIdeas Table

Stores feature ideas generated by the PM Agent, along with approval status and feedback.

| Field | Type | Description |
|-------|------|-------------|
| `pk` | S | `USER#{user_id}` |
| `sk` | S | `IDEA#{idea_id}` |
| `idea_id` | S | UUID hex |
| `user_id` | S | Platform owner |
| `agent_id` | S | PM Agent instance that generated this idea |
| `worker_id` | S | Worker that executed the review session |
| `title` | S | Short idea title (max 200 chars) |
| `description` | S | Detailed description with rationale (max 5000 chars) |
| `category` | S | `ux`, `feature`, `performance`, `integration`, `monetization`, `accessibility` |
| `priority_suggestion` | S | `critical`, `high`, `medium`, `low` |
| `user_impact` | S | Expected user impact narrative (max 1000 chars) |
| `mockup_description` | S (optional) | Text description of proposed UI/UX (max 2000 chars) |
| `evidence` | S (optional) | JSON array of evidence items (screenshots, support ticket refs, competitor URLs) |
| `competitor_refs` | S (optional) | JSON array of competitor feature references |
| `support_ticket_refs` | S (optional) | JSON array of support ticket IDs that informed this idea |
| `status` | S | `pending`, `approved`, `rejected`, `archived` |
| `rejection_reason` | S (optional) | Owner's reason for rejection |
| `created_ticket_id` | S (optional) | Ticket ID created on approval |
| `created_at` | N | Unix timestamp |
| `reviewed_at` | N (optional) | Unix timestamp of approval/rejection |
| `GSI1PK` | S | `USER#{user_id}#STATUS#{status}` |
| `GSI1SK` | N | `created_at` |
| `GSI2PK` | S | `AGENT#{agent_id}` |
| `GSI2SK` | N | `created_at` |

```python
TableDef(
    "agent_feature_ideas", "pk", "sk",
    gsi=[
        {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
        {"index_name": "GSI2", "partition_key": "GSI2PK", "sort_key": "GSI2SK"},
    ],
    attr_types={"created_at": "N", "reviewed_at": "N", "GSI1SK": "N", "GSI2SK": "N"},
),
```

#### 3.1.2 AgentPreferenceLearning Table

Tracks owner approval/rejection patterns to improve future suggestions.

| Field | Type | Description |
|-------|------|-------------|
| `pk` | S | `USER#{user_id}` |
| `sk` | S | `PREF#{category}` |
| `category` | S | Idea category |
| `total_suggested` | N | Total ideas suggested in this category |
| `total_approved` | N | Total approved |
| `total_rejected` | N | Total rejected |
| `approval_rate` | N | Computed approval rate (0.0-1.0) |
| `common_rejection_reasons` | S | JSON array of frequently cited rejection reasons |
| `last_updated` | N | Unix timestamp |

```python
TableDef(
    "agent_preference_learning", "pk", "sk",
    attr_types={
        "total_suggested": "N", "total_approved": "N",
        "total_rejected": "N", "approval_rate": "N", "last_updated": "N",
    },
),
```

#### 3.1.3 PM Agent Configuration (on Agent Registry Record)

Stored as a DDB map on the agent registry entry (`pm_config` field):

```json
{
  "review_frequency": "weekly",
  "review_day": "monday",
  "review_hour_utc": 9,
  "focus_areas": ["messaging", "billing", "ux", "feed"],
  "competitor_urls": [
    {"url": "https://competitor1.com", "name": "Competitor A"},
    {"url": "https://competitor2.com", "name": "Competitor B"}
  ],
  "max_ideas_per_review": 5,
  "analyze_support_tickets": true,
  "support_ticket_lookback_days": 30,
  "app_url": "https://localhost:3000",
  "app_auth_credentials_secret": "pm-agent-creds"
}
```

### 3.2 DynamoDB Access Patterns

| Access Pattern | Table | PK | SK | GSI | Notes |
|----------------|-------|----|----|-----|-------|
| Get idea by ID | `agent_feature_ideas` | `USER#{user_id}` | `IDEA#{idea_id}` | -- | Single item read |
| List ideas by status | `agent_feature_ideas` | -- | -- | `GSI1PK=USER#{user_id}#STATUS#{status}, GSI1SK=created_at` | Paginated, newest first |
| List all ideas for user | `agent_feature_ideas` | `USER#{user_id}` | begins_with `IDEA#` | -- | All statuses |
| List ideas by agent | `agent_feature_ideas` | -- | -- | `GSI2PK=AGENT#{agent_id}, GSI2SK=created_at` | All ideas from one agent run |
| Update idea status | `agent_feature_ideas` | `USER#{user_id}` | `IDEA#{idea_id}` | -- | Conditional: status=pending |
| Get preference by category | `agent_preference_learning` | `USER#{user_id}` | `PREF#{category}` | -- | Single item |
| List all preferences | `agent_preference_learning` | `USER#{user_id}` | begins_with `PREF#` | -- | All categories |
| Update preference counters | `agent_preference_learning` | `USER#{user_id}` | `PREF#{category}` | -- | ADD total_approved/rejected |

**Example DynamoDB item -- feature idea:**

```json
{
  "pk": {"S": "USER#alice-sub-001"},
  "sk": {"S": "IDEA#idea-abc-123"},
  "idea_id": {"S": "idea-abc-123"},
  "user_id": {"S": "alice-sub-001"},
  "agent_id": {"S": "pm-agent-001"},
  "title": {"S": "Add emoji reactions to newsfeed posts"},
  "description": {"S": "Users frequently request the ability to react to posts with emoji..."},
  "category": {"S": "feature"},
  "priority_suggestion": {"S": "high"},
  "user_impact": {"S": "Increases engagement by 20-30% based on competitor data"},
  "status": {"S": "pending"},
  "created_at": {"N": "1748534400"},
  "GSI1PK": {"S": "USER#alice-sub-001#STATUS#pending"},
  "GSI1SK": {"N": "1748534400"},
  "GSI2PK": {"S": "AGENT#pm-agent-001"},
  "GSI2SK": {"N": "1748534400"}
}
```

### 3.3 Backend Service (`app/services/agent_pm.py`)

```python
def create_feature_idea(*, user_id: str, agent_id: str, worker_id: str,
                         title: str, description: str, category: str,
                         priority_suggestion: str, user_impact: str,
                         mockup_description: str | None = None,
                         evidence: list[dict] | None = None,
                         competitor_refs: list[dict] | None = None,
                         support_ticket_refs: list[str] | None = None) -> dict:
    """Create a new feature idea from a PM Agent review session."""
    # 1. Validate category and priority_suggestion enums
    # 2. Generate idea_id
    # 3. Write to AgentFeatureIdeas table with status=pending
    # 4. Return idea dict

def list_feature_ideas(*, user_id: str, status: str | None = None,
                        limit: int = 25, cursor: str | None = None) -> dict:
    """List feature ideas for a user, optionally filtered by status."""
    # 1. Query GSI1 if status filter, else query PK
    # 2. Paginate with cursor
    # 3. Return {"ideas": [...], "next_cursor": ...}

def approve_idea(*, user_id: str, idea_id: str) -> dict:
    """Approve a feature idea, creating a product_request ticket."""
    # 1. Fetch idea, verify ownership and status=pending
    # 2. Create ticket via TicketStore.create_ticket with type=product_request
    # 3. Update idea: status=approved, reviewed_at, created_ticket_id
    # 4. Update preference learning: increment approved count
    # 5. Return updated idea with ticket_id

def reject_idea(*, user_id: str, idea_id: str, reason: str) -> dict:
    """Reject a feature idea with a reason."""
    # 1. Fetch idea, verify ownership and status=pending
    # 2. Update idea: status=rejected, reviewed_at, rejection_reason
    # 3. Update preference learning: increment rejected count, append reason
    # 4. Return updated idea

def archive_idea(*, user_id: str, idea_id: str) -> dict:
    """Archive an idea (approved or rejected) to remove from active list."""

def get_preference_summary(*, user_id: str) -> list[dict]:
    """Return preference learning summary per category."""
    # Query all PREF# records for user
    # Return sorted by approval_rate descending

def get_review_context(*, user_id: str, agent_id: str) -> dict:
    """Build context for a PM Agent review session."""
    # 1. Fetch PM config from agent registry
    # 2. Fetch recent support tickets (if analyze_support_tickets=True)
    # 3. Fetch preference learning data (categories to emphasize/avoid)
    # 4. Fetch recently rejected ideas (to avoid re-suggesting)
    # 5. Return context dict for injection into agent terminal

def store_review_artifacts(*, user_id: str, agent_id: str,
                            worker_id: str, screenshots: list[dict],
                            trace_url: str | None = None) -> dict:
    """Store screenshots and Playwright traces from a review session in S3."""
```

### 3.3 Backend Router (`app/routers/agent_pm.py`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/ui/agents/pm/ideas` | `require_ui_session` | List feature ideas (optional `?status=` filter) |
| GET | `/ui/agents/pm/ideas/{idea_id}` | `require_ui_session` | Get single idea detail |
| POST | `/ui/agents/pm/ideas/{idea_id}/approve` | `require_ui_session` | Approve idea, create ticket |
| POST | `/ui/agents/pm/ideas/{idea_id}/reject` | `require_ui_session` | Reject idea with reason |
| POST | `/ui/agents/pm/ideas/{idea_id}/archive` | `require_ui_session` | Archive idea |
| GET | `/ui/agents/pm/preferences` | `require_ui_session` | Get preference learning summary |
| GET | `/ui/agents/pm/reviews` | `require_ui_session` | List past review sessions with artifacts |
| GET | `/ui/agents/pm/reviews/{review_id}/screenshots` | `require_ui_session` | Get screenshots from a review session |
| PUT | `/ui/agents/pm/config` | `require_ui_session` | Update PM Agent configuration |
| POST | `/ui/agents/pm/trigger-review` | `require_ui_session` | Manually trigger a review cycle |

**Key request models**:

```python
class RejectIdeaIn(BaseModel):
    reason: str = Field(..., min_length=1, max_length=1000)

class UpdatePmConfigIn(BaseModel):
    review_frequency: Optional[Literal["daily", "weekly", "biweekly"]] = None
    review_day: Optional[Literal["monday", "tuesday", "wednesday", "thursday", "friday"]] = None
    review_hour_utc: Optional[int] = Field(default=None, ge=0, le=23)
    focus_areas: Optional[List[str]] = None
    competitor_urls: Optional[List[dict]] = None
    max_ideas_per_review: Optional[int] = Field(default=None, ge=1, le=20)
    analyze_support_tickets: Optional[bool] = None
    support_ticket_lookback_days: Optional[int] = Field(default=None, ge=1, le=90)
```

Response models: `FeatureIdeaOut` mirrors DDB fields; `PreferenceSummaryOut` has category, approval_rate, total counts; `ReviewSessionOut` has session timestamp, idea count, screenshots count, worker_id.

Register in `app/main.py`:

```python
from app.routers.agent_pm import router as agent_pm_router
app.include_router(agent_pm_router, prefix="/ui")
```

### 3.4 Frontend Types (`frontend/src/api/types.ts`)

```typescript
export interface FeatureIdea {
  idea_id: string;
  user_id: string;
  agent_id: string;
  title: string;
  description: string;
  category: "ux" | "feature" | "performance" | "integration" | "monetization" | "accessibility";
  priority_suggestion: "critical" | "high" | "medium" | "low";
  user_impact: string;
  mockup_description?: string;
  evidence?: Array<{ type: string; url?: string; description: string }>;
  competitor_refs?: Array<{ url: string; feature: string; notes: string }>;
  support_ticket_refs?: string[];
  status: "pending" | "approved" | "rejected" | "archived";
  rejection_reason?: string;
  created_ticket_id?: string;
  created_at: number;
  reviewed_at?: number;
}

export interface PreferenceSummary {
  category: string;
  total_suggested: number;
  total_approved: number;
  total_rejected: number;
  approval_rate: number;
}

export interface PmAgentConfig {
  review_frequency: "daily" | "weekly" | "biweekly";
  review_day?: string;
  review_hour_utc: number;
  focus_areas: string[];
  competitor_urls: Array<{ url: string; name: string }>;
  max_ideas_per_review: number;
  analyze_support_tickets: boolean;
  support_ticket_lookback_days: number;
}
```

### 3.5 API Request/Response Examples

```bash
# --- GET /ui/agents/pm/ideas?status=pending ---
curl http://localhost:8000/ui/agents/pm/ideas?status=pending \
  -H "Cookie: ui_session=sess_abc; ui_access_token=eyJ..."

# Response 200:
{
  "ideas": [
    {
      "idea_id": "idea-abc-123",
      "title": "Add emoji reactions to newsfeed posts",
      "category": "feature",
      "priority_suggestion": "high",
      "user_impact": "Increases engagement by 20-30%",
      "status": "pending",
      "created_at": 1748534400
    }
  ],
  "next_cursor": null
}

# --- POST /ui/agents/pm/ideas/{idea_id}/approve ---
curl -X POST http://localhost:8000/ui/agents/pm/ideas/idea-abc-123/approve \
  -H "Cookie: ui_session=sess_abc; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_tok_123"

# Response 200:
{
  "idea_id": "idea-abc-123",
  "status": "approved",
  "created_ticket_id": "TICKET-600",
  "reviewed_at": 1748538000
}

# --- POST /ui/agents/pm/ideas/{idea_id}/reject ---
curl -X POST http://localhost:8000/ui/agents/pm/ideas/idea-def-456/reject \
  -H "Cookie: ui_session=sess_abc; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_tok_123" \
  -H "Content-Type: application/json" \
  -d '{"reason": "Not aligned with current roadmap priorities"}'

# Response 200:
{
  "idea_id": "idea-def-456",
  "status": "rejected",
  "rejection_reason": "Not aligned with current roadmap priorities",
  "reviewed_at": 1748538100
}

# --- GET /ui/agents/pm/preferences ---
curl http://localhost:8000/ui/agents/pm/preferences \
  -H "Cookie: ui_session=sess_abc; ui_access_token=eyJ..."

# Response 200:
{
  "preferences": [
    {"category": "feature", "total_suggested": 12, "total_approved": 8, "total_rejected": 4, "approval_rate": 0.667},
    {"category": "ux", "total_suggested": 5, "total_approved": 1, "total_rejected": 4, "approval_rate": 0.2},
    {"category": "monetization", "total_suggested": 3, "total_approved": 3, "total_rejected": 0, "approval_rate": 1.0}
  ]
}
```

### 3.6 Pydantic Models

```python
from pydantic import BaseModel, Field
from typing import Literal, Optional, List
from enum import Enum


class IdeaCategory(str, Enum):
    UX = "ux"
    FEATURE = "feature"
    PERFORMANCE = "performance"
    INTEGRATION = "integration"
    MONETIZATION = "monetization"
    ACCESSIBILITY = "accessibility"


class IdeaPriority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class IdeaStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    ARCHIVED = "archived"


class EvidenceItem(BaseModel):
    type: str = Field(max_length=50)
    url: Optional[str] = Field(default=None, max_length=500)
    description: str = Field(max_length=500)


class CompetitorRef(BaseModel):
    url: str = Field(max_length=500)
    feature: str = Field(max_length=200)
    notes: str = Field(max_length=500)


class FeatureIdeaOut(BaseModel):
    idea_id: str
    user_id: str
    agent_id: str
    title: str
    description: str
    category: IdeaCategory
    priority_suggestion: IdeaPriority
    user_impact: str
    mockup_description: Optional[str] = None
    evidence: Optional[List[EvidenceItem]] = None
    competitor_refs: Optional[List[CompetitorRef]] = None
    support_ticket_refs: Optional[List[str]] = None
    status: IdeaStatus
    rejection_reason: Optional[str] = None
    created_ticket_id: Optional[str] = None
    created_at: int
    reviewed_at: Optional[int] = None


class RejectIdeaIn(BaseModel):
    reason: str = Field(..., min_length=1, max_length=1000)


class PreferenceSummaryOut(BaseModel):
    category: str
    total_suggested: int = Field(ge=0)
    total_approved: int = Field(ge=0)
    total_rejected: int = Field(ge=0)
    approval_rate: float = Field(ge=0.0, le=1.0)


class UpdatePmConfigIn(BaseModel):
    review_frequency: Optional[Literal["daily", "weekly", "biweekly"]] = None
    review_day: Optional[Literal["monday", "tuesday", "wednesday", "thursday", "friday"]] = None
    review_hour_utc: Optional[int] = Field(default=None, ge=0, le=23)
    focus_areas: Optional[List[str]] = None
    competitor_urls: Optional[List[dict]] = None
    max_ideas_per_review: Optional[int] = Field(default=None, ge=1, le=20)
    analyze_support_tickets: Optional[bool] = None
    support_ticket_lookback_days: Optional[int] = Field(default=None, ge=1, le=90)
```

### 3.7 Frontend Component Tree

```
FeatureIdeasPage                      data-testid="feature-ideas-page"
├── Tabs (status filter)
│   ├── TabsTrigger "Pending"
│   ├── TabsTrigger "Approved"
│   ├── TabsTrigger "Rejected"
│   └── TabsTrigger "Archived"
├── div.grid.grid-cols-1.md:grid-cols-2.lg:grid-cols-3
│   └── ideas.map(idea =>
│       ├── Card
│       │   ├── CardHeader
│       │   │   ├── span.font-semibold (idea.title)
│       │   │   ├── Badge (category)
│       │   │   └── Badge (priority_suggestion)
│       │   ├── CardContent
│       │   │   └── p.text-sm (user_impact, truncated)
│       │   └── CardFooter (if pending)
│       │       ├── Button "Approve" variant="default"
│       │       └── Button "Reject" variant="outline"
│       └── onClick → open IdeaDetailDialog
│   )
└── PmConfigPanel (collapsible sidebar or separate tab)

IdeaDetailDialog                      data-testid="idea-detail-dialog"
├── DialogHeader (idea.title)
├── div.space-y-4
│   ├── div "Category" + Badge
│   ├── div "Priority" + Badge
│   ├── div "User Impact" + p
│   ├── div "Description" + Markdown render
│   ├── div "Mockup" + p (if mockup_description)
│   ├── div "Evidence" + list (if evidence)
│   ├── div "Competitor Refs" + list (if competitor_refs)
│   └── div "Support Tickets" + links (if support_ticket_refs)
├── (if pending) div.flex.gap-2
│   ├── Button "Approve"
│   └── Button "Reject" → shows Textarea for reason
└── (if rejected) div "Rejection Reason" + p

PreferenceDashboard                   data-testid="preference-dashboard"
├── BarChart (approval_rate per category)
└── Table
    └── columns: [category, total_suggested, total_approved, total_rejected, approval_rate]
```

### 3.8 Frontend API (`frontend/src/api/endpoints/agents.ts`)

Standard CRUD wrappers: `listFeatureIdeas(status?)`, `getFeatureIdea(ideaId)`, `approveIdea(ideaId)`, `rejectIdea(ideaId, reason)`, `archiveIdea(ideaId)`, `getPreferenceSummary()`, `listReviewSessions()`, `getReviewScreenshots(reviewId)`, `updatePmConfig(config)`, `triggerReview()`.

### 3.6 Frontend Pages

- **FeatureIdeasPage** (`frontend/src/pages/agents/FeatureIdeasPage.tsx`): Route `/agents/pm/ideas`. Tab bar for status filters (Pending / Approved / Rejected / Archived). Each idea card shows title, category badge, priority badge, user impact snippet, approve/reject buttons (for pending). Clicking a card opens detail dialog with full description, evidence, competitor refs. `data-testid="feature-ideas-page"`.
- **IdeaDetailDialog** (`frontend/src/pages/agents/IdeaDetailDialog.tsx`): Full idea view with description, mockup description, evidence gallery (screenshots), competitor references, support ticket links. Approve and Reject buttons with reason input for rejection. `data-testid="idea-detail-dialog"`.
- **PmConfigPanel** (`frontend/src/pages/agents/PmConfigPanel.tsx`): Configuration form for PM Agent. Schedule picker, focus area checkboxes, competitor URL list, support ticket analysis toggle. `data-testid="pm-config-panel"`.
- **PreferenceDashboard** (`frontend/src/pages/agents/PreferenceDashboard.tsx`): Bar chart of approval rates per category. Table of preference summaries. Helps owner understand what the agent has learned. `data-testid="preference-dashboard"`.

---

## 4. Implementation Plan

### 4.1 Files to Create

| File | Purpose |
|------|---------|
| `app/services/agent_pm.py` | Feature idea CRUD, preference learning, review context builder |
| `app/routers/agent_pm.py` | PM Agent API endpoints |
| `frontend/src/pages/agents/FeatureIdeasPage.tsx` | Feature ideas list with approve/reject |
| `frontend/src/pages/agents/IdeaDetailDialog.tsx` | Idea detail view and actions |
| `frontend/src/pages/agents/PmConfigPanel.tsx` | PM Agent configuration UI |
| `frontend/src/pages/agents/PreferenceDashboard.tsx` | Preference learning visualization |

### 4.2 Files to Modify

| File | Changes |
|------|---------|
| `scripts/local-ddb-init.py` | Add `agent_feature_ideas`, `agent_preference_learning` TableDefs |
| `app/core/settings.py` | Add table name settings for new tables |
| `app/core/tables.py` | Add table handles |
| `app/main.py` | Register `agent_pm_router` |
| `app/models.py` | Add `FeatureIdeaOut`, `PreferenceSummaryOut`, `PmAgentConfigOut` models |
| `frontend/src/api/types.ts` | Add FeatureIdea, PreferenceSummary, PmAgentConfig types |
| `frontend/src/api/endpoints/agents.ts` | Add PM Agent API functions |
| `frontend/src/App.tsx` | Add `/agents/pm/ideas` route |

---

## 5. E2E Test Plan

### 5.1 Test File

`frontend/e2e/agent-pm.spec.ts` -- 16 tests across 4 sections.

### 5.2 Test Setup

```typescript
const TS = Date.now();
let ideaId1: string;
let ideaId2: string;
let ideaId3: string;
// Alice = platform owner
```

### 5.3 Section 671: Feature Idea CRUD API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 671.1 | Create feature idea via internal API | POST `/ui/agents/pm/ideas` (simulating agent output); 201; returns `idea_id`, `status=pending`, `category`, `priority_suggestion` |
| 671.2 | List pending ideas | GET `/ui/agents/pm/ideas?status=pending`; array includes created idea; each has `title`, `description`, `category` |
| 671.3 | Get single idea detail | GET `/ui/agents/pm/ideas/{ideaId1}`; 200; full idea object with `user_impact`, `evidence` |
| 671.4 | Create multiple ideas with different categories | POST 2 more ideas (category=ux, category=monetization); 201; list length >= 3 |

### 5.4 Section 672: Approval & Rejection Workflow API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 672.1 | Approve idea creates ticket | POST `/ui/agents/pm/ideas/{ideaId1}/approve`; 200; `status=approved`, `created_ticket_id` present |
| 672.2 | Reject idea with reason | POST `/ui/agents/pm/ideas/{ideaId2}/reject` with `reason="Not aligned with roadmap"`; 200; `status=rejected`, `rejection_reason` matches |
| 672.3 | Archive rejected idea | POST `/ui/agents/pm/ideas/{ideaId2}/archive`; 200; `status=archived` |
| 672.4 | Cannot approve already rejected idea | POST `/ui/agents/pm/ideas/{ideaId2}/approve`; 409; idea is archived |

### 5.5 Section 673: Preference Learning API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 673.1 | Preference summary reflects approvals | GET `/ui/agents/pm/preferences`; array includes entry for idea1's category with `total_approved >= 1` |
| 673.2 | Preference summary reflects rejections | Same response includes entry for idea2's category with `total_rejected >= 1` |
| 673.3 | Approval rate computed correctly | Category with 1 approve, 0 reject has `approval_rate=1.0` |
| 673.4 | Update PM config | PUT `/ui/agents/pm/config` with `review_frequency=daily`, `max_ideas_per_review=10`; 200; echoed config matches |

### 5.6 Section 674: Feature Ideas UI (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 674.1 | Feature ideas page loads | Navigate `/agents/pm/ideas`; `[data-testid="feature-ideas-page"]` visible; pending ideas listed |
| 674.2 | Idea card shows category and priority badges | Idea card for ideaId3 visible with category badge and priority badge |
| 674.3 | Approve idea via UI | Click idea card; detail dialog opens; click Approve; idea moves to Approved tab |
| 674.4 | Reject idea via UI | Create new pending idea; click Reject; enter reason in dialog; confirm; idea moves to Rejected tab |

### 5.7 Expanded E2E Test Details

#### Section 675: Edge Cases (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 675.1 | Approve already-approved idea | POST approve on approved idea; 409 |
| 675.2 | Reject without reason | POST reject with empty body; 422 |
| 675.3 | List ideas with pagination | Create 30 ideas; GET with limit=10; verify cursor and next page |
| 675.4 | Trigger review while one is running | POST trigger-review twice; second returns 409 |

#### Section 676: Negative Tests (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 676.1 | Other user cannot view ideas | Bob tries to GET Alice's idea; 403 |
| 676.2 | Invalid category in idea creation | POST idea with category="invalid"; 422 |
| 676.3 | Exceed max_ideas_per_review | Set max to 2; create 3 ideas in one batch; third rejected |
| 676.4 | Invalid review frequency | PUT config with review_frequency="hourly"; 422 |

---

## 6. Error Handling

| Scenario | Status | Detail |
|----------|--------|--------|
| Idea not found | 404 | "Feature idea not found" |
| Not idea owner | 403 | "You do not own this feature idea" |
| Invalid status transition | 409 | "Cannot approve an idea with status: {status}" |
| Rejection without reason | 422 | "Rejection reason is required" |
| Invalid category | 422 | "Invalid category: {value}" |
| Config validation error | 422 | "review_hour_utc must be between 0 and 23" |
| Agent not configured | 404 | "No PM Agent configured for this user" |
| Review already in progress | 409 | "A review session is already running" |
| Max ideas per review exceeded | 400 | "Cannot create more than {max} ideas per review" |

### 6.2 Error Handling Matrix

| Error Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|----------------|-------------|------------|---------------------|-----------------|
| Idea not found | 404 | `IDEA_NOT_FOUND` | "Feature idea not found." | Verify idea_id |
| Not owner | 403 | `NOT_IDEA_OWNER` | "You do not own this idea." | Use own account |
| Invalid status transition | 409 | `INVALID_STATUS_TRANSITION` | "Cannot approve idea with status: {s}." | Check current status first |
| No rejection reason | 422 | `REASON_REQUIRED` | "Rejection reason is required." | Provide reason text |
| Invalid category | 422 | `INVALID_CATEGORY` | "Invalid category: {value}." | Use valid category enum |
| Config validation | 422 | `CONFIG_INVALID` | "review_hour_utc must be 0-23." | Fix config value |
| No PM agent configured | 404 | `PM_NOT_CONFIGURED` | "No PM Agent configured." | Create PM agent type first |
| Review in progress | 409 | `REVIEW_IN_PROGRESS` | "A review is already running." | Wait for completion |
| Max ideas exceeded | 400 | `MAX_IDEAS_EXCEEDED` | "Max ideas per review reached." | Increase limit or wait |
| Rate limit on trigger | 429 | `RATE_LIMITED` | "Manual trigger limited to 1/hour." | Wait and retry |

---

## 7. Observability & Monitoring

### 7.1 Metrics

| Metric Name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `pm_ideas_created_total` | Counter | `category`, `priority` | Ideas generated |
| `pm_ideas_approved_total` | Counter | `category` | Ideas approved |
| `pm_ideas_rejected_total` | Counter | `category` | Ideas rejected |
| `pm_review_duration_seconds` | Histogram | -- | Review session duration |
| `pm_review_ideas_count` | Histogram | -- | Ideas per review session |
| `pm_approval_rate` | Gauge | `category` | Rolling approval rate |
| `pm_pending_ideas_gauge` | Gauge | -- | Pending ideas awaiting review |

### 7.2 Log Events

| Event | Level | Fields |
|-------|-------|--------|
| `pm_review_started` | INFO | agent_id, user_id, focus_areas |
| `pm_idea_created` | INFO | idea_id, category, priority |
| `pm_idea_approved` | INFO | idea_id, ticket_id |
| `pm_idea_rejected` | INFO | idea_id, reason |
| `pm_review_completed` | INFO | agent_id, ideas_count, duration |
| `pm_preference_updated` | DEBUG | user_id, category, approval_rate |

### 7.3 Alerts

| Alert | Condition | Severity |
|-------|-----------|----------|
| No reviews in 7 days | review count = 0 (7d) | P3 |
| Approval rate < 10% | Rolling 30d approval rate < 0.1 | P3 |
| Review session stuck | Duration > 45 min | P2 |

---

## 8. Rollout Plan

### 8.1 Feature Flags

| Flag | Default | Description |
|------|---------|-------------|
| `PM_AGENT_ENABLED` | `false` | Master kill switch |
| `PM_COMPETITOR_ANALYSIS_ENABLED` | `false` | Allow competitor URL browsing |
| `PM_SUPPORT_ANALYSIS_ENABLED` | `true` | Analyze support tickets |
| `PM_AUTO_TICKET_CREATION` | `true` | Create tickets on approval (vs manual) |

### 8.2 Canary Deployment

1. **Week 1**: Enable for a single test user. Review ideas manually. Verify preference learning.
2. **Week 2**: Enable for all users with `PM_COMPETITOR_ANALYSIS_ENABLED=false` (no external browsing).
3. **Week 3**: Enable competitor analysis. Monitor for SSRF or credential leak.

### 8.3 Rollback

Set `PM_AGENT_ENABLED=false`. Existing ideas and preferences remain; no new reviews scheduled.

---

## 9. Security Considerations

- **Ownership enforcement**: All idea operations verify `user_id` matches the authenticated session. Users cannot view or act on other users' ideas.
- **Agent credential isolation**: PM Agent's app browsing credentials are stored in a secrets manager reference (`app_auth_credentials_secret`), never in the DDB config directly. The agent terminal receives credentials via environment variable injection.
- **Screenshot storage**: Screenshots are stored in S3 with per-user prefix isolation (`s3://bucket/agent-artifacts/{user_id}/pm/`). Presigned URLs used for frontend display (15-minute expiry).
- **Competitor URL validation**: Competitor URLs are validated as HTTPS URLs. No internal/localhost URLs allowed to prevent SSRF. URL list capped at 10 entries.
- **Support ticket access**: PM Agent only reads support tickets owned by the same user. Cross-tenant ticket access is blocked at the service layer.
- **Rate limiting**: `trigger-review` endpoint rate-limited to 1 per hour per user to prevent abuse of compute resources.
- **Idea content sanitization**: Title, description, and mockup_description are sanitized to prevent XSS when rendered in the frontend.

---

## 8. Performance Considerations

| Concern | Mitigation |
|---------|-----------|
| Review session compute cost | Capped at `max_ideas_per_review` (default 5); review sessions time-limited to 30 minutes |
| Feature idea list growth | GSI1 query with status filter + pagination; archived ideas can be TTL-expired after 180 days |
| Preference learning updates | Atomic counter increments; no read-before-write needed |
| Screenshot storage | S3 lifecycle policy: move to IA after 30 days, delete after 180 days |
| Support ticket analysis | Limited to `support_ticket_lookback_days` (default 30); query capped at 100 tickets |

---

## 9. Dependencies

| Dependency | Ticket | Status |
|------------|--------|--------|
| AGENT-001 (Agent Registry) | AGENT-001 | Required (agent type definitions, config storage) |
| AGENT-002 (Terminal Provisioning) | AGENT-002 | Required (EC2/K8s instances with Playwright) |
| AGENT-003 (Worker Agent Framework) | AGENT-003 | Required (task execution loop, schedule-driven mode) |
| AGENT-004 (Ticket Lifecycle Bridge) | AGENT-004 | Required (creating product_request tickets on approval) |
| AGENT-005 (Context Injection) | AGENT-005 | Required (injecting review context into agent terminal) |
| AGENT-006 (Agent Monitoring) | AGENT-006 | Required (health checks for long-running review sessions) |
| AGENT-007 (Orchestration Dashboard) | AGENT-007 | Required (viewing PM Agent status and review history) |
| Ticketing system | Existing | Available (ticket creation for approved ideas) |
| Helpdesk/support | Existing | Available (reading support tickets for pain point analysis) |

### Downstream

| Ticket | Depends On |
|--------|-----------|
| AGENT-014 (Documentation Agent) | May document features generated from PM Agent ideas |
| AGENT-016 (Stylist/UI Agent) | Reviews UI mockup descriptions from PM Agent ideas |
