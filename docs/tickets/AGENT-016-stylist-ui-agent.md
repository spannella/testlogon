# AGENT-016: Stylist / UI Agent

**Ticket**: AGENT-016
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: Medium
**Estimated effort**: 10-12 days
**Dependencies**: AGENT-001 (Agent Registry), AGENT-002 (Terminal Provisioning), AGENT-003 (Worker Agent Framework), AGENT-004 (Ticket Lifecycle Bridge), AGENT-005 (Context Injection & Output Parsing), AGENT-006 (Agent Monitoring & Health), AGENT-007 (Orchestration Dashboard)

---

## 1. Overview & Motivation

### 1.1 Purpose

AGENT-016 defines the Stylist / UI Agent type -- a visual design review agent that picks up tickets labeled `type:ui_review` or activates when UI-related PRs are merged. The agent uses Playwright in its terminal session to capture screenshots and recordings of the application UI, then analyzes them for visual consistency, spacing, color harmony, typography, and responsive layout compliance against the design system (shadcn/ui + Tailwind conventions). It creates improvement tickets for UI issues such as misalignment, inconsistent spacing, poor contrast ratios, and missing responsive breakpoints. For UI-related coder tickets, it comments with design suggestions before implementation begins. After UI work is completed, it reviews the result and either approves or requests design changes. The agent also checks WCAG accessibility requirements including color contrast ratios, keyboard navigation, and screen reader compatibility.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Owner | As a platform owner, I want consistent visual design across all pages. | Agent detects inconsistencies in spacing, colors, typography across pages. |
| Owner | As a platform owner, I want UI improvements suggested with annotated screenshots. | Agent produces screenshots with annotations marking issues. |
| Owner | As a platform owner, I want accessibility compliance verified. | Agent checks WCAG contrast ratios, keyboard nav, ARIA labels. |
| Developer | As a developer, I want design guidance before I implement a UI ticket. | Agent comments on UI tickets with design suggestions and component recommendations. |
| Developer | As a developer, I want my UI changes reviewed for visual quality. | Agent reviews completed UI work and provides feedback. |
| Owner | As a platform owner, I want responsive design verified across breakpoints. | Agent captures screenshots at mobile, tablet, desktop widths. |
| Owner | As a platform owner, I want design system compliance enforced. | Agent flags usage of non-standard colors, spacing values, or components. |
| Owner | As a platform owner, I want a visual design consistency score for my app. | Dashboard shows per-page design scores and overall consistency. |

### 1.3 Why This Is Needed

Visual design consistency directly impacts user trust and engagement. Applications with inconsistent UI (different button sizes on different pages, misaligned elements, inconsistent color usage) appear unprofessional and erode confidence. Manual design review is subjective, time-consuming, and often skipped under deadline pressure. An autonomous Stylist Agent provides objective, comprehensive visual analysis using LLM vision capabilities to evaluate screenshots against design system standards. It catches issues that developers overlook (slight misalignments, color inconsistencies between sections) and ensures accessibility compliance that is legally required but frequently neglected.

---

## 2. Current State Analysis

### 2.1 Existing Infrastructure

- **Agent Registry** (AGENT-001): Agent type definitions, configuration schemas.
- **Worker Agent Framework** (AGENT-003): Task execution, context injection, Playwright available in terminals.
- **Ticket Lifecycle Bridge** (AGENT-004): Agent-to-ticket integration.
- **Frontend design system**: shadcn/ui components (`frontend/src/components/ui/`), Tailwind CSS configuration.
- **Frontend pages**: 20+ feature pages under `frontend/src/pages/`.
- **Existing UI components**: `Button`, `Dialog`, `Card`, `Badge`, `Input`, `Select` from shadcn/ui.
- **Tailwind config**: Tailwind CSS v4 via `@tailwindcss/vite` plugin (`frontend/vite.config.ts:3,7`); theme tokens in `frontend/src/globals.css` (CSS `@theme` block). <!-- NOTE: `frontend/tailwind.config.js` does NOT exist — Tailwind v4 uses the Vite plugin and CSS-based configuration, not a JS config file. -->
- **Playwright**: Installed and configured for E2E tests in `frontend/playwright.config.ts`.

### 2.2 Gaps

1. No agent type profile for visual design review workflows.
2. No screenshot capture and annotation system for design review.
3. No design consistency scoring model.
4. No accessibility audit integration (contrast, keyboard, ARIA).
5. No design system rule definitions for automated enforcement.
6. No responsive design verification across breakpoints.
7. No mechanism for agents to comment on tickets with design suggestions before implementation.

---

## 3. Technical Design

### 3.1 Data Model

#### 3.1.1 UIReviews Table

Stores UI review results per page or component, including design scores and issues.

| Field | Type | Description |
|-------|------|-------------|
| `pk` | S | `USER#{user_id}` |
| `sk` | S | `REVIEW#{review_id}` |
| `review_id` | S | UUID hex |
| `user_id` | S | Platform owner |
| `agent_id` | S | Stylist Agent instance |
| `worker_id` | S | Worker that performed the review |
| `page_url` | S | URL path reviewed (e.g., `/messages`, `/billing`) |
| `page_name` | S | Human-readable page name |
| `review_type` | S | `full_page`, `component`, `responsive`, `accessibility`, `pr_review` |
| `source_ref` | S (optional) | PR number or ticket ID that triggered the review |
| `screenshots` | S | JSON array of `{"url": "s3://...", "viewport": "1280x720", "label": "desktop"}` |
| `annotations` | S (optional) | JSON array of `{"screenshot_index": 0, "x": 100, "y": 200, "width": 50, "height": 50, "issue": "..."}` |
| `design_score` | N | 0.0-100.0 overall design consistency score |
| `accessibility_score` | N (optional) | 0.0-100.0 WCAG compliance score |
| `issues_found` | N | Number of issues identified |
| `issues` | S | JSON array of issue objects (see 3.1.3) |
| `status` | S | `completed`, `in_progress`, `failed` |
| `created_at` | N | Unix timestamp |
| `GSI1PK` | S | `USER#{user_id}#PAGE#{page_url_hash}` |
| `GSI1SK` | N | `created_at` |
| `GSI2PK` | S | `USER#{user_id}#TYPE#{review_type}` |
| `GSI2SK` | N | `created_at` |

```python
TableDef(
    "agent_ui_reviews", "pk", "sk",
    gsi=[
        {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
        {"index_name": "GSI2", "partition_key": "GSI2PK", "sort_key": "GSI2SK"},
    ],
    attr_types={
        "design_score": "N", "accessibility_score": "N", "issues_found": "N",
        "created_at": "N", "GSI1SK": "N", "GSI2SK": "N",
    },
),
```

#### 3.1.2 DesignRules Table

Stores configurable design system rules the agent enforces.

| Field | Type | Description |
|-------|------|-------------|
| `pk` | S | `USER#{user_id}` |
| `sk` | S | `RULE#{rule_id}` |
| `rule_id` | S | UUID hex |
| `name` | S | Rule name (e.g., "Button consistency", "Spacing uniformity") |
| `category` | S | `spacing`, `color`, `typography`, `layout`, `component`, `responsive`, `accessibility` |
| `description` | S | What the rule checks |
| `severity` | S | `error`, `warning`, `info` |
| `enabled` | BOOL | Whether rule is active |
| `config` | S (optional) | JSON rule-specific config (thresholds, allowed values) |
| `created_at` | N | Unix timestamp |

```python
TableDef(
    "agent_design_rules", "pk", "sk",
    attr_types={"created_at": "N"},
),
```

#### 3.1.3 Issue Object Structure (within UIReviews.issues)

```json
{
  "issue_id": "uuid-hex",
  "category": "spacing",
  "severity": "warning",
  "title": "Inconsistent card padding",
  "description": "Card on /messages uses p-4 while equivalent card on /feed uses p-3",
  "page_element": "div.message-card",
  "screenshot_index": 0,
  "annotation_rect": {"x": 100, "y": 200, "width": 300, "height": 150},
  "design_rule_id": "rule-uuid",
  "suggestion": "Standardize to p-4 across all card components",
  "created_ticket_id": null
}
```

#### 3.1.4 Stylist Agent Configuration (on Agent Registry Record)

Stored as a DDB map on the agent registry entry (`stylist_config` field):

```json
{
  "review_on_pr_merge": true,
  "review_on_ui_ticket": true,
  "periodic_review_frequency": "weekly",
  "periodic_review_day": "wednesday",
  "periodic_review_hour_utc": 10,
  "viewports": [
    {"name": "mobile", "width": 375, "height": 812},
    {"name": "tablet", "width": 768, "height": 1024},
    {"name": "desktop", "width": 1280, "height": 720}
  ],
  "pages_to_review": ["/messages", "/feed", "/billing", "/files", "/settings"],
  "design_system_ref": "shadcn-ui",
  "tailwind_config_path": "frontend/src/globals.css",  // NOTE: Tailwind v4 — theme tokens are in globals.css, not tailwind.config.js
  "contrast_ratio_min": 4.5,
  "auto_create_tickets": true,
  "ticket_min_severity": "warning",
  "brand_colors": ["#000000", "#ffffff", "#3b82f6", "#ef4444"],
  "font_families": ["Inter", "system-ui"]
}
```

### 3.2 Backend Service (`app/services/agent_stylist.py`)

```python
def create_review(*, user_id: str, agent_id: str, worker_id: str,
                   page_url: str, page_name: str, review_type: str,
                   screenshots: list[dict], design_score: float,
                   accessibility_score: float | None = None,
                   issues: list[dict] | None = None,
                   annotations: list[dict] | None = None,
                   source_ref: str | None = None) -> dict:
    """Create a UI review result."""
    # 1. Generate review_id
    # 2. Count issues, compute issues_found
    # 3. Store screenshots in S3, record URLs
    # 4. If auto_create_tickets, create tickets for issues >= min_severity
    # 5. Write to UIReviews table
    # 6. Return review dict

def list_reviews(*, user_id: str, page_url: str | None = None,
                  review_type: str | None = None,
                  limit: int = 25, cursor: str | None = None) -> dict:
    """List UI reviews, optionally filtered by page or type."""

def get_review(*, user_id: str, review_id: str) -> dict:
    """Get a single review with full issues and screenshots."""

def get_page_scores(*, user_id: str) -> list[dict]:
    """Get latest design score per page (most recent review per page_url)."""
    # 1. Query all reviews, group by page_url
    # 2. For each page, take the most recent review's scores
    # 3. Return sorted by design_score ascending (worst first)

def get_overall_score(*, user_id: str) -> dict:
    """Compute overall design consistency and accessibility scores."""
    # Average of latest per-page scores

def create_design_rule(*, user_id: str, name: str, category: str,
                        description: str, severity: str,
                        config: dict | None = None) -> dict:
    """Create a custom design rule."""

def list_design_rules(*, user_id: str, category: str | None = None,
                       enabled_only: bool = True) -> list[dict]:
    """List design rules."""

def update_design_rule(*, user_id: str, rule_id: str, **fields) -> dict:
    """Update a design rule."""

def delete_design_rule(*, user_id: str, rule_id: str) -> dict:
    """Delete a custom design rule."""

def create_issue_ticket(*, user_id: str, review_id: str,
                          issue_id: str) -> dict:
    """Create a ticket for a specific UI issue from a review."""
    # 1. Fetch review and issue
    # 2. Create type:ui_review ticket with issue details
    # 3. Attach screenshot with annotation
    # 4. Update issue.created_ticket_id
    # 5. Return ticket dict
```

### 3.3 Backend Router (`app/routers/agent_stylist.py`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/ui/agents/stylist/reviews` | `require_ui_session` | List UI reviews (filters: `?page_url=`, `?review_type=`) |
| GET | `/ui/agents/stylist/reviews/{review_id}` | `require_ui_session` | Get review detail with screenshots and issues |
| GET | `/ui/agents/stylist/scores` | `require_ui_session` | Get per-page design scores |
| GET | `/ui/agents/stylist/scores/overall` | `require_ui_session` | Get overall design consistency score |
| POST | `/ui/agents/stylist/reviews/{review_id}/issues/{issue_id}/ticket` | `require_ui_session` | Create ticket for a specific issue |
| GET | `/ui/agents/stylist/rules` | `require_ui_session` | List design rules |
| POST | `/ui/agents/stylist/rules` | `require_ui_session` | Create design rule |
| PUT | `/ui/agents/stylist/rules/{rule_id}` | `require_ui_session` | Update design rule |
| DELETE | `/ui/agents/stylist/rules/{rule_id}` | `require_ui_session` | Delete design rule |
| PUT | `/ui/agents/stylist/config` | `require_ui_session` | Update Stylist Agent config |
| POST | `/ui/agents/stylist/trigger-review` | `require_ui_session` | Manually trigger a UI review for specific pages |

**Key request models**:

```python
class CreateDesignRuleIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    category: Literal["spacing", "color", "typography", "layout", "component", "responsive", "accessibility"]
    description: str = Field(..., min_length=1, max_length=1000)
    severity: Literal["error", "warning", "info"]
    config: Optional[Dict[str, Any]] = None

class TriggerReviewIn(BaseModel):
    pages: List[str] = Field(..., min_length=1, max_length=20)
    review_type: Literal["full_page", "responsive", "accessibility"] = "full_page"
    viewports: Optional[List[Dict[str, int]]] = None

class UpdateStylistConfigIn(BaseModel):
    review_on_pr_merge: Optional[bool] = None
    review_on_ui_ticket: Optional[bool] = None
    periodic_review_frequency: Optional[Literal["daily", "weekly", "biweekly"]] = None
    periodic_review_day: Optional[str] = None
    periodic_review_hour_utc: Optional[int] = Field(default=None, ge=0, le=23)
    viewports: Optional[List[Dict[str, int]]] = None
    pages_to_review: Optional[List[str]] = None
    contrast_ratio_min: Optional[float] = Field(default=None, ge=3.0, le=7.0)
    auto_create_tickets: Optional[bool] = None
    ticket_min_severity: Optional[Literal["error", "warning", "info"]] = None
    brand_colors: Optional[List[str]] = None
    font_families: Optional[List[str]] = None
```

Register in `app/main.py`:

```python
from app.routers.agent_stylist import router as agent_stylist_router
app.include_router(agent_stylist_router, prefix="/ui")
```

### 3.4 Frontend Types (`frontend/src/api/types.ts`)

```typescript
export interface UIReview {
  review_id: string;
  agent_id: string;
  page_url: string;
  page_name: string;
  review_type: "full_page" | "component" | "responsive" | "accessibility" | "pr_review";
  source_ref?: string;
  screenshots: Array<{ url: string; viewport: string; label: string }>;
  annotations?: Array<{ screenshot_index: number; x: number; y: number; width: number; height: number; issue: string }>;
  design_score: number;
  accessibility_score?: number;
  issues_found: number;
  issues: UIReviewIssue[];
  status: "completed" | "in_progress" | "failed";
  created_at: number;
}

export interface UIReviewIssue {
  issue_id: string;
  category: string;
  severity: "error" | "warning" | "info";
  title: string;
  description: string;
  page_element?: string;
  screenshot_index?: number;
  annotation_rect?: { x: number; y: number; width: number; height: number };
  suggestion: string;
  created_ticket_id?: string;
}

export interface PageDesignScore {
  page_url: string;
  page_name: string;
  design_score: number;
  accessibility_score?: number;
  issues_found: number;
  last_reviewed: number;
}

export interface DesignRule {
  rule_id: string;
  name: string;
  category: string;
  description: string;
  severity: "error" | "warning" | "info";
  enabled: boolean;
  config?: Record<string, any>;
  created_at: number;
}

export interface StylistConfig {
  review_on_pr_merge: boolean;
  periodic_review_frequency: string;
  viewports: Array<{ name: string; width: number; height: number }>;
  pages_to_review: string[];
  contrast_ratio_min: number;
  auto_create_tickets: boolean;
  brand_colors: string[];
  font_families: string[];
}
```

### 3.5 Frontend API (`frontend/src/api/endpoints/agents.ts`)

Standard wrappers: `listUIReviews(filters?)`, `getUIReview(reviewId)`, `getPageScores()`, `getOverallScore()`, `createIssueTicket(reviewId, issueId)`, `listDesignRules(category?)`, `createDesignRule(data)`, `updateDesignRule(ruleId, data)`, `deleteDesignRule(ruleId)`, `updateStylistConfig(config)`, `triggerUIReview(pages, reviewType?)`.

### 3.6 Frontend Pages

- **DesignOverviewPage** (`frontend/src/pages/agents/DesignOverviewPage.tsx`): Route `/agents/stylist`. Top: overall design score (large circular gauge) + accessibility score. Grid of per-page score cards sorted worst-first: each shows page name, design score bar, issue count, last reviewed date. Click card to view latest review detail. "Run Review" button. `data-testid="design-overview-page"`.
- **ReviewDetailPage** (`frontend/src/pages/agents/ReviewDetailPage.tsx`): Route `/agents/stylist/reviews/:reviewId`. Screenshot gallery with viewport tabs (mobile/tablet/desktop). Issues list below screenshots with severity badges. Click issue to highlight annotation on screenshot. "Create Ticket" button per issue. `data-testid="review-detail-page"`.
- **DesignRulesPage** (`frontend/src/pages/agents/DesignRulesPage.tsx`): Route `/agents/stylist/rules`. List of design rules with category badges, severity, enabled toggle. Create/edit rules via dialog. `data-testid="design-rules-page"`.

---

## 4. Implementation Plan

### 4.1 Files to Create

| File | Purpose |
|------|---------|
| `app/services/agent_stylist.py` | Review CRUD, design scoring, rule management |
| `app/routers/agent_stylist.py` | Stylist Agent API endpoints |
| `frontend/src/pages/agents/DesignOverviewPage.tsx` | Per-page design scores dashboard |
| `frontend/src/pages/agents/ReviewDetailPage.tsx` | Screenshot gallery with annotated issues |
| `frontend/src/pages/agents/DesignRulesPage.tsx` | Design rule management |

### 4.2 Files to Modify

| File | Changes |
|------|---------|
| `scripts/local-ddb-init.py` | Add `agent_ui_reviews`, `agent_design_rules` TableDefs |
| `app/core/settings.py` | Add table name settings |
| `app/core/tables.py` | Add table handles |
| `app/main.py` | Register `agent_stylist_router` |
| `app/models.py` | Add `UIReviewOut`, `PageDesignScoreOut`, `DesignRuleOut` models |
| `frontend/src/api/types.ts` | Add UI review, design rule types |
| `frontend/src/api/endpoints/agents.ts` | Add Stylist Agent API functions |
| `frontend/src/App.tsx` | Add `/agents/stylist`, `/agents/stylist/reviews/:reviewId`, `/agents/stylist/rules` routes |

---

## 5. E2E Test Plan

### 5.1 Test File

`frontend/e2e/agent-stylist.spec.ts` -- 15 tests across 4 sections.

### 5.2 Test Setup

```typescript
const TS = Date.now();
let reviewId: string;
let ruleId: string;
let issueId: string;
// Alice = platform owner
```

### 5.3 Section 683: UI Review CRUD API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 683.1 | Create UI review result | POST review with `page_url="/messages"`, `design_score=82.5`, `issues` array with 2 issues; 201; returns `review_id`, `issues_found=2` |
| 683.2 | Create responsive review | POST review with `review_type="responsive"`, screenshots for 3 viewports; 201; `screenshots` length=3 |
| 683.3 | Get review detail | GET `/ui/agents/stylist/reviews/{reviewId}`; 200; full object with `screenshots`, `issues`, `annotations` |
| 683.4 | List reviews by page | GET `/ui/agents/stylist/reviews?page_url=/messages`; 200; all results have `page_url="/messages"` |

### 5.4 Section 684: Design Scores & Issue Tickets API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 684.1 | Get per-page design scores | GET `/ui/agents/stylist/scores`; 200; array with `page_url`, `design_score`, `issues_found` per page |
| 684.2 | Get overall design score | GET `/ui/agents/stylist/scores/overall`; 200; `overall_design_score` is numeric, `overall_accessibility_score` present |
| 684.3 | Create ticket from issue | POST `/ui/agents/stylist/reviews/{reviewId}/issues/{issueId}/ticket`; 200; returns `ticket_id`; issue now has `created_ticket_id` |
| 684.4 | Cannot create duplicate ticket for same issue | POST same endpoint again; 409; "Ticket already created for this issue" |

### 5.5 Section 685: Design Rules API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 685.1 | Create design rule | POST `/ui/agents/stylist/rules` with `name="Button spacing"`, `category="spacing"`, `severity="warning"`; 201; returns `rule_id` |
| 685.2 | List design rules | GET `/ui/agents/stylist/rules`; array includes created rule |
| 685.3 | Update design rule | PUT `/ui/agents/stylist/rules/{ruleId}` with `severity="error"`; 200; severity updated |
| 685.4 | Delete design rule | DELETE `/ui/agents/stylist/rules/{ruleId}`; 200; list no longer includes rule |

### 5.6 Section 686: Design Overview UI (3 tests)

| # | Test | Assertion |
|---|------|-----------|
| 686.1 | Design overview page loads | Navigate `/agents/stylist`; `[data-testid="design-overview-page"]` visible; page score cards rendered |
| 686.2 | Review detail shows screenshots | Navigate `/agents/stylist/reviews/{reviewId}`; `[data-testid="review-detail-page"]` visible; screenshot images present |
| 686.3 | Design rules page CRUD | Navigate `/agents/stylist/rules`; `[data-testid="design-rules-page"]` visible; create rule via form; rule appears in list |

---

## 6. Error Handling

| Scenario | Status | Detail |
|----------|--------|--------|
| Review not found | 404 | "UI review not found" |
| Issue not found in review | 404 | "Issue not found in review" |
| Duplicate ticket for issue | 409 | "Ticket already created for this issue" |
| Rule not found | 404 | "Design rule not found" |
| Invalid category | 422 | "Invalid category: {value}" |
| Invalid viewport dimensions | 422 | "Viewport width must be between 320 and 3840" |
| Too many pages in trigger | 422 | "Maximum 20 pages per review trigger" |
| Agent not configured | 404 | "No Stylist Agent configured for this user" |
| Review already in progress | 409 | "A UI review is already running for this page" |

---

## 7. Security Considerations

- **Ownership enforcement**: All reviews, rules, and scores scoped to authenticated `user_id`.
- **Screenshot storage**: Screenshots stored in S3 with per-user prefix (`s3://bucket/agent-artifacts/{user_id}/stylist/`). Presigned URLs with 15-minute expiry for frontend display.
- **Screenshot content**: Screenshots may capture sensitive UI state (logged-in user data). Access restricted to the platform owner only.
- **Annotation data**: Stored as JSON; no executable content. Validated structure before storage.
- **Design rule config**: Rule config values validated against allowed types (numbers, strings, arrays). No code execution from rule configs.
- **App credentials**: The Stylist Agent browses the live app using a dedicated test account. Credentials stored in secrets manager, not in DDB. The test account has limited permissions (read-only, cannot modify data).
- **Rate limiting**: `trigger-review` endpoint rate-limited to 5 per hour per user.

---

## 8. Performance Considerations

| Concern | Mitigation |
|---------|-----------|
| Screenshot capture and upload | Playwright captures are async; S3 uploads parallelized; 3 viewports * 20 pages = 60 screenshots max |
| Review result storage | Issues array capped at 100 per review; screenshots capped at 60 per review |
| Page scores aggregation | Computed from most recent review per page; cached in DDB summary record |
| Design rule evaluation | Rules evaluated during agent session (in terminal), not in backend API |
| Screenshot display in frontend | Lazy-loaded images with thumbnails; full-size on click |

---

## 9. Dependencies

| Dependency | Ticket | Status |
|------------|--------|--------|
| AGENT-001 (Agent Registry) | AGENT-001 | Required (agent type definitions, config storage) |
| AGENT-002 (Terminal Provisioning) | AGENT-002 | Required (terminal with Playwright and browser) |
| AGENT-003 (Worker Agent Framework) | AGENT-003 | Required (task execution, PR-merge trigger support) |
| AGENT-004 (Ticket Lifecycle Bridge) | AGENT-004 | Required (creating UI improvement tickets) |
| AGENT-005 (Context Injection) | AGENT-005 | Required (injecting design system context, PR diffs) |
| AGENT-006 (Agent Monitoring) | AGENT-006 | Required (monitoring review sessions) |
| AGENT-007 (Orchestration Dashboard) | AGENT-007 | Required (viewing stylist agent activity) |
| Ticketing system | Existing | Available (UI improvement ticket creation) |
| shadcn/ui + Tailwind | Existing | Available (design system reference for rules) |

### Downstream

| Ticket | Depends On |
|--------|-----------|
| AGENT-013 (PM Agent) | May reference design scores when suggesting UX improvements |
| AGENT-015 (Security Agent) | Accessibility findings may overlap with WCAG compliance checks |

---

## 10. Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                Stylist / UI Agent Architecture                       │
└─────────────────────────────────────────────────────────────────────┘

  ┌──────────────┐   ┌──────────────┐
  │ PR Merge     │   │ Schedule /   │
  │ Trigger      │   │ Manual       │
  └──────┬───────┘   └──────┬───────┘
         └──────────────────┘
                  ▼
  ┌──────────────────────────────────────┐
  │   Stylist Agent Core                 │
  │                                      │
  │  1. Load design rules               │
  │  2. Browse app via Playwright        │
  │  3. Screenshot 3 viewports           │
  │  4. Evaluate accessibility (axe)     │
  │  5. Compare against design system    │
  │  6. Score each page                  │
  │  7. Generate review report           │
  └──────┬────────────┬────────┬────────┘
         │            │        │
         ▼            ▼        ▼
  ┌──────────┐ ┌──────────┐ ┌──────────┐
  │ UIReviews│ │ Design   │ │ S3       │
  │ Table    │ │ Rules    │ │ screens  │
  │ (DDB)    │ │ Table    │ │          │
  └──────────┘ └──────────┘ └──────────┘
```

---

## 11. DynamoDB Access Patterns

| Access Pattern | Table | PK | SK | GSI | Notes |
|----------------|-------|----|----|-----|-------|
| Get review | `ui_reviews` | `USER#{user_id}` | `REVIEW#{review_id}` | -- | Single item |
| List reviews | `ui_reviews` | `USER#{user_id}` | begins_with `REVIEW#` | -- | All reviews |
| List reviews by page | `ui_reviews` | -- | -- | `GSI1PK=USER#{id}#PAGE#{path}` | Reviews for one page |
| Get design rule | `design_rules` | `USER#{user_id}` | `RULE#{rule_id}` | -- | Single item |
| List all rules | `design_rules` | `USER#{user_id}` | begins_with `RULE#` | -- | All configured rules |

---

## 12. API Request/Response Examples

```bash
# --- GET /ui/agents/stylist/reviews ---
curl http://localhost:8000/ui/agents/stylist/reviews \
  -H "Cookie: ui_session=sess_abc; ui_access_token=eyJ..."

# Response 200:
{
  "reviews": [
    {
      "review_id": "rev-001",
      "page_path": "/messages",
      "overall_score": 87,
      "accessibility_score": 92,
      "design_score": 82,
      "issues_count": 3,
      "screenshots": ["mobile.png", "tablet.png", "desktop.png"],
      "created_at": 1748534400
    }
  ]
}

# --- GET /ui/agents/stylist/reviews/{review_id}/issues ---
curl http://localhost:8000/ui/agents/stylist/reviews/rev-001/issues \
  -H "Cookie: ui_session=sess_abc; ui_access_token=eyJ..."

# Response 200:
{
  "issues": [
    {
      "severity": "medium",
      "category": "accessibility",
      "title": "Missing alt text on avatar images",
      "selector": "img.avatar",
      "description": "WCAG 2.1 Level A: Images must have alt text",
      "recommendation": "Add alt={user.displayName} to Avatar component",
      "screenshot_url": "https://s3.../rev-001/issue-1.png"
    }
  ]
}
```

---

## 13. Error Handling Matrix

| Error Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|----------------|-------------|------------|---------------------|-----------------|
| Review not found | 404 | `REVIEW_NOT_FOUND` | "UI review not found." | Verify review_id |
| Rule not found | 404 | `RULE_NOT_FOUND` | "Design rule not found." | Verify rule_id |
| Review in progress | 409 | `REVIEW_IN_PROGRESS` | "A review is already running." | Wait for completion |
| Invalid page path | 422 | `INVALID_PAGE_PATH` | "Page path must start with /." | Fix path |
| Duplicate rule name | 409 | `RULE_EXISTS` | "A rule with this name already exists." | Use unique name |
| Agent not configured | 404 | `AGENT_NOT_CONFIGURED` | "No Stylist Agent configured." | Create agent |

---

## 14. Pydantic Models

```python
from pydantic import BaseModel, Field
from typing import Literal, Optional, List

class UIIssueOut(BaseModel):
    severity: Literal["critical", "high", "medium", "low"]
    category: Literal["accessibility", "design", "responsive", "performance"]
    title: str
    selector: Optional[str] = None
    description: str
    recommendation: str
    screenshot_url: Optional[str] = None

class UIReviewOut(BaseModel):
    review_id: str
    page_path: str
    overall_score: int = Field(ge=0, le=100)
    accessibility_score: int = Field(ge=0, le=100)
    design_score: int = Field(ge=0, le=100)
    issues: List[UIIssueOut] = Field(default_factory=list)
    screenshots: List[str] = Field(default_factory=list)
    created_at: int

class DesignRuleIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    category: Literal["spacing", "color", "typography", "layout", "accessibility"]
    description: str = Field(max_length=2000)
    selector_pattern: Optional[str] = Field(default=None, max_length=500)
    expected_value: Optional[str] = Field(default=None, max_length=200)
    severity: Literal["critical", "high", "medium", "low"] = "medium"
```

---

## 15. Frontend Component Tree

```
UIReviewDashboard                     data-testid="stylist-dashboard"
├── div.grid.grid-cols-3
│   ├── StatCard "Overall Score" → avg overall_score
│   ├── StatCard "Accessibility" → avg accessibility_score
│   └── StatCard "Design" → avg design_score
├── DataTable (reviews)
│   ├── columns: [page_path, overall_score, issues_count, created_at]
│   └── row click → ReviewDetail
├── ReviewDetail
│   ├── Screenshot gallery (3 viewports)
│   ├── Issues list with severity badges
│   └── Recommendations panel
└── Card "Design Rules"
    ├── Button "Add Rule"
    └── DataTable (rules)
```

---

## 16. Observability & Monitoring

| Metric Name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `stylist_reviews_total` | Counter | -- | Total reviews completed |
| `stylist_issues_found_total` | Counter | `severity`, `category` | Issues detected |
| `stylist_score_avg` | Gauge | `score_type={overall,accessibility,design}` | Average scores |
| `stylist_review_duration_seconds` | Histogram | -- | Review duration |

### Alerts

| Alert | Condition | Severity |
|-------|-----------|----------|
| Accessibility score drop | avg score < 70 | P2 |
| Critical UI issue | critical issues > 0 in review | P2 |

---

## 17. Rollout Plan

### Feature Flags

| Flag | Default | Description |
|------|---------|-------------|
| `STYLIST_AGENT_ENABLED` | `false` | Master kill switch |
| `STYLIST_PR_TRIGGER_ENABLED` | `false` | Auto-review on PR merge |
| `STYLIST_TICKET_CREATION_ENABLED` | `false` | Auto-file UI improvement tickets |

### Canary

1. **Week 1**: Manual trigger only. Review and validate scoring accuracy.
2. **Week 2**: Enable `STYLIST_PR_TRIGGER_ENABLED`.
3. **Week 3**: Enable `STYLIST_TICKET_CREATION_ENABLED`.

---

## 18. Expanded E2E Test Details

### Additional Edge Case Tests (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| E1 | Review page that returns 404 | Agent logs warning; page skipped; review completes without crash |
| E2 | No design rules configured | Review runs with defaults; design_score based on built-in checks |
| E3 | Duplicate review trigger | POST review while one is running; 409 |
| E4 | 100-score page (perfect) | Page with no issues; issues array empty; all scores = 100 |

### Additional Negative Tests (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| N1 | Non-admin cannot trigger review | Alice (USER) POSTs review; 403 |
| N2 | Invalid rule category | POST rule with category="invalid"; 422 |
| N3 | Delete non-existent rule | DELETE rule with fake ID; 404 |
| N4 | Review for non-existent page | Review completes but page marked as "not found" in results |

---

## Codebase References

| Reference | File | Line(s) | Notes |
|-----------|------|---------|-------|
| shadcn/ui components | `frontend/src/components/ui/` | — | Confirmed exists; `Button`, `Dialog`, `Card`, `Badge`, etc. |
| Frontend pages | `frontend/src/pages/` | — | 20+ feature page directories confirmed |
| Tailwind CSS v4 | `frontend/vite.config.ts` | 3, 7 | `@tailwindcss/vite` plugin; NO `tailwind.config.js` file exists |
| Theme tokens | `frontend/src/globals.css` | — | CSS-based theme configuration (Tailwind v4 pattern) |
| Playwright config | `frontend/playwright.config.ts` | — | Confirmed exists; used for E2E tests |
| `require_ui_session` | `app/services/sessions.py` | — | User auth dependency |
| `audit_event` | `app/services/alerts.py` | 695 | Signature: `(event, user_sub, request, **fields)` |
| Settings singleton | `app/core/settings.py` | 1-1494 | Frozen `Settings` dataclass; singleton `S` |
| Tables singleton | `app/core/tables.py` | — | `T` object |
| Router registration | `app/main.py` | 297-465 | No `agent_stylist_router` registered yet |
| `agent_ui_reviews` DDB table | `scripts/local-ddb-init.py` | — | Does NOT exist yet — new table proposed in this ticket |
| `agent_stylist.py` service | `app/services/` | — | Does NOT exist yet — new implementation in this ticket |
| `agent_stylist.py` router | `app/routers/` | — | Does NOT exist yet — new implementation in this ticket |
| `tickets` DDB table | `scripts/local-ddb-init.py` | 494-510 | Existing table |
| `now_ts` | `app/core/time.py` | — | Unix timestamp helper |

---

## Testing Strategy


### Unit Tests (pytest)


**Test file**: `tests/test_stylist_agent.py`


**Mock setup**: moto for DynamoDB tables, `unittest.mock.patch` for external services (S3, Cognito, Stripe mock). All DDB tables created in-memory via moto `@mock_dynamodb` decorator.


| Test Function | Verifies |
|---|---|
| `test_create_stylist_agent` | Creates record with correct fields and generated ID |
| `test_create_stylist_agent_validation` | Rejects invalid input (missing required fields, out-of-range values) |
| `test_get_stylist_agent_found` | Returns correct record by ID |
| `test_get_stylist_agent_not_found` | Returns None for non-existent ID |
| `test_list_stylist_agent` | Returns all records for the given scope/owner |
| `test_update_stylist_agent` | Updates mutable fields and sets updated_at |
| `test_delete_stylist_agent` | Removes record; subsequent get returns None |
| `test_stylist_agent_owner_check` | Rejects operations from non-owner users |
| `test_stylist_agent_admin_only` | Admin/root endpoints reject USER role with 403 |
| `test_stylist_agent_concurrent_write` | Conditional update prevents stale overwrites |

### Integration Tests


Cross-service tests with real DDB (moto), verifying end-to-end flows:


1. Full CRUD lifecycle: create -> read -> update -> delete with real DDB (moto)
2. Authorization enforcement: non-owner access returns 403/404
3. Admin review/approval workflow with role-gated endpoints
4. Concurrent write safety: conditional updates prevent stale overwrites
5. Edge case: empty list returns `[]` not error; missing optional fields use defaults

### E2E Tests (Playwright)


**Test file**: `frontend/e2e/agent-stylist.spec.ts`


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
| AGENT-007 | PR/ticket integration | Pending | No |

### Depended On By


| Ticket | What It Needs From This |
|--------|------------------------|
| (none currently identified) | -- |

### Merge Strategy


**Sequential (after AGENT-007)**


- Must merge after: AGENT-001, AGENT-002, AGENT-003, AGENT-004, AGENT-005, AGENT-006, AGENT-007
- Branch from `main` after dependencies are merged
- Can begin development in parallel but must rebase before merge
- DDB table creation is additive (no migration needed for new tables)

### Merge Checklist


- [ ] DDB tables verified (uses existing tables only)
- [ ] `.env.local` updated with any new environment variables
- [ ] Router registered in `app/main.py` (from `app/routers/agent_workers.py`)
- [ ] Frontend route(s) added to `App.tsx`: `/agents/stylist`
- [ ] All E2E tests passing (`just e2e` or targeted spec file)
- [ ] No breaking changes to existing endpoints or UI components
- [ ] `just restart` succeeds with new table definitions
