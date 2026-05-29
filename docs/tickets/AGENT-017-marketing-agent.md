# AGENT-017: Marketing Agent

**Ticket**: AGENT-017
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: Medium
**Estimated effort**: 10-12 days
**Dependencies**: AGENT-001 (Agent Registry), AGENT-002 (Terminal Provisioning), AGENT-003 (Worker Agent Framework), AGENT-004 (Ticket Lifecycle Bridge), AGENT-005 (Context Injection & Output Parsing), AGENT-006 (Agent Monitoring & Health), AGENT-007 (Orchestration Dashboard)

---

## 1. Overview & Motivation

### 1.1 Purpose

AGENT-017 defines the Marketing Agent type -- a feature-completion-triggered agent that generates marketing content whenever new features ship or significant platform updates are completed. The agent picks up tickets labeled `type:marketing` and also activates automatically when feature tickets transition to `done`. It reads completed feature documentation, changelog data, and product descriptions to generate blog posts, social media content, email newsletter drafts, changelog entries, release notes, and SEO-optimized landing page copy. Content is generated following configurable brand voice guidelines and target audience definitions. The agent supports scheduling content for specific publish dates and can produce A/B test variations of marketing copy. It tracks which content drives engagement via click and signup analytics integration.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Owner | As a platform owner, I want blog posts generated when features ship. | Feature completion triggers blog post draft with feature description and screenshots. |
| Owner | As a platform owner, I want social media posts drafted automatically. | Agent produces platform-specific posts (Twitter/X, LinkedIn, Instagram captions). |
| Owner | As a platform owner, I want professional release notes for each deployment. | Agent summarizes completed tickets into release notes document. |
| Owner | As a platform owner, I want SEO-optimized content for my landing pages. | Agent generates meta descriptions, title tags, and landing page body copy. |
| Owner | As a platform owner, I want email newsletter drafts for subscriber updates. | Agent produces newsletter content summarizing recent platform updates. |
| Owner | As a platform owner, I want to schedule content for future publish dates. | Content can be queued with a target publish date. |
| Owner | As a platform owner, I want A/B test variations for my marketing copy. | Agent produces 2-3 headline/body variations per content piece. |
| Owner | As a platform owner, I want to configure brand voice and target audience. | Agent follows brand guidelines for tone, vocabulary, and audience targeting. |
| Owner | As a platform owner, I want to track which marketing content drives engagement. | Analytics: clicks, signups attributed to content pieces. |

### 1.3 Why This Is Needed

Marketing content creation is a critical but time-consuming task that many technical teams neglect. Features ship without announcements, release notes accumulate as raw ticket lists, and SEO opportunities go unrealized. An autonomous Marketing Agent transforms feature completions into polished marketing collateral, ensuring every significant update is communicated to users and prospects. The A/B testing capability allows data-driven optimization of messaging, while the scheduling system enables a consistent content calendar without manual coordination. This is particularly valuable for small teams that lack a dedicated marketing person.

---

## 2. Current State Analysis

### 2.1 Existing Infrastructure

- **Agent Registry** (AGENT-001): Agent type definitions, configuration schemas.
- **Worker Agent Framework** (AGENT-003): Task execution, context injection.
- **Ticket Lifecycle Bridge** (AGENT-004): Agent-to-ticket integration; feature completion events.
- **Ticketing system** (`app/services/tickets.py`): Ticket status transitions, labels, metadata.
- **Newsfeed** (`app/routers/newsfeed.py`): Blog-like posts with markdown/rich text support.
- **Existing docs**: Feature documentation in `docs/`, ticket specs in `docs/tickets/`.

### 2.2 Gaps

1. No agent type profile for marketing content generation workflows.
2. No marketing content model with drafts, review states, and publish scheduling.
3. No brand voice configuration system.
4. No A/B test variation model.
5. No content calendar with scheduled publish dates.
6. No engagement analytics integration for marketing content.
7. No SEO analysis or optimization tools integrated.
8. No feature-completion trigger for content generation.

---

## 3. Technical Design

### 3.1 Data Model

#### 3.1.1 MarketingContent Table

Stores marketing content drafts, variations, and scheduling metadata.

| Field | Type | Description |
|-------|------|-------------|
| `pk` | S | `USER#{user_id}` |
| `sk` | S | `CONTENT#{content_id}` |
| `content_id` | S | UUID hex |
| `user_id` | S | Platform owner |
| `agent_id` | S | Marketing Agent instance |
| `content_type` | S | `blog_post`, `social_twitter`, `social_linkedin`, `social_instagram`, `newsletter`, `release_notes`, `changelog`, `landing_page`, `meta_seo` |
| `title` | S | Content title (max 200 chars) |
| `body` | S | Content body, markdown (max 20000 chars) |
| `summary` | S (optional) | Short summary/excerpt (max 500 chars) |
| `feature_refs` | S (optional) | JSON array of ticket IDs this content promotes |
| `tags` | S (optional) | JSON array of content tags |
| `seo_meta` | S (optional) | JSON `{"title": "...", "description": "...", "keywords": [...]}` |
| `variations` | S (optional) | JSON array of `{"variant_id": "A", "title": "...", "body": "..."}` for A/B tests |
| `status` | S | `draft`, `review`, `approved`, `scheduled`, `published`, `archived` |
| `scheduled_publish_at` | N (optional) | Unix timestamp for scheduled publish |
| `published_at` | N (optional) | Unix timestamp when published |
| `target_platform` | S (optional) | Platform-specific content target |
| `created_at` | N | Unix timestamp |
| `updated_at` | N | Unix timestamp |
| `GSI1PK` | S | `USER#{user_id}#TYPE#{content_type}` |
| `GSI1SK` | N | `created_at` |
| `GSI2PK` | S | `USER#{user_id}#STATUS#{status}` |
| `GSI2SK` | N | `created_at` |
| `GSI3PK` | S | `USER#{user_id}#SCHEDULED` |
| `GSI3SK` | N | `scheduled_publish_at` |

```python
TableDef(
    "agent_marketing_content", "pk", "sk",
    gsi=[
        {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
        {"index_name": "GSI2", "partition_key": "GSI2PK", "sort_key": "GSI2SK"},
        {"index_name": "GSI3", "partition_key": "GSI3PK", "sort_key": "GSI3SK"},
    ],
    attr_types={
        "created_at": "N", "updated_at": "N", "scheduled_publish_at": "N",
        "published_at": "N", "GSI1SK": "N", "GSI2SK": "N", "GSI3SK": "N",
    },
),
```

#### 3.1.2 ContentEngagement Table

Tracks engagement metrics (clicks, views, signups) per content piece.

| Field | Type | Description |
|-------|------|-------------|
| `pk` | S | `CONTENT#{content_id}` |
| `sk` | S | `DAY#{YYYY-MM-DD}` |
| `views` | N | Page views or impressions |
| `clicks` | N | Link clicks |
| `signups` | N | Signups attributed to this content |
| `shares` | N | Social shares |
| `variant_id` | S (optional) | A/B variant for split tracking |
| `ttl` | N | DDB TTL (expire after 365 days) |

```python
TableDef(
    "agent_content_engagement", "pk", "sk",
    attr_types={"views": "N", "clicks": "N", "signups": "N", "shares": "N", "ttl": "N"},
),
```

#### 3.1.3 Marketing Agent Configuration (on Agent Registry Record)

Stored as a DDB map on the agent registry entry (`marketing_config` field):

```json
{
  "trigger_on_feature_completion": true,
  "auto_generate_content_types": ["blog_post", "social_twitter", "changelog", "release_notes"],
  "brand_voice": {
    "tone": "professional yet approachable",
    "vocabulary_level": "accessible",
    "personality_traits": ["helpful", "innovative", "reliable"],
    "words_to_avoid": ["synergy", "leverage", "disrupt"],
    "tagline": "Build better, ship faster"
  },
  "target_audience": {
    "primary": "SaaS platform operators",
    "secondary": "developers",
    "demographics": "tech-savvy, 25-45"
  },
  "social_platforms": ["twitter", "linkedin"],
  "content_calendar_enabled": true,
  "newsletter_frequency": "weekly",
  "newsletter_day": "friday",
  "ab_test_variations": 2,
  "seo_keywords": ["saas platform", "messaging", "creator economy"],
  "max_content_per_feature": 3
}
```

### 3.2 Backend Service (`app/services/agent_marketing.py`)

```python
def create_content(*, user_id: str, agent_id: str, content_type: str,
                    title: str, body: str, summary: str | None = None,
                    feature_refs: list[str] | None = None,
                    tags: list[str] | None = None,
                    seo_meta: dict | None = None,
                    variations: list[dict] | None = None,
                    target_platform: str | None = None) -> dict:
    """Create a marketing content draft."""
    # 1. Validate content_type
    # 2. Generate content_id
    # 3. Write to MarketingContent with status=draft
    # 4. Return content dict

def list_content(*, user_id: str, content_type: str | None = None,
                  status: str | None = None,
                  limit: int = 25, cursor: str | None = None) -> dict:
    """List marketing content, filtered by type or status."""

def get_content(*, user_id: str, content_id: str) -> dict:
    """Get a single content piece with full body and variations."""

def update_content(*, user_id: str, content_id: str, **fields) -> dict:
    """Update content fields (title, body, status, etc.)."""

def approve_content(*, user_id: str, content_id: str) -> dict:
    """Approve content for publishing or scheduling."""
    # 1. Validate status=draft or status=review
    # 2. Update status=approved
    # 3. Return updated content

def schedule_content(*, user_id: str, content_id: str,
                      publish_at: int) -> dict:
    """Schedule approved content for future publish."""
    # 1. Validate status=approved
    # 2. Validate publish_at is in the future
    # 3. Update status=scheduled, scheduled_publish_at
    # 4. Return updated content

def publish_content(*, user_id: str, content_id: str) -> dict:
    """Publish content immediately."""
    # 1. Validate status=approved or status=scheduled
    # 2. Update status=published, published_at=now
    # 3. Return updated content

def archive_content(*, user_id: str, content_id: str) -> dict:
    """Archive content."""

def delete_content(*, user_id: str, content_id: str) -> dict:
    """Hard-delete a draft content piece."""
    # Only allowed for status=draft

def get_calendar(*, user_id: str, month: str) -> list[dict]:
    """Get content calendar for a given month (YYYY-MM)."""
    # 1. Query GSI3 for scheduled content in the month range
    # 2. Also include published content from that month
    # 3. Return sorted by date

def record_engagement(*, content_id: str, event_type: str,
                        variant_id: str | None = None) -> None:
    """Record an engagement event (view, click, signup, share)."""
    # Atomic increment on daily counter

def get_engagement_stats(*, user_id: str, content_id: str,
                          days: int = 30) -> dict:
    """Get engagement stats for a content piece."""
    # Query daily counters and aggregate

def get_engagement_summary(*, user_id: str, days: int = 30) -> dict:
    """Get aggregate engagement across all content."""
    # Total views, clicks, signups, conversion rates
```

### 3.3 Backend Router (`app/routers/agent_marketing.py`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/ui/agents/marketing/content` | `require_ui_session` | List content (filters: `?type=`, `?status=`) |
| POST | `/ui/agents/marketing/content` | `require_ui_session` | Create content draft (manual) |
| GET | `/ui/agents/marketing/content/{content_id}` | `require_ui_session` | Get content detail |
| PUT | `/ui/agents/marketing/content/{content_id}` | `require_ui_session` | Update content |
| POST | `/ui/agents/marketing/content/{content_id}/approve` | `require_ui_session` | Approve content |
| POST | `/ui/agents/marketing/content/{content_id}/schedule` | `require_ui_session` | Schedule content |
| POST | `/ui/agents/marketing/content/{content_id}/publish` | `require_ui_session` | Publish content |
| POST | `/ui/agents/marketing/content/{content_id}/archive` | `require_ui_session` | Archive content |
| DELETE | `/ui/agents/marketing/content/{content_id}` | `require_ui_session` | Delete draft content |
| GET | `/ui/agents/marketing/calendar` | `require_ui_session` | Get content calendar (`?month=YYYY-MM`) |
| GET | `/ui/agents/marketing/content/{content_id}/engagement` | `require_ui_session` | Get engagement stats |
| GET | `/ui/agents/marketing/engagement/summary` | `require_ui_session` | Get aggregate engagement summary |
| PUT | `/ui/agents/marketing/config` | `require_ui_session` | Update Marketing Agent config |
| POST | `/ui/agents/marketing/generate` | `require_ui_session` | Manually trigger content generation for a feature |

**Key request models**:

```python
class CreateContentIn(BaseModel):
    content_type: Literal["blog_post", "social_twitter", "social_linkedin",
                          "social_instagram", "newsletter", "release_notes",
                          "changelog", "landing_page", "meta_seo"]
    title: str = Field(..., min_length=1, max_length=200)
    body: str = Field(..., min_length=1, max_length=20000)
    summary: Optional[str] = Field(default=None, max_length=500)
    feature_refs: Optional[List[str]] = None
    tags: Optional[List[str]] = None
    seo_meta: Optional[Dict[str, Any]] = None
    variations: Optional[List[Dict[str, str]]] = None
    target_platform: Optional[str] = None

class ScheduleContentIn(BaseModel):
    publish_at: int = Field(..., gt=0)

class GenerateContentIn(BaseModel):
    feature_ticket_ids: List[str] = Field(..., min_length=1, max_length=10)
    content_types: List[str] = Field(default_factory=lambda: ["blog_post", "changelog"])

class UpdateMarketingConfigIn(BaseModel):
    trigger_on_feature_completion: Optional[bool] = None
    auto_generate_content_types: Optional[List[str]] = None
    brand_voice: Optional[Dict[str, Any]] = None
    target_audience: Optional[Dict[str, Any]] = None
    social_platforms: Optional[List[str]] = None
    content_calendar_enabled: Optional[bool] = None
    newsletter_frequency: Optional[Literal["daily", "weekly", "biweekly", "monthly"]] = None
    newsletter_day: Optional[str] = None
    ab_test_variations: Optional[int] = Field(default=None, ge=0, le=5)
    seo_keywords: Optional[List[str]] = None
    max_content_per_feature: Optional[int] = Field(default=None, ge=1, le=10)
```

Register in `app/main.py`:

```python
from app.routers.agent_marketing import router as agent_marketing_router
app.include_router(agent_marketing_router, prefix="/ui")
```

### 3.4 Frontend Types (`frontend/src/api/types.ts`)

```typescript
export interface MarketingContent {
  content_id: string;
  agent_id: string;
  content_type: "blog_post" | "social_twitter" | "social_linkedin" | "social_instagram"
    | "newsletter" | "release_notes" | "changelog" | "landing_page" | "meta_seo";
  title: string;
  body: string;
  summary?: string;
  feature_refs?: string[];
  tags?: string[];
  seo_meta?: { title: string; description: string; keywords: string[] };
  variations?: Array<{ variant_id: string; title: string; body: string }>;
  status: "draft" | "review" | "approved" | "scheduled" | "published" | "archived";
  scheduled_publish_at?: number;
  published_at?: number;
  target_platform?: string;
  created_at: number;
  updated_at: number;
}

export interface ContentEngagementStats {
  content_id: string;
  total_views: number;
  total_clicks: number;
  total_signups: number;
  total_shares: number;
  click_rate: number;
  signup_rate: number;
  by_day: Array<{ date: string; views: number; clicks: number; signups: number }>;
  by_variant?: Array<{ variant_id: string; views: number; clicks: number; signups: number }>;
}

export interface ContentCalendarEntry {
  content_id: string;
  title: string;
  content_type: string;
  status: string;
  date: number;
}

export interface MarketingConfig {
  trigger_on_feature_completion: boolean;
  auto_generate_content_types: string[];
  brand_voice: {
    tone: string;
    vocabulary_level: string;
    personality_traits: string[];
    words_to_avoid: string[];
    tagline: string;
  };
  target_audience: { primary: string; secondary: string; demographics: string };
  social_platforms: string[];
  content_calendar_enabled: boolean;
  newsletter_frequency: string;
  ab_test_variations: number;
  seo_keywords: string[];
}

export interface EngagementSummary {
  total_content: number;
  total_views: number;
  total_clicks: number;
  total_signups: number;
  avg_click_rate: number;
  avg_signup_rate: number;
  top_performing: Array<{ content_id: string; title: string; clicks: number }>;
}
```

### 3.5 Frontend API (`frontend/src/api/endpoints/agents.ts`)

Standard wrappers: `listContent(filters?)`, `createContent(data)`, `getContent(contentId)`, `updateContent(contentId, data)`, `approveContent(contentId)`, `scheduleContent(contentId, publishAt)`, `publishContent(contentId)`, `archiveContent(contentId)`, `deleteContent(contentId)`, `getCalendar(month)`, `getContentEngagement(contentId, days?)`, `getEngagementSummary(days?)`, `updateMarketingConfig(config)`, `generateContent(featureTicketIds, contentTypes)`.

### 3.6 Frontend Pages

- **ContentDashboardPage** (`frontend/src/pages/agents/ContentDashboardPage.tsx`): Route `/agents/marketing`. Tab bar: All / Blog / Social / Newsletter / Release Notes. Each content card shows title, type badge, status badge, feature refs, created date. Draft actions: edit, approve. Approved actions: schedule, publish. Engagement sparkline on published content. `data-testid="content-dashboard-page"`.
- **ContentEditorPage** (`frontend/src/pages/agents/ContentEditorPage.tsx`): Route `/agents/marketing/content/:contentId`. Markdown editor with live preview. Side panel for: SEO meta editing, tag management, variation A/B editing, schedule picker. `data-testid="content-editor-page"`.
- **ContentCalendarPage** (`frontend/src/pages/agents/ContentCalendarPage.tsx`): Route `/agents/marketing/calendar`. Monthly calendar view showing scheduled and published content on their dates. Color-coded by content type. Click date to see content details. Drag to reschedule. `data-testid="content-calendar-page"`.
- **EngagementDashboardPage** (`frontend/src/pages/agents/EngagementDashboardPage.tsx`): Route `/agents/marketing/engagement`. Summary cards: total views, clicks, signups. Line chart of engagement over time. Top-performing content table. A/B test comparison charts. `data-testid="engagement-dashboard-page"`.

---

## 4. Implementation Plan

### 4.1 Files to Create

| File | Purpose |
|------|---------|
| `app/services/agent_marketing.py` | Content CRUD, scheduling, engagement tracking |
| `app/routers/agent_marketing.py` | Marketing Agent API endpoints |
| `frontend/src/pages/agents/ContentDashboardPage.tsx` | Content list with filters and actions |
| `frontend/src/pages/agents/ContentEditorPage.tsx` | Markdown editor with SEO/variation panels |
| `frontend/src/pages/agents/ContentCalendarPage.tsx` | Calendar view of content schedule |
| `frontend/src/pages/agents/EngagementDashboardPage.tsx` | Analytics dashboard |

### 4.2 Files to Modify

| File | Changes |
|------|---------|
| `scripts/local-ddb-init.py` | Add `agent_marketing_content`, `agent_content_engagement` TableDefs |
| `app/core/settings.py` | Add table name settings |
| `app/core/tables.py` | Add table handles |
| `app/main.py` | Register `agent_marketing_router` |
| `app/models.py` | Add `MarketingContentOut`, `EngagementStatsOut`, `CalendarEntryOut` models |
| `frontend/src/api/types.ts` | Add marketing content, engagement, calendar types |
| `frontend/src/api/endpoints/agents.ts` | Add Marketing Agent API functions |
| `frontend/src/App.tsx` | Add `/agents/marketing`, `/agents/marketing/content/:contentId`, `/agents/marketing/calendar`, `/agents/marketing/engagement` routes |

---

## 5. E2E Test Plan

### 5.1 Test File

`frontend/e2e/agent-marketing.spec.ts` -- 18 tests across 4 sections.

### 5.2 Test Setup

```typescript
const TS = Date.now();
let contentId1: string;  // blog post
let contentId2: string;  // social post
let contentId3: string;  // release notes
// Alice = platform owner
```

### 5.3 Section 687: Content CRUD API (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 687.1 | Create blog post draft | POST with `content_type="blog_post"`, `title`, `body`, `tags=["launch"]`; 201; returns `content_id`, `status=draft` |
| 687.2 | Create social media post | POST with `content_type="social_twitter"`, body <= 280 chars; 201; `content_type=social_twitter` |
| 687.3 | Create release notes with feature refs | POST with `content_type="release_notes"`, `feature_refs=["TICKET-123"]`; 201; `feature_refs` stored |
| 687.4 | Get content detail | GET `/ui/agents/marketing/content/{contentId1}`; 200; full body, tags, seo_meta |
| 687.5 | List content by type | GET `content?type=blog_post`; 200; all results have `content_type="blog_post"` |

### 5.4 Section 688: Content Lifecycle API (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 688.1 | Approve content | POST `content/{contentId1}/approve`; 200; `status=approved` |
| 688.2 | Schedule content for future | POST `content/{contentId1}/schedule` with `publish_at` 1 hour from now; 200; `status=scheduled`, `scheduled_publish_at` set |
| 688.3 | Publish content immediately | POST `content/{contentId2}/approve` then `content/{contentId2}/publish`; 200; `status=published`, `published_at` set |
| 688.4 | Archive published content | POST `content/{contentId2}/archive`; 200; `status=archived` |
| 688.5 | Delete draft content | DELETE `content/{contentId3}`; 200; GET returns 404 |

### 5.5 Section 689: Calendar & Engagement API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 689.1 | Get content calendar | GET `/ui/agents/marketing/calendar?month=YYYY-MM`; 200; array includes scheduled content |
| 689.2 | Get engagement stats for published content | GET `content/{contentId2}/engagement`; 200; `total_views`, `total_clicks` are numeric (may be 0) |
| 689.3 | Get engagement summary | GET `/ui/agents/marketing/engagement/summary`; 200; `total_content >= 1` |
| 689.4 | Update marketing config | PUT `/ui/agents/marketing/config` with `brand_voice.tone="friendly"`, `ab_test_variations=3`; 200; config echoed |

### 5.6 Section 690: Marketing UI (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 690.1 | Content dashboard loads | Navigate `/agents/marketing`; `[data-testid="content-dashboard-page"]` visible; content cards listed |
| 690.2 | Content editor opens | Navigate `/agents/marketing/content/{contentId1}`; `[data-testid="content-editor-page"]` visible; markdown editor present |
| 690.3 | Calendar page shows scheduled content | Navigate `/agents/marketing/calendar`; `[data-testid="content-calendar-page"]` visible |
| 690.4 | Engagement dashboard loads | Navigate `/agents/marketing/engagement`; `[data-testid="engagement-dashboard-page"]` visible; summary cards rendered |

---

## 6. Error Handling

| Scenario | Status | Detail |
|----------|--------|--------|
| Content not found | 404 | "Marketing content not found" |
| Invalid content_type | 422 | "Invalid content_type: {value}" |
| Invalid status transition | 409 | "Cannot approve content with status: {status}" |
| Schedule in the past | 400 | "publish_at must be in the future" |
| Delete non-draft content | 409 | "Only draft content can be deleted; use archive instead" |
| Body too long | 422 | "body must not exceed 20000 characters" |
| Too many variations | 422 | "Maximum 5 A/B variations per content piece" |
| Config validation error | 422 | Specific field error |
| Agent not configured | 404 | "No Marketing Agent configured for this user" |
| Too many feature refs | 422 | "Maximum 10 feature references per content piece" |

---

## 7. Security Considerations

- **Ownership enforcement**: All content operations scoped to authenticated `user_id`. Cross-tenant access blocked.
- **Content sanitization**: Content body is markdown; rendered with XSS protection. No raw HTML injection allowed.
- **Brand voice config**: Stored as structured JSON, not executable code. No template injection risks.
- **Engagement tracking**: Anonymous tracking (no PII in engagement records). Daily aggregates only, no individual user tracking.
- **Social platform credentials**: If social media posting is integrated, OAuth tokens stored in secrets manager, not in DDB config.
- **Content moderation**: Agent-generated content is always created as `draft` first, requiring owner approval before publish. No automatic publishing without explicit approval.
- **SEO meta validation**: Meta descriptions and keywords validated for length limits. No script injection in meta tags.
- **Rate limiting**: `generate` endpoint rate-limited to 10 per hour to prevent excessive LLM usage.
- **Engagement TTL**: Engagement records auto-expire after 365 days via DDB TTL.

---

## 8. Performance Considerations

| Concern | Mitigation |
|---------|-----------|
| Content body storage | 20KB max per content piece; large bodies stored as S3 references |
| Content list pagination | GSI queries with status/type filter; paginated with cursor |
| Calendar query | GSI3 query scoped to 1-month range; returns at most ~100 entries |
| Engagement counter writes | Atomic counter increments; fire-and-forget; batched daily |
| Engagement summary aggregation | Pre-computed on daily aggregation; cached in summary record |
| Content generation compute | Capped at `max_content_per_feature` (default 3); generation time-limited to 15 minutes |

---

## 9. Dependencies

| Dependency | Ticket | Status |
|------------|--------|--------|
| AGENT-001 (Agent Registry) | AGENT-001 | Required (agent type definitions, config storage) |
| AGENT-002 (Terminal Provisioning) | AGENT-002 | Required (terminal for content generation) |
| AGENT-003 (Worker Agent Framework) | AGENT-003 | Required (feature-completion trigger support) |
| AGENT-004 (Ticket Lifecycle Bridge) | AGENT-004 | Required (reading feature ticket descriptions) |
| AGENT-005 (Context Injection) | AGENT-005 | Required (injecting feature docs and changelog context) |
| AGENT-006 (Agent Monitoring) | AGENT-006 | Required (monitoring content generation runs) |
| AGENT-007 (Orchestration Dashboard) | AGENT-007 | Required (viewing marketing agent activity) |
| Ticketing system | Existing | Available (feature completion events) |
| Newsfeed | Existing | Available (blog post publishing integration) |

### Downstream

| Ticket | Depends On |
|--------|-----------|
| AGENT-014 (Documentation Agent) | Marketing agent reads documentation for content generation |
| AGENT-018 (Accountant Agent) | Tracks LLM costs for content generation |
