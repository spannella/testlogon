# BOT-002: Template & Scheduled Messages

**Ticket**: BOT-002
**Author**: Engineering
**Status**: Implemented
**Date**: 2026-05-29
**Priority**: High
**Estimated effort**: 8-10 days
**Dependencies**: BOT-001 (Bot Framework & Lifecycle)

---

## 1. Overview & Motivation

### 1.1 Purpose

BOT-002 adds a template engine and scheduled message system to the bot framework. Creators define reusable message templates for common interactions -- greetings, FAQ answers, promotions, away messages -- and bind them to bot triggers. Templates support variable substitution (`{user_name}`, `{creator_name}`, `{subscriber_status}`, etc.), letting bots personalize responses dynamically. Quick-reply buttons allow bots to present structured choices to users, guiding conversations into pre-defined flows. Scheduled sends enable bots to push messages at configured times (e.g., daily promotions at 2pm) without requiring an incoming message as a trigger. A/B testing lets creators assign multiple templates to the same trigger, with the bot randomly selecting one to measure engagement.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Creator | As a creator, I want to define reusable message templates for my bot. | Template CRUD; templates stored per bot. |
| Creator | As a creator, I want templates to include variables like `{user_name}`. | Variable substitution at send time; preview available in editor. |
| Creator | As a creator, I want my bot to greet new users automatically. | `first_message` trigger bound to greeting template; bot sends personalized greeting. |
| Creator | As a creator, I want my bot to send FAQ answers when keywords are detected. | `keyword` trigger with keyword list; bot sends matching template. |
| Creator | As a creator, I want my bot to send quick-reply buttons. | Template with `quick_replies` array; rendered as clickable buttons in UI. |
| Creator | As a creator, I want my bot to send a daily promotion at 2pm. | Scheduled send with cron expression; bot posts at configured time. |
| Creator | As a creator, I want to A/B test different greeting messages. | Multiple templates for same trigger; bot picks randomly; track impressions. |
| User | As a user, I want to tap quick-reply buttons to respond to a bot. | Clicking button sends the button text as a user message. |
| Creator | As a creator, I want my bot to send an away message when I am idle. | `idle` trigger with configurable timeout; bot sends after N minutes of creator inactivity. |

### 1.3 Why This Is Needed

Without templates, bots would require custom code for every response. Templates make bot configuration accessible to non-technical creators through a visual editor. Variable substitution personalizes the experience without manual per-user configuration. Scheduled sends automate recurring promotions. Quick replies reduce friction in bot-driven conversations by presenting structured options. A/B testing enables data-driven content optimization.

---

## 2. Current State Analysis

### 2.1 Existing Infrastructure

- **Bot framework** (BOT-001): `ChatBots` table stores bot records with `trigger_config`; `evaluate_triggers()` determines which template to fire; `send_bot_message()` sends messages with bot identity.
- **Messaging** (`app/routers/messaging.py`): `send_text_message()` (see `app/routers/messaging.py:7684`) handles text messages. `MessageOut` (see `app/routers/messaging.py:2325`) supports arbitrary `kind` values via Literal union (see line 2330). Scheduled message support exists (`send_at` field on message input models at lines 1853, 1930, 1952, 1994, 2018; background dispatch at `dispatch_due_scheduled_mass_campaigns` line 737).
- **Broadcast chat** (`app/services/broadcast_chat_store.py`): `send_chat_message()` (see line 136) supports text + product link messages. No template support.
- **Newsfeed scheduler** (`app/services/newsfeed_scheduler.py`): Background task pattern for scheduled content (see `_query_due_posts` at line 76). Bot scheduler follows the same pattern.
- **Variable data**: User profiles in `profiles` table; subscription status queryable from `subscriptions` table; creator name from profile.

### 2.2 Gaps

1. No template storage or management -- no way to define reusable message content.
2. No variable substitution engine for template content.
3. No quick-reply message kind or rendering.
4. No bot-specific scheduled message system (existing scheduled messages are user-initiated, not bot-driven).
5. No A/B testing framework for templates.
6. No template category system for organization.
7. No template analytics (impression/response tracking).

---

## 3. Technical Design

### 3.1 Data Model

#### 3.1.1 BotTemplates Table

Stores message templates per bot.

| Field | Type | Description |
|-------|------|-------------|
| `pk` | S | `BOT#{bot_id}` |
| `sk` | S | `TEMPLATE#{template_id}` |
| `template_id` | S | UUID hex |
| `bot_id` | S | Parent bot |
| `name` | S | Template display name (max 100 chars) |
| `category` | S | `greeting`, `support`, `promotion`, `farewell`, `away`, `custom` |
| `text` | S | Template body with variable placeholders (max 4000 chars) |
| `body_format` | S | `plain`, `markdown` (default `plain`) |
| `quick_replies` | L (list of maps, optional) | Quick-reply buttons: `[{"label": "Yes", "value": "yes"}, ...]` (max 5) |
| `variables_used` | SS (string set) | Auto-detected variables: `["user_name", "creator_name"]` |
| `ab_group` | S (optional) | A/B test group name; templates with same `ab_group` are alternates |
| `ab_weight` | N | Weight for random selection within A/B group (default 1) |
| `impression_count` | N | Times this template was sent |
| `response_count` | N | Times a user responded after receiving this template |
| `created_at` | N | Unix timestamp |
| `updated_at` | N | Unix timestamp |
| `GSI1PK` | S | `BOT#{bot_id}#CAT#{category}` |
| `GSI1SK` | N | `created_at` |

**GSI1** (`GSI1PK`, `GSI1SK`): List templates by category, sorted by creation date.

**DDB init**:

```python
TableDef(
    "bot_templates", "pk", "sk",
    gsi=[
        {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
    ],
    attr_types={"created_at": "N", "updated_at": "N", "ab_weight": "N",
                "impression_count": "N", "response_count": "N", "GSI1SK": "N"},
),
```

#### 3.1.2 BotScheduledSends Table

Stores scheduled send jobs. Background loop picks up due sends.

| Field | Type | Description |
|-------|------|-------------|
| `pk` | S | `BOT#{bot_id}` |
| `sk` | S | `SCHED#{schedule_id}` |
| `schedule_id` | S | UUID hex |
| `bot_id` | S | Bot sending the message |
| `creator_id` | S | Bot owner |
| `template_id` | S | Template to send |
| `target_type` | S | `conversation`, `all_dms`, `all_groups`, `all_broadcasts` |
| `target_id` | S (optional) | Specific conversation/broadcast ID |
| `cron_expression` | S | Cron expression (e.g., `0 14 * * *`) |
| `timezone` | S | IANA timezone (default `UTC`) |
| `next_run_at` | N | Unix timestamp of next scheduled run |
| `last_run_at` | N (optional) | Unix timestamp of last successful run |
| `enabled` | BOOL | Whether the schedule is active |
| `created_at` | N | Unix timestamp |
| `GSI1PK` | S | `BOTSCHED#PENDING` |
| `GSI1SK` | N | `next_run_at` |

**GSI1** (`GSI1PK`, `GSI1SK`): Query all pending scheduled sends ordered by `next_run_at`. Background worker queries `GSI1PK=BOTSCHED#PENDING` with `GSI1SK <= now_ts`.

```python
TableDef(
    "bot_scheduled_sends", "pk", "sk",
    gsi=[
        {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
    ],
    attr_types={"next_run_at": "N", "last_run_at": "N", "created_at": "N", "GSI1SK": "N"},
),
```

### 3.2 Variable Substitution Engine

Supported variables and their data sources:

| Variable | Source | Description |
|----------|--------|-------------|
| `{user_name}` | Profiles table by `sender_id` | Display name of the user who triggered the bot |
| `{creator_name}` | Profiles table by `creator_id` | Display name of the bot owner |
| `{bot_name}` | ChatBots table | Name of the bot |
| `{current_time}` | `datetime.now(tz)` | Current time in creator's timezone |
| `{current_date}` | `datetime.now(tz).date()` | Current date |
| `{subscriber_status}` | Subscriptions table | `active`, `expired`, `none` |
| `{conversation_name}` | Conversations table | Conversation or group name |

`resolve_variables(template_text, context)` uses `re.compile(r"\{(\w+)\}")` to replace placeholders. Unknown variables are left as-is. `build_variable_context()` lazily fetches data only for variables present in the template.

### 3.3 Quick Replies

Quick-reply buttons are delivered as `quick_replies: Optional[List[Dict[str, str]]]` on `MessageOut`. Each dict has `{"label": "...", "value": "..."}`. When a user taps a button, the frontend sends `value` as a regular text message. Buttons are disabled after first tap to prevent duplicates. Rendered in `MessageBubble.tsx` as `<Button variant="outline" size="sm">` with `data-testid="quick-reply-{i}"`.

### 3.4 A/B Testing

When multiple templates share the same `ab_group` and are linked to the same trigger, `select_ab_template()` performs weighted random selection based on `ab_weight`. Impression and response counts are tracked per template to calculate conversion rates.

### 3.5 Backend Service (`app/services/bot_template.py`)

```python
def create_template(*, bot_id: str, creator_id: str, name: str, text: str,
                     category: str = "custom", body_format: str = "plain",
                     quick_replies: list[dict] | None = None,
                     ab_group: str | None = None, ab_weight: int = 1) -> dict:
    """Create a message template for a bot."""
    # 1. Verify bot ownership
    # 2. Validate quick_replies (max 5, label max 40 chars, value max 200 chars)
    # 3. Auto-detect variables_used from text
    # 4. Generate template_id
    # 5. Write to BotTemplates table

def get_template(*, bot_id: str, template_id: str) -> dict | None:
    """Fetch a single template."""

def list_templates(*, bot_id: str, category: str | None = None) -> list[dict]:
    """List templates for a bot, optionally filtered by category."""

def update_template(*, bot_id: str, template_id: str, creator_id: str, **fields) -> dict:
    """Update template text, name, category, quick_replies, etc."""

def delete_template(*, bot_id: str, template_id: str, creator_id: str) -> dict:
    """Delete a template."""

def render_template(*, template: dict, sender_id: str, creator_id: str,
                     bot: dict, conversation_id: str) -> dict:
    """Resolve variables and return rendered message content."""
    # 1. Build variable context
    # 2. Resolve variables in text
    # 3. Return {"text": resolved_text, "quick_replies": template.get("quick_replies")}

def record_impression(*, bot_id: str, template_id: str) -> None:
    """Increment impression_count atomically."""

def record_response(*, bot_id: str, template_id: str) -> None:
    """Increment response_count atomically."""

def get_templates_for_trigger(*, bot_id: str, trigger: dict) -> list[dict]:
    """Get all templates linked to a trigger, resolving A/B groups."""
    # If trigger has response_template_id, fetch that template
    # If template has ab_group, fetch all templates in that group
    # Return list (caller uses select_ab_template if >1)
```

### 3.6 Scheduled Send Service (`app/services/bot_scheduler.py`)

```python
def create_scheduled_send(*, bot_id: str, creator_id: str, template_id: str,
                           target_type: str, target_id: str | None,
                           cron_expression: str, timezone: str = "UTC") -> dict:
    """Create a scheduled send job."""
    # 1. Validate cron expression
    # 2. Calculate next_run_at from cron + timezone
    # 3. Write to BotScheduledSends table

def list_scheduled_sends(*, bot_id: str) -> list[dict]:
    """List all scheduled sends for a bot."""

def update_scheduled_send(*, bot_id: str, schedule_id: str,
                           creator_id: str, **fields) -> dict:
    """Update schedule (cron, timezone, template_id, enabled)."""

def delete_scheduled_send(*, bot_id: str, schedule_id: str, creator_id: str) -> dict:
    """Delete a scheduled send."""

def dispatch_due_scheduled_sends(*, now_ts_value: int | None = None,
                                   limit: int = 50) -> dict[str, int]:
    """Background worker: query GSI1 for due sends, execute each."""
    # 1. Query GSI1PK=BOTSCHED#PENDING, GSI1SK <= now
    # 2. For each due send:
    #    a. Fetch bot + template
    #    b. Resolve target conversations (expand wildcards)
    #    c. Render template per conversation
    #    d. Send bot message to each conversation
    #    e. Update last_run_at, calculate next next_run_at
    #    f. Record impression
    # 3. Return {"dispatched": N, "failed": M}

async def run_bot_scheduler_loop() -> None:
    """Background async loop, runs every 60 seconds."""
    while True:
        try:
            dispatch_due_scheduled_sends()
        except Exception:
            logger.exception("bot_scheduler: dispatch error")
        await asyncio.sleep(60)

def start_bot_scheduler_task() -> None:
    """Called from main.py startup to launch background scheduler."""
    asyncio.create_task(run_bot_scheduler_loop())
```

### 3.7 Backend Router (`app/routers/bot_template.py`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/ui/bots/{bot_id}/templates` | `require_ui_session` | Create template |
| GET | `/ui/bots/{bot_id}/templates` | `require_ui_session` | List templates (optional `?category=` filter) |
| GET | `/ui/bots/{bot_id}/templates/{template_id}` | `require_ui_session` | Get template |
| PUT | `/ui/bots/{bot_id}/templates/{template_id}` | `require_ui_session` | Update template |
| DELETE | `/ui/bots/{bot_id}/templates/{template_id}` | `require_ui_session` | Delete template |
| POST | `/ui/bots/{bot_id}/templates/{template_id}/preview` | `require_ui_session` | Preview rendered template with sample data |
| POST | `/ui/bots/{bot_id}/schedules` | `require_ui_session` | Create scheduled send |
| GET | `/ui/bots/{bot_id}/schedules` | `require_ui_session` | List scheduled sends |
| PUT | `/ui/bots/{bot_id}/schedules/{schedule_id}` | `require_ui_session` | Update schedule |
| DELETE | `/ui/bots/{bot_id}/schedules/{schedule_id}` | `require_ui_session` | Delete schedule |
| POST | `/ui/bots/{bot_id}/templates/{template_id}/send-test` | `require_ui_session` | Send test message to a specific conversation |

**Key request models**:

```python
class CreateTemplateIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    text: str = Field(..., min_length=1, max_length=4000)
    category: Literal["greeting", "support", "promotion", "farewell", "away", "custom"] = "custom"
    body_format: Literal["plain", "markdown"] = "plain"
    quick_replies: Optional[List[QuickReplyIn]] = Field(default=None, max_length=5)
    ab_group: Optional[str] = Field(default=None, max_length=50)
    ab_weight: int = Field(default=1, ge=1, le=100)

class QuickReplyIn(BaseModel):
    label: str = Field(..., min_length=1, max_length=40)
    value: str = Field(..., min_length=1, max_length=200)

class CreateScheduledSendIn(BaseModel):
    template_id: str
    target_type: Literal["conversation", "all_dms", "all_groups", "all_broadcasts"]
    target_id: Optional[str] = None
    cron_expression: str = Field(..., min_length=5, max_length=100)
    timezone: str = Field(default="UTC", max_length=50)
```

Update models (`UpdateTemplateIn`, `UpdateScheduledSendIn`) follow the same pattern with all fields optional. Response models (`TemplateOut`, `ScheduledSendOut`) mirror the DDB record fields.

Register in `app/main.py`:

```python
from app.routers.bot_template import router as bot_template_router
app.include_router(bot_template_router, prefix="/ui")
```

### 3.8 Frontend Types (`frontend/src/api/types.ts`)

```typescript
export interface BotTemplate {
  template_id: string;
  bot_id: string;
  name: string;
  text: string;
  category: "greeting" | "support" | "promotion" | "farewell" | "away" | "custom";
  body_format: "plain" | "markdown";
  quick_replies?: QuickReply[];
  variables_used?: string[];
  ab_group?: string;
  ab_weight: number;
  impression_count: number;
  response_count: number;
  created_at: number;
  updated_at: number;
}

export interface QuickReply { label: string; value: string; }

export interface BotScheduledSend {
  schedule_id: string;
  bot_id: string;
  template_id: string;
  target_type: string;
  target_id?: string;
  cron_expression: string;
  timezone: string;
  next_run_at: number;
  last_run_at?: number;
  enabled: boolean;
  created_at: number;
}
```

Extend `MessageOut` with `quick_replies?: QuickReply[]`.

### 3.9 Frontend API (`frontend/src/api/endpoints/bots.ts`)

Standard CRUD wrappers for template and schedule endpoints (matching the router paths in 3.7). Key functions: `createTemplate`, `listTemplates`, `updateTemplate`, `deleteTemplate`, `previewTemplate`, `sendTestTemplate`, `createScheduledSend`, `listScheduledSends`, `updateScheduledSend`, `deleteScheduledSend`.

### 3.10 Frontend Pages

- **TemplateEditorPage** (`frontend/src/pages/bots/TemplateEditorPage.tsx`): Route `/bots/:botId/templates`. Lists templates in a table grouped by category. Inline preview panel on the right. Variable insertion toolbar. Quick-reply builder (add/remove/reorder buttons). A/B group assignment. Impression/response stats per template. `data-testid="template-editor-page"`.
- **TemplateFormDialog** (`frontend/src/pages/bots/TemplateFormDialog.tsx`): Dialog for creating/editing a single template. Text area with variable autocomplete (`{` triggers dropdown). Category selector. Quick-reply section. "Preview" button sends a rendered preview to a test conversation. `data-testid="template-form-dialog"`.
- **ScheduleManagerPanel** (`frontend/src/pages/bots/ScheduleManagerPanel.tsx`): Panel within BotEditorDialog or TemplateEditorPage. Shows scheduled sends as cards with cron description (human-readable), next run time, enable/disable toggle. Add new schedule: pick template + target + cron. `data-testid="schedule-manager-panel"`.

### 3.11 Quick-Reply Rendering in MessageBubble

In `MessageBubble.tsx`, add below the message text:

```tsx
{message.quick_replies && message.sender_type === "bot" && (
  <div className="flex flex-wrap gap-2 mt-2" data-testid="quick-replies">
    {message.quick_replies.map((qr, i) => (
      <Button
        key={i}
        variant="outline"
        size="sm"
        disabled={quickReplySent}
        onClick={() => {
          setQuickReplySent(true);
          sendMessage({ text: qr.value });
        }}
        data-testid={`quick-reply-${i}`}
      >
        {qr.label}
      </Button>
    ))}
  </div>
)}
```

---

## 4. Implementation Plan

### 4.1 Files to Create

| File | Purpose |
|------|---------|
| `app/services/bot_template.py` | Template CRUD, variable resolution, A/B selection |
| `app/services/bot_scheduler.py` | Scheduled send management + background dispatch loop |
| `app/routers/bot_template.py` | Template + schedule endpoints |
| `frontend/src/pages/bots/TemplateEditorPage.tsx` | Template list + editor UI |
| `frontend/src/pages/bots/TemplateFormDialog.tsx` | Template create/edit dialog |
| `frontend/src/pages/bots/ScheduleManagerPanel.tsx` | Scheduled send management |

### 4.2 Files to Modify

| File | Changes |
|------|---------|
| `scripts/local-ddb-init.py` | Add `bot_templates` and `bot_scheduled_sends` TableDefs <!-- NOTE: Neither table exists yet — new implementation required --> |
| `app/core/settings.py` | Add `bot_templates_table_name`, `bot_scheduled_sends_table_name` <!-- NOTE: Neither setting exists yet — new implementation required --> |
| `app/core/tables.py` | Add table handles <!-- NOTE: Neither handle exists yet — new implementation required --> |
| `app/main.py` | Register `bot_template_router`; start bot scheduler task on startup <!-- NOTE: Neither registration nor startup task exists yet — new implementation required --> |
| `app/routers/messaging.py` | Add `quick_replies` field to `MessageOut` <!-- NOTE: quick_replies does not exist on MessageOut at line 2325 — new field required --> |
| `app/services/chat_bot.py` | Wire `evaluate_triggers()` to template resolution + rendering <!-- NOTE: chat_bot.py does not exist yet — depends on BOT-001 --> |
| `frontend/src/api/types.ts` | Add `BotTemplate`, `QuickReply`, `BotScheduledSend` types |
| `frontend/src/api/endpoints/bots.ts` | Add template + schedule API functions |
| `frontend/src/pages/messages/MessageBubble.tsx` | Render quick-reply buttons on bot messages |
| `frontend/src/App.tsx` | Add `/bots/:botId/templates` route |

---

## 5. E2E Test Plan

### 5.1 Test File

`frontend/e2e/bot-templates.spec.ts` -- 16 tests across 4 sections.

### 5.2 Test Setup

```typescript
const TS = Date.now();
let botId: string;
let templateId: string;
let greetingTemplateId: string;
let scheduleId: string;
let conversationId: string;
// Alice = creator (bot owner), Bob = user receiving bot messages
```

### 5.3 Section 511: Template CRUD API (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 511.1 | Create a greeting template | POST `/ui/bots/{botId}/templates` with `category=greeting`, text `"Hello {user_name}!"`; 201; `template_id`, `variables_used` includes `user_name` |
| 511.2 | Create a template with quick replies | POST with `quick_replies=[{label:"Yes",value:"yes"},{label:"No",value:"no"}]`; 201; `quick_replies` length 2 |
| 511.3 | List templates by category | GET `/ui/bots/{botId}/templates?category=greeting`; array includes greeting template only |
| 511.4 | Update template text | PUT with new text; 200; text updated; `variables_used` updated |
| 511.5 | Delete template | DELETE; 200; GET returns 404 |

### 5.4 Section 512: Variable Substitution & Preview (3 tests)

| # | Test | Assertion |
|---|------|-----------|
| 512.1 | Preview template with variables | POST `/ui/bots/{botId}/templates/{id}/preview` with `sample_user_name="TestUser"`; 200; `rendered_text` contains "TestUser" |
| 512.2 | Send test message | POST `/ui/bots/{botId}/templates/{id}/send-test` with `conversation_id`; 200; message appears in conversation |
| 512.3 | Unknown variables preserved | Create template with `{unknown_var}`; preview; `{unknown_var}` appears literally in output |

### 5.5 Section 513: Scheduled Sends API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 513.1 | Create scheduled send | POST `/ui/bots/{botId}/schedules` with `cron_expression="0 14 * * *"`, `timezone="UTC"`; 201; `next_run_at` set |
| 513.2 | List scheduled sends | GET; array includes created schedule |
| 513.3 | Disable schedule | PUT with `enabled=false`; 200; `enabled=false` |
| 513.4 | Delete schedule | DELETE; 200; list length decremented |

### 5.6 Section 514: Template Editor UI (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 514.1 | Template editor page loads | Navigate `/bots/{botId}/templates`; `[data-testid="template-editor-page"]` visible |
| 514.2 | Create template via dialog | Click "New Template"; fill name + text with `{user_name}`; save; template appears in list |
| 514.3 | Quick-reply buttons render in message | Send bot message with quick replies; navigate to conversation; `[data-testid="quick-replies"]` visible; 2 buttons rendered |
| 514.4 | Quick reply sends user message | Click `[data-testid="quick-reply-0"]`; user message with button value appears in conversation |

---

## 6. Error Handling

| Scenario | Status | Detail |
|----------|--------|--------|
| Bot not found | 404 | "Bot not found" |
| Template not found | 404 | "Template not found" |
| Not bot owner | 403 | "You do not own this bot" |
| Max templates exceeded | 409 | "Maximum of 50 templates per bot" |
| Invalid cron expression | 422 | "Invalid cron expression" |
| Quick replies > 5 | 422 | "Maximum of 5 quick replies" |
| Quick reply label too long | 422 | "Quick reply label must be 40 characters or fewer" |
| Schedule target not found | 404 | "Target conversation not found" |
| Template text empty | 422 | "Template text is required" |
| Invalid timezone | 422 | "Invalid timezone: {value}" |

---

## 7. Security Considerations

- **Ownership enforcement**: All template and schedule operations verify the bot belongs to the authenticated user. No cross-creator access.
- **Variable injection safety**: Variable values are HTML-escaped before insertion to prevent XSS. Template text is sanitized the same as regular message text.
- **Cron expression validation**: Cron expressions are validated server-side using a strict parser. Maximum frequency: once per hour (`* * * * *` is rejected; minimum interval enforced).
- **Scheduled send rate limiting**: Each bot is limited to 20 scheduled sends. Each send expands to at most 500 conversations (wildcard targets are capped).
- **Template text size**: 4000 char max prevents DDB item size bloat. Quick-reply values are capped at 200 chars to prevent payload abuse.
- **Test send audit**: `send-test` endpoint logs which template was sent to which conversation for abuse tracing.

---

## 8. Performance Considerations

| Concern | Mitigation |
|---------|-----------|
| Variable resolution requires multiple DDB reads | Lazy resolution: only fetch data for variables present in template text |
| Scheduled send fan-out to many conversations | Cap wildcard expansion at 500 conversations per schedule execution; process in batches of 25 |
| Background scheduler contention | Single-leader scheduler (only one worker processes due sends); idempotent execution via `ConditionExpression` on `last_run_at` |
| Template list for bots with many templates | Paginate with `Limit=50`; category filter via GSI1 reduces scan scope |
| Impression/response counter hot partition | Use `ADD` atomic counter (no read-before-write); acceptable for per-template granularity |

---

## 9. Dependencies

| Dependency | Ticket | Status |
|------------|--------|--------|
| BOT-001 (Bot Framework) | BOT-001 | Required (bot CRUD, assignment, trigger evaluation) |
| Messaging infrastructure | Existing | Available (`send_text_message`, `MessageOut`) |
| Profiles table | Existing | Available (for `{user_name}`, `{creator_name}` resolution) |
| Subscriptions table | Existing | Available (for `{subscriber_status}` resolution) |

### Downstream

| Ticket | Depends On |
|--------|-----------|
| BOT-003 (Content Promotion) | Templates for content card rendering and scheduled promotion sends |
| BOT-004 (AI Chat) | Template system for fallback messages and escalation templates |

---

## 10. Architecture & Data Flow

```
                    Template Message Creation Flow
  ┌───────────────┐     ┌────────────────────┐     ┌──────────────┐
  │ Bot Config UI  │────>│ POST /ui/bots/     │────>│  DynamoDB     │
  │  (frontend)    │     │  {id}/templates    │     │  bot_templates│
  │                │     │  (bot_router.py)    │     │  table        │
  │  template_name │     │                    │     │               │
  │  body w/ vars  │     │  1. validate vars  │     │  PK=BOT#id   │
  │  quick_replies │     │  2. store template │     │  SK=TPL#tpl_id│
  └───────────────┘     └────────────────────┘     └──────────────┘

                    Scheduled Message Execution Flow
  ┌───────────────┐     ┌────────────────────┐     ┌──────────────┐
  │ Background     │────>│ scan_due_scheduled │────>│  DynamoDB     │
  │ Loop (30s)     │     │ _messages()        │     │  bot_scheduled│
  │                │     │                    │     │  _messages    │
  │ check          │     │ for each due msg:  │     │               │
  │ deliver_at     │     │  1. resolve vars   │     │  GSI: by      │
  │ <= now_ts()    │     │  2. render template│     │  deliver_at   │
  │                │     │  3. send_text_msg  │     │               │
  │                │     │  4. mark delivered │     │               │
  └───────────────┘     └────────────────────┘     └──────────────┘
```

---

## 11. Observability

### 11.1 Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `bot_template_created_total` | Counter | `bot_id` | Number of templates created |
| `bot_scheduled_message_created_total` | Counter | `bot_id` | Number of scheduled messages created |
| `bot_scheduled_message_delivered_total` | Counter | `bot_id`, `status` | Delivered vs failed scheduled messages |
| `bot_template_render_duration_ms` | Histogram | `bot_id` | Time to resolve variables and render template |
| `bot_variable_resolution_errors_total` | Counter | `variable_name` | Failed variable resolutions |
| `bot_scheduled_message_latency_ms` | Histogram | -- | Delay between deliver_at and actual delivery |

### 11.2 Logging

| Event | Level | Fields |
|-------|-------|--------|
| Template created | INFO | `bot_id`, `template_id`, `variable_count` |
| Scheduled message created | INFO | `bot_id`, `message_id`, `deliver_at`, `recipient_count` |
| Scheduled message delivered | INFO | `bot_id`, `message_id`, `conversation_id`, `latency_ms` |
| Variable resolution failed | WARN | `bot_id`, `template_id`, `variable_name`, `reason` |
| Scheduled message delivery failed | ERROR | `bot_id`, `message_id`, `error` |

### 11.3 Alerts

| Alert | Condition | Severity |
|-------|-----------|----------|
| Scheduled message delivery backlog | > 100 undelivered messages past deliver_at | High |
| Template variable resolution failures | > 20/hour | Medium |
| Background loop stalled | No scan in > 5 minutes | High |

---

## 12. Rollout Plan

### 12.1 Feature Flag

```python
# app/core/settings.py
bot_templates_enabled: bool = os.environ.get("BOT_TEMPLATES_ENABLED", "true").lower() == "true"
bot_scheduled_messages_enabled: bool = os.environ.get("BOT_SCHEDULED_MESSAGES_ENABLED", "true").lower() == "true"
```

### 12.2 Phased Rollout

| Phase | Description | Duration | Criteria |
|-------|-------------|----------|----------|
| Phase 1: Templates only | Deploy template CRUD; no scheduled execution | 2 days | Unit tests pass; template creation/preview works |
| Phase 2: Scheduled messages | Enable background loop for scheduled delivery | 2 days | E2E tests pass; delivery latency < 60s |
| Phase 3: Quick replies | Enable quick reply buttons on template messages | 1 day | Quick reply callbacks trigger correct bot actions |
| Phase 4: GA | Remove feature flags; full template + scheduling system | Permanent | All tests pass; monitoring clean for 48h |

---

## 13. Performance Considerations

| Concern | Target | Mitigation |
|---------|--------|-----------|
| Background scan latency | < 2s per scan cycle | GSI query on deliver_at; process in batches of 25 |
| Variable resolution per message | < 50ms | Cache profile data per batch; parallel DDB lookups |
| Template render time | < 10ms | Simple string substitution; no complex templating engine |
| Scheduled message delivery accuracy | Within 60s of deliver_at | 30s scan interval; worst case = 30s delay |
| Many concurrent scheduled messages | 100+/minute | Batch processing with rate limiting to prevent messaging API overload |
| Quick reply callback latency | < 200ms | Direct bot trigger invocation; no queue |

---

## 14. Error Handling Matrix

| Scenario | HTTP Status | Error Code | Error Message | Recovery Action |
|----------|-------------|------------|---------------|-----------------|
| Template not found | 404 | `template_not_found` | "Template not found" | Show error; refresh template list |
| Invalid variable syntax | 422 | `invalid_variable` | "Invalid variable: {bad_var}" | Show inline error on template editor |
| Bot not found | 404 | `bot_not_found` | "Bot not found" | Redirect to bot list |
| Scheduled time in past | 400 | `time_in_past` | "deliver_at must be in the future" | Show date picker error |
| Template body empty | 422 | `validation_error` | "Template body is required" | Show form validation |
| Variable resolution failed | 200 (degraded) | -- | Variable left as `{unknown_var}` literal | Log warning; deliver with unresolved vars |
| Recipient not in conversation | 400 | `invalid_recipient` | "Recipient is not in this conversation" | Show error; suggest valid recipients |
| Max templates per bot exceeded | 400 | `template_limit` | "Maximum 100 templates per bot" | Show limit reached message |

---

## 15. API Request/Response Examples

**Create template**:

```
POST /ui/bots/bot_abc123/templates
Content-Type: application/json
x-csrf-token: <csrf>

{
  "name": "Welcome New Subscriber",
  "body": "Hey {user_name}! Welcome to the community. Your subscription to {plan_name} is now active. Check out the latest content at {creator_page_url}.",
  "quick_replies": [
    {"label": "View Content", "action": "navigate", "payload": "/feed"},
    {"label": "Settings", "action": "navigate", "payload": "/settings"}
  ]
}
```

**Response (201)**:
```json
{
  "template_id": "tpl_7a8b9c0d",
  "bot_id": "bot_abc123",
  "name": "Welcome New Subscriber",
  "body": "Hey {user_name}! Welcome to the community...",
  "variables": ["user_name", "plan_name", "creator_page_url"],
  "quick_replies": [
    {"label": "View Content", "action": "navigate", "payload": "/feed"},
    {"label": "Settings", "action": "navigate", "payload": "/settings"}
  ],
  "created_at": 1748520100
}
```

**Schedule a message**:

```
POST /ui/bots/bot_abc123/scheduled-messages
Content-Type: application/json
x-csrf-token: <csrf>

{
  "template_id": "tpl_7a8b9c0d",
  "conversation_id": "conv_xyz789",
  "deliver_at": 1748606500,
  "variable_overrides": {
    "plan_name": "Premium Monthly"
  }
}
```

**Response (201)**:
```json
{
  "scheduled_message_id": "sm_d4e5f6a7",
  "bot_id": "bot_abc123",
  "template_id": "tpl_7a8b9c0d",
  "conversation_id": "conv_xyz789",
  "deliver_at": 1748606500,
  "status": "pending",
  "created_at": 1748520200
}
```

**Preview rendered template**:

```
POST /ui/bots/bot_abc123/templates/tpl_7a8b9c0d/preview
Content-Type: application/json
x-csrf-token: <csrf>

{
  "user_sub": "bob@test.local"
}
```

**Response (200)**:
```json
{
  "rendered_body": "Hey Bob! Welcome to the community. Your subscription to Premium Monthly is now active. Check out the latest content at /creators/alice.",
  "resolved_variables": {
    "user_name": "Bob",
    "plan_name": "Premium Monthly",
    "creator_page_url": "/creators/alice"
  },
  "unresolved_variables": []
}
```

---

## 16. Architecture Diagram

```
                  Bot Templates & Scheduled Messages — System Architecture
  ┌─────────────────────────────────────────────────────────────────────────────┐
  │                            Platform Frontend                                │
  │  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────────────┐  │
  │  │ TemplateEditor    │  │ TemplateForm     │  │ ScheduleManager          │  │
  │  │ Page              │  │ Dialog           │  │ Panel                    │  │
  │  │                   │  │                  │  │                          │  │
  │  │ - template list   │  │ - text editor    │  │ - schedule list          │  │
  │  │ - category filter │  │ - variable {..}  │  │ - cron description       │  │
  │  │ - A/B stats       │  │ - quick replies  │  │ - next run time          │  │
  │  │ - inline preview  │  │ - A/B groups     │  │ - enable/disable         │  │
  │  └────────┬─────────┘  └────────┬─────────┘  └─────────────┬────────────┘  │
  │           │                     │                           │               │
  │  ┌────────┴─────────────────────┴───────────────────────────┴────────────┐  │
  │  │                     React Query + Axios Client                        │  │
  │  │  createTemplate() | previewTemplate() | createScheduledSend()         │  │
  │  └───────────────────────────────────┬──────────────────────────────────┘  │
  └──────────────────────────────────────┼──────────────────────────────────────┘
                                         │ HTTP (CSRF + cookies)
  ┌──────────────────────────────────────┼──────────────────────────────────────┐
  │                           FastAPI Backend                                   │
  │  ┌───────────────────────────────────┴──────────────────────────────────┐  │
  │  │              app/routers/bot_template.py                              │  │
  │  │   POST /bots/{id}/templates    GET /bots/{id}/templates              │  │
  │  │   PUT /bots/{id}/templates/{tId}    DELETE .../templates/{tId}       │  │
  │  │   POST .../templates/{tId}/preview  POST .../templates/{tId}/send-test│  │
  │  │   POST /bots/{id}/schedules    GET .../schedules                     │  │
  │  │   PUT .../schedules/{sId}      DELETE .../schedules/{sId}            │  │
  │  └───────────────────────────────────┬──────────────────────────────────┘  │
  │                                      │                                     │
  │  ┌───────────────────────────────────┴──────────────────────────────────┐  │
  │  │              app/services/bot_template.py                             │  │
  │  │                                                                       │  │
  │  │   create_template()  list_templates()  update_template()              │  │
  │  │   delete_template()  render_template()  record_impression()           │  │
  │  │   record_response()  get_templates_for_trigger()                      │  │
  │  │   select_ab_template()  build_variable_context()                      │  │
  │  │   resolve_variables()                                                 │  │
  │  │                                                                       │  │
  │  │   Variable Resolution Pipeline:                                       │  │
  │  │   ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐      │  │
  │  │   │ {user_name}  │  │ {creator_    │  │ {subscriber_status}  │      │  │
  │  │   │ → Profiles   │  │  name}       │  │ → Subscriptions      │      │  │
  │  │   │   table      │  │ → Profiles   │  │   table              │      │  │
  │  │   │   by sender  │  │   table by   │  │   by sender          │      │  │
  │  │   │              │  │   creator    │  │                      │      │  │
  │  │   └──────────────┘  └──────────────┘  └──────────────────────┘      │  │
  │  │   ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐      │  │
  │  │   │ {bot_name}   │  │ {current_    │  │ {conversation_name}  │      │  │
  │  │   │ → ChatBots   │  │  time/date}  │  │ → Conversations      │      │  │
  │  │   │   table      │  │ → datetime   │  │   table              │      │  │
  │  │   └──────────────┘  └──────────────┘  └──────────────────────┘      │  │
  │  └──────────────────────────────────────────────────────────────────────┘  │
  │                                                                            │
  │  ┌──────────────────────────────────────────────────────────────────────┐  │
  │  │              app/services/bot_scheduler.py                            │  │
  │  │                                                                       │  │
  │  │   create_scheduled_send()    list_scheduled_sends()                   │  │
  │  │   update_scheduled_send()    delete_scheduled_send()                  │  │
  │  │   dispatch_due_scheduled_sends()    run_bot_scheduler_loop()          │  │
  │  │                                                                       │  │
  │  │   ┌──────────────────────────────────────────────────────────────┐   │  │
  │  │   │  Background Scheduler Loop (every 60s)                       │   │  │
  │  │   │  1. Query GSI1: BOTSCHED#PENDING, next_run_at <= now        │   │  │
  │  │   │  2. For each due send:                                       │   │  │
  │  │   │     a. Fetch bot + template                                  │   │  │
  │  │   │     b. Expand wildcards → list of conversations              │   │  │
  │  │   │     c. Render template (resolve variables per conversation)  │   │  │
  │  │   │     d. send_bot_message() to each conversation               │   │  │
  │  │   │     e. Record impression per template                        │   │  │
  │  │   │     f. Calculate next_run_at from cron                       │   │  │
  │  │   │     g. Update last_run_at + next_run_at                      │   │  │
  │  │   └──────────────────────────────────────────────────────────────┘   │  │
  │  └──────────────────────────────────────────────────────────────────────┘  │
  │                                                                            │
  │  ┌──────────────────────────────────────────────────────────────────────┐  │
  │  │                          DynamoDB Tables                              │  │
  │  │   ┌─────────────────────┐    ┌──────────────────────────────┐       │  │
  │  │   │ bot_templates       │    │ bot_scheduled_sends           │       │  │
  │  │   │                     │    │                              │       │  │
  │  │   │ PK=BOT#{bot_id}    │    │ PK=BOT#{bot_id}             │       │  │
  │  │   │ SK=TEMPLATE#{tpl_id}│    │ SK=SCHED#{schedule_id}      │       │  │
  │  │   │                     │    │                              │       │  │
  │  │   │ GSI1: by category   │    │ GSI1: pending sends         │       │  │
  │  │   │   + created_at     │    │  PK=BOTSCHED#PENDING        │       │  │
  │  │   │                     │    │  SK=next_run_at              │       │  │
  │  │   └─────────────────────┘    └──────────────────────────────┘       │  │
  │  └──────────────────────────────────────────────────────────────────────┘  │
  └─────────────────────────────────────────────────────────────────────────────┘
```

---

## 17. DynamoDB Access Patterns

| # | Access Pattern | Table | Key Condition | GSI | Example |
|---|---------------|-------|---------------|-----|---------|
| 1 | Create template | `bot_templates` | `PK=BOT#{bot_id}, SK=TEMPLATE#{template_id}` | -- | `put_item` with name, text, category, quick_replies |
| 2 | Get template by ID | `bot_templates` | `PK=BOT#{bot_id}, SK=TEMPLATE#{template_id}` | -- | `get_item` |
| 3 | List all templates for bot | `bot_templates` | `PK=BOT#{bot_id}, SK begins_with("TEMPLATE#")` | -- | All templates for a bot |
| 4 | List templates by category | `bot_templates` | `GSI1PK=BOT#{bot_id}#CAT#{category}, GSI1SK desc` | GSI1 | Templates of category "greeting" sorted by created_at |
| 5 | Update template | `bot_templates` | `PK=BOT#{bot_id}, SK=TEMPLATE#{template_id}` | -- | `update_item` set text, quick_replies, etc. |
| 6 | Delete template | `bot_templates` | `PK=BOT#{bot_id}, SK=TEMPLATE#{template_id}` | -- | `delete_item` |
| 7 | Increment impression count | `bot_templates` | `PK=BOT#{bot_id}, SK=TEMPLATE#{template_id}` | -- | `update_item` ADD impression_count 1 |
| 8 | Increment response count | `bot_templates` | `PK=BOT#{bot_id}, SK=TEMPLATE#{template_id}` | -- | `update_item` ADD response_count 1 |
| 9 | Get templates in A/B group | `bot_templates` | `PK=BOT#{bot_id}, SK begins_with("TEMPLATE#")` + FilterExpression `ab_group = :group` | -- | Templates sharing same A/B group |
| 10 | Create scheduled send | `bot_scheduled_sends` | `PK=BOT#{bot_id}, SK=SCHED#{schedule_id}` | -- | `put_item` with cron, timezone, next_run_at |
| 11 | List schedules for bot | `bot_scheduled_sends` | `PK=BOT#{bot_id}, SK begins_with("SCHED#")` | -- | All scheduled sends |
| 12 | Query due scheduled sends | `bot_scheduled_sends` | `GSI1PK=BOTSCHED#PENDING, GSI1SK <= now_ts` | GSI1 | Background worker picks up due sends |
| 13 | Update schedule after execution | `bot_scheduled_sends` | `PK=BOT#{bot_id}, SK=SCHED#{schedule_id}` | -- | Set last_run_at, recalculate next_run_at |

**Example DynamoDB item (BotTemplates)**:

```json
{
  "pk": {"S": "BOT#b1c2d3e4f5a6"},
  "sk": {"S": "TEMPLATE#tpl_7a8b9c0d1e2f"},
  "template_id": {"S": "tpl_7a8b9c0d1e2f"},
  "bot_id": {"S": "b1c2d3e4f5a6"},
  "name": {"S": "Welcome Greeting"},
  "category": {"S": "greeting"},
  "text": {"S": "Hey {user_name}! Welcome to {creator_name}'s community. Feel free to ask me anything!"},
  "body_format": {"S": "plain"},
  "quick_replies": {"L": [
    {"M": {"label": {"S": "What's new?"}, "value": {"S": "whats_new"}}},
    {"M": {"label": {"S": "Pricing info"}, "value": {"S": "pricing"}}},
    {"M": {"label": {"S": "Contact support"}, "value": {"S": "support"}}}
  ]},
  "variables_used": {"SS": ["user_name", "creator_name"]},
  "ab_group": {"S": "greeting_test_1"},
  "ab_weight": {"N": "2"},
  "impression_count": {"N": "534"},
  "response_count": {"N": "198"},
  "created_at": {"N": "1748520100"},
  "updated_at": {"N": "1748520300"},
  "GSI1PK": {"S": "BOT#b1c2d3e4f5a6#CAT#greeting"},
  "GSI1SK": {"N": "1748520100"}
}
```

**Example DynamoDB item (BotScheduledSends)**:

```json
{
  "pk": {"S": "BOT#b1c2d3e4f5a6"},
  "sk": {"S": "SCHED#sch_9a0b1c2d3e4f"},
  "schedule_id": {"S": "sch_9a0b1c2d3e4f"},
  "bot_id": {"S": "b1c2d3e4f5a6"},
  "creator_id": {"S": "alice_sub_123"},
  "template_id": {"S": "tpl_promo_daily"},
  "target_type": {"S": "all_dms"},
  "target_id": {"NULL": true},
  "cron_expression": {"S": "0 14 * * *"},
  "timezone": {"S": "America/New_York"},
  "next_run_at": {"N": "1748620800"},
  "last_run_at": {"N": "1748534400"},
  "enabled": {"BOOL": true},
  "created_at": {"N": "1748100000"},
  "GSI1PK": {"S": "BOTSCHED#PENDING"},
  "GSI1SK": {"N": "1748620800"}
}
```

---

## 18. Pydantic Models

```python
# In app/models.py

from pydantic import BaseModel, Field, model_validator
from typing import Optional, List, Literal


class QuickReplyIn(BaseModel):
    """A single quick-reply button definition."""
    label: str = Field(..., min_length=1, max_length=40)
    value: str = Field(..., min_length=1, max_length=200)


class CreateTemplateIn(BaseModel):
    """Request model for creating a bot message template."""
    name: str = Field(..., min_length=1, max_length=100)
    text: str = Field(..., min_length=1, max_length=4000)
    category: Literal[
        "greeting", "support", "promotion", "farewell", "away", "custom"
    ] = "custom"
    body_format: Literal["plain", "markdown"] = "plain"
    quick_replies: Optional[List[QuickReplyIn]] = Field(
        default=None, max_length=5,
        description="Up to 5 quick-reply buttons"
    )
    ab_group: Optional[str] = Field(
        default=None, max_length=50,
        description="A/B test group name; templates in same group are alternates"
    )
    ab_weight: int = Field(
        default=1, ge=1, le=100,
        description="Weight for random selection within A/B group"
    )


class UpdateTemplateIn(BaseModel):
    """Request model for updating a bot message template."""
    name: Optional[str] = Field(default=None, min_length=1, max_length=100)
    text: Optional[str] = Field(default=None, min_length=1, max_length=4000)
    category: Optional[Literal[
        "greeting", "support", "promotion", "farewell", "away", "custom"
    ]] = None
    body_format: Optional[Literal["plain", "markdown"]] = None
    quick_replies: Optional[List[QuickReplyIn]] = Field(default=None, max_length=5)
    ab_group: Optional[str] = Field(default=None, max_length=50)
    ab_weight: Optional[int] = Field(default=None, ge=1, le=100)


class PreviewTemplateIn(BaseModel):
    """Request model for previewing a rendered template."""
    sample_user_name: Optional[str] = Field(
        default=None, max_length=100,
        description="Override {user_name} for preview"
    )
    sample_subscriber_status: Optional[str] = Field(
        default=None, max_length=50,
        description="Override {subscriber_status} for preview"
    )
    conversation_id: Optional[str] = Field(
        default=None, max_length=100,
        description="Conversation context for {conversation_name}"
    )


class SendTestTemplateIn(BaseModel):
    """Request model for sending a test message using a template."""
    conversation_id: str = Field(..., min_length=1, max_length=100)


class CreateScheduledSendIn(BaseModel):
    """Request model for creating a bot scheduled send."""
    template_id: str = Field(..., min_length=1, max_length=100)
    target_type: Literal[
        "conversation", "all_dms", "all_groups", "all_broadcasts"
    ]
    target_id: Optional[str] = Field(
        default=None, max_length=100,
        description="Specific conversation ID (required for target_type=conversation)"
    )
    cron_expression: str = Field(
        ..., min_length=5, max_length=100,
        description="Cron expression (minimum frequency: once per hour)"
    )
    timezone: str = Field(
        default="UTC", max_length=50,
        description="IANA timezone identifier"
    )

    @model_validator(mode="after")
    def validate_target_id(self):
        if self.target_type == "conversation" and not self.target_id:
            raise ValueError("target_id is required when target_type is 'conversation'")
        return self


class UpdateScheduledSendIn(BaseModel):
    """Request model for updating a bot scheduled send."""
    template_id: Optional[str] = Field(default=None, max_length=100)
    cron_expression: Optional[str] = Field(default=None, min_length=5, max_length=100)
    timezone: Optional[str] = Field(default=None, max_length=50)
    enabled: Optional[bool] = None


class TemplateOut(BaseModel):
    """Response model for a bot message template."""
    template_id: str
    bot_id: str
    name: str
    text: str
    category: str = "custom"
    body_format: str = "plain"
    quick_replies: Optional[List[dict]] = None
    variables_used: Optional[List[str]] = None
    ab_group: Optional[str] = None
    ab_weight: int = 1
    impression_count: int = 0
    response_count: int = 0
    created_at: int = 0
    updated_at: int = 0


class ScheduledSendOut(BaseModel):
    """Response model for a bot scheduled send."""
    schedule_id: str
    bot_id: str
    template_id: str
    target_type: str
    target_id: Optional[str] = None
    cron_expression: str
    timezone: str = "UTC"
    next_run_at: int = 0
    last_run_at: Optional[int] = None
    enabled: bool = True
    created_at: int = 0


class TemplatePreviewOut(BaseModel):
    """Response model for a rendered template preview."""
    rendered_text: str
    resolved_variables: dict = Field(default_factory=dict)
    unresolved_variables: List[str] = Field(default_factory=list)
    quick_replies: Optional[List[dict]] = None
```

---

## 19. Frontend Component Tree

```
/bots/:botId/templates — TemplateEditorPage
├── PageHeader
│   ├── BackButton → BotManagerPage (/bots)
│   ├── BotName display
│   └── CreateTemplateButton → opens TemplateFormDialog (mode="create")
├── CategoryTabs
│   ├── Tab: "All"
│   ├── Tab: "Greeting"
│   ├── Tab: "Support"
│   ├── Tab: "Promotion"
│   ├── Tab: "Farewell"
│   ├── Tab: "Away"
│   └── Tab: "Custom"
├── TemplateListPanel (left side)
│   └── TemplateRow (one per template)
│       ├── NameText
│       ├── CategoryBadge (colored pill)
│       ├── ABGroupBadge (if ab_group set, shows group name + weight)
│       ├── StatsRow
│       │   ├── ImpressionCount ("534 sent")
│       │   └── ResponseRate ("37% response")
│       ├── QuickReplyIndicator (pill count if quick_replies present)
│       ├── VariablesChips (shows detected variables as small chips)
│       └── ActionsDropdown (Edit, Duplicate, Delete)
├── PreviewPanel (right side, shows selected template)
│   ├── PreviewHeader
│   │   ├── TemplateName
│   │   └── PreviewButton ("Preview with sample data")
│   ├── RenderedPreview
│   │   ├── MockBotAvatar + BotName + "Bot" badge
│   │   ├── RenderedText (variables replaced with sample values)
│   │   └── QuickReplyButtons (rendered as outline buttons)
│   └── RawTextView (toggle to see raw template with {variables})
└── ScheduleManagerPanel (bottom section)
    ├── SectionHeader ("Scheduled Sends")
    ├── ScheduleList
    │   └── ScheduleCard (one per scheduled send)
    │       ├── TemplateName (linked template)
    │       ├── CronDescription (human-readable: "Every day at 2:00 PM EST")
    │       ├── TargetLabel ("All DMs" / specific conversation name)
    │       ├── NextRunDisplay ("Next: Jun 1, 2026 at 2:00 PM")
    │       ├── LastRunDisplay ("Last: May 29, 2026 at 2:00 PM")
    │       ├── EnabledToggle (switch)
    │       └── ActionsDropdown (Edit, Delete)
    └── AddScheduleButton → ScheduleFormDialog

TemplateFormDialog (shared dialog for create + edit)
├── DialogHeader ("New Template" or "Edit Template")
├── NameInput (<Input> max 100 chars)
├── CategorySelect (dropdown: greeting, support, promotion, farewell, away, custom)
├── BodyFormatSelect (radio: Plain Text / Markdown)
├── TextEditorArea
│   ├── VariableToolbar (button row)
│   │   ├── "{user_name}" button (inserts at cursor)
│   │   ├── "{creator_name}" button
│   │   ├── "{bot_name}" button
│   │   ├── "{current_time}" button
│   │   ├── "{subscriber_status}" button
│   │   └── "{conversation_name}" button
│   └── Textarea (with auto-detection of variables; highlights {vars})
├── QuickReplyBuilder
│   ├── QuickReplyRow (one per button, max 5)
│   │   ├── LabelInput (max 40 chars)
│   │   ├── ValueInput (max 200 chars)
│   │   ├── ReorderHandle (drag)
│   │   └── RemoveButton
│   └── AddQuickReplyButton (if < 5)
├── ABTestSection (collapsible)
│   ├── ABGroupInput (text, shared name across variants)
│   └── ABWeightSlider (1-100)
├── PreviewButton ("Preview" → sends to preview endpoint)
├── SaveButton
└── CancelButton

ScheduleFormDialog
├── DialogHeader ("New Scheduled Send" or "Edit Schedule")
├── TemplateSelect (dropdown of bot templates)
├── TargetTypeSelect (conversation / all_dms / all_groups / all_broadcasts)
├── ConversationPicker (visible when target_type=conversation)
├── CronBuilder
│   ├── FrequencySelect (Daily / Weekly / Custom)
│   ├── TimeInput (hour:minute)
│   ├── DayOfWeekCheckboxes (visible for weekly)
│   ├── CronExpressionInput (visible for custom, raw cron)
│   └── CronPreview (human-readable description of the cron)
├── TimezoneSelect (IANA timezone dropdown)
├── SaveButton
└── CancelButton

MessageBubble enhancement (for quick replies)
├── ...existing message content...
└── QuickRepliesContainer (if message.quick_replies && sender_type="bot")
    ├── QuickReplyButton (Button variant="outline" size="sm")
    │   ├── Label text
    │   └── onClick → sendMessage({ text: qr.value })
    ├── QuickReplyButton (disabled after first tap)
    └── ...up to 5 buttons
```

---

## Testing Strategy

### Unit Tests (pytest)

**Test file**: `tests/test_bot_templates.py`

**Mock setup**: moto mock for DynamoDB (bot tables, messages table). Mock LLM API for BOT-004.

| Test Function | Description |
|---|---|
| `test_create_bot` | Create bot with name, avatar, description; verify stored |
| `test_list_bots_for_creator` | List bots; returns only creator's bots |
| `test_update_bot_state` | Transition active -> paused -> active; verify state |
| `test_assign_bot_to_conversation` | Assign bot; verify assignment stored |
| `test_trigger_evaluation` | Send message matching keyword trigger; bot responds |
| `test_bot_message_has_sender_type_bot` | Bot message has `sender_type=bot` and bot identity |
| `test_max_bots_per_creator` | Exceed limit (10); returns 409 |

### Integration Tests

Cross-service tests with real DynamoDB Local:

1. Create bot -> assign to conversation -> send trigger message -> verify bot response
2. Bot message appears in conversation with correct sender identity
3. Paused bot does not respond to triggers

### E2E Tests (Playwright)

**Test file**: `frontend/e2e/bot-templates.spec.ts`

**Auth pattern**: `injectAuth(page, "alice")` for creator; `injectAuth(page, "bob")` for user interacting with bot; CSRF header for mutations

| # | Test Name | Assertion |
|---|---|---|
| 1 | API creates bot | POST returns bot with ID |
| 2 | API lists creator bots | GET returns array of bots |
| 3 | API updates bot state | PATCH state to paused; verify |
| 4 | API assigns bot to conversation | POST assignment; verify |
| 5 | Bot responds to trigger | Send keyword message; bot reply appears |
| 6 | Bot message shows bot badge | Bot message has 'Bot' indicator |
| 7 | UI bot management page loads | Navigate to bot management; heading visible |
| 8 | UI create bot form works | Fill form; submit; bot appears in list |
| 9 | Paused bot does not respond | Pause bot; send trigger; no response |
| 10 | Unauthenticated returns 401 | No session -> 401 |
| 11 | Non-owner bot access returns 403 | Bob tries to edit Alice's bot -> 403 |
| 12 | Max bots limit enforced | Create 11th bot -> 409 |

**Negative tests**: 401 unauthenticated, 403 non-owner, 404 non-existent bot, 409 max limit, 422 validation

**Edge cases**: Bot assigned to ALL_DMS wildcard, concurrent trigger messages, empty trigger config, bot in disabled state

### Test Data Requirements

Create test bot via API in `beforeAll`. Create test conversation between Alice and Bob for trigger testing.

**Test users**: Alice (USER, bot creator), Bob (USER, message sender), Root (ROOT, admin)

### CI/Pipeline

Serial execution. Retry-safe (unique bot names per run).

---

## Dependencies & Merge Safety

### Depends On

| Ticket | What's Needed | Status | Can Overlap? |
|---|---|---|---|
| BOT-001 | Bot framework CRUD, trigger evaluation, `send_bot_message()` | Implemented | No -- must merge after |

### Depended On By

| Ticket | What It Needs |
|---|---|
| BOT-003 | Template engine for content promotion cards |

### Merge Strategy

Sequential after BOT-001. Adds template engine, scheduled sends, and quick-reply buttons to bot framework.

### Merge Checklist

- [ ] DDB table `ChatBots` added to `scripts/local-ddb-init.py`
- [ ] Bot service and router registered in `app/main.py`
- [ ] Frontend bot management page and API wrappers created
- [ ] E2E tests pass in CI
- [ ] No breaking changes to existing messaging system

---

## Codebase References

| Claim | File | Line(s) | Status |
|-------|------|---------|--------|
| `send_text_message()` exists | `app/routers/messaging.py` | 7684 | VERIFIED |
| `MessageOut` model exists | `app/routers/messaging.py` | 2325 | VERIFIED |
| `MessageOut.kind` Literal union | `app/routers/messaging.py` | 2330 | VERIFIED |
| `send_at` scheduled message field | `app/routers/messaging.py` | 1853, 1930, 1952 | VERIFIED (on message input models) |
| Scheduled dispatch background loop | `app/routers/messaging.py` | 737 | VERIFIED (`dispatch_due_scheduled_mass_campaigns`) |
| `send_chat_message()` in broadcast store | `app/services/broadcast_chat_store.py` | 136 | VERIFIED |
| `newsfeed_scheduler.py` background pattern | `app/services/newsfeed_scheduler.py` | 76 | VERIFIED (`_query_due_posts`) |
| No `quick_replies` field on MessageOut | `app/routers/messaging.py` | 2325-2380 | VERIFIED (field does not exist — new implementation required) |
| No `bot_templates` DDB table | `scripts/local-ddb-init.py` | full file | VERIFIED (table does not exist — new implementation required) |
| No `bot_scheduled_sends` DDB table | `scripts/local-ddb-init.py` | full file | VERIFIED (table does not exist — new implementation required) |
| No `bot_templates_table_name` setting | `app/core/settings.py` | full file | VERIFIED (setting does not exist — new implementation required) |
| No `bot_template_router` in main.py | `app/main.py` | full file | VERIFIED (not registered — new implementation required) |
| No `app/services/bot_template.py` | `app/services/` | N/A | VERIFIED (file does not exist — new implementation required) |
| No `app/services/bot_scheduler.py` | `app/services/` | N/A | VERIFIED (file does not exist — new implementation required) |
| No `app/routers/bot_template.py` | `app/routers/` | N/A | VERIFIED (file does not exist — new implementation required) |
| BOT-001 dependency (chat_bot.py) | `app/services/chat_bot.py` | N/A | NOT YET IMPLEMENTED (depends on BOT-001) |
