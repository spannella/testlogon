# BOT-002: Template & Scheduled Messages

**Ticket**: BOT-002
**Author**: Engineering
**Status**: Design
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
- **Messaging** (`app/routers/messaging.py`): `send_text_message()` handles text messages. `MessageOut` supports arbitrary `kind` values via Literal union. Scheduled message support exists (`send_at` field, background dispatch loop at 30s intervals).
- **Broadcast chat** (`app/services/broadcast_chat_store.py`): `send_chat_message()` supports text + product link messages. No template support.
- **Newsfeed scheduler** (`app/services/newsfeed_scheduler.py`): Background task pattern for scheduled content. Bot scheduler follows the same pattern.
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

```python
VARIABLE_PATTERN = re.compile(r"\{(\w+)\}")

def resolve_variables(template_text: str, *, context: dict[str, str]) -> str:
    """Replace {variable_name} placeholders with values from context.
    Unknown variables are left as-is (not replaced)."""
    def replacer(match: re.Match) -> str:
        key = match.group(1)
        return context.get(key, match.group(0))
    return VARIABLE_PATTERN.sub(replacer, template_text)

def build_variable_context(*, sender_id: str, creator_id: str,
                            bot: dict, conversation_id: str,
                            timezone: str = "UTC") -> dict[str, str]:
    """Build context dict by fetching data from various tables."""
    # Lazy-load: only fetch data for variables actually used in the template
```

### 3.3 Quick Replies

Quick-reply buttons are delivered as a special field on bot messages. When a user taps a quick-reply, the frontend sends the button's `value` as a regular text message.

**Message extension**:

```python
# In MessageOut (app/routers/messaging.py)
quick_replies: Optional[List[Dict[str, str]]] = None
# Each dict: {"label": "Yes, I'm interested", "value": "interested"}
```

**Frontend rendering** (`MessageBubble.tsx`):

```tsx
{message.quick_replies && (
  <div className="flex flex-wrap gap-2 mt-2">
    {message.quick_replies.map((qr, i) => (
      <Button key={i} variant="outline" size="sm"
              onClick={() => sendMessage(qr.value)}
              data-testid={`quick-reply-${i}`}>
        {qr.label}
      </Button>
    ))}
  </div>
)}
```

Quick-reply buttons are only interactive for the message recipient (not the sender/bot). After tapping, the buttons are disabled to prevent duplicate sends.

### 3.4 A/B Testing

When multiple templates share the same `ab_group` value and are linked to the same trigger, the bot selects one randomly using weighted probability:

```python
def select_ab_template(templates: list[dict]) -> dict:
    """Weighted random selection from A/B group."""
    weights = [int(t.get("ab_weight", 1)) for t in templates]
    total = sum(weights)
    r = random.randint(1, total)
    cumulative = 0
    for t, w in zip(templates, weights):
        cumulative += w
        if r <= cumulative:
            return t
    return templates[-1]  # fallback
```

Impression and response counts are tracked per template to calculate conversion rates in the creator's bot analytics.

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
| `scripts/local-ddb-init.py` | Add `bot_templates` and `bot_scheduled_sends` TableDefs |
| `app/core/settings.py` | Add `bot_templates_table_name`, `bot_scheduled_sends_table_name` |
| `app/core/tables.py` | Add table handles |
| `app/main.py` | Register `bot_template_router`; start bot scheduler task on startup |
| `app/routers/messaging.py` | Add `quick_replies` field to `MessageOut` |
| `app/services/chat_bot.py` | Wire `evaluate_triggers()` to template resolution + rendering |
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
