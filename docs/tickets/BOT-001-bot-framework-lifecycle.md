# BOT-001: Bot Framework & Lifecycle

**Ticket**: BOT-001
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: High
**Estimated effort**: 10-12 days
**Dependencies**: None (uses existing messaging infrastructure)

---

## 1. Overview & Motivation

### 1.1 Purpose

BOT-001 establishes the foundational bot framework for the platform. Creators can define chat bots that operate within their messaging ecosystem -- DMs, group chats, and broadcast chat. Each bot has its own identity (name, avatar, description) and sends messages that display the bot's branding rather than the creator's personal identity. Bots are scoped to the creator's account: they share the creator's billing context and permissions but appear as distinct entities in conversations. The framework supports multiple bots per creator (e.g., a sales bot, a support bot, a broadcast greeter), each with independent activation state and assignment rules.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Creator | As a creator, I want to create a bot with a name, avatar, and description. | POST creates bot; bot appears in bot management list. |
| Creator | As a creator, I want to manage multiple bots for different purposes. | Creator can have up to 10 bots; each independently configurable. |
| Creator | As a creator, I want to assign a bot to specific conversations. | Bot assignment links bot to one or more conversations. |
| Creator | As a creator, I want to assign a bot to all DMs automatically. | Wildcard assignment `ALL_DMS` activates bot for every DM. |
| Creator | As a creator, I want to pause a bot without deleting it. | Bot state transitions: active -> paused -> active; paused bots ignore triggers. |
| Creator | As a creator, I want to disable a bot permanently. | Disabled state; bot stops responding; assignments preserved for re-enable. |
| Creator | As a creator, I want to configure what triggers my bot. | Trigger config: keyword match, first message, @mention, all messages, scheduled. |
| User | As a user, I want to know when I am talking to a bot. | Bot messages show bot name/avatar and a "Bot" badge in the UI. |
| User | As a user, I want bot messages to appear inline in the conversation. | Bot messages use existing message infrastructure with `sender_type=bot`. |

### 1.3 Why This Is Needed

Creators who receive hundreds of DMs daily cannot respond to every message personally. Bots automate common interactions -- greeting new fans, answering FAQs, promoting content, and handling scheduling. Without a bot framework, creators either ignore messages (reducing engagement) or spend hours on repetitive replies. The bot framework is also the foundation for BOT-002 (templates), BOT-003 (content promotion), and BOT-004 (AI chat).

---

## 2. Current State Analysis

### 2.1 Existing Infrastructure

- **Messaging** (`app/routers/messaging.py`): `send_text_message()` (line ~7684) creates message items in the Messages table with `sender_id`, `kind`, `text`. `_message_out_from_item()` (line ~3766) maps DDB items to `MessageOut`. The `MessageOut` model has `sender_id`, `kind`, and extensible fields.
- **Conversations** (`app/routers/messaging.py`): `ConversationOut` (line ~1729) includes participant list, conversation type (`dm`, `group`), and metadata.
- **Broadcast chat** (`app/services/broadcast_chat_store.py`): `send_chat_message()` writes messages to the broadcast chat table with `sender_id`, `sender_display_name`, `sender_badge`.
- **Message kinds**: `MessageOut.kind` already supports many kinds (`text`, `image`, `file`, `calendar_share`, etc.) via a `Literal` union.
- **Profiles** (`app/services/`): User profiles stored in `profiles` table with `user_sub` PK.
- **SSE events** (`app/routers/messaging.py`): Real-time message delivery via SSE stream; bot messages can use the same channel.

### 2.2 Gaps

1. No bot entity model or storage -- no way to define a bot with its own identity.
2. No `sender_type` field on messages to distinguish bot messages from human messages.
3. No bot-to-conversation assignment mechanism.
4. No trigger configuration system to determine when a bot should respond.
5. No bot management UI for creators.
6. No "Bot" badge rendering in the frontend message bubble.
7. No bot-scoped rate limiting or activation state machine.

---

## 3. Technical Design

### 3.1 Data Model

#### 3.1.1 ChatBots Table

Stores bot definitions. Each bot belongs to a single creator.

| Field | Type | Description |
|-------|------|-------------|
| `pk` | S | `CREATOR#{creator_id}` |
| `sk` | S | `BOT#{bot_id}` |
| `bot_id` | S | UUID hex |
| `creator_id` | S | Owner user_sub |
| `name` | S | Display name (max 50 chars) |
| `avatar_url` | S (optional) | S3 URL for bot avatar |
| `description` | S (optional) | Bot description (max 500 chars) |
| `personality` | S (optional) | Personality/tone setting: `friendly`, `professional`, `casual`, `custom` |
| `custom_personality` | S (optional) | Free-text personality instructions when `personality=custom` |
| `status` | S | `active`, `paused`, `disabled` |
| `trigger_config` | M (map) | Trigger rules (see 3.1.3) |
| `created_at` | N | Unix timestamp |
| `updated_at` | N | Unix timestamp |
| `message_count` | N | Total messages sent by this bot |
| `GSI1PK` | S | `BOT#{bot_id}` (for lookup by bot_id) |
| `GSI1SK` | S | `META` |

**GSI1** (`GSI1PK`, `GSI1SK`): Lookup a bot by its `bot_id` without knowing the creator. Used when processing incoming messages to resolve bot identity.

**DDB init** (`scripts/local-ddb-init.py`):

```python
TableDef(
    "chat_bots", "pk", "sk",
    gsi=[
        {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
    ],
    attr_types={"created_at": "N", "updated_at": "N"},
),
```

#### 3.1.2 BotAssignments Table

Maps bots to conversations or broadcast sessions. A bot can be assigned to specific conversations or to wildcard scopes.

| Field | Type | Description |
|-------|------|-------------|
| `pk` | S | `BOT#{bot_id}` |
| `sk` | S | `CONV#{conversation_id}` or `BCAST#{session_id}` or `SCOPE#ALL_DMS` or `SCOPE#ALL_GROUPS` or `SCOPE#ALL_BROADCASTS` |
| `bot_id` | S | Bot UUID |
| `creator_id` | S | Bot owner |
| `target_type` | S | `conversation`, `broadcast`, `all_dms`, `all_groups`, `all_broadcasts` |
| `target_id` | S (optional) | Specific conversation_id or session_id (null for wildcard scopes) |
| `created_at` | N | Unix timestamp |
| `GSI1PK` | S | `CONV#{conversation_id}` or `BCAST#{session_id}` (for "which bots are assigned to this conversation?") |
| `GSI1SK` | S | `BOT#{bot_id}` |

**GSI1** (`GSI1PK`, `GSI1SK`): Given a conversation or broadcast, find all bots assigned to it.

```python
TableDef(
    "bot_assignments", "pk", "sk",
    gsi=[
        {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
    ],
    attr_types={"created_at": "N"},
),
```

#### 3.1.3 Trigger Configuration

Stored as a DynamoDB map on the bot record:

```json
{
  "triggers": [
    {"type": "keyword", "keywords": ["price", "cost", "how much"], "response_template_id": "tpl_abc"},
    {"type": "first_message", "response_template_id": "tpl_welcome"},
    {"type": "mention", "response_template_id": "tpl_mention"},
    {"type": "all_messages"},
    {"type": "idle", "idle_minutes": 5, "response_template_id": "tpl_idle"},
    {"type": "scheduled", "cron": "0 14 * * *", "response_template_id": "tpl_daily"}
  ],
  "priority_order": ["keyword", "mention", "first_message", "idle", "all_messages"]
}
```

Trigger types:
- `keyword` -- respond when any keyword appears in incoming message text (case-insensitive substring match)
- `first_message` -- respond when a user sends their first-ever message in the conversation
- `mention` -- respond when the bot is @mentioned by name
- `all_messages` -- respond to every incoming message (used for AI bots in BOT-004)
- `idle` -- respond when conversation has been idle for N minutes
- `scheduled` -- send a message on a cron schedule (no incoming message needed)

### 3.2 MessageOut Extension

Add optional bot identity fields to the existing `MessageOut` model:

```python
# In MessageOut (app/routers/messaging.py)
sender_type: Literal["user", "bot", "system"] = "user"
bot_id: Optional[str] = None
bot_name: Optional[str] = None
bot_avatar_url: Optional[str] = None
```

`_message_out_from_item()` populates these fields from the stored message item. Frontend renders the bot name/avatar instead of the user's profile when `sender_type == "bot"`.

### 3.3 Backend Service (`app/services/chat_bot.py`)

```python
def create_bot(*, creator_id: str, name: str, avatar_url: str | None = None,
               description: str | None = None, personality: str = "friendly",
               custom_personality: str | None = None) -> dict:
    """Create a new bot for a creator. Max 10 bots per creator."""
    # 1. Count existing bots for creator (query PK=CREATOR#{creator_id})
    # 2. Enforce limit of 10
    # 3. Generate bot_id = uuid4().hex
    # 4. Write to ChatBots table
    # 5. Return bot dict

def get_bot(*, bot_id: str) -> dict | None:
    """Fetch bot by bot_id via GSI1."""

def list_bots(*, creator_id: str) -> list[dict]:
    """List all bots for a creator."""

def update_bot(*, creator_id: str, bot_id: str, **fields) -> dict:
    """Update bot name, avatar, description, personality, trigger_config."""
    # Verify ownership; apply updates

def update_bot_status(*, creator_id: str, bot_id: str, status: str) -> dict:
    """Transition bot status: active <-> paused <-> disabled."""
    # Validate state transitions; update status + updated_at

def delete_bot(*, creator_id: str, bot_id: str) -> dict:
    """Delete a bot and all its assignments."""
    # 1. Delete all BotAssignments for this bot (query PK=BOT#{bot_id})
    # 2. Delete the bot record

def assign_bot(*, bot_id: str, creator_id: str, target_type: str,
               target_id: str | None = None) -> dict:
    """Assign bot to a conversation, broadcast, or wildcard scope."""
    # Verify bot ownership
    # Build sk based on target_type
    # Write to BotAssignments

def unassign_bot(*, bot_id: str, creator_id: str, target_type: str,
                 target_id: str | None = None) -> dict:
    """Remove bot assignment."""

def list_assignments(*, bot_id: str, creator_id: str) -> list[dict]:
    """List all assignments for a bot."""

def get_bots_for_conversation(*, conversation_id: str) -> list[dict]:
    """Find all bots assigned to a conversation (direct + wildcard).
    Used by the message processing pipeline."""
    # 1. Query GSI1 for CONV#{conversation_id}
    # 2. Also check for wildcard scopes matching conversation type
    # 3. Return list of active bot records

def send_bot_message(*, bot_id: str, conversation_id: str, text: str,
                     kind: str = "text", extra_fields: dict | None = None) -> dict:
    """Send a message as a bot. Uses existing send_text_message infrastructure
    with sender_type=bot and bot identity fields."""
    # 1. Fetch bot record
    # 2. Verify bot is active
    # 3. Call send_text_message with additional fields:
    #    sender_type="bot", bot_id, bot_name, bot_avatar_url
    # 4. Increment bot message_count
    # 5. Return message dict

def evaluate_triggers(*, bot: dict, conversation_id: str,
                       incoming_message: dict | None = None,
                       event_type: str = "message") -> str | None:
    """Evaluate trigger rules against incoming message or event.
    Returns template_id to use, or None if no trigger matched."""
    # Walk priority_order; check each trigger
    # For keyword: substring match in message text
    # For first_message: check if sender has previous messages in conversation
    # For mention: check if bot name appears in message text prefixed by @
    # Return first matching template_id
```

### 3.4 Backend Router (`app/routers/chat_bot.py`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/ui/bots` | `require_ui_session` | Create a new bot |
| GET | `/ui/bots` | `require_ui_session` | List creator's bots |
| GET | `/ui/bots/{bot_id}` | `require_ui_session` | Get bot details |
| PUT | `/ui/bots/{bot_id}` | `require_ui_session` | Update bot config |
| PATCH | `/ui/bots/{bot_id}/status` | `require_ui_session` | Change bot status (active/paused/disabled) |
| DELETE | `/ui/bots/{bot_id}` | `require_ui_session` | Delete bot and assignments |
| POST | `/ui/bots/{bot_id}/assignments` | `require_ui_session` | Assign bot to target |
| DELETE | `/ui/bots/{bot_id}/assignments/{assignment_sk}` | `require_ui_session` | Remove assignment |
| GET | `/ui/bots/{bot_id}/assignments` | `require_ui_session` | List bot assignments |
| POST | `/ui/bots/{bot_id}/avatar/presign` | `require_ui_session` | Presign S3 upload for bot avatar |
| GET | `/ui/bots/{bot_id}/stats` | `require_ui_session` | Bot message count + last active |

**Request models** (`app/routers/chat_bot.py`):

```python
class CreateBotIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=50)
    avatar_url: Optional[str] = None
    description: Optional[str] = Field(default=None, max_length=500)
    personality: Literal["friendly", "professional", "casual", "custom"] = "friendly"
    custom_personality: Optional[str] = Field(default=None, max_length=2000)

class UpdateBotIn(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=50)
    avatar_url: Optional[str] = None
    description: Optional[str] = Field(default=None, max_length=500)
    personality: Optional[Literal["friendly", "professional", "casual", "custom"]] = None
    custom_personality: Optional[str] = Field(default=None, max_length=2000)
    trigger_config: Optional[Dict[str, Any]] = None

class UpdateBotStatusIn(BaseModel):
    status: Literal["active", "paused", "disabled"]

class AssignBotIn(BaseModel):
    target_type: Literal["conversation", "broadcast", "all_dms", "all_groups", "all_broadcasts"]
    target_id: Optional[str] = None  # Required for conversation/broadcast

class BotOut(BaseModel):
    bot_id: str
    creator_id: str
    name: str
    avatar_url: Optional[str] = None
    description: Optional[str] = None
    personality: str
    custom_personality: Optional[str] = None
    status: str
    trigger_config: Optional[Dict[str, Any]] = None
    created_at: int
    updated_at: int
    message_count: int = 0

class BotAssignmentOut(BaseModel):
    bot_id: str
    target_type: str
    target_id: Optional[str] = None
    created_at: int
```

Register in `app/main.py`:

```python
from app.routers.chat_bot import router as chat_bot_router
app.include_router(chat_bot_router, prefix="/ui")
```

### 3.5 Frontend Types (`frontend/src/api/types.ts`)

```typescript
export interface ChatBot {
  bot_id: string;
  creator_id: string;
  name: string;
  avatar_url?: string;
  description?: string;
  personality: "friendly" | "professional" | "casual" | "custom";
  custom_personality?: string;
  status: "active" | "paused" | "disabled";
  trigger_config?: BotTriggerConfig;
  created_at: number;
  updated_at: number;
  message_count: number;
}

export interface BotTriggerConfig {
  triggers: BotTrigger[];
  priority_order: string[];
}

export interface BotTrigger {
  type: "keyword" | "first_message" | "mention" | "all_messages" | "idle" | "scheduled";
  keywords?: string[];
  response_template_id?: string;
  idle_minutes?: number;
  cron?: string;
}

export interface BotAssignment {
  bot_id: string;
  target_type: "conversation" | "broadcast" | "all_dms" | "all_groups" | "all_broadcasts";
  target_id?: string;
  created_at: number;
}

// Extend MessageOut
export interface MessageOut {
  // ... existing fields ...
  sender_type?: "user" | "bot" | "system";
  bot_id?: string;
  bot_name?: string;
  bot_avatar_url?: string;
}
```

### 3.6 Frontend API (`frontend/src/api/endpoints/bots.ts`)

```typescript
export const createBot = (data: {
  name: string; avatar_url?: string; description?: string;
  personality?: string; custom_personality?: string;
}) => api.post<ChatBot>("/ui/bots", data);

export const listBots = () => api.get<{ bots: ChatBot[] }>("/ui/bots");

export const getBot = (botId: string) => api.get<ChatBot>(`/ui/bots/${botId}`);

export const updateBot = (botId: string, data: Partial<ChatBot>) =>
  api.put<ChatBot>(`/ui/bots/${botId}`, data);

export const updateBotStatus = (botId: string, status: string) =>
  api.patch<ChatBot>(`/ui/bots/${botId}/status`, { status });

export const deleteBot = (botId: string) => api.delete(`/ui/bots/${botId}`);

export const assignBot = (botId: string, data: {
  target_type: string; target_id?: string;
}) => api.post<BotAssignment>(`/ui/bots/${botId}/assignments`, data);

export const unassignBot = (botId: string, assignmentSk: string) =>
  api.delete(`/ui/bots/${botId}/assignments/${assignmentSk}`);

export const listAssignments = (botId: string) =>
  api.get<{ assignments: BotAssignment[] }>(`/ui/bots/${botId}/assignments`);

export const getBotStats = (botId: string) =>
  api.get<{ message_count: number; last_active_at?: number }>(`/ui/bots/${botId}/stats`);
```

### 3.7 Frontend Pages

- **BotManagerPage** (`frontend/src/pages/bots/BotManagerPage.tsx`): Route `/bots`. Lists all bots for the current user with status badges (green=active, yellow=paused, gray=disabled). Cards show bot name, avatar, description, message count. Actions: create, edit, pause/resume, delete. `data-testid="bot-manager-page"`.
- **BotEditorDialog** (`frontend/src/pages/bots/BotEditorDialog.tsx`): Dialog for creating/editing a bot. Fields: name, avatar upload, description, personality dropdown, custom personality textarea. Trigger configuration section with add/remove trigger rows. `data-testid="bot-editor-dialog"`.
- **BotAssignmentsDialog** (`frontend/src/pages/bots/BotAssignmentsDialog.tsx`): Dialog for managing bot assignments. Shows current assignments; add new: pick conversation from list, or select wildcard scope. `data-testid="bot-assignments-dialog"`.

### 3.8 MessageBubble Enhancement (`frontend/src/pages/messages/MessageBubble.tsx`)

When `message.sender_type === "bot"`:
- Display bot avatar (or fallback icon) instead of user avatar
- Show bot name with a `<Badge variant="outline">Bot</Badge>` next to it
- Use a slightly different background tint (e.g., `bg-muted/50`) to visually distinguish bot messages

### 3.9 Sidebar & Navigation

- Add "Bots" link in Sidebar (`frontend/src/components/layout/Sidebar.tsx`) under the Productivity group with `Bot` icon from lucide-react.
- Add route `/bots` to `App.tsx` (lazy-loaded `BotManagerPage`).
- Add "Bots" to `MORE_LINKS` in `MobileNav.tsx`.

---

## 4. Implementation Plan

### 4.1 Files to Create

| File | Purpose |
|------|---------|
| `app/services/chat_bot.py` | Bot CRUD, assignment management, trigger evaluation |
| `app/routers/chat_bot.py` | Bot management endpoints |
| `frontend/src/pages/bots/BotManagerPage.tsx` | Bot list + management UI |
| `frontend/src/pages/bots/BotEditorDialog.tsx` | Bot create/edit dialog |
| `frontend/src/pages/bots/BotAssignmentsDialog.tsx` | Assignment management dialog |
| `frontend/src/api/endpoints/bots.ts` | API client functions |

### 4.2 Files to Modify

| File | Changes |
|------|---------|
| `scripts/local-ddb-init.py` | Add `chat_bots` and `bot_assignments` TableDefs |
| `app/core/settings.py` | Add `chat_bots_table_name`, `bot_assignments_table_name` |
| `app/core/tables.py` | Add `chat_bots`, `bot_assignments` table handles |
| `app/main.py` | Register `chat_bot_router` |
| `app/routers/messaging.py` | Add `sender_type`, `bot_id`, `bot_name`, `bot_avatar_url` to `MessageOut`; populate in `_message_out_from_item()` |
| `frontend/src/api/types.ts` | Add `ChatBot`, `BotAssignment`, `BotTriggerConfig` types; extend `MessageOut` |
| `frontend/src/pages/messages/MessageBubble.tsx` | Render bot badge and avatar for bot messages |
| `frontend/src/components/layout/Sidebar.tsx` | Add "Bots" nav link |
| `frontend/src/components/layout/AppShell.tsx` | Add "Bots" to mobile sidebar |
| `frontend/src/pages/messages/MobileNav.tsx` | Add "Bots" to MORE_LINKS |
| `frontend/src/App.tsx` | Add `/bots` route |

---

## 5. E2E Test Plan

### 5.1 Test File

`frontend/e2e/chat-bots.spec.ts` -- 16 tests across 4 sections.

### 5.2 Test Setup

```typescript
const TS = Date.now();
let botId: string;
let secondBotId: string;
let conversationId: string;
// Alice = creator, Bob = user who messages Alice
```

### 5.3 Section 507: Bot CRUD API (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 507.1 | Creator creates a bot | POST `/ui/bots` with name, description, personality; 201; `bot_id`, `status=active`, `name` matches |
| 507.2 | Creator lists bots | GET `/ui/bots`; array includes created bot |
| 507.3 | Creator updates bot name and personality | PUT `/ui/bots/{bot_id}` with new name + `personality=professional`; 200; fields updated |
| 507.4 | Creator creates a second bot | POST; 201; different `bot_id` |
| 507.5 | Creator deletes second bot | DELETE `/ui/bots/{bot_id}`; 200; GET returns 404 |

### 5.4 Section 508: Bot Status Lifecycle (3 tests)

| # | Test | Assertion |
|---|------|-----------|
| 508.1 | Pause a bot | PATCH `/ui/bots/{bot_id}/status` with `status=paused`; 200; `status=paused` |
| 508.2 | Resume a paused bot | PATCH with `status=active`; 200; `status=active` |
| 508.3 | Disable a bot | PATCH with `status=disabled`; 200; `status=disabled` |

### 5.5 Section 509: Bot Assignment API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 509.1 | Assign bot to a conversation | POST `/ui/bots/{bot_id}/assignments` with `target_type=conversation`, `target_id=conversationId`; 201 |
| 509.2 | Assign bot to all DMs | POST with `target_type=all_dms`; 201 |
| 509.3 | List bot assignments | GET `/ui/bots/{bot_id}/assignments`; array length >= 2 |
| 509.4 | Remove conversation assignment | DELETE assignment; 200; list length decremented |

### 5.6 Section 510: Bot Manager UI (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 510.1 | Bot Manager page loads | Navigate `/bots`; `[data-testid="bot-manager-page"]` visible; bot card displayed |
| 510.2 | Create bot via dialog | Click "New Bot"; fill name + description; save; new card appears |
| 510.3 | Pause bot via UI | Click pause button on bot card; status badge changes to "Paused" |
| 510.4 | Bot badge appears on messages | Send a bot message (via API); navigate to conversation; "Bot" badge visible next to bot name |

---

## 6. Error Handling

| Scenario | Status | Detail |
|----------|--------|--------|
| Bot not found | 404 | "Bot not found" |
| Not bot owner | 403 | "You do not own this bot" |
| Max bots exceeded | 409 | "Maximum of 10 bots per creator" |
| Invalid status transition | 400 | "Cannot transition from {current} to {target}" |
| Assignment target not found | 404 | "Conversation not found" |
| Duplicate assignment | 409 | "Bot is already assigned to this target" |
| Bot paused/disabled (send attempt) | 409 | "Bot is not active" |
| Missing target_id for conversation type | 422 | "target_id is required for conversation assignments" |

---

## 7. Security Considerations

- **Ownership enforcement**: All bot operations verify `creator_id` matches the authenticated user. A user cannot manage another creator's bots.
- **Bot impersonation prevention**: `sender_type=bot` is set server-side only; clients cannot forge bot identity. The frontend does not accept `sender_type` in send requests.
- **Bot message attribution**: Every bot message stores both `bot_id` (bot identity) and `sender_id` (creator's user_sub) so moderation can trace bot messages back to their owner.
- **Assignment scope validation**: Bot can only be assigned to conversations where the creator is a participant. Wildcard scopes only apply to conversations the creator is part of.
- **Rate limiting**: Bot messages are rate-limited separately from human messages (max 60 bot messages per conversation per hour) to prevent spam.
- **Avatar upload**: Bot avatar presigned uploads use the same S3 upload validation as user avatars (content-type whitelist, max file size).

---

## 8. Performance Considerations

| Concern | Mitigation |
|---------|-----------|
| Bot lookup on every incoming message | Cache active bot assignments in-memory with 60s TTL; invalidate on assignment change |
| Multiple bots per conversation | Limit 3 active bots per conversation; evaluate triggers in priority order, stop at first match |
| Bot message flood | Per-bot, per-conversation rate limit: 60 messages/hour; 10 messages/minute burst |
| Wildcard assignment expansion | Wildcard assignments evaluated at trigger time (not pre-expanded); no fan-out write amplification |
| Bot record size | Trigger config stored as DDB map; max 20 triggers per bot enforced in validation |

---

## 9. Dependencies

| Dependency | Ticket | Status |
|------------|--------|--------|
| Messaging infrastructure | Existing | Available (`send_text_message`, `MessageOut`, SSE) |
| Broadcast chat | Existing | Available (`send_chat_message`) |
| S3 upload (avatars) | Existing | Available (presign pattern) |

### Downstream

| Ticket | Depends On |
|--------|-----------|
| BOT-002 (Templates) | Bot framework for template storage and trigger evaluation |
| BOT-003 (Content Promotion) | Bot framework for content delivery and scheduling |
| BOT-004 (AI Chat) | Bot framework for AI bot configuration and message routing |
