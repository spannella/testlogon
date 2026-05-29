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

- **Messaging** (`app/routers/messaging.py`): `send_text_message()` (see `app/routers/messaging.py:7684`) creates message items in the Messages table with `sender_id`, `kind`, `text`. `_message_out_from_item()` (see `app/routers/messaging.py:3766`) maps DDB items to `MessageOut`. The `MessageOut` model (see `app/routers/messaging.py:2325`) has `sender_id`, `kind`, and extensible fields.
- **Conversations** (`app/routers/messaging.py`): `ConversationOut` (see `app/routers/messaging.py:1729`) includes participant list, conversation type (`dm`, `group`), and metadata.
- **Broadcast chat** (`app/services/broadcast_chat_store.py`): `send_chat_message()` (see `app/services/broadcast_chat_store.py:136`) writes messages to the broadcast chat table with `sender_id`, `sender_display_name`, `sender_badge`.
- **Message kinds**: `MessageOut.kind` (see `app/routers/messaging.py:2330`) already supports many kinds (`text`, `image`, `file`, `calendar_share`, etc.) via a `Literal` union.
- **Profiles** (`app/services/`): User profiles stored in `profiles` table with `user_sub` PK.
- **SSE events** (`app/routers/messaging.py`): Real-time message delivery via SSE stream; bot messages can use the same channel.

### 2.2 Gaps

1. No bot entity model or storage -- no way to define a bot with its own identity.
2. No `sender_type` field on messages to distinguish bot messages from human messages. <!-- NOTE: Confirmed — MessageOut at messaging.py:2325 has no sender_type, bot_id, bot_name, or bot_avatar_url fields. These are new additions required. -->
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

**Key request models**:

```python
class CreateBotIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=50)
    avatar_url: Optional[str] = None
    description: Optional[str] = Field(default=None, max_length=500)
    personality: Literal["friendly", "professional", "casual", "custom"] = "friendly"
    custom_personality: Optional[str] = Field(default=None, max_length=2000)

class UpdateBotStatusIn(BaseModel):
    status: Literal["active", "paused", "disabled"]

class AssignBotIn(BaseModel):
    target_type: Literal["conversation", "broadcast", "all_dms", "all_groups", "all_broadcasts"]
    target_id: Optional[str] = None  # Required for conversation/broadcast
```

Additional models: `UpdateBotIn` (all fields optional + `trigger_config`). Response models: `BotOut` (mirrors DDB record fields), `BotAssignmentOut` (bot_id, target_type, target_id, created_at).

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
| `scripts/local-ddb-init.py` | Add `chat_bots` and `bot_assignments` TableDefs <!-- NOTE: Neither table exists yet in local-ddb-init.py — new implementation required --> |
| `app/core/settings.py` | Add `chat_bots_table_name`, `bot_assignments_table_name` <!-- NOTE: Neither setting exists yet — new implementation required --> |
| `app/core/tables.py` | Add `chat_bots`, `bot_assignments` table handles <!-- NOTE: Neither table handle exists yet — new implementation required --> |
| `app/main.py` | Register `chat_bot_router` <!-- NOTE: No bot router registered yet in main.py — new implementation required --> |
| `app/routers/messaging.py` | Add `sender_type`, `bot_id`, `bot_name`, `bot_avatar_url` to `MessageOut`; populate in `_message_out_from_item()` |
| `frontend/src/api/types.ts` | Add `ChatBot`, `BotAssignment`, `BotTriggerConfig` types; extend `MessageOut` |
| `frontend/src/pages/messages/MessageBubble.tsx` | Render bot badge and avatar for bot messages |
| `frontend/src/components/layout/Sidebar.tsx` | Add "Bots" nav link |
| `frontend/src/components/layout/AppShell.tsx` | Add "Bots" to mobile sidebar |
| `frontend/src/components/layout/MobileNav.tsx` | Add "Bots" to MORE_LINKS (see `MobileNav.tsx:64` for `MORE_LINKS` array) |
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

---

## 10. Architecture & Data Flow

```
                    Bot Framework Overview
  ┌───────────────┐     ┌────────────────────┐     ┌──────────────┐
  │ Creator Config │────>│ POST /ui/bots      │────>│  DynamoDB     │
  │ UI (BotPage)   │     │ (bot_router.py)    │     │  bots table   │
  │                │     │                    │     │               │
  │ name, avatar,  │     │ create_bot()       │     │ PK=BOT#id    │
  │ trigger_config,│     │ validate_config()  │     │ SK=META       │
  │ assignment     │     │ store to DDB       │     │               │
  └───────────────┘     └────────────────────┘     └──────────────┘

                    Bot Trigger Evaluation Flow
  ┌───────────────┐     ┌────────────────────┐     ┌──────────────┐
  │ Incoming Event │────>│ Trigger Evaluator  │────>│ Match?        │
  │                │     │                    │     │               │
  │ message_sent   │     │ For each bot:      │     │ Yes → execute │
  │ user_joined    │     │  evaluate triggers │     │   bot action  │
  │ subscription   │     │  against event     │     │               │
  │ _created       │     │  context           │     │ No → skip     │
  │ schedule_tick  │     │                    │     │               │
  └───────────────┘     └────────────────────┘     └──────────────┘
                                │
                                v
  ┌───────────────┐     ┌────────────────────┐     ┌──────────────┐
  │ Bot Action     │────>│ Action Executor    │────>│ Messaging     │
  │ send_message   │     │                    │     │ send_text_msg │
  │ send_template  │     │ Render template    │     │               │
  │ ai_respond     │     │ Resolve variables  │     │ SSE events    │
  │ api_webhook    │     │ Execute action     │     │ to recipients │
  └───────────────┘     └────────────────────┘     └──────────────┘
```

---

## 11. Observability

### 11.1 Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `bot_created_total` | Counter | `creator_id` | Number of bots created |
| `bot_trigger_evaluated_total` | Counter | `bot_id`, `trigger_type` | Trigger evaluations performed |
| `bot_trigger_matched_total` | Counter | `bot_id`, `trigger_type` | Triggers that matched and fired |
| `bot_action_executed_total` | Counter | `bot_id`, `action_type`, `status` | Actions executed (success/fail) |
| `bot_action_latency_ms` | Histogram | `bot_id`, `action_type` | Time to execute a bot action |
| `bot_status_transitions_total` | Counter | `from_status`, `to_status` | Bot status changes |
| `bot_assignment_count` | Gauge | `bot_id` | Number of active assignments per bot |

### 11.2 Logging

| Event | Level | Fields |
|-------|-------|--------|
| Bot created | INFO | `bot_id`, `creator_id`, `name`, `trigger_count` |
| Bot status changed | INFO | `bot_id`, `from_status`, `to_status`, `reason` |
| Trigger evaluated (matched) | DEBUG | `bot_id`, `trigger_type`, `event_type`, `context` |
| Trigger evaluated (no match) | DEBUG | `bot_id`, `trigger_type`, `event_type` |
| Action executed | INFO | `bot_id`, `action_type`, `target_conversation`, `duration_ms` |
| Action failed | ERROR | `bot_id`, `action_type`, `error`, `target_conversation` |
| Bot assigned to conversation | INFO | `bot_id`, `conversation_id`, `assigned_by` |
| Bot unassigned from conversation | INFO | `bot_id`, `conversation_id`, `reason` |

### 11.3 Alerts

| Alert | Condition | Severity |
|-------|-----------|----------|
| Bot action failure rate high | > 10% failures for any bot in 1 hour | High |
| Trigger evaluation backlog | > 500 pending evaluations | Medium |
| Bot stuck in "starting" state | > 5 minutes in starting state | Medium |
| Excessive bot assignments | > 1000 active assignments for one bot | Low |

---

## 12. Rollout Plan

### 12.1 Feature Flag

```python
# app/core/settings.py
bot_framework_enabled: bool = os.environ.get("BOT_FRAMEWORK_ENABLED", "true").lower() == "true"
```

### 12.2 Phased Rollout

| Phase | Description | Duration | Criteria |
|-------|-------------|----------|----------|
| Phase 1: CRUD only | Bot creation, config, assignment without trigger execution | 2 days | Unit tests pass; UI functional |
| Phase 2: Manual triggers | Trigger evaluation on manual API call (no auto-fire) | 2 days | Triggers evaluate correctly |
| Phase 3: Auto triggers | Background trigger evaluation on real events | 2 days | E2E tests pass; no excessive firing |
| Phase 4: GA | Full bot lifecycle with all trigger types | Permanent | All tests pass; monitoring clean |

---

## 13. Performance Considerations

| Concern | Target | Mitigation |
|---------|--------|-----------|
| Trigger evaluation per event | < 50ms | Cache active bot configs; evaluate in-memory |
| Bot CRUD operations | < 100ms p95 | Single DDB put/get; no joins |
| Listing bots for creator | < 100ms | GSI query on creator_id; paginated |
| Assignment scan | < 200ms | GSI query on bot_id for assigned conversations |
| Concurrent trigger fires | Handle 50+ events/sec | Async evaluation; rate limit per bot to 10 fires/sec |
| Bot config cache TTL | 60 seconds | In-process cache; invalidated on config update |

---

## 14. Error Handling Matrix

| Scenario | HTTP Status | Error Code | Error Message | Recovery Action |
|----------|-------------|------------|---------------|-----------------|
| Bot not found | 404 | `bot_not_found` | "Bot not found" | Redirect to bot list |
| Bot name already exists | 409 | `name_conflict` | "A bot with this name already exists" | Suggest alternative name |
| Invalid trigger config | 422 | `invalid_trigger` | "Invalid trigger configuration" | Show inline form errors |
| Max bots per creator exceeded | 400 | `bot_limit` | "Maximum 20 bots per creator" | Show limit reached |
| Assignment to non-existent conversation | 404 | `conversation_not_found` | "Conversation not found" | Show error; refresh list |
| Bot already assigned to conversation | 409 | `already_assigned` | "Bot is already assigned to this conversation" | No-op; show info toast |
| Trigger evaluation error | 500 (internal) | `trigger_error` | Logged internally | Skip trigger; continue with others |
| Action execution timeout | 504 | `action_timeout` | "Bot action timed out" | Retry once; log failure |

---

## 15. API Request/Response Examples

**Create a bot**:

```
POST /ui/bots
Content-Type: application/json
x-csrf-token: <csrf>

{
  "name": "Welcome Bot",
  "description": "Sends welcome messages to new subscribers",
  "avatar_url": "/mock/s3/avatars/welcome-bot.png",
  "triggers": [
    {
      "type": "subscription_created",
      "conditions": {"plan_type": "any"}
    }
  ],
  "actions": [
    {
      "type": "send_template",
      "template_id": "tpl_welcome_001"
    }
  ]
}
```

**Response (201)**:
```json
{
  "bot_id": "bot_abc123",
  "name": "Welcome Bot",
  "description": "Sends welcome messages to new subscribers",
  "status": "active",
  "trigger_count": 1,
  "action_count": 1,
  "assignment_count": 0,
  "created_at": 1748520100,
  "creator_id": "alice@test.local"
}
```

**Assign bot to conversation**:

```
POST /ui/bots/bot_abc123/assignments
Content-Type: application/json
x-csrf-token: <csrf>

{
  "conversation_id": "conv_xyz789"
}
```

**Response (201)**:
```json
{
  "assignment_id": "asgn_d4e5f6",
  "bot_id": "bot_abc123",
  "conversation_id": "conv_xyz789",
  "status": "active",
  "assigned_at": 1748520200
}
```

**Update bot status**:

```
PATCH /ui/bots/bot_abc123
Content-Type: application/json
x-csrf-token: <csrf>

{
  "status": "paused"
}
```

**Response (200)**:
```json
{
  "bot_id": "bot_abc123",
  "status": "paused",
  "previous_status": "active",
  "updated_at": 1748520300
}
```

---

## 16. Architecture Diagram

```
                       Bot Framework — System Architecture
  ┌─────────────────────────────────────────────────────────────────────────────┐
  │                            Platform Frontend                                │
  │  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────────────┐  │
  │  │ BotManagerPage    │  │ BotEditorDialog  │  │ BotAssignmentsDialog     │  │
  │  │                   │  │                  │  │                          │  │
  │  │ - bot cards       │  │ - name/avatar    │  │ - conversation picker    │  │
  │  │ - status badges   │  │ - personality    │  │ - wildcard scopes        │  │
  │  │ - pause/resume    │  │ - trigger config │  │ - assignment list        │  │
  │  │ - create/delete   │  │ - custom prompt  │  │ - remove assignment      │  │
  │  └────────┬─────────┘  └────────┬─────────┘  └─────────────┬────────────┘  │
  │           │                     │                           │               │
  │  ┌────────┴─────────────────────┴───────────────────────────┴────────────┐  │
  │  │                     React Query + Axios Client                        │  │
  │  │    createBot() | listBots() | updateBot() | assignBot() | deleteBot() │  │
  │  └───────────────────────────────────┬──────────────────────────────────┘  │
  └──────────────────────────────────────┼──────────────────────────────────────┘
                                         │ HTTP (CSRF + cookies)
  ┌──────────────────────────────────────┼──────────────────────────────────────┐
  │                           FastAPI Backend                                   │
  │  ┌───────────────────────────────────┴──────────────────────────────────┐  │
  │  │              app/routers/chat_bot.py                                  │  │
  │  │   POST /bots    GET /bots    PUT /bots/{id}    DELETE /bots/{id}     │  │
  │  │   PATCH /bots/{id}/status    POST /bots/{id}/assignments             │  │
  │  │   GET /bots/{id}/assignments DELETE /bots/{id}/assignments/{sk}      │  │
  │  │   POST /bots/{id}/avatar/presign    GET /bots/{id}/stats             │  │
  │  └───────────────────────────────────┬──────────────────────────────────┘  │
  │                                      │                                     │
  │  ┌───────────────────────────────────┴──────────────────────────────────┐  │
  │  │              app/services/chat_bot.py (Business Logic)                │  │
  │  │                                                                       │  │
  │  │   create_bot()    get_bot()    list_bots()    update_bot()            │  │
  │  │   update_bot_status()    delete_bot()                                 │  │
  │  │   assign_bot()    unassign_bot()    list_assignments()                │  │
  │  │   get_bots_for_conversation()                                         │  │
  │  │   send_bot_message()    evaluate_triggers()                           │  │
  │  └───────────────────────────────────┬──────────────────────────────────┘  │
  │                                      │                                     │
  │  ┌───────────────────┐  ┌────────────┴──────┐  ┌──────────────────────┐  │
  │  │ Trigger Evaluator │  │ DynamoDB Tables   │  │ Messaging Pipeline   │  │
  │  │                   │  │                   │  │                      │  │
  │  │ keyword match     │  │ chat_bots         │  │ send_text_message()  │  │
  │  │ first_message     │  │ PK=CREATOR#id     │  │ _message_out_from_  │  │
  │  │ @mention          │  │ SK=BOT#bot_id     │  │   item()             │  │
  │  │ idle timeout      │  │                   │  │                      │  │
  │  │ all_messages      │  │ bot_assignments   │  │ SSE events           │  │
  │  │ cron scheduled    │  │ PK=BOT#bot_id     │  │ sender_type="bot"    │  │
  │  │                   │  │ SK=CONV#/SCOPE#   │  │ bot_name, bot_avatar │  │
  │  └───────────────────┘  └───────────────────┘  └──────────────────────┘  │
  │                                                                            │
  │  Message Processing Pipeline (on incoming message):                        │
  │  ┌────────────────────────────────────────────────────────────────────────┐│
  │  │  1. Incoming message received via POST /messages                       ││
  │  │  2. get_bots_for_conversation(conversation_id)                         ││
  │  │     └─ GSI1 query on bot_assignments + wildcard scope check            ││
  │  │  3. For each active bot:                                               ││
  │  │     └─ evaluate_triggers(bot, conversation_id, incoming_message)       ││
  │  │        └─ Walk priority_order; check keyword/mention/first_msg/etc.    ││
  │  │  4. If trigger matched → template_id returned                          ││
  │  │  5. send_bot_message(bot_id, conversation_id, rendered_text)           ││
  │  │     └─ sender_type="bot", bot_id, bot_name, bot_avatar_url            ││
  │  │  6. SSE event pushed to conversation participants                      ││
  │  └────────────────────────────────────────────────────────────────────────┘│
  └─────────────────────────────────────────────────────────────────────────────┘
```

---

## 17. DynamoDB Access Patterns

| # | Access Pattern | Table | Key Condition | GSI | Example |
|---|---------------|-------|---------------|-----|---------|
| 1 | Create bot | `chat_bots` | `PK=CREATOR#{creator_id}, SK=BOT#{bot_id}` | -- | `put_item` with status=active |
| 2 | Get bot by bot_id | `chat_bots` | `GSI1PK=BOT#{bot_id}, GSI1SK=META` | GSI1 | Lookup bot without knowing creator |
| 3 | List bots for creator | `chat_bots` | `PK=CREATOR#{creator_id}, SK begins_with("BOT#")` | -- | All bots for the creator |
| 4 | Count bots for creator | `chat_bots` | `PK=CREATOR#{creator_id}, SK begins_with("BOT#")` + Select=COUNT | -- | Enforce max 10 bots limit |
| 5 | Update bot config | `chat_bots` | `PK=CREATOR#{creator_id}, SK=BOT#{bot_id}` | -- | `update_item` with ConditionExpression on ownership |
| 6 | Update bot status | `chat_bots` | `PK=CREATOR#{creator_id}, SK=BOT#{bot_id}` | -- | `update_item` status + updated_at |
| 7 | Delete bot | `chat_bots` | `PK=CREATOR#{creator_id}, SK=BOT#{bot_id}` | -- | `delete_item` |
| 8 | Assign bot to conversation | `bot_assignments` | `PK=BOT#{bot_id}, SK=CONV#{conversation_id}` | -- | `put_item` |
| 9 | Assign bot to wildcard scope | `bot_assignments` | `PK=BOT#{bot_id}, SK=SCOPE#ALL_DMS` | -- | `put_item` |
| 10 | List assignments for bot | `bot_assignments` | `PK=BOT#{bot_id}, SK begins_with("CONV#" or "SCOPE#" or "BCAST#")` | -- | All assignments |
| 11 | Find bots for conversation | `bot_assignments` | `GSI1PK=CONV#{conversation_id}` | GSI1 | Which bots are assigned to this conversation |
| 12 | Delete all assignments for bot | `bot_assignments` | `PK=BOT#{bot_id}` (query + batch delete) | -- | Cascade delete on bot deletion |
| 13 | Increment bot message count | `chat_bots` | `PK=CREATOR#{creator_id}, SK=BOT#{bot_id}` | -- | `update_item` ADD message_count 1 |

**Example DynamoDB item (ChatBots)**:

```json
{
  "pk": {"S": "CREATOR#alice_sub_123"},
  "sk": {"S": "BOT#b1c2d3e4f5a6"},
  "bot_id": {"S": "b1c2d3e4f5a6"},
  "creator_id": {"S": "alice_sub_123"},
  "name": {"S": "Sales Bot"},
  "avatar_url": {"S": "/mock/s3/avatars/sales-bot.png"},
  "description": {"S": "Handles pricing questions and upsells premium features"},
  "personality": {"S": "professional"},
  "status": {"S": "active"},
  "trigger_config": {"M": {
    "triggers": {"L": [
      {"M": {"type": {"S": "keyword"}, "keywords": {"L": [{"S": "price"}, {"S": "cost"}, {"S": "how much"}]}, "response_template_id": {"S": "tpl_pricing"}}},
      {"M": {"type": {"S": "first_message"}, "response_template_id": {"S": "tpl_welcome"}}}
    ]},
    "priority_order": {"L": [{"S": "keyword"}, {"S": "first_message"}]}
  }},
  "created_at": {"N": "1748520100"},
  "updated_at": {"N": "1748520100"},
  "message_count": {"N": "1247"},
  "GSI1PK": {"S": "BOT#b1c2d3e4f5a6"},
  "GSI1SK": {"S": "META"}
}
```

**Example DynamoDB item (BotAssignments)**:

```json
{
  "pk": {"S": "BOT#b1c2d3e4f5a6"},
  "sk": {"S": "CONV#conv_abc123"},
  "bot_id": {"S": "b1c2d3e4f5a6"},
  "creator_id": {"S": "alice_sub_123"},
  "target_type": {"S": "conversation"},
  "target_id": {"S": "conv_abc123"},
  "created_at": {"N": "1748520200"},
  "GSI1PK": {"S": "CONV#conv_abc123"},
  "GSI1SK": {"S": "BOT#b1c2d3e4f5a6"}
}
```

---

## 18. Pydantic Models

```python
# In app/models.py

from pydantic import BaseModel, Field, model_validator
from typing import Optional, List, Dict, Any, Literal


class CreateBotIn(BaseModel):
    """Request model for creating a chat bot."""
    name: str = Field(..., min_length=1, max_length=50)
    avatar_url: Optional[str] = Field(
        default=None, max_length=2048,
        description="S3 URL for bot avatar image"
    )
    description: Optional[str] = Field(
        default=None, max_length=500,
        description="Bot description visible to users"
    )
    personality: Literal["friendly", "professional", "casual", "custom"] = Field(
        default="friendly",
        description="Personality preset for bot tone"
    )
    custom_personality: Optional[str] = Field(
        default=None, max_length=2000,
        description="Free-text personality instructions (only when personality=custom)"
    )

    @model_validator(mode="after")
    def validate_custom_personality(self):
        if self.personality == "custom" and not self.custom_personality:
            raise ValueError("custom_personality is required when personality is 'custom'")
        if self.personality != "custom" and self.custom_personality:
            raise ValueError("custom_personality should only be set when personality is 'custom'")
        return self


class UpdateBotIn(BaseModel):
    """Request model for updating a chat bot."""
    name: Optional[str] = Field(default=None, min_length=1, max_length=50)
    avatar_url: Optional[str] = Field(default=None, max_length=2048)
    description: Optional[str] = Field(default=None, max_length=500)
    personality: Optional[Literal["friendly", "professional", "casual", "custom"]] = None
    custom_personality: Optional[str] = Field(default=None, max_length=2000)
    trigger_config: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Trigger rules configuration"
    )


class UpdateBotStatusIn(BaseModel):
    """Request model for changing bot status."""
    status: Literal["active", "paused", "disabled"]


class AssignBotIn(BaseModel):
    """Request model for assigning a bot to a target."""
    target_type: Literal["conversation", "broadcast", "all_dms", "all_groups", "all_broadcasts"]
    target_id: Optional[str] = Field(
        default=None, max_length=100,
        description="Conversation or broadcast ID (required for conversation/broadcast types)"
    )

    @model_validator(mode="after")
    def validate_target_id(self):
        if self.target_type in ("conversation", "broadcast") and not self.target_id:
            raise ValueError("target_id is required for conversation and broadcast assignments")
        return self


class BotTriggerRule(BaseModel):
    """A single trigger rule definition."""
    type: Literal["keyword", "first_message", "mention", "all_messages", "idle", "scheduled"]
    keywords: Optional[List[str]] = Field(default=None, max_length=50)
    response_template_id: Optional[str] = Field(default=None, max_length=100)
    idle_minutes: Optional[int] = Field(default=None, ge=1, le=1440)
    cron: Optional[str] = Field(default=None, max_length=100)

    @model_validator(mode="after")
    def validate_trigger_fields(self):
        if self.type == "keyword" and not self.keywords:
            raise ValueError("keywords list is required for keyword triggers")
        if self.type == "idle" and self.idle_minutes is None:
            raise ValueError("idle_minutes is required for idle triggers")
        if self.type == "scheduled" and not self.cron:
            raise ValueError("cron expression is required for scheduled triggers")
        return self


class BotTriggerConfigIn(BaseModel):
    """Trigger configuration for a bot."""
    triggers: List[BotTriggerRule] = Field(..., max_length=20)
    priority_order: List[str] = Field(
        default_factory=lambda: ["keyword", "mention", "first_message", "idle", "all_messages"]
    )


class BotOut(BaseModel):
    """Response model for a chat bot."""
    bot_id: str
    creator_id: str
    name: str
    avatar_url: Optional[str] = None
    description: Optional[str] = None
    personality: str = "friendly"
    custom_personality: Optional[str] = None
    status: str = "active"
    trigger_config: Optional[Dict[str, Any]] = None
    created_at: int = 0
    updated_at: int = 0
    message_count: int = 0


class BotAssignmentOut(BaseModel):
    """Response model for a bot assignment."""
    bot_id: str
    target_type: str
    target_id: Optional[str] = None
    created_at: int = 0


class BotStatsOut(BaseModel):
    """Response model for bot statistics."""
    message_count: int = 0
    last_active_at: Optional[int] = None
    assignment_count: int = 0
    trigger_match_count_24h: int = 0
```

---

## 19. Frontend Component Tree

```
/bots — BotManagerPage
├── PageHeader
│   ├── <h1> "Chat Bots"
│   ├── BotCountBadge ("3 bots")
│   └── CreateBotButton → opens BotEditorDialog (mode="create")
├── BotGrid
│   └── BotCard (one per bot)
│       ├── AvatarDisplay (bot avatar or fallback robot icon)
│       ├── BotName (<h3>)
│       ├── Description (truncated to 2 lines)
│       ├── StatusBadge
│       │   ├── green dot + "Active" (status=active)
│       │   ├── yellow dot + "Paused" (status=paused)
│       │   └── gray dot + "Disabled" (status=disabled)
│       ├── PersonalityBadge (friendly / professional / casual / custom)
│       ├── StatsRow
│       │   ├── MessageCountIcon + count
│       │   ├── AssignmentCountIcon + count
│       │   └── LastActiveTimestamp
│       ├── TriggerSummary (e.g., "3 triggers: keyword, first_message, idle")
│       └── ActionsRow
│           ├── EditButton → opens BotEditorDialog (mode="edit")
│           ├── AssignmentsButton → opens BotAssignmentsDialog
│           ├── PauseResumeButton (toggles active <-> paused)
│           └── DeleteButton (with confirmation dialog)
├── EmptyState (if no bots)
│   ├── Robot illustration
│   ├── "No bots yet"
│   └── "Create your first bot" button
└── BotLimitWarning (if approaching 10 bot limit)

BotEditorDialog (shared dialog for create + edit)
├── DialogHeader ("New Bot" or "Edit Bot")
├── IdentitySection
│   ├── AvatarUpload (click to upload, drag-and-drop, presigned S3)
│   ├── NameInput (<Input> max 50 chars)
│   └── DescriptionTextarea (<Textarea> max 500 chars)
├── PersonalitySection
│   ├── PersonalityRadioGroup
│   │   ├── Radio: "Friendly" (warm, approachable tone)
│   │   ├── Radio: "Professional" (formal, business tone)
│   │   ├── Radio: "Casual" (laid-back, conversational)
│   │   └── Radio: "Custom" (free-text instructions)
│   └── CustomPersonalityTextarea (visible only when custom selected)
├── TriggerConfigSection
│   ├── TriggerList
│   │   └── TriggerRow (one per trigger)
│   │       ├── TypeSelect (keyword / first_message / mention / all_messages / idle / scheduled)
│   │       ├── KeywordsInput (visible for keyword type, comma-separated)
│   │       ├── IdleMinutesInput (visible for idle type)
│   │       ├── CronInput (visible for scheduled type)
│   │       ├── TemplateSelect (dropdown of bot templates, links to BOT-002)
│   │       └── RemoveTriggerButton
│   ├── AddTriggerButton
│   └── PriorityOrderSortable (drag to reorder trigger priority)
├── SaveButton
└── CancelButton

BotAssignmentsDialog
├── DialogHeader ("Bot Assignments — {bot_name}")
├── CurrentAssignmentsList
│   └── AssignmentRow (one per assignment)
│       ├── TargetIcon (conversation icon / broadcast icon / wildcard icon)
│       ├── TargetLabel
│       │   ├── Conversation: conversation name + participant count
│       │   ├── Broadcast: broadcast session name
│       │   └── Wildcard: "All DMs" / "All Groups" / "All Broadcasts"
│       ├── CreatedAtTimestamp
│       └── RemoveButton (X icon)
├── AddAssignmentSection
│   ├── TargetTypeSelect
│   │   ├── Option: "Specific Conversation"
│   │   ├── Option: "Specific Broadcast"
│   │   ├── Option: "All DMs" (wildcard)
│   │   ├── Option: "All Groups" (wildcard)
│   │   └── Option: "All Broadcasts" (wildcard)
│   ├── ConversationPicker (visible for specific conversation)
│   │   ├── SearchInput (filter conversations by name)
│   │   └── ConversationList (scrollable, selectable)
│   └── AssignButton
└── CloseButton

MessageBubble enhancement (for bot messages)
├── BotAvatarDisplay (instead of user avatar when sender_type="bot")
├── BotNameRow
│   ├── BotName text
│   └── Badge variant="outline" → "Bot"
├── MessageContent (standard text/image rendering)
└── BotBackground (slightly different tint: bg-muted/50)
```

---

## Testing Strategy

### Unit Tests (pytest)

**Test file**: `tests/test_bot_framework.py`

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

**Test file**: `frontend/e2e/bot-framework.spec.ts`

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

No upstream dependencies. This ticket is self-contained.

### Depended On By

| Ticket | What It Needs |
|---|---|
| BOT-002 | Bot framework CRUD and trigger evaluation |
| BOT-003 | Bot identity and `send_bot_message()` |
| BOT-004 | Bot framework for AI integration |

### Merge Strategy

Independent. New DDB table (`ChatBots`), new service + router. Foundation for all BOT tickets.

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
| `_message_out_from_item()` exists | `app/routers/messaging.py` | 3766 | VERIFIED |
| `MessageOut` model exists | `app/routers/messaging.py` | 2325 | VERIFIED |
| `MessageOut.kind` Literal union | `app/routers/messaging.py` | 2330 | VERIFIED (text, image, file, audio, video, gallery, file_share, calendar_share, calendar_event, meeting_poll, video_share, voice_message, voicemail) |
| `ConversationOut` model | `app/routers/messaging.py` | 1729 | VERIFIED |
| `send_chat_message()` in broadcast store | `app/services/broadcast_chat_store.py` | 136 | VERIFIED |
| No `sender_type` field on MessageOut | `app/routers/messaging.py` | 2325-2380 | VERIFIED (field does not exist — new implementation required) |
| No `chat_bots` DDB table | `scripts/local-ddb-init.py` | full file | VERIFIED (table does not exist — new implementation required) |
| No `bot_assignments` DDB table | `scripts/local-ddb-init.py` | full file | VERIFIED (table does not exist — new implementation required) |
| No `chat_bots_table_name` setting | `app/core/settings.py` | full file | VERIFIED (setting does not exist — new implementation required) |
| No `bot_framework_enabled` setting | `app/core/settings.py` | full file | VERIFIED (setting does not exist — new implementation required) |
| No `chat_bot_router` in main.py | `app/main.py` | full file | VERIFIED (not registered — new implementation required) |
| No `app/services/chat_bot.py` | `app/services/` | N/A | VERIFIED (file does not exist — new implementation required) |
| No `app/routers/chat_bot.py` | `app/routers/` | N/A | VERIFIED (file does not exist — new implementation required) |
| No `frontend/src/pages/bots/` dir | `frontend/src/pages/` | N/A | VERIFIED (directory does not exist — new implementation required) |
| No `frontend/src/api/endpoints/bots.ts` | `frontend/src/api/endpoints/` | N/A | VERIFIED (file does not exist — new implementation required) |
| `MORE_LINKS` array in MobileNav | `frontend/src/components/layout/MobileNav.tsx` | 64 | VERIFIED |
| Sidebar Commerce group | `frontend/src/components/layout/Sidebar.tsx` | 94-107 | VERIFIED |
