# MSG-011: Emoji Reactions Enhancement

**Ticket**: MSG-011
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: Medium
**Estimated effort**: 5-6 days
**Depends on**: MSG-006 (EmojiPicker), MSG-007 (Custom Emojis)

---

## 1. Overview & Motivation

### 1.1 Purpose

MSG-011 enhances the existing message reaction system with custom emoji support (from MSG-007), reaction detail popovers showing who reacted with what, quick-react via double-tap, reaction animations, and a per-message reaction limit. The existing reaction infrastructure stores reactions as a DynamoDB map (`reactions: { emoji: { user_id: True } }`). This ticket extends the frontend UX while preserving the backend storage pattern.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| User | As a user, I want to double-tap a message to add a heart reaction quickly. | Double-tap → heart added; animation plays; reaction count updates. |
| User | As a user, I want to see who reacted with what emoji by tapping the reaction count. | Popover shows avatar + name list per emoji. |
| User | As a user, I want to react with custom emojis from MSG-007. | Custom emojis appear in reaction picker; stored as `custom:shortcode`. |
| User | As a user, I want to see a brief pop animation when a reaction is added. | CSS scale+opacity animation plays on the reaction badge. |
| User | As a user, I want to change my default quick-react emoji. | Settings option to choose default (stored in localStorage). |
| System | As the system, I want to limit reactions to 20 unique emojis per message. | 21st unique emoji reaction returns 400. |

### 1.3 Why This Is Needed Now

Reactions are already functional but lack polish. The current implementation shows reaction counts but not who reacted, has no quick-react gesture, no animation feedback, and no custom emoji support. These enhancements transform reactions from a basic feature into an engaging interaction layer.

---

## 2. Current State Analysis

### 2.1 Existing Reaction System

**Backend** (`app/routers/messaging.py`):
- `POST /messaging/conversations/{conv_id}/messages/{msg_id}/reactions` (line 10087) — add or remove reaction via `ReactIn.action` ("add" | "remove")
- Reactions stored on message item as DynamoDB String Sets: `reactions: { "smiley": SS["user_sub_1", "user_sub_2"] }` (see `ADD reactions.#e :u` at line 10106)
- `MessageOut.reactions_counts` (line 2365) returns `Dict[str, int]` (emoji to count), and `MessageOut.my_reactions` (line 2366) returns `List[str]` of emojis the viewer reacted with — computed by `_reaction_summaries()` (line 5363)

<!-- NOTE: There is NO separate "/unreact" endpoint. The single reaction endpoint at line 10087 uses ReactIn with action: Literal["add", "remove"] to handle both cases. -->
<!-- NOTE: Reactions are stored as DDB String Sets (via ADD/DELETE set operations), NOT as maps { user_id: True }. The _reaction_summaries function at line 5363 uses isinstance(userset, set) to process them. -->

**Frontend** (`frontend/src/pages/messages/MessageBubble.tsx`):
- Displays reaction badges below message content (line 1688: renders `reactions_counts` entries)
- Each badge shows emoji + count (line 1690)
- Click on existing badge to toggle own reaction via `reactMut.mutate(emoji)` (line 1694)
- React button opens a small emoji row with 6 quick-pick emojis (line 789)
- `reactMut` uses `reactToMessage()` from `frontend/src/api/endpoints/messaging.ts:447`

### 2.2 Reaction Data Shape

```typescript
// Current reactions on MessageOut (see frontend/src/api/types.ts)
reactions_counts?: Record<string, number>;    // e.g., { "smiley": 1, "heart": 2 }
my_reactions?: string[];                       // e.g., ["heart"]
```

This structure supports displaying counts directly and checking the current user's reaction via `my_reactions.includes(emoji)`. The raw DDB storage uses sets (not maps of boolean), but the API transforms them in `_reaction_summaries()` (see `app/routers/messaging.py:5363`).

<!-- NOTE: The frontend MessageOut does NOT expose the raw reactions map { emoji: { user_id: true } }. It exposes reactions_counts (Dict[str, int]) and my_reactions (List[str]). The raw user IDs per emoji are not returned in the standard message response — they would need a new details endpoint. -->

### 2.3 Custom Emoji Storage (MSG-007)

<!-- NOTE: MSG-007 (Custom Emojis) does not exist yet — there is no custom_emojis DDB table, no resolveCustomShortcodes API, and no custom emoji support anywhere in the codebase. All references to custom emoji functionality in this ticket are forward-looking and require MSG-007 to be implemented first. -->

Custom emojis will be stored in a `custom_emojis` table (to be created by MSG-007). In reactions, they'll be represented as `custom:shortcode` keys (e.g., `custom:my_cat`). A `resolveCustomShortcodes` API will resolve shortcodes to image URLs for rendering.

### 2.4 Gaps

1. **No reaction detail popover** — can't see who reacted with what.
2. **No quick-react (double-tap)** — no gesture for fast reactions.
3. **No custom emoji in reaction picker** — picker only shows Unicode emojis.
4. **No reaction animation** — no visual feedback when adding reactions.
5. **No reaction limit** — unlimited unique emojis per message.
6. **No configurable default quick-react emoji** — hardcoded would need to be set.

---

## 3. Architecture Diagram

```
┌──────────────────────────────────────────────────────────────────────┐
│                       FRONTEND (React)                                │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │  MessageBubble                                                 │  │
│  │                                                                │  │
│  │  ┌──────────────────────────────────────────────────────────┐  │  │
│  │  │  Message Content                                         │  │  │
│  │  │  (text, image, GIF, etc.)                                │  │  │
│  │  │                                                          │  │  │
│  │  │  onDoubleClick → quickReact (add/remove default emoji)   │  │  │
│  │  └──────────────────────────────────────────────────────────┘  │  │
│  │                                                                │  │
│  │  ┌──────────────────────────────────────────────────────────┐  │  │
│  │  │  ReactionBar                                             │  │  │
│  │  │                                                          │  │  │
│  │  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────────┐   │  │  │
│  │  │  │ smiley 3│ │ heart 5 │ │ fire 2  │ │ custom:cat 1│   │  │  │
│  │  │  │  (pop)  │ │  (pop)  │ │  (pop)  │ │   (pop)     │   │  │  │
│  │  │  └────┬────┘ └────┬────┘ └────┬────┘ └──────┬──────┘   │  │  │
│  │  │       │            │           │              │          │  │  │
│  │  │       └────────────┴───────────┴──────────────┘          │  │  │
│  │  │                        │ click                            │  │  │
│  │  │                        ▼                                  │  │  │
│  │  │  ┌──────────────────────────────────────────────────┐    │  │  │
│  │  │  │  ReactionDetailPopover                           │    │  │  │
│  │  │  │  ┌────────┬────────┬────────┐                    │    │  │  │
│  │  │  │  │smiley 3│heart 5 │fire 2  │  ← emoji tabs     │    │  │  │
│  │  │  │  ├────────┴────────┴────────┤                    │    │  │  │
│  │  │  │  │ avatar  Alice            │                    │    │  │  │
│  │  │  │  │ avatar  Bob              │  ← user list       │    │  │  │
│  │  │  │  │ avatar  Charlie          │                    │    │  │  │
│  │  │  │  └──────────────────────────┘                    │    │  │  │
│  │  │  └──────────────────────────────────────────────────┘    │  │  │
│  │  │                                                          │  │  │
│  │  │  ┌──────────────────────────────────────────────────┐    │  │  │
│  │  │  │  Enhanced Reaction Picker (SmilePlus button)     │    │  │  │
│  │  │  │  ┌──────────────────────────────────────────┐    │    │  │  │
│  │  │  │  │ Quick row: thumbsup heart laugh wow cry fire│   │    │  │  │
│  │  │  │  ├──────────────────────────────────────────┤    │    │  │  │
│  │  │  │  │ Custom: [img] [img] [img] [img]          │    │    │  │  │
│  │  │  │  ├──────────────────────────────────────────┤    │    │  │  │
│  │  │  │  │ [+ More] → Full EmojiPicker (MSG-006)    │    │    │  │  │
│  │  │  │  └──────────────────────────────────────────┘    │    │  │  │
│  │  │  └──────────────────────────────────────────────────┘    │  │  │
│  │  └──────────────────────────────────────────────────────────┘  │  │
│  └────────────────────────────────────────────────────────────────┘  │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │  emojiStore (Zustand + localStorage)                           │  │
│  │  quickReactEmoji: "heart" (configurable)                       │  │
│  │  recentEmojis: ["thumbsup", "heart", "laugh", ...]             │  │
│  └────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────┬─────────────────────────────────────┘
                                 │ HTTP
┌────────────────────────────────▼─────────────────────────────────────┐
│                       BACKEND (FastAPI)                               │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │  messaging router                                              │  │
│  │                                                                │  │
│  │  POST /messages/{id}/reactions  (existing, line 10087)          │  │
│  │       → validate limit (20 unique emojis max) ← NEW           │  │
│  │       → action="add": ADD reactions.#e :u (DDB Set add)       │  │
│  │       → action="remove": DELETE reactions.#e :u (Set remove)  │  │
│  │                                                                │  │
│  │  GET  /messages/{id}/reactions/details   ← NEW                 │  │
│  │       → batch_get_user_profiles for display names              │  │
│  │       → return { reactions: { emoji: [{user_sub, name}] } }    │  │
│  └────────────────────────────────────────────────────────────────┘  │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │  Messages DDB Table                                            │  │
│  │  reactions MAP: { "heart": { "alice-sub": true, "bob-sub": t } │  │
│  │                   "custom:cat": { "alice-sub": true } }        │  │
│  └────────────────────────────────────────────────────────────────┘  │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │  custom_emojis DDB Table (MSG-007)                             │  │
│  │  Resolves "custom:shortcode" → image_url for rendering         │  │
│  └────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────┘
```

**Data Flow — Quick React (Double-Tap)**:
1. User double-clicks a message
2. `handleDoubleClick` reads `emojiStore.quickReactEmoji` (default: heart)
3. Check if user already reacted with that emoji
4. If not: POST `/messages/{id}/reactions` with `emoji=heart`
5. If yes: POST `/messages/{id}/unreact` with `emoji=heart`
6. Optimistic update: immediately add/remove badge with pop animation
7. SSE broadcasts reaction update to other participants

**Data Flow — Reaction Detail Popover**:
1. User clicks on reaction badge area
2. ReactionDetailPopover fetches GET `/messages/{id}/reactions/details`
3. Backend batch-fetches user profiles for all reacting user_subs
4. Returns `{ reactions: { "heart": [{ user_sub, display_name }], ... } }`
5. Popover renders tabs per emoji, each showing list of user names

**Data Flow — Custom Emoji Reaction**:
1. User opens enhanced reaction picker (SmilePlus button)
2. Custom emojis section shows user's custom emojis (from MSG-007)
3. User clicks custom emoji → POST `/messages/{id}/reactions` with `emoji=custom:shortcode`
4. Backend stores `reactions.custom:shortcode.{user_sub} = true`
5. Rendering: ReactionBadge detects `custom:` prefix, resolves shortcode to image URL via `resolveCustomShortcodes`

---

## 4. Technical Design

### 4.1 Backend: Reaction Limit

Add validation to the existing `react_to_message` endpoint (see `app/routers/messaging.py:10087`) to enforce max 20 unique emojis:

```python
# Existing endpoint at messaging.py:10087 — add limit check before the ADD operation
@router.post("/conversations/{conversation_id}/messages/{message_id}/reactions")
def react_to_message(
    conversation_id: str,
    message_id: str,
    inp: ReactIn,         # existing model at line 2150: emoji + action("add"|"remove")
    req: Request = None,
    user_id: str = Depends(get_messaging_user_id),
):
    require_participant_active(user_id, conversation_id)
    msg = _get_message_or_404(conversation_id, message_id)  # line 5383
    reactions = msg.get("reactions", {})

    # NEW: Check limit — max 20 unique emoji keys
    if inp.action == "add" and inp.emoji not in reactions and len(reactions) >= 20:
        raise HTTPException(
            status_code=400,
            detail="Maximum 20 unique reactions per message"
        )

    # ... existing ADD/DELETE logic continues (line 10103) ...
```

### 4.2 Backend: Reaction User Info Endpoint

Add an endpoint to get reaction details (who reacted with what):

```python
@router.get("/conversations/{conv_id}/messages/{msg_id}/reactions/details")
def get_reaction_details(conv_id: str, msg_id: str, ctx=Depends(require_ui_session)):
    """Get detailed reaction information including user display names."""
    msg = _get_message_or_404(conv_id, msg_id)
    reactions = msg.get("reactions", {})

    details = {}
    all_user_subs = set()
    for emoji, users in reactions.items():
        all_user_subs.update(users.keys())

    # Batch fetch user profiles for display names
    user_profiles = _batch_get_user_profiles(list(all_user_subs))

    for emoji, users in reactions.items():
        details[emoji] = [
            {
                "user_sub": uid,
                "display_name": user_profiles.get(uid, {}).get("display_name", uid[:8]),
            }
            for uid in users.keys()
        ]

    return {"reactions": details}
```

### 4.3 DynamoDB Access Patterns

| # | Access Pattern | Table/Index | PK | SK | Operation | Notes |
|---|---------------|-------------|----|----|-----------|-------|
| 1 | Add reaction | `Messages` | `conversation_id` | `message_id` | `UpdateItem` | `ADD reactions.#e :u` — DDB String Set add (see `messaging.py:10106`); `:u = {user_id}` |
| 2 | Remove reaction | `Messages` | `conversation_id` | `message_id` | `UpdateItem` | `DELETE reactions.#e :u` — DDB String Set remove (see `messaging.py:10115`) |
| 3 | Check reaction limit | `Messages` | `conversation_id` | `message_id` | `GetItem` | Read reactions map via `_get_message_or_404` (line 5383), count unique keys before ADD |
| 4 | Get reaction details | `Messages` | `conversation_id` | `message_id` | `GetItem` | Read reactions map for user_subs — NEW endpoint |
| 5 | Batch get user profiles | `Users` | `user_sub` | — | `BatchGetItem` | Fetch display_name for each reacting user |
| 6 | Get custom emoji image | `custom_emojis` | — | — | — | Resolve `custom:shortcode` to image_url — requires MSG-007 |

<!-- NOTE: custom_emojis table does not exist yet — MSG-007 dependency. -->

**Example DynamoDB Item (message with reactions)**:

```json
{
  "conversation_id": {"S": "conv_abc123"},
  "message_id": {"S": "m_def456"},
  "kind": {"S": "text"},
  "text": {"S": "Great work everyone!"},
  "sender_id": {"S": "alice-sub-001"},
  "created_at": {"N": "1748500000"},
  "reactions": {"M": {
    "thumbsup": {"SS": ["alice-sub-001", "bob-sub-002", "charlie-sub-003"]},
    "heart": {"SS": ["bob-sub-002"]},
    "fire": {"SS": ["alice-sub-001", "charlie-sub-003"]},
    "custom:party_parrot": {"SS": ["alice-sub-001"]}
  }}
}
```

<!-- NOTE: Reactions are stored as String Sets (SS), not Maps of booleans. The existing code uses ADD/DELETE set operations (see messaging.py:10106-10117). The _reaction_summaries function at line 5363 handles both set and dict formats. -->

**Reaction Details API Response Example**:

```json
{
  "reactions": {
    "thumbsup": [
      {"user_sub": "alice-sub-001", "display_name": "Alice"},
      {"user_sub": "bob-sub-002", "display_name": "Bob"},
      {"user_sub": "charlie-sub-003", "display_name": "Charlie"}
    ],
    "heart": [
      {"user_sub": "bob-sub-002", "display_name": "Bob"}
    ],
    "fire": [
      {"user_sub": "alice-sub-001", "display_name": "Alice"},
      {"user_sub": "charlie-sub-003", "display_name": "Charlie"}
    ],
    "custom:party_parrot": [
      {"user_sub": "alice-sub-001", "display_name": "Alice"}
    ]
  }
}
```

### 4.4 API Request/Response Examples

#### 4.4.1 Add Reaction

```bash
curl -s -X POST \
  "http://localhost:8000/ui/messaging/conversations/conv_abc123/messages/m_def456/reactions" \
  -H "Cookie: ui_session=sess_alice; ui_csrf=csrf_alice; ui_access_token=jwt_alice" \
  -H "x-csrf-token: csrf_alice" \
  -H "Content-Type: application/json" \
  -d '{"emoji": "heart"}' \
  | jq .
```

**Response** (200):
```json
{
  "ok": true,
  "conversation_id": "conv_abc123",
  "message_id": "m_def456",
  "emoji": "heart",
  "action": "added"
}
```

#### 4.4.2 Add Custom Emoji Reaction

```bash
curl -s -X POST \
  "http://localhost:8000/ui/messaging/conversations/conv_abc123/messages/m_def456/reactions" \
  -H "Cookie: ui_session=sess_alice; ui_csrf=csrf_alice; ui_access_token=jwt_alice" \
  -H "x-csrf-token: csrf_alice" \
  -H "Content-Type: application/json" \
  -d '{"emoji": "custom:party_parrot"}' \
  | jq .
```

**Response** (200):
```json
{
  "ok": true,
  "conversation_id": "conv_abc123",
  "message_id": "m_def456",
  "emoji": "custom:party_parrot",
  "action": "added"
}
```

#### 4.4.3 Remove Reaction

```bash
# NOTE: Uses the same /reactions endpoint with action="remove" — there is no separate /unreact endpoint
curl -s -X POST \
  "http://localhost:8000/ui/messaging/conversations/conv_abc123/messages/m_def456/reactions" \
  -H "Cookie: ui_session=sess_alice; ui_csrf=csrf_alice; ui_access_token=jwt_alice" \
  -H "x-csrf-token: csrf_alice" \
  -H "Content-Type: application/json" \
  -d '{"emoji": "heart", "action": "remove"}' \
  | jq .
```

**Response** (200):
```json
{
  "ok": true
}
```

<!-- NOTE: The existing react_to_message endpoint returns only {"ok": true} (see messaging.py:10150). The richer response shape shown elsewhere in this ticket (with conversation_id, message_id, emoji, action) would need to be added. -->

#### 4.4.4 Get Reaction Details

```bash
curl -s -X GET \
  "http://localhost:8000/ui/messaging/conversations/conv_abc123/messages/m_def456/reactions/details" \
  -H "Cookie: ui_session=sess_alice; ui_csrf=csrf_alice; ui_access_token=jwt_alice" \
  | jq .
```

**Response** (200):
```json
{
  "reactions": {
    "thumbsup": [
      {"user_sub": "alice-sub-001", "display_name": "Alice"},
      {"user_sub": "bob-sub-002", "display_name": "Bob"}
    ],
    "heart": [
      {"user_sub": "bob-sub-002", "display_name": "Bob"}
    ],
    "custom:party_parrot": [
      {"user_sub": "alice-sub-001", "display_name": "Alice"}
    ]
  }
}
```

#### 4.4.5 Reaction Limit Exceeded

```bash
# After 20 unique emojis already added:
curl -s -X POST \
  "http://localhost:8000/ui/messaging/conversations/conv_abc123/messages/m_def456/reactions" \
  -H "Cookie: ui_session=sess_alice; ui_csrf=csrf_alice; ui_access_token=jwt_alice" \
  -H "x-csrf-token: csrf_alice" \
  -H "Content-Type: application/json" \
  -d '{"emoji": "emoji_21"}' \
  | jq .
```

**Response** (400):
```json
{
  "detail": "Maximum 20 unique reactions per message"
}
```

### 4.5 Pydantic Models

```python
# NOTE: ReactIn already exists at app/routers/messaging.py:2150
# class ReactIn(BaseModel):
#     emoji: str = Field(min_length=1, max_length=32)
#     action: Literal["add", "remove"] = "add"
#
# The ticket calls it "ReactionIn" but the existing class is "ReactIn".
# Consider extending max_length from 32 to 64 for custom emoji shortcodes.

class ReactionOut(BaseModel):
    """Response from add/remove reaction."""
    ok: bool = True
    conversation_id: str
    message_id: str
    emoji: str
    action: str  # "added" | "removed"

class ReactionUserOut(BaseModel):
    """A user who reacted with a specific emoji."""
    user_sub: str
    display_name: str

class ReactionDetailsOut(BaseModel):
    """Detailed reaction breakdown for a message."""
    reactions: dict[str, list[ReactionUserOut]] = Field(
        default_factory=dict,
        description="Map of emoji → list of users who reacted")

    model_config = {"json_schema_extra": {"examples": [
        {"reactions": {
            "heart": [
                {"user_sub": "alice-sub-001", "display_name": "Alice"},
                {"user_sub": "bob-sub-002", "display_name": "Bob"}
            ],
            "custom:cat": [
                {"user_sub": "alice-sub-001", "display_name": "Alice"}
            ]
        }}
    ]}}
```

### 4.6 Frontend: ReactionDetailPopover

**File**: `frontend/src/pages/messages/ReactionDetailPopover.tsx`

```typescript
interface ReactionDetailPopoverProps {
  conversationId: string;
  messageId: string;
  reactions: Record<string, Record<string, boolean>>;
  trigger: React.ReactNode;
}
```

- Triggered by clicking on the reaction count area
- Fetches `/reactions/details` via React Query
- Displays a popover with tabs per emoji:
  ```
  +---------------------------------+
  |  smiley (3)  |  heart (5)  |  fire (2)  |
  +---------------------------------+
  |  avatar  Alice                  |
  |  avatar  Bob                    |
  |  avatar  Charlie                |
  +---------------------------------+
  ```
- Custom emojis render as `<img>` in tabs
- `data-testid="reaction-detail-popover"`

### 4.7 Frontend: Quick React (Double-Tap)

**File**: `frontend/src/pages/messages/MessageBubble.tsx`

```typescript
const handleDoubleClick = useCallback(() => {
  const defaultEmoji = emojiStore.quickReactEmoji || "heart";
  const existingReaction = message.reactions?.[defaultEmoji]?.[currentUserSub];

  if (existingReaction) {
    // Already reacted with default — remove it
    unreactMutation.mutate({ emoji: defaultEmoji });
  } else {
    // Add default reaction
    reactMutation.mutate({ emoji: defaultEmoji });
  }
}, [message.reactions, currentUserSub]);

// On the message content wrapper:
<div onDoubleClick={handleDoubleClick} className="cursor-pointer">
  {/* message content */}
</div>
```

### 4.8 Frontend: Reaction Animation

CSS animation for reaction badges:

```css
/* In MessageBubble or shared styles */
@keyframes reaction-pop {
  0% { transform: scale(0.5); opacity: 0; }
  50% { transform: scale(1.2); }
  100% { transform: scale(1); opacity: 1; }
}

.reaction-badge-enter {
  animation: reaction-pop 0.3s ease-out;
}
```

Apply animation class when a reaction is newly added:

```tsx
const [animatingEmoji, setAnimatingEmoji] = useState<string | null>(null);

const handleReact = async (emoji: string) => {
  await reactMutation.mutateAsync({ emoji });
  setAnimatingEmoji(emoji);
  setTimeout(() => setAnimatingEmoji(null), 300);
};

// In reaction badge rendering:
<span className={cn(
  "reaction-badge",
  animatingEmoji === emoji && "reaction-badge-enter"
)}>
  {emoji} {count}
</span>
```

### 4.9 Frontend: Enhanced Reaction Picker

Extend the reaction picker in MessageBubble to include:
1. A row of frequently used emojis (from emojiStore.recentEmojis)
2. A "+" button that opens the full EmojiPicker
3. A "Custom" section with custom emojis (if any exist)

```tsx
<Popover>
  <PopoverTrigger asChild>
    <Button variant="ghost" size="icon" className="h-6 w-6">
      <SmilePlus className="h-3.5 w-3.5" />
    </Button>
  </PopoverTrigger>
  <PopoverContent className="w-auto p-2">
    {/* Quick row: 6 common emojis */}
    <div className="flex gap-1 mb-2">
      {["thumbsup", "heart", "laugh", "wow", "cry", "fire"].map(emoji => (
        <button key={emoji} onClick={() => handleReact(emoji)} className="text-xl hover:scale-125 transition">
          {emoji}
        </button>
      ))}
    </div>
    {/* Custom emojis row (if any) */}
    {customEmojis.length > 0 && (
      <div className="flex gap-1 mb-2 border-t pt-2">
        {customEmojis.slice(0, 6).map(ce => (
          <button key={ce.shortcode} onClick={() => handleReact(`custom:${ce.shortcode}`)}>
            <img src={ce.image_url} alt={ce.alt_text} className="h-5 w-5" />
          </button>
        ))}
      </div>
    )}
    {/* "More" button to open full EmojiPicker */}
    <Button variant="ghost" size="sm" onClick={() => setFullPickerOpen(true)}>
      <Plus className="h-3 w-3 mr-1" /> More
    </Button>
  </PopoverContent>
</Popover>
```

### 4.10 Frontend Component Tree

```
MessageBubble (enhanced)
├── ContentWrapper (onDoubleClick → quickReact)
│   └── ... (existing message content)
│
├── ReactionBar (enhanced)
│   ├── ReactionBadge[] (per unique emoji)
│   │   ├── EmojiDisplay
│   │   │   ├── Unicode: <span>heart</span>
│   │   │   └── Custom: <img src={resolvedUrl} alt={shortcode} />
│   │   ├── Count <span>{count}</span>
│   │   ├── OwnReactionHighlight (bg-primary/20 if current user reacted)
│   │   └── PopAnimation (reaction-badge-enter CSS class)
│   │
│   ├── ReactionDetailPopover (on badge click)
│   │   ├── EmojiTabs
│   │   │   └── Tab[] (emoji icon + count)
│   │   └── UserList (per selected tab)
│   │       └── UserRow[] (avatar + display_name)
│   │
│   └── AddReactionButton (SmilePlus icon)
│       └── EnhancedReactionPicker (Popover)
│           ├── QuickRow (6 common emojis)
│           ├── CustomRow (up to 6 custom emojis, if any)
│           └── MoreButton → Full EmojiPicker (MSG-006)
│
└── MessageMeta (existing: timestamp, read status)

emojiStore (Zustand)
├── quickReactEmoji: string (default "heart", persisted in localStorage)
├── recentEmojis: string[] (last 20 used, persisted)
└── setQuickReactEmoji: (emoji: string) => void
```

**State Management (MessageBubble)**:
```typescript
// Reaction mutations
const reactMut = useMutation({
  mutationFn: (data: { emoji: string }) =>
    addReaction(conversationId, messageId, data),
  onMutate: async ({ emoji }) => {
    // Optimistic update: add reaction badge immediately
    await queryClient.cancelQueries(["messages", conversationId]);
    const prev = queryClient.getQueryData(["messages", conversationId]);
    // ... optimistic update logic ...
    return { prev };
  },
  onError: (_, __, ctx) => queryClient.setQueryData(["messages", conversationId], ctx?.prev),
  onSettled: () => queryClient.invalidateQueries(["messages", conversationId]),
});

const unreactMut = useMutation({
  mutationFn: (data: { emoji: string }) =>
    removeReaction(conversationId, messageId, data),
  // ... same optimistic pattern ...
});

// Animation state
const [animatingEmoji, setAnimatingEmoji] = useState<string | null>(null);
```

### 4.11 Frontend: Quick-React Default Setting

**File**: `frontend/src/stores/emojiStore.ts` **(NEW — does not exist yet)**

<!-- NOTE: emojiStore.ts does not exist in the codebase. The existing Zustand stores are: authStore.ts, impersonationStore.ts, offlineStore.ts, shortcutStore.ts, tenantStore.ts, uiStore.ts (all in frontend/src/stores/). This store would need to be created as part of MSG-006 or this ticket. -->

```typescript
interface EmojiStore {
  quickReactEmoji: string;  // Default: "heart"
  recentEmojis: string[];   // Last 20 used
  setQuickReactEmoji: (emoji: string) => void;
}
```

Persisted in localStorage. Configurable from the emoji picker settings or a messaging preferences page.

### 4.12 Custom Emoji Reaction Rendering

In the reaction badge display:

```tsx
function ReactionBadge({ emoji, count, isOwn }: { emoji: string; count: number; isOwn: boolean }) {
  const isCustom = emoji.startsWith("custom:");
  const shortcode = isCustom ? emoji.slice(7) : null;

  // Use resolveCustomShortcodes to get image URL for custom emojis
  const { data: customEmojiMap } = useQuery({
    queryKey: ["custom-emoji-resolve", shortcode],
    queryFn: () => resolveCustomShortcodes([shortcode!]),
    enabled: isCustom && !!shortcode,
    staleTime: 10 * 60 * 1000,
  });

  return (
    <span className={cn(
      "inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs",
      isOwn ? "bg-primary/20" : "bg-muted"
    )}>
      {isCustom && customEmojiMap?.[shortcode!] ? (
        <img src={customEmojiMap[shortcode!]} alt={shortcode!} className="h-4 w-4" />
      ) : (
        <span>{emoji}</span>
      )}
      <span>{count}</span>
    </span>
  );
}
```

---

## 5. Error Handling Matrix

| # | Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|---|----------|-------------|------------|---------------------|-----------------|
| 1 | 21st unique emoji reaction | 400 | `reaction_limit` | "Maximum 20 unique reactions per message" | Use an existing emoji or remove one first |
| 2 | React on non-existent message | 404 | `message_not_found` | "Message not found" | Refresh conversation |
| 3 | React on non-existent conversation | 404 | `conversation_not_found` | "Conversation not found" | Navigate back to messages list |
| 4 | User not conversation participant | 403 | `not_participant` | "You are not a participant in this conversation" | Join the conversation first |
| 5 | Invalid custom emoji shortcode | 200 | — | (Stored as-is; frontend shows `custom:unknown` text fallback) | No server error; shortcode resolution handles missing emojis gracefully |
| 6 | Empty emoji string | 422 | `validation_error` | "emoji is required" | Select a valid emoji |
| 7 | Emoji string too long (>64 chars) | 422 | `validation_error` | "emoji must be 64 characters or fewer" | Use a shorter emoji identifier |
| 8 | Unreact emoji not in reactions | 200 | — | (Idempotent; no error) | No action needed |
| 9 | Double-click on expired message | 200 | — | (Reaction added normally; expired messages can still receive reactions) | No restriction |
| 10 | Reaction details for message with no reactions | 200 | — | `{ "reactions": {} }` | No error; empty state |
| 11 | Batch user profile fetch partial failure | 200 | — | Missing names show truncated user_sub | Degraded gracefully; retry on next popover open |
| 12 | Custom emoji deleted after reaction added | 200 | — | Badge shows `:shortcode:` text instead of image | Custom emoji deletion doesn't remove historical reactions |

---

## 6. Implementation Plan

### 6.1 Files to Create

| File | Purpose |
|------|---------|
| `frontend/src/pages/messages/ReactionDetailPopover.tsx` | Popover showing who reacted with what |

### 6.2 Files to Modify

| File | Changes |
|------|---------|
| `app/routers/messaging.py` | Add 20-emoji limit to `react_to_message` (line 10087), add new `/reactions/details` GET endpoint |
| `frontend/src/pages/messages/MessageBubble.tsx` | Double-tap quick-react, animation, enhanced picker, custom emoji rendering |
| `frontend/src/api/endpoints/messaging.ts` | Add `getReactionDetails()` function (existing `reactToMessage` at line 447 covers add/remove) |
| `frontend/src/stores/emojiStore.ts` | **New file** — create Zustand store for `quickReactEmoji` and `recentEmojis` |

### 6.3 Step-by-Step Order

1. Add reaction limit validation (backend)
2. Add reaction details endpoint (backend)
3. Build ReactionDetailPopover
4. Add quick-react double-tap handler
5. Add reaction animation CSS + logic
6. Enhance reaction picker with full EmojiPicker + custom emojis
7. Add quick-react default setting to emojiStore
8. Add custom emoji rendering in reaction badges
9. Write E2E tests

---

## 7. Observability & Monitoring

### 7.1 Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `msg011_reaction_added_total` | Counter | `type` (unicode/custom), `source` (picker/quick_react) | Reactions added |
| `msg011_reaction_removed_total` | Counter | `type` (unicode/custom) | Reactions removed |
| `msg011_reaction_limit_hit_total` | Counter | — | Times the 20-emoji limit was reached |
| `msg011_reaction_details_fetched_total` | Counter | — | Reaction detail popover opened |
| `msg011_quick_react_total` | Counter | `emoji` | Quick-react (double-tap) uses |
| `msg011_custom_emoji_reaction_total` | Counter | — | Custom emoji reactions added |

### 7.2 Log Events

| Event | Level | Fields | Description |
|-------|-------|--------|-------------|
| `reaction.added` | DEBUG | `user_sub`, `message_id`, `emoji`, `source` | Reaction added |
| `reaction.removed` | DEBUG | `user_sub`, `message_id`, `emoji` | Reaction removed |
| `reaction.limit_reached` | INFO | `user_sub`, `message_id`, `unique_count` | Attempt to add 21st unique emoji |
| `reaction.details.fetched` | DEBUG | `user_sub`, `message_id`, `emoji_count`, `user_count` | Reaction details endpoint called |
| `reaction.custom_emoji.unresolvable` | WARN | `shortcode` | Custom emoji shortcode could not be resolved to image URL |

### 7.3 Alerts

| Alert | Condition | Severity | Action |
|-------|-----------|----------|--------|
| Reaction limit hit rate > 100/hr | `increase(msg011_reaction_limit_hit_total[1h]) > 100` | Info | May indicate abuse or need to increase limit |
| Reaction details latency p95 > 1s | `histogram_quantile(0.95, msg011_reaction_details_latency_ms) > 1000` | Warning | Check batch user profile fetch; add caching |
| Custom emoji resolve failure rate > 10% | Custom emoji reactions with unresolvable shortcodes | Warning | Check custom_emojis table; verify shortcode cleanup on emoji deletion |

### 7.4 Dashboard Queries

```promql
# Reaction engagement rate (reactions per message)
sum(increase(msg011_reaction_added_total[24h])) / sum(increase(messages_sent_total[24h]))

# Quick-react vs picker usage
sum(increase(msg011_reaction_added_total{source="quick_react"}[24h]))
sum(increase(msg011_reaction_added_total{source="picker"}[24h]))

# Custom emoji reaction adoption
sum(increase(msg011_custom_emoji_reaction_total[7d]))
```

---

## 8. Rollout Plan

### 8.1 Feature Flags

| Flag | Default | Description |
|------|---------|-------------|
| `MSG011_REACTION_LIMIT` | `true` | Enforce 20 unique emoji limit per message |
| `MSG011_REACTION_DETAILS` | `false` | Enable reaction detail popover |
| `MSG011_QUICK_REACT` | `false` | Enable double-tap quick-react gesture |
| `MSG011_REACTION_ANIMATION` | `false` | Enable pop animation on reaction badges |
| `MSG011_CUSTOM_EMOJI_REACTIONS` | `false` | Enable custom emoji in reaction picker |

### 8.2 Rollout Phases

| Phase | Duration | Actions |
|-------|----------|---------|
| 1. Backend deploy | Day 1 | Deploy reaction limit (always on) + details endpoint. Frontend flags OFF. |
| 2. Reaction details | Day 2-3 | Enable `MSG011_REACTION_DETAILS`. Test popover with existing reactions. Verify user profile batch fetch performance. |
| 3. Quick-react + animation | Day 4-5 | Enable `MSG011_QUICK_REACT` + `MSG011_REACTION_ANIMATION`. Test double-tap UX on desktop and mobile. |
| 4. Custom emoji reactions | Day 6-7 | Enable `MSG011_CUSTOM_EMOJI_REACTIONS` (depends on MSG-007 being deployed). Test custom emoji rendering in badges and popover. |
| 5. GA | Day 8 | Remove feature flags. All features enabled for all users. |

### 8.3 Rollback Procedure

1. **Reaction limit**: Cannot easily roll back (data is already limited). If limit causes issues, increase to 50 via config.
2. **Reaction details**: Disable `MSG011_REACTION_DETAILS` → popover button hidden. No data impact.
3. **Quick-react**: Disable `MSG011_QUICK_REACT` → double-tap handler removed. No data impact.
4. **Animation**: Disable `MSG011_REACTION_ANIMATION` → CSS class not applied. No data impact.
5. **Custom emoji reactions**: Disable `MSG011_CUSTOM_EMOJI_REACTIONS` → custom section hidden in picker. Existing `custom:*` reactions still render (shortcode text fallback if image unresolvable).

---

## 9. Performance Considerations

| # | Concern | Impact | Mitigation |
|---|---------|--------|------------|
| 1 | Reaction details batch profile fetch | 20 unique emojis * N users per emoji = up to hundreds of profile fetches | `BatchGetItem` (DDB) with max 100 keys per call. Cache user profiles in a local TTL map (60s). Limit response to first 50 users per emoji. |
| 2 | Custom emoji shortcode resolution | Each custom emoji badge triggers a `useQuery` | `staleTime: 10min` + `cacheTime: 30min` on resolve query. Batch all `custom:*` shortcodes in a single `resolveCustomShortcodes` call per message. |
| 3 | Optimistic reaction updates | Updating React Query cache for every reaction toggle | Use granular cache update: modify only the affected message's `reactions` field, not the entire page list. Avoid full query invalidation on optimistic path. |
| 4 | Animation re-renders | `animatingEmoji` state change triggers re-render of all badges | Isolate animation state per badge using `ReactionBadge` as a separate `React.memo` component. |
| 5 | Double-click event conflicts | Double-click can conflict with text selection | Cancel text selection on double-click of message content. Use `event.preventDefault()` in handler. Only apply to message content area, not reaction bar. |
| 6 | Reaction detail popover data freshness | Stale user list if reactions change while popover is open | `refetchOnWindowFocus: true` on the details query. Close popover on SSE reaction update. |
| 7 | Many reactions on a single message | 20 unique emojis each with 100+ users = large reactions map | DDB item size: 20 emojis * 100 users * ~50 bytes = ~100KB — well within 400KB limit. Frontend renders up to 20 badges — negligible DOM. |
| 8 | Quick-react default emoji not in recent | emojiStore.quickReactEmoji might be stale after emoji store reset | Default to "heart" if stored emoji is invalid. localStorage read on store init is sync — no flash. |

---

## 10. E2E Test Plan

### 10.1 Test File

`frontend/e2e/emoji-reactions-enhanced.spec.ts` — 16 tests across 4 sections.

### 10.2 Test Setup

```typescript
const TS = Date.now();
let dmConvoId: string;
let testMsgId: string;

test.beforeAll(async ({ browser }) => {
  // Set up Alice and Bob sessions
  // Create DM conversation
  // Alice sends a test message for reactions
});
```

### 10.3 Section 326: Reaction Limit & Details API (5 tests)

| # | Test | Assertion |
|---|------|-----------|
| 326.1 | Add reaction to message | POST `/messages/{id}/reactions` with `emoji=smiley`; 200 |
| 326.2 | Reaction details endpoint returns user info | GET `/messages/{id}/reactions/details`; 200; has `reactions.smiley` array with `user_sub` and `display_name` |
| 326.3 | 20 unique reactions allowed | Add 20 different emojis; all succeed |
| 326.4 | 21st unique reaction rejected | Add 21st emoji; 400; "Maximum 20 unique reactions per message" |
| 326.5 | Adding same emoji by second user succeeds (not a new unique) | Bob adds `smiley` (already exists from Alice); 200; count increases |

### 10.4 Section 327: Quick-React & Animation (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 327.1 | Double-click message adds default reaction | Navigate to conversation; double-click message; heart reaction appears |
| 327.2 | Double-click again removes reaction | Double-click same message; heart reaction removed |
| 327.3 | Reaction badge shows count | After reaction; badge shows emoji + "1" |
| 327.4 | Reaction badge has pop animation class | After adding reaction; badge element has `reaction-badge-enter` class |

### 10.5 Section 328: Reaction Detail Popover UI (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 328.1 | Clicking reaction area opens detail popover | Click on reaction badge area; `[data-testid="reaction-detail-popover"]` visible |
| 328.2 | Popover shows emoji tabs | Popover has tabs for each reacted emoji |
| 328.3 | Popover shows user names | Under emoji tab; display name of reactor visible |
| 328.4 | Closing popover hides it | Click outside popover; `[data-testid="reaction-detail-popover"]` not visible |

### 10.6 Section 329: Custom Emoji Reactions (3 tests)

| # | Test | Assertion |
|---|------|-----------|
| 329.1 | React with custom emoji via API | POST with `emoji=custom:test_emoji`; 200 |
| 329.2 | Custom emoji reaction appears in message | GET messages; message has `reactions.custom:test_emoji` with user entry |
| 329.3 | Reaction details includes custom emoji | GET details; `reactions["custom:test_emoji"]` has user list |

---

## 11. Security Considerations

- Reaction limit (20) prevents abuse/spam
- Reaction details only visible to conversation participants
- Custom emoji images served from platform S3 (no external URLs)
- Double-tap handler is client-side only — no new attack surface
- Emoji strings are stored as map keys in DDB — max key length enforced by validation (64 chars)
- Custom emoji shortcodes are validated to match `^[a-zA-Z0-9_-]+$` pattern
- No script injection possible via emoji keys (stored as DDB map keys, not rendered as HTML)

---

## 12. Dependencies

| Dependency | Ticket | Status |
|------------|--------|--------|
| EmojiPicker component | MSG-006 | Required |
| Custom emoji system | MSG-007 | Required (for custom emoji in reactions) — does not exist yet |
| Existing reaction endpoints | Existing | Available (see `messaging.py:10087`) |

---

## Codebase References

### Backend — `app/routers/messaging.py`
| Reference | Line | Notes |
|-----------|------|-------|
| `ReactIn` model | 2150 | Existing input model: `emoji: str` + `action: Literal["add", "remove"]`; ticket calls it "ReactionIn" but actual name is `ReactIn`; max_length=32 (may need increase for custom emoji shortcodes) |
| `MessageOut.reactions_counts` | 2365 | `Optional[Dict[str, int]]` — emoji-to-count mapping |
| `MessageOut.my_reactions` | 2366 | `Optional[List[str]]` — emojis the viewer has reacted with |
| `_reaction_summaries(message_item, viewer_user_id)` | 5363 | Computes `reactions_counts` and `my_reactions` from raw DDB set data |
| `_get_message_or_404(conversation_id, message_id)` | 5383 | Reads message item for reaction limit check |
| `react_to_message()` endpoint | 10087 | Existing reaction endpoint; uses ADD/DELETE DDB set operations |
| DDB Set operations (ADD/DELETE) | 10106-10117 | Reactions stored as DDB String Sets, not maps of booleans |
| `fanout_event_to_conversation()` | 5297 | Used at line 10127 to broadcast `reaction:update` SSE events |

### Frontend — Existing Files
| File | Line | Notes |
|------|------|-------|
| `frontend/src/pages/messages/MessageBubble.tsx` | 485 | `reactMut` mutation; line 789: quick emoji row; line 1688: reaction badge rendering |
| `frontend/src/api/endpoints/messaging.ts` | 447 | `reactToMessage()` — existing API function for add/remove reactions |
| `frontend/src/api/types.ts` | — | `MessageOut` type with `reactions_counts`, `my_reactions` fields |

### Frontend — New Files
| File | Notes |
|------|-------|
| `frontend/src/pages/messages/ReactionDetailPopover.tsx` | New component for reaction details |
| `frontend/src/stores/emojiStore.ts` | New Zustand store for `quickReactEmoji` + `recentEmojis` |

### DynamoDB Tables
| Table | Notes |
|-------|-------|
| `Messages` (PK: `conversation_id`, SK: `message_id`) | Reactions stored as nested map of String Sets (`reactions.{emoji}` = SS[user_ids]) |
| `custom_emojis` | Does NOT exist yet — requires MSG-007 |

### Corrections Applied
| Original Claim | Correction |
|----------------|------------|
| Separate `/unreact` endpoint | Does not exist; `react_to_message` (line 10087) handles both add/remove via `ReactIn.action` |
| Reactions stored as `{ emoji: { user_id: True } }` (map of booleans) | Actually stored as DDB String Sets via ADD/DELETE operations (line 10106) |
| `ReactionIn` model name | Actual name is `ReactIn` (line 2150) |
| `MessageOut.reactions` as `Record<string, Record<string, boolean>>` | Actual fields are `reactions_counts: Dict[str, int]` and `my_reactions: List[str]` (lines 2365-2366) |
| `emojiStore.ts` referenced as existing | Does not exist; must be created |
| `custom_emojis` table referenced as existing | Does not exist; requires MSG-007 |
| `resolveCustomShortcodes` API referenced | Does not exist; requires MSG-007 |
| Reaction endpoint returns `{ok, conversation_id, message_id, emoji, action}` | Actually returns only `{"ok": true}` (line 10150) |
