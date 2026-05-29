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
| User | As a user, I want to double-tap a message to add a ❤️ reaction quickly. | Double-tap → ❤️ added; animation plays; reaction count updates. |
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
- `POST /messaging/conversations/{conv_id}/messages/{msg_id}/reactions` — add reaction
- `POST /messaging/conversations/{conv_id}/messages/{msg_id}/unreact` — remove reaction
- Reactions stored on message item as: `reactions: { "😀": { "user_sub_1": True, "user_sub_2": True } }`
- `MessageOut.reactions` returns this map in the API response

**Frontend** (`MessageBubble.tsx`):
- Displays reaction badges below message content
- Each badge shows emoji + count
- Click on existing badge to toggle own reaction
- React button opens a small emoji row (limited selection)

### 2.2 Reaction Data Shape

```typescript
// Current reactions on MessageOut
reactions?: Record<string, Record<string, boolean>>;
// Example: { "😀": { "user_sub_1": true }, "❤️": { "user_sub_1": true, "user_sub_2": true } }
```

This structure supports both displaying counts (Object.keys(users).length) and checking the current user's reaction (users[currentUserSub]).

### 2.3 Custom Emoji Storage (MSG-007)

Custom emojis are stored in the `custom_emojis` table. In reactions, they're represented as `custom:shortcode` keys (e.g., `custom:my_cat`). The `resolveCustomShortcodes` API resolves shortcodes to image URLs for rendering.

### 2.4 Gaps

1. **No reaction detail popover** — can't see who reacted with what.
2. **No quick-react (double-tap)** — no gesture for fast reactions.
3. **No custom emoji in reaction picker** — picker only shows Unicode emojis.
4. **No reaction animation** — no visual feedback when adding reactions.
5. **No reaction limit** — unlimited unique emojis per message.
6. **No configurable default quick-react emoji** — hardcoded would need to be set.

---

## 3. Technical Design

### 3.1 Backend: Reaction Limit

Add validation in the reaction endpoint to enforce max 20 unique emojis:

```python
@router.post("/conversations/{conv_id}/messages/{msg_id}/reactions")
def add_reaction(conv_id: str, msg_id: str, body: ReactionIn, ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    emoji = body.emoji

    msg = _get_message_or_404(conv_id, msg_id)
    reactions = msg.get("reactions", {})

    # Check limit: max 20 unique emoji keys
    if emoji not in reactions and len(reactions) >= 20:
        raise HTTPException(
            status_code=400,
            detail="Maximum 20 unique reactions per message"
        )

    # Add reaction (existing logic)
    ...
```

### 3.2 Backend: Reaction User Info Endpoint

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

### 3.3 Frontend: ReactionDetailPopover

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
  ┌────────────────────────────────┐
  │  😀 (3)  │  ❤️ (5)  │  🔥 (2)  │
  ├────────────────────────────────┤
  │  👤 Alice                      │
  │  👤 Bob                        │
  │  👤 Charlie                    │
  └────────────────────────────────┘
  ```
- Custom emojis render as `<img>` in tabs
- `data-testid="reaction-detail-popover"`

### 3.4 Frontend: Quick React (Double-Tap)

**File**: `frontend/src/pages/messages/MessageBubble.tsx`

```typescript
const handleDoubleClick = useCallback(() => {
  const defaultEmoji = emojiStore.quickReactEmoji || "❤️";
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

### 3.5 Frontend: Reaction Animation

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

### 3.6 Frontend: Enhanced Reaction Picker

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
      {["👍", "❤️", "😂", "😮", "😢", "🔥"].map(emoji => (
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

### 3.7 Frontend: Quick-React Default Setting

**File**: `frontend/src/stores/emojiStore.ts`

```typescript
interface EmojiStore {
  // ... existing fields from MSG-006 ...
  quickReactEmoji: string;  // Default: "❤️"
  setQuickReactEmoji: (emoji: string) => void;
}
```

Persisted in localStorage. Configurable from the emoji picker settings or a messaging preferences page.

### 3.8 Custom Emoji Reaction Rendering

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

## 4. Implementation Plan

### 4.1 Files to Create

| File | Purpose |
|------|---------|
| `frontend/src/pages/messages/ReactionDetailPopover.tsx` | Popover showing who reacted with what |

### 4.2 Files to Modify

| File | Changes |
|------|---------|
| `app/routers/messaging.py` | Add reaction limit (20), reaction details endpoint |
| `frontend/src/pages/messages/MessageBubble.tsx` | Double-tap quick-react, animation, enhanced picker, custom emoji rendering |
| `frontend/src/stores/emojiStore.ts` | Add `quickReactEmoji` field |

### 4.3 Step-by-Step Order

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

## 5. E2E Test Plan

### 5.1 Test File

`frontend/e2e/emoji-reactions-enhanced.spec.ts` — 10 tests across 3 sections.

### 5.2 Test Setup

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

### 5.3 Section 326: Reaction Limit & Details API (4 tests)

| # | Test | Assertion |
|---|------|-----------|
| 326.1 | Add reaction to message | POST `/messages/{id}/reactions` with `emoji=😀`; 200 |
| 326.2 | Reaction details endpoint returns user info | GET `/messages/{id}/reactions/details`; 200; has `reactions.😀` array with `user_sub` and `display_name` |
| 326.3 | 20 unique reactions allowed | Add 20 different emojis; all succeed |
| 326.4 | 21st unique reaction rejected | Add 21st emoji; 400; "Maximum 20 unique reactions per message" |

### 5.4 Section 327: Quick-React & Animation (3 tests)

| # | Test | Assertion |
|---|------|-----------|
| 327.1 | Double-click message adds default reaction | Navigate to conversation; double-click message; ❤️ reaction appears |
| 327.2 | Double-click again removes reaction | Double-click same message; ❤️ reaction removed |
| 327.3 | Reaction badge shows count | After reaction; badge shows emoji + "1" |

### 5.5 Section 328: Reaction Detail Popover UI (3 tests)

| # | Test | Assertion |
|---|------|-----------|
| 328.1 | Clicking reaction area opens detail popover | Click on reaction badge area; `[data-testid="reaction-detail-popover"]` visible |
| 328.2 | Popover shows emoji tabs | Popover has tabs for each reacted emoji |
| 328.3 | Popover shows user names | Under emoji tab; display name of reactor visible |

---

## 6. Error Handling

| Scenario | Status | Detail |
|----------|--------|--------|
| 21st unique emoji | 400 | "Maximum 20 unique reactions per message" |
| React on non-existent message | 404 | "Message not found" |
| Invalid custom emoji shortcode | 200 | Stored as-is; frontend shows fallback text |

---

## 7. Security Considerations

- Reaction limit (20) prevents abuse/spam
- Reaction details only visible to conversation participants
- Custom emoji images served from platform S3 (no external URLs)
- Double-tap handler is client-side only — no new attack surface

---

## 8. Dependencies

| Dependency | Ticket | Status |
|------------|--------|--------|
| EmojiPicker component | MSG-006 | Required |
| Custom emoji system | MSG-007 | Required (for custom emoji in reactions) |
| Existing reaction endpoints | Existing | Available |
