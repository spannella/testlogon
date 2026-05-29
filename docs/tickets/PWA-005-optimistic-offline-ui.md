# PWA-005: Optimistic UI for Offline-Queued Items

**Ticket**: PWA-005
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-28
**Depends on**: PWA-003, PWA-004

---

## 1. Overview & Motivation

### 1.1 Problem Statement

When a user sends a message or creates a post while offline, the current code enqueues the
action in the offline store and displays a toast notification. However, the queued item
does NOT appear inline in the UI. The user sees:

- **Messages**: The toast "You're offline -- message queued and will send when reconnected"
  appears, but the conversation view does NOT show the queued message. The compose bar
  clears, the message seemingly vanishes, and the user has no visual confirmation that
  their message exists or will be sent. The only feedback is the transient toast and the
  queue count badge in the `OfflineBanner`.
- **Feed**: Similarly, the toast "You're offline -- post queued and will publish when
  reconnected" appears, but the compose area resets and the queued post is not shown in the
  feed timeline.

This creates a jarring experience: the user types a message, hits send, and it disappears
into a void. Worse, if the user does not notice the toast (which auto-dismisses after a
few seconds), they may assume the message was lost and re-type it.

The platform already has optimistic UI patterns for online sends. The `sendText` mutation
in `ConversationView.tsx` (lines 207-269) creates an optimistic `Message` object and
prepends it to the React Query cache via `onMutate`. This ticket extends that pattern to
offline-queued items, showing them inline with a visual "pending" state that animates to
"sent" when the queue flushes successfully.

### 1.2 User Stories

1. **As a user who sends a message while offline**, I want the message to appear
   immediately in the conversation with a "pending" clock icon, so I know it was captured.
2. **As a user**, I want to see my queued message transition from "pending" to "sent"
   (clock icon fading to checkmark) when connectivity returns and the flush succeeds.
3. **As a user**, I want a queued message that permanently fails to show a red error icon
   with "Retry" and "Discard" options, so I can act on the failure directly in context.
4. **As a user who creates a post while offline**, I want the post to appear at the top
   of my feed with a "waiting to send" indicator, so I know it will be published later.
5. **As a user**, I want queued feed posts to transition smoothly from "pending" to
   "published" without a jarring page jump.

### 1.3 Design Principles

- **Immediate Feedback**: Queued items appear instantly at the insertion point, before any
  network activity.
- **Distinguishable State**: Pending items are visually distinct from sent items (muted
  color, clock icon, progress animation).
- **Graceful Transitions**: Success animates from clock to checkmark; failure animates to
  error icon. No page reloads or hard refreshes.
- **Consistent with Online Optimistic UI**: The offline optimistic path reuses the same
  optimistic message shape as the online path, differing only in the status indicator.
- **Resilient to Page Reloads**: If the user reloads while offline, the optimistic items
  should re-appear from the persisted queue (they are in the offline store).

### 1.4 Scope & Non-Goals

**In scope**:
- Offline optimistic display for text messages in both DMs and group chats
- Offline optimistic display for feed posts (plain text, markdown, rich text)
- Pending, sending, sent, and failed state indicators
- Retry and discard actions for failed items
- Restoration of optimistic items after page reload (from persisted localStorage queue)
- Sidebar preview updates for offline-queued last messages
- Accessibility: screen reader announcements for state transitions

**Out of scope (future tickets)**:
- Image/file message offline queueing (requires serializing `File` objects to IndexedDB)
- Offline editing of queued messages before flush
- Offline queueing of reactions, tips, or unlocks
- Offline drafts auto-save (handled by existing draft system in `CreatePost.tsx`)
- Service Worker Background Sync integration (covered by PWA-004; this ticket consumes
  its success/failure signals)

---

## 2. Current State Analysis

### 2.1 Online Optimistic Message (`ConversationView.tsx`, lines 207-269)
<!-- VERIFIED: ConversationView.tsx:207-269 -->

The `sendText` mutation's `onMutate` callback creates an optimistic `Message` object:

```typescript
const sendText = useMutation({
  mutationFn: (payload: SendTextMessageReq) => sendTextMessage(convoId, payload),
  onMutate: async (payload) => {
    if (payload.send_at) return { snapshot: undefined, isScheduled: true };

    await queryClient.cancelQueries({ queryKey: ["messages", convoId] });
    const snapshot = queryClient.getQueryData(["messages", convoId]);

    const optimistic: Message = {
      message_id: `optimistic-${Date.now()}`,
      conversation_id: convoId,
      sender_id: userId ?? "",
      kind: "text",
      text: payload.encryption ? "" : (payload.text ?? ""),
      is_encrypted: !!payload.encryption,
      encryption: payload.encryption,
      created_at: Date.now() / 1000,
      reactions_counts: {},
      reply_to_message_id: payload.reply_to_message_id,
    };

    queryClient.setQueryData<InfiniteData<MessagesPage>>(
      ["messages", convoId],
      (old) => {
        if (!old?.pages.length) return old;
        const pages = old.pages.map((p, i) =>
          i === 0 ? { ...p, messages: [optimistic, ...(p.messages ?? [])] } : p,
        );
        return { ...old, pages };
      },
    );

    return { snapshot, isScheduled: false };
  },
  onSuccess: (_data, payload, context) => {
    // ... invalidate queries to replace optimistic with real ...
  },
  onError: (err, _payload, context) => {
    if (context?.snapshot) {
      queryClient.setQueryData(["messages", convoId], context.snapshot);
    }
    toast.error(err.message || "Failed to send message");
  },
});
```

Key observations:
- The optimistic message has `message_id: "optimistic-${Date.now()}"` -- a unique ID that
  starts with `"optimistic-"`.
- It is prepended to `pages[0].messages` (the newest page, newest-first), so after
  `allMessages` reversal it appears at the bottom (newest position).
- On success, `queryClient.invalidateQueries` replaces the optimistic entry with the real
  server response.
- On error, the snapshot is restored, removing the optimistic message.

#### 2.1.1 Detailed Line-by-Line Analysis of Online Optimistic Flow

**Lines 207-211 -- Mutation setup and scheduled message bypass**:
The `sendText` mutation wraps `sendTextMessage(convoId, payload)` from
`@/api/endpoints/messaging`. The `onMutate` callback checks `payload.send_at` first: if
the message is scheduled, it skips optimistic injection entirely (scheduled messages appear
in the `ScheduledMessages` panel, not the conversation timeline). This is critical because
we must replicate the same guard for offline queuing: scheduled messages must NOT be queued
offline (they need server-side delivery at the exact scheduled time).

**Lines 213-214 -- Cancel in-flight queries and snapshot**:
`cancelQueries` prevents any pending `getMessages` refetch from overwriting the optimistic
update. The snapshot is taken for rollback on error. The `["messages", convoId]` query key
targets the `useInfiniteQuery` that powers the conversation view.

**Lines 216-227 -- Optimistic message shape**:
The optimistic `Message` object must satisfy the `Message` interface from
`frontend/src/api/types.ts` (starting at line 882). Required fields:
<!-- VERIFIED: types.ts:882 -- Message interface starts at line 882 -->
- `message_id`: Must start with `"optimistic-"` so `MessageBubble` can detect it (line 1145:
  `message.message_id.startsWith("optimistic-")` is already used to skip `markViewed` for
  optimistic messages).
  <!-- VERIFIED: MessageBubble.tsx:1145 -->
- `conversation_id`: Must match the current conversation.
- `sender_id`: Current user's ID from `authStore`.
- `kind`: Always `"text"` for text messages.
- `created_at`: Unix timestamp in seconds (not milliseconds).
- `reactions_counts`: Empty object `{}` (no reactions yet).
- `text`: The plain text, or empty string if encrypted.
- `is_encrypted` / `encryption`: Forwarded from the payload.

**Lines 229-241 -- Cache injection**:
`setQueryData` modifies the infinite query cache in-place. The callback receives the
current `InfiniteData<MessagesPage>` structure, which has `pages: MessagesPage[]` where
each `MessagesPage` is `{ messages: Message[]; next_cursor?: string }`. The optimistic
message is prepended to `pages[0].messages`. Since `pages[0]` contains the newest messages
in newest-first order, prepending places the optimistic message at position 0 (newest).

**Lines 245-268 -- Success and error handling**:
On success, `invalidateQueries` triggers a background refetch that replaces the optimistic
message with the real server-returned message (which has a different `message_id`). On
error, the snapshot is restored, which removes the optimistic message entirely. The user
sees a toast error instead.

### 2.2 Offline Enqueue Path (`ConversationView.tsx`, lines 1028-1033)
<!-- VERIFIED: ConversationView.tsx:1028-1033 -->

The offline path bypasses the mutation entirely:

```typescript
if (!isOnline && !fullPayload.send_at) {
  addToQueue({ type: "send_message", payload: { conversationId: convoId, req: fullPayload } });
  toast.info("You're offline — message queued and will send when reconnected");
  setReplyingTo(null);
  return;
}
```

This calls `addToQueue` (which writes to `offlineStore` and localStorage) but does NOT:
- Create an optimistic message
- Update the React Query cache
- Show the message inline in the conversation

#### 2.2.1 The `addToQueue` Implementation (`offlineStore.ts`, lines 46-55)
<!-- VERIFIED: offlineStore.ts lines 46-55 contain the addToQueue implementation -->

The `addToQueue` method in the Zustand store generates a unique ID and timestamp:

```typescript
addToQueue: (action) =>
  set((s) => ({
    queue: [
      ...s.queue,
      {
        ...action,
        id: `offline-${Date.now()}-${Math.random().toString(36).slice(2)}`,
        enqueuedAt: Date.now(),
      } as OfflineAction,
    ],
  })),
```

The generated `id` format is `offline-<timestamp>-<random>`. This ID is critical because:
1. It uniquely identifies the queued action for later removal via `removeFromQueue`.
2. It will serve as the correlation key between the offline store entry, the optimistic
   React Query cache entry, and the IndexedDB sync queue entry (from PWA-004).
3. The random suffix (`Math.random().toString(36).slice(2)`) prevents collisions when
   multiple messages are queued within the same millisecond.

**Problem**: The current `addToQueue` does not return the generated ID. The caller cannot
know the ID before calling `addToQueue`, which means it cannot construct the optimistic
message with a matching `message_id`. We need a new method `addToQueueWithId` that accepts
a pre-generated ID, or we need to modify `addToQueue` to return the generated ID.

#### 2.2.2 The `fullPayload` Construction (`ConversationView.tsx`, lines 1021-1025)

The `fullPayload` is constructed by merging the ComposeBar payload with reply linkage:

```typescript
const fullPayload = {
  ...payload,
  ...buildReplyLinkagePayload(replyingTo),
};
```

Where `buildReplyLinkagePayload` (lines 151-160) adds:
- `reply_to_message_id`: The message being replied to.
- `parent_message_id`: Same as `reply_to_message_id`.
- `thread_id`: If the reply target is part of a thread.
- `thread_root_message_id`: The thread root.

The optimistic offline message must include these fields so that if the user is replying
to a message, the reply preview shows correctly in the conversation view even while offline.

#### 2.2.3 The `isOnline` State Source

The `isOnline` value comes from `useOfflineStore((s) => s.isOnline)` (line 72). This is
hydrated from `navigator.onLine` on page load (line 42 of `offlineStore.ts`) and updated
by the `useOfflineQueue` hook (lines 17-27 of `useOfflineQueue.ts`) which listens to
`window.addEventListener("online"/"offline")`. The OfflineBanner also independently
listens to these events (lines 9-18 of `OfflineBanner.tsx`).
<!-- VERIFIED: ConversationView.tsx:72, offlineStore.ts:42, useOfflineQueue.ts:17-27 -->

**Important**: The `isOnline` state in the Zustand store and the `offline` state in the
`OfflineBanner` component are maintained independently. They should always agree, but in
edge cases (e.g., Zustand hydration from localStorage restoring a stale `isOnline` value),
they could diverge. The Zustand persist middleware's `partialize` function (line 66 of
`offlineStore.ts`) explicitly excludes `isOnline` from persistence:
<!-- VERIFIED: offlineStore.ts:66 partialize excludes isOnline -->

```typescript
partialize: (state) => ({ queue: state.queue }),
```

This means `isOnline` is always re-derived from `navigator.onLine` on hydration, which is
the correct behavior.

### 2.3 Offline Enqueue in CreatePost (`CreatePost.tsx`, lines 635-654)
<!-- VERIFIED: CreatePost.tsx:635-654 -->

```typescript
if (!isOnline) {
  const queuedPayload = {
    ...buildContentPayload(body, editorMode, richDoc),
    ...(imageUrls.length > 0 ? { image_urls: imageUrls } : {}),
    ...(pendingFiles.length > 0 ? { file_paths: pendingFiles.map((f) => f.path) } : {}),
    ...(unlockPriceCents ? { unlock_price_cents: unlockPriceCents } : {}),
    // ... more fields ...
  };
  addToQueue({ type: "create_post", payload: queuedPayload });
  toast.info("You're offline — post queued and will publish when reconnected");
  resetComposer();
  return;
}
```

Similarly, no optimistic post is shown in the feed.

#### 2.3.1 Detailed Payload Construction

The `queuedPayload` merges several sources:

1. **`buildContentPayload(body, editorMode, richDoc)`** (from `MarkdownComposer`):
   Returns `{ body_plain, body_markdown?, body_rich?, body_format }` depending on the
   current editor mode. For `editorMode === "plain"`, only `body_plain` and
   `body_format: "plain"` are set. For `"markdown"`, `body_markdown` is also included.
   For `"rich"`, the full `body_rich` JSON document is included.

2. **`imageUrls`**: Array of server-side image URLs that were uploaded BEFORE going offline.
   These are valid S3 mock URLs (e.g., `http://localhost:4566/...`). If the user went
   offline mid-upload, these may be partial.

3. **`pendingFiles`**: Array of `FileEntry` objects from the file picker. The
   `file_paths` property sends path references to the file manager, not raw file data.

4. **Scheduling fields**: `publish_at`, `schedule_timezone`, `scheduled_at_local`. These
   are included even when offline, though scheduled posts offline have the same limitation
   as scheduled messages: they need server-side timing.

5. **Lock fields**: `unlock_price_cents`, `unlock_limit`, and lottery configuration fields.

6. **Video field**: `video_id` from the video picker.

**Key observation**: The `resetComposer()` call (line 653) clears the compose area
immediately. After PWA-005, we should still reset the composer (the user's input is
captured in the queue), but the queued post should appear in the feed timeline.

#### 2.3.2 The `CreatePost` Rendering Context

`CreatePost` (defined in `frontend/src/pages/feed/CreatePost.tsx`) is rendered inside the
`FeedTimeline` component (line 88 of `FeedTimeline.tsx`):

```typescript
{showComposer ? <CreatePost /> : null}
```

`FeedTimeline` itself is rendered inside `NewsFeed` (line 9 of `NewsFeed.tsx`):

```typescript
<FeedTimeline showComposer />
```

And `NewsFeed` is rendered inside `FeedPage` (line 15 of `FeedPage.tsx`):
<!-- CORRECTED: was "line 13", actually line 15 -->

```typescript
<NewsFeed />
```

The feed data comes from `useFeedTimelineQuery` (in `FeedTimeline.tsx`, line 35):

```typescript
const feedQuery = useFeedTimelineQuery({ authorId, q, from, to, hasMedia, cursor });
const allPosts = useMemo(() => mergeFeedPages((feedQuery.data?.pages ?? []) as any), [feedQuery.data?.pages]);
```

The `allPosts` array is then mapped to `PostCard` components (lines 98-113). Offline
optimistic posts must be prepended to this `allPosts` array.

### 2.4 Image Optimistic Flow (`ConversationView.tsx`, lines 298-334)
<!-- VERIFIED: ConversationView.tsx:298-334 (onMutate of sendImage mutation) -->

The `sendImage` mutation also creates an optimistic entry, including a local object URL
for the image preview:

```typescript
const optimistic: Message = {
  message_id: `optimistic-img-${Date.now()}`,
  conversation_id: convoId,
  sender_id: userId ?? "",
  kind: args.file.type === "application/pdf" ? "file" : "image",
  text: args.caption,
  created_at: Date.now() / 1000,
  reactions_counts: {},
  image: args.file.type.startsWith("image/")
    ? { url: URL.createObjectURL(args.file) }
    : undefined,
  // ...
};
```

Images are NOT queued when offline (the `sendImage` mutation simply fails). PWA-005 does
not change this -- image queueing requires serializing `File` objects, which is a separate
concern (future ticket).

#### 2.4.1 Why Image Offline Queueing Is Out of Scope

The `sendImage` mutation (lines 271-297) wraps `sendImageMessage(convoId, fd, opts)` which
<!-- VERIFIED: ConversationView.tsx:271-297 -->
sends a `FormData` object containing the raw `File`. Offline queueing requires persisting
the file to IndexedDB, which involves:
- Reading the file into an `ArrayBuffer` or `Blob`
- Storing it in IndexedDB (localStorage has a ~5MB limit)
- Reconstructing the `FormData` on flush

This is feasible but complex, especially for large files (video, multi-image gallery).
The offline store currently uses `localStorage` via Zustand's `persist` middleware, which
cannot handle binary data. A separate IndexedDB-based media queue is needed (future ticket).

**For PWA-005**: When the user attempts to send an image while offline, display a clear
toast: "Images cannot be sent while offline. Your message text has been queued." If the
compose bar has both text and an image, queue only the text portion.

### 2.5 `MessageBubble` Rendering (`MessageBubble.tsx`)

The `MessageBubble` component renders each message. It does not currently have any
"pending" state visualization. The component receives a `Message` object and renders
based on `kind`, `is_encrypted`, `text`, `image`, etc. There is no `status` field on
the `Message` type that distinguishes pending from sent.

#### 2.5.1 MessageBubble Component Structure (lines 315-691+)

The component is defined at line 315:

```typescript
export function MessageBubble({
  message, isOwn, showSender, conversationId,
  onReply, onViewThread, replyToMessage,
  viewedOnceIds, onViewOnce
}: MessageBubbleProps)
```

**Internal state** (lines 318-348): The component maintains extensive local state for
decrypt dialogs, tip workflows, edit mode, lottery reveal, etc. None of this state relates
to offline status, which will be a new concern.

**Rendering structure** (starting line 691):
1. **Outer flex container**: `cn("flex", isOwn ? "justify-end" : "justify-start")`
2. **Bubble wrapper**: `cn("group relative max-w-[75%] rounded-2xl px-4 py-2", ...)`
3. **Hover toolbar** (lines 702-821): Quick emoji reactions, reply, more actions dropdown.
   For offline messages, this toolbar should be disabled (cannot react/reply/forward/etc.
   to a message that has not reached the server yet).
4. **Reply preview** (lines 823-833): Shows the replied-to message. Should work normally
   for offline messages if the reply target exists in the cache.
5. **Message content** (lines 840-1190+): Complex conditional rendering tree:
   - Expired messages
   - Lottery lock card
   - Lottery result
   - Lock paywall (recipient view)
   - Encrypted content (decrypt dialog)
   - Lock badge (sender view)
   - Edit mode
   - View-once text
   - Plain text
   - Link previews
   - Image rendering
   - File rendering
   - Calendar share / event / meeting poll cards
   - Video share
   - Voice message / voicemail
   - Gallery
6. **Reactions bar** (rendered after content)
7. **Thread footer** (reply count, last activity)
8. **Timestamp** (the `time` variable at line 512)
9. **Delivery status** (ReadReceipts, DeliveryStatus components)

The `OfflineStatusBadge` should be inserted AFTER the message content and BEFORE the
timestamp/delivery status, so it appears naturally in the message flow.

#### 2.5.2 Hover Toolbar Disabling for Offline Messages

The hover toolbar (lines 702-821) contains actions that require server communication:
- React (emoji reaction)
- Reply (can be done locally -- reply state is client-side)
- Forward
- Hide
- Report
- Send Tip
- Edit
- Delete

For messages with `__offline`, most of these should be disabled. Only "Reply" makes sense
(setting `replyingTo` state). The toolbar could be hidden entirely, or each action could
check `message.__offline` and disable itself.

Recommended approach: hide the entire toolbar for offline messages since none of these
server-side actions can be performed until the message is sent:

```typescript
{!message.__offline && (
  <div className={cn(
    "absolute -top-2 opacity-0 transition-opacity group-hover:opacity-100 ...",
    // ...
  )}>
    {/* Quick emoji reactions, Reply, More actions */}
  </div>
)}
```

### 2.6 `allMessages` Assembly (`ConversationView.tsx`, lines 112-123)
<!-- VERIFIED: ConversationView.tsx:112-123 -->

```typescript
const allMessages = React.useMemo(() => {
  if (!data?.pages) return [];
  const msgs: Message[] = [];
  for (let i = data.pages.length - 1; i >= 0; i--) {
    const page = data.pages[i];
    if (page) msgs.push(...(page.messages ?? []).slice().reverse());
  }
  return msgs;
}, [data]);
```

This assembles messages from React Query infinite pages. Offline optimistic messages would
need to be injected into this list. Two approaches:

1. **Inject into React Query cache** (same as online optimistic): Modify `pages[0]` to
   include the queued message. This is consistent with the online path.
2. **Append to `allMessages` memo**: Add a secondary merge step that appends queue items
   after the query data. This keeps the query cache clean.

We use approach 1 for consistency.

#### 2.6.1 Detailed `allMessages` Assembly Logic

The infinite query data has this structure:

```
data = {
  pages: [
    { messages: [msg_newest, msg_2nd_newest, ...], next_cursor: "abc" },  // page 0 (newest)
    { messages: [msg_older_1, msg_older_2, ...], next_cursor: "def" },   // page 1
    { messages: [msg_oldest_1, msg_oldest_2, ...] },                     // page N (oldest)
  ],
  pageParams: [undefined, "abc", "def"],
}
```

The assembly loop iterates from the LAST page (oldest) to the FIRST page (newest), and
reverses each page's messages. The result is a chronological array: `[oldest, ..., newest]`.

When an optimistic message is prepended to `pages[0].messages`, it becomes position 0 in
the newest page. After the assembly reversal, it appears at the END of `allMessages`,
which is the bottom of the conversation view (newest position). This is correct.

For multiple offline messages queued in rapid succession:
- Queue order: msg_A queued first, msg_B queued second
- `pages[0].messages` after both: `[msg_B, msg_A, ...existing...]`
  (each prepend pushes the previous one down)
- After reversal: `[...existing..., msg_A, msg_B]`
- Display order: msg_A appears above msg_B (chronological order preserved)

This is correct: messages queued earlier appear higher in the conversation.

### 2.7 `OfflineBanner` Queue Count

The `OfflineBanner` (in `frontend/src/components/shared/OfflineBanner.tsx`) shows the
queue count:

```typescript
{queueCount > 0 && (
  <span className="ml-1 rounded-full bg-warning-foreground/20 px-2 py-0.5 text-xs font-semibold">
    {queueCount} queued
  </span>
)}
```

This provides a global indicator but not per-item inline feedback.

#### 2.7.1 OfflineBanner Architecture Analysis

The `OfflineBanner` component (33 lines) maintains its own `offline` state via
`useState(!navigator.onLine)` and listens to `window.addEventListener("online"/"offline")`.
The queue count comes from `useOfflineStore((s) => s.queue.length)`.

**Enhancement opportunity**: After PWA-005, the banner could show a breakdown:
- "3 queued (2 messages, 1 post)"
- Link to failed items: "1 failed -- tap to review"
- Progress during flush: "Sending 2 of 3..."

The banner renders at the top of the `AppShell` (line 61 of `AppShell.tsx`), above the
header. It slides in from the top with `animate-in slide-in-from-top duration-200`.

#### 2.7.2 OfflineBanner Enhanced Design

```typescript
export function OfflineBanner() {
  const [offline, setOffline] = useState(!navigator.onLine);
  const queue = useOfflineStore((s) => s.queue);
  const queueCount = queue.length;
  const failedCount = queue.filter((a) => a.__status === "failed").length;
  const pendingCount = queueCount - failedCount;

  // ... event listeners ...

  if (!offline && queueCount === 0) return null;

  return (
    <div className="flex w-full items-center justify-center gap-2 bg-warning px-4 py-2 ...">
      <WifiOff className="h-4 w-4" />
      {offline ? (
        <>
          You&apos;re offline &mdash; actions will be sent when reconnected
          {pendingCount > 0 && (
            <span className="ml-1 rounded-full bg-warning-foreground/20 px-2 py-0.5 text-xs font-semibold">
              {pendingCount} queued
            </span>
          )}
        </>
      ) : null}
      {failedCount > 0 && (
        <span className="ml-1 rounded-full bg-destructive/20 px-2 py-0.5 text-xs font-semibold text-destructive">
          {failedCount} failed
        </span>
      )}
    </div>
  );
}
```

### 2.8 `FeedPage` and `NewsFeed` Component

The `FeedPage` (`frontend/src/pages/feed/FeedPage.tsx`) is a minimal wrapper:

```typescript
export default function FeedPage() {
  return (
    <div className="mx-auto w-full max-w-2xl space-y-6 p-4 sm:p-6">
      <PageMeta title="Feed" />
      <PageHeader title="Feed" description="See what's happening in your community" />
      <StoryBar />
      <NewsFeed />
    </div>
  );
}
```

The `CreatePost` component is rendered inside `NewsFeed`, which fetches the feed via
`useInfiniteQuery`. Optimistic posts would be injected at the top of the feed list.

#### 2.8.1 FeedTimeline Component Analysis (131 lines)
<!-- VERIFIED: FeedTimeline.tsx is 131 lines -->

`FeedTimeline` is the core rendering component for the feed:

```typescript
export function FeedTimeline({ showComposer = false, ... }: FeedTimelineProps) {
  const feedQuery = useFeedTimelineQuery({ authorId, q, from, to, hasMedia, cursor });
  const allPosts = useMemo(
    () => mergeFeedPages((feedQuery.data?.pages ?? []) as any),
    [feedQuery.data?.pages],
  );
  // ...
  return (
    <div className="space-y-4">
      {showComposer ? <CreatePost /> : null}
      {allPosts.map((post) => (
        <div key={post.post_id}>
          {/* repost attribution */}
          <PostCard post={post} />
        </div>
      ))}
      <div ref={sentinelRef} className="h-4" />
    </div>
  );
}
```

The `allPosts` array is built via `mergeFeedPages` which deduplicates by `post_id`.
Offline optimistic posts will have IDs like `optimistic-post-<queueId>` which will never
collide with server-side post IDs.

The `sentinelRef` at the end triggers infinite scroll via `IntersectionObserver`. Offline
posts appear above the sentinel, at the top of the feed (before server-fetched posts).

#### 2.8.2 `mergeFeedPages` Utility (`feedPagination.ts`, 19 lines)
<!-- VERIFIED: feedPagination.ts exists at frontend/src/lib/feedPagination.ts, 19 lines -->

```typescript
export function mergeFeedPages(pages: FeedPage[]): FeedPost[] {
  const seen = new Set<string>();
  const out: FeedPost[] = [];
  for (const page of pages) {
    for (const post of page.items ?? []) {
      if (!post?.post_id || seen.has(post.post_id)) continue;
      seen.add(post.post_id);
      out.push(post);
    }
  }
  return out;
}
```

This iterates pages in order and skips duplicates. Since feed pages are newest-first,
`out[0]` is the most recent post. Offline posts should be prepended before the first page,
or the `allPosts` array should be extended after `mergeFeedPages` returns.

#### 2.8.3 PostCard Component Analysis (881 lines)
<!-- VERIFIED: PostCard.tsx is 881 lines -->

`PostCard` (line 188 of `PostCard.tsx`) renders a single feed post. Key fields used:
<!-- VERIFIED: PostCard.tsx:188 -->
- `post.author_id` -- compared to `userId` for `isOwn` flag
- `post.body` -- the main text content
- `post.body_format` -- determines rendering mode (plain/markdown/rich)
- `post.image_urls` -- image grid
- `post.video` -- video player
- `post.file_attachments` -- file attachment cards
- `post.unlock_price_cents` / `post.locked` / `post.unlocked` -- lock paywall
- `post.like_count` / `post.comment_count` -- engagement metrics
- `post.created_at` -- timestamp (ISO string, used by `formatRelative`)

For an offline optimistic post, many of these fields are unavailable:
- `like_count` and `comment_count` are 0
- `created_at` is set to `new Date().toISOString()` (renders as "Just now")
- `author_id` is the current user's ID
- `body` / `body_format` come directly from the queued payload
- `image_urls` may be present if images were uploaded before going offline
- Lock/lottery fields come from the queued payload

The `PostCard` must handle the `__offline` field gracefully:
- Disable like/comment/react/tip/bookmark/share actions
- Show the offline status indicator
- Suppress lock paywall (cannot unlock an optimistic post)

### 2.9 `useOfflineQueue` Flush Hook (`useOfflineQueue.ts`, 96 lines)
<!-- VERIFIED: useOfflineQueue.ts is 96 lines -->

The queue flush logic is in `useOfflineQueue.ts`:

```typescript
export function useOfflineQueue() {
  const queue = useOfflineStore((s) => s.queue);
  const isOnline = useOfflineStore((s) => s.isOnline);
  const removeFromQueue = useOfflineStore((s) => s.removeFromQueue);
  const queryClient = useQueryClient();
  const isFlushing = React.useRef(false);

  // Flush the queue whenever we come back online
  React.useEffect(() => {
    if (!isOnline || queue.length === 0 || isFlushing.current) return;
    const flush = async () => {
      isFlushing.current = true;
      const snapshot = [...queue];
      for (const action of snapshot) {
        try {
          await dispatchAction(action);
          removeFromQueue(action.id);
          successCount += 1;
        } catch {
          failCount += 1;
        }
      }
      if (successCount > 0) {
        void queryClient.invalidateQueries({ queryKey: ["messages"] });
        void queryClient.invalidateQueries({ queryKey: ["conversations"] });
        void invalidateFeedCaches(queryClient);
      }
      isFlushing.current = false;
    };
    void flush();
  }, [isOnline, queue.length]);
}
```

#### 2.9.1 Flush Lifecycle for PWA-005 Integration

The current flush loop has a critical gap: it does not update the optimistic message status
during the flush process. The enhanced flow needs to:

1. **Before flush starts**: Update all queued messages from `"pending"` to `"sending"`.
2. **Per-action success**: Update that message from `"sending"` to transitional state,
   then remove the `__offline` field.
3. **Per-action failure**: Update that message from `"sending"` to `"failed"` with the
   error message.
4. **After flush completes**: Invalidate queries to replace optimistic messages with real
   server data.

The `dispatchAction` function (lines 84-96) handles the actual API call:

```typescript
async function dispatchAction(action: OfflineAction): Promise<void> {
  if (action.type === "send_message") {
    await sendTextMessage(action.payload.conversationId, action.payload.req);
    return;
  }
  if (action.type === "create_post") {
    await createPost(action.payload);
    return;
  }
  const _exhaustive: never = action;
  throw new Error(`Unknown offline action type: ${(_exhaustive as OfflineAction).type}`);
}
```

**Note**: `sendTextMessage` and `createPost` are the same functions used by the online
paths. They return the created message/post data, but the current code discards the return
value. After PWA-005, the return value should be used to correlate the server-assigned ID
with the optimistic ID for smoother transitions.

### 2.10 AppShell Integration (`AppShell.tsx`, lines 20-78)

The `AppShell` mounts two offline-related components:

```typescript
<OfflineBanner />
<OfflineQueueFlusher />
```

Where `OfflineQueueFlusher` is a headless component that calls `useOfflineQueue()`:

```typescript
function OfflineQueueFlusher() {
  useOfflineQueue();
  return null;
}
```

After PWA-005, a third component `OfflineOptimisticRestorer` will be mounted here:

```typescript
function OfflineOptimisticRestorer() {
  useOfflineOptimisticRestore(useQueryClient());
  return null;
}
```

This must run AFTER the query client is available but BEFORE the user navigates to any
conversation, so that restored optimistic messages are in the cache when the conversation
view mounts.

### 2.11 Conversation Sidebar Preview Impact

The `ConversationList` component shows the last message for each conversation as a preview.
The `last_message` field on `ConversationOut` is populated by the backend. For offline
optimistic messages, the sidebar should show the queued message text as the preview.

This requires updating the sidebar's data: either by modifying the conversations query
cache to include the optimistic last message, or by overlaying the preview text from the
offline store.

**Recommended approach**: Modify the conversations query cache alongside the messages
query cache when injecting an offline optimistic message. Set the conversation's
`last_message` to the optimistic message and update `last_message_at` to the current
timestamp. This way, the sidebar preview automatically reflects the queued message.

```typescript
// After injecting the optimistic message into ["messages", convoId]:
queryClient.setQueryData<InfiniteData<ConversationsPage>>(
  ["conversations"],
  (old) => {
    if (!old?.pages) return old;
    return {
      ...old,
      pages: old.pages.map((page) => ({
        ...page,
        conversations: page.conversations.map((c) =>
          c.conversation_id === convoId
            ? {
                ...c,
                last_message: optimistic,
                last_message_at: optimistic.created_at,
              }
            : c,
        ),
      })),
    };
  },
);
```

---

## 3. Technical Design

### 3.1 Extended Message Type

Add optional fields to the `Message` type to represent offline status:

```typescript
// In frontend/src/api/types.ts, at line 987 (inside the Message interface)
export interface Message {
  // ... existing fields ...

  /** Offline queue metadata — only present for locally-queued messages */
  __offline?: {
    queueId: string;         // matches offlineStore action id
    status: "pending" | "sending" | "failed";
    error?: string;          // error message if status === "failed"
    enqueuedAt: number;      // timestamp when queued
  };
}
```

Using a `__offline` prefix signals that this is a client-side-only field never returned
by the API. The double underscore convention is used elsewhere in the codebase (e.g.,
`__cachedAt` and `__fromOfflineCache` proposed in PWA-003).

#### 3.1.1 Extended FeedPost Type

Similarly, add `__offline` to the `FeedPost` type:

```typescript
// In frontend/src/api/types.ts, inside the FeedPost interface
export interface FeedPost {
  // ... existing fields ...

  /** Offline queue metadata — only present for locally-queued posts */
  __offline?: {
    queueId: string;
    status: "pending" | "sending" | "failed";
    error?: string;
    enqueuedAt: number;
  };
}
```

#### 3.1.2 Type Guard Utility

Create a type guard to check if a message or post is an offline optimistic item:

```typescript
// In frontend/src/lib/offlineMessageHelpers.ts

export function isOfflineOptimistic(item: { __offline?: unknown }): boolean {
  return !!item.__offline;
}

export function isOfflinePending(item: { __offline?: { status: string } }): boolean {
  return item.__offline?.status === "pending";
}

export function isOfflineSending(item: { __offline?: { status: string } }): boolean {
  return item.__offline?.status === "sending";
}

export function isOfflineFailed(item: { __offline?: { status: string } }): boolean {
  return item.__offline?.status === "failed";
}

export function isOptimisticMessageId(messageId: string): boolean {
  return messageId.startsWith("optimistic-");
}

export function isOfflineOptimisticMessageId(messageId: string): boolean {
  return messageId.startsWith("optimistic-offline-");
}
```

#### 3.1.3 OfflineAction Type Extension

Extend the `OfflineAction` types in `offlineStore.ts` to track per-item status and error:

```typescript
// In frontend/src/stores/offlineStore.ts

export interface OfflineActionSendMessage {
  id: string;
  type: "send_message";
  enqueuedAt: number;
  __status?: "pending" | "sending" | "failed";   // NEW
  __error?: string;                               // NEW
  __retryCount?: number;                          // NEW
  payload: {
    conversationId: string;
    req: SendTextMessageReq;
  };
}

export interface OfflineActionCreatePost {
  id: string;
  type: "create_post";
  enqueuedAt: number;
  __status?: "pending" | "sending" | "failed";   // NEW
  __error?: string;                               // NEW
  __retryCount?: number;                          // NEW
  payload: CreatePostReq;
}
```

### 3.2 Optimistic Injection for Offline Messages

Modify the offline enqueue path in `ConversationView.tsx`:

```typescript
if (!isOnline && !fullPayload.send_at) {
  const queueId = `offline-${Date.now()}-${Math.random().toString(36).slice(2)}`;

  // 1. Add to persistent queue (same as before, but with known ID)
  addToQueueWithId(queueId, {
    type: "send_message",
    payload: { conversationId: convoId, req: fullPayload },
  });

  // 2. Create optimistic message in React Query cache
  const optimistic: Message = {
    message_id: `optimistic-offline-${queueId}`,
    conversation_id: convoId,
    sender_id: userId ?? "",
    kind: "text",
    text: fullPayload.encryption ? "" : (fullPayload.text ?? ""),
    is_encrypted: !!fullPayload.encryption,
    encryption: fullPayload.encryption,
    created_at: Date.now() / 1000,
    reactions_counts: {},
    reply_to_message_id: fullPayload.reply_to_message_id,
    __offline: {
      queueId,
      status: "pending",
      enqueuedAt: Date.now(),
    },
  };

  queryClient.setQueryData<InfiniteData<MessagesPage>>(
    ["messages", convoId],
    (old) => {
      if (!old?.pages.length) return old;
      const pages = old.pages.map((p, i) =>
        i === 0 ? { ...p, messages: [optimistic, ...(p.messages ?? [])] } : p,
      );
      return { ...old, pages };
    },
  );

  toast.info("You're offline — message queued");
  setReplyingTo(null);
  return;
}
```

#### 3.2.1 Full Implementation of `addToQueueWithId`

Add a new method to the offline store that accepts a pre-generated ID:

```typescript
// In frontend/src/stores/offlineStore.ts

interface OfflineState {
  queue: OfflineAction[];
  isOnline: boolean;

  setOnline: (online: boolean) => void;
  addToQueue: (action: Omit<OfflineAction, "id" | "enqueuedAt">) => string;  // CHANGED: returns id
  addToQueueWithId: (
    id: string,
    action: Omit<OfflineAction, "id" | "enqueuedAt">,
  ) => void;  // NEW
  removeFromQueue: (id: string) => void;
  updateActionStatus: (
    id: string,
    status: "pending" | "sending" | "failed",
    error?: string,
  ) => void;  // NEW
  retryAction: (id: string) => void;  // NEW
  clearQueue: () => void;
}

export const useOfflineStore = create<OfflineState>()(
  persist(
    (set, get) => ({
      queue: [],
      isOnline: typeof navigator !== "undefined" ? navigator.onLine : true,

      setOnline: (online) => set({ isOnline: online }),

      addToQueue: (action) => {
        const id = `offline-${Date.now()}-${Math.random().toString(36).slice(2)}`;
        set((s) => ({
          queue: [
            ...s.queue,
            {
              ...action,
              id,
              enqueuedAt: Date.now(),
            } as OfflineAction,
          ],
        }));
        return id;
      },

      addToQueueWithId: (id, action) =>
        set((s) => ({
          queue: [
            ...s.queue,
            {
              ...action,
              id,
              enqueuedAt: Date.now(),
            } as OfflineAction,
          ],
        })),

      removeFromQueue: (id) =>
        set((s) => ({ queue: s.queue.filter((a) => a.id !== id) })),

      updateActionStatus: (id, status, error) =>
        set((s) => ({
          queue: s.queue.map((a) =>
            a.id === id
              ? { ...a, __status: status, __error: error }
              : a,
          ),
        })),

      retryAction: (id) =>
        set((s) => ({
          queue: s.queue.map((a) =>
            a.id === id
              ? {
                  ...a,
                  __status: "pending" as const,
                  __error: undefined,
                  __retryCount: (a.__retryCount ?? 0) + 1,
                }
              : a,
          ),
        })),

      clearQueue: () => set({ queue: [] }),
    }),
    {
      name: "offline-store",
      partialize: (state) => ({ queue: state.queue }),
    },
  ),
);
```

#### 3.2.2 Offline Optimistic Message with Reply Preview

When the user is replying to a message while offline, the optimistic message must include
the reply linkage fields. The `buildReplyLinkagePayload` function (lines 151-160 of
`ConversationView.tsx`) generates these fields:

```typescript
const buildReplyLinkagePayload = React.useCallback((target: Message | null) => {
  if (!target) return {};
  const threadRoot = target.thread_root_message_id ?? target.parent_message_id ?? target.message_id;
  return {
    reply_to_message_id: target.message_id,
    parent_message_id: target.message_id,
    ...(target.thread_id ? { thread_id: target.thread_id } : {}),
    ...(threadRoot ? { thread_root_message_id: threadRoot } : {}),
  };
}, []);
```

The offline optimistic message already includes `reply_to_message_id` from the
`fullPayload`. Additionally, the `replyToMessage` prop in `MessageBubble` looks up the
replied-to message from `messageById` (line 1006 of `ConversationView.tsx`):

```typescript
replyToMessage={msg.reply_to_message_id ? messageById.get(msg.reply_to_message_id) : undefined}
```

This works for offline messages as long as the replied-to message is in the cache (which
it will be if the user has the conversation open). The reply preview will render correctly.

#### 3.2.3 Offline Optimistic Message with Encryption

When the user sends an encrypted message while offline, the `encryption` envelope is
included in the payload. The optimistic message sets `is_encrypted: true` and
`text: ""` (same as the online path at line 221). The `MessageBubble` renders this as
"Encrypted message" with the lock badge (lines 1014-1088).

The encrypted envelope data is persisted in the offline store (in `req.encryption`). When
the queue flushes, the backend receives the envelope and stores it alongside the message.
No special handling is needed for offline encrypted messages beyond what the online path
already does.

#### 3.2.4 Offline Queue Deduplication Guard

Users who type quickly or double-tap the send button could inadvertently queue the same
message twice. Add a guard in the offline enqueue path:

```typescript
// Guard against duplicate enqueue (same text within 500ms)
const recentQueue = useOfflineStore.getState().queue;
const duplicateThreshold = 500; // milliseconds
const isDuplicate = recentQueue.some(
  (a) =>
    a.type === "send_message" &&
    a.payload.conversationId === convoId &&
    a.payload.req.text === fullPayload.text &&
    Date.now() - a.enqueuedAt < duplicateThreshold,
);

if (isDuplicate) {
  toast.warning("Message already queued");
  return;
}
```

### 3.3 `MessageBubble` Pending State

Extend `MessageBubble` to render the offline status:

```typescript
// In MessageBubble.tsx — new component, add before the MessageBubble export

import { Clock, Loader2, AlertCircle, Check, RotateCcw, Trash2 } from "lucide-react";

interface OfflineStatusBadgeProps {
  offline: Message["__offline"];
  onRetry?: () => void;
  onDiscard?: () => void;
}

function OfflineStatusBadge({ offline, onRetry, onDiscard }: OfflineStatusBadgeProps) {
  if (!offline) return null;

  if (offline.status === "pending") {
    return (
      <div
        className="flex items-center gap-1 text-xs text-muted-foreground mt-1 animate-pulse"
        role="status"
        aria-label="Message queued, will send when online"
      >
        <Clock className="h-3 w-3" />
        <span>Sending when online...</span>
      </div>
    );
  }

  if (offline.status === "sending") {
    return (
      <div
        className="flex items-center gap-1 text-xs text-blue-500 mt-1"
        role="status"
        aria-label="Sending message"
      >
        <Loader2 className="h-3 w-3 animate-spin" />
        <span>Sending...</span>
      </div>
    );
  }

  if (offline.status === "failed") {
    return (
      <div
        className="flex items-center gap-1 text-xs text-destructive mt-1 flex-wrap"
        role="alert"
        aria-label={`Message failed to send: ${offline.error ?? "Unknown error"}`}
      >
        <AlertCircle className="h-3 w-3 shrink-0" />
        <span>{offline.error ?? "Failed to send"}</span>
        {onRetry && (
          <Button
            variant="ghost"
            size="sm"
            className="h-5 px-1.5 text-xs text-destructive hover:text-destructive"
            onClick={(e) => { e.stopPropagation(); onRetry(); }}
            aria-label="Retry sending message"
          >
            <RotateCcw className="h-3 w-3 mr-0.5" />
            Retry
          </Button>
        )}
        {onDiscard && (
          <Button
            variant="ghost"
            size="sm"
            className="h-5 px-1.5 text-xs text-muted-foreground hover:text-destructive"
            onClick={(e) => { e.stopPropagation(); onDiscard(); }}
            aria-label="Discard queued message"
          >
            <Trash2 className="h-3 w-3 mr-0.5" />
            Discard
          </Button>
        )}
      </div>
    );
  }

  return null;
}
```

#### 3.3.1 Transition Animation: Pending to Sent

When the status changes from "pending" to "sending" to removal (sent), add a CSS
transition class that animates the opacity and badge:

```typescript
// In MessageBubble.tsx — new component for the success checkmark flash

function SentCheckmark() {
  const [visible, setVisible] = React.useState(true);

  React.useEffect(() => {
    const timer = setTimeout(() => setVisible(false), 2000);
    return () => clearTimeout(timer);
  }, []);

  if (!visible) return null;

  return (
    <div className="flex items-center gap-1 text-xs text-green-600 mt-1 animate-in fade-in duration-300">
      <Check className="h-3 w-3" />
      <span>Sent</span>
    </div>
  );
}
```

This component appears briefly after a successful flush, then fades out. It is rendered
when the message transitions from having `__offline` to not having it (during the brief
window before `invalidateQueries` replaces the optimistic message with the real one).

#### 3.3.2 MessageBubble Integration Points

Inside the `MessageBubble` render function, add the following at three points:

**Point 1 -- Opacity class on the bubble wrapper** (line 696):

```typescript
<div
  className={cn(
    "group relative max-w-[75%] rounded-2xl px-4 py-2",
    isOwn
      ? "bg-primary text-primary-foreground"
      : "bg-muted text-foreground",
    // NEW: offline pending state
    message.__offline?.status === "pending" && "opacity-70",
    message.__offline?.status === "sending" && "opacity-85",
    message.__offline?.status === "failed" && "opacity-90 ring-1 ring-destructive/30",
  )}
>
```

**Point 2 -- Disable hover toolbar** (before line 702):

```typescript
{!message.__offline && (
  <div className={cn(
    "absolute -top-2 opacity-0 transition-opacity group-hover:opacity-100 ...",
  )}>
    {/* Quick emoji reactions, Reply, More actions */}
  </div>
)}
```

**Point 3 -- OfflineStatusBadge after message content** (after the timestamp at ~line 1380):

```typescript
{/* Offline status badge */}
{message.__offline && (
  <OfflineStatusBadge
    offline={message.__offline}
    onRetry={() => handleRetry(message)}
    onDiscard={() => handleDiscard(message)}
  />
)}
```

#### 3.3.3 Retry and Discard Handler Implementations

```typescript
// Inside MessageBubble component body

const handleRetry = (msg: Message) => {
  if (!msg.__offline) return;
  const queueId = msg.__offline.queueId;

  // Re-enqueue the action (move from dead-letter back to queue)
  const { retryAction } = useOfflineStore.getState();
  retryAction(queueId);

  // Update the optimistic message status back to "pending"
  updateOfflineMessageStatus(queryClient, queueId, "pending");

  toast.info("Message re-queued -- will send when online");
};

const handleDiscard = (msg: Message) => {
  if (!msg.__offline) return;
  const queueId = msg.__offline.queueId;

  // Remove from offline store
  const { removeFromQueue } = useOfflineStore.getState();
  removeFromQueue(queueId);

  // Remove the optimistic message from the React Query cache
  removeOptimisticMessage(queryClient, conversationId, msg.message_id);

  toast.info("Queued message discarded");
};
```

### 3.4 Transition Animation: Pending to Sent

When the queue flush completes (via `useOfflineQueue` or Background Sync postMessage from
PWA-004), the optimistic message must transition from "pending" to "sent". The flow:

1. **Flush success**: The `removeFromQueue(queueId)` call fires. The SW postMessage or
   `useOfflineQueue` success handler knows the `queueId`.
2. **Update optimistic message**: Find the message with
   `message_id === "optimistic-offline-${queueId}"` in the React Query cache and remove
   its `__offline` field.
3. **Invalidate query**: The `queryClient.invalidateQueries(["messages", convoId])` call
   triggers a refetch. The server response replaces the optimistic message with the real
   one (different `message_id`).
4. **Visual transition**: During the brief period between "pending removed" and "real
   message loaded", the optimistic message appears as a normal sent message. When the
   refetch completes, React rerenders with the real data. If the content matches, the
   transition is seamless.

To animate the transition, add a CSS transition on the opacity:

```css
.message-bubble {
  transition: opacity 300ms ease-in-out;
}
.message-bubble--pending {
  opacity: 0.75;
}
.message-bubble--sent {
  opacity: 1;
}
```

#### 3.4.1 Detailed Flush Success Flow (Sequence)

```
1. User goes online
   |
2. useOfflineQueue effect fires (isOnline=true, queue.length>0)
   |
3. flush() begins — isFlushing.current = true
   |
4. For each action in snapshot:
   |
   4a. updateActionStatus(action.id, "sending")
       |
       --> offlineStore: action.__status = "sending"
       |
   4b. updateOfflineMessageStatus(queryClient, action.id, "sending")
       |
       --> React Query cache: message.__offline.status = "sending"
       --> MessageBubble re-renders with spinning loader
       |
   4c. await dispatchAction(action)
       |
       [SUCCESS]:
       |
   4d. removeFromQueue(action.id)
       |
       --> offlineStore: action removed from queue
       |
   4e. removeOfflineField(queryClient, action.id)
       |
       --> React Query cache: message.__offline deleted
       --> MessageBubble re-renders without offline badge, full opacity
       |
       [FAILURE]:
       |
   4f. updateActionStatus(action.id, "failed", error.message)
       |
   4g. markOfflineMessageFailed(queryClient, action.id, error.message)
       |
       --> React Query cache: message.__offline.status = "failed"
       --> MessageBubble re-renders with red error badge + retry/discard
       |
5. After all actions processed:
   |
6. queryClient.invalidateQueries(["messages"])
   |
   --> Refetch replaces optimistic messages with real server data
   |
7. queryClient.invalidateQueries(["conversations"])
   |
   --> Sidebar previews update with real last_message
   |
8. invalidateFeedCaches(queryClient)
   |
   --> Feed timeline refetch replaces optimistic posts
   |
9. isFlushing.current = false
```

#### 3.4.2 Race Condition: Flush Starts Before Page Mount

If the user goes online while on a different page (not the conversation view), the flush
runs in the `AppShell`-mounted `OfflineQueueFlusher`. The optimistic message may not be in
the React Query cache if the conversation was never opened after reload.

**Mitigation**: The `updateOfflineMessageStatus` and `removeOfflineField` helpers use
`queryClient.setQueriesData` with a broad `{ queryKey: ["messages"] }` filter, which
matches all conversation message caches. If the specific conversation's cache does not
exist, `setQueriesData` is a no-op (it only updates existing entries). The subsequent
`invalidateQueries` will refetch when the user navigates to the conversation.

This is acceptable behavior: the user will not see the transition animation, but the
message will appear correctly once they open the conversation.

### 3.5 Flush Failure: Mark as Failed

When an offline action fails permanently (dead-letter from PWA-004, or persistent error
in `useOfflineQueue`), update the optimistic message's `__offline.status` to `"failed"`:

```typescript
function markOfflineMessageFailed(
  queryClient: QueryClient,
  queueId: string,
  error: string,
) {
  // Find which conversation contains this optimistic message
  queryClient.setQueriesData<InfiniteData<MessagesPage>>(
    { queryKey: ["messages"] },
    (old) => {
      if (!old?.pages) return old;
      const targetMsgId = `optimistic-offline-${queueId}`;
      const pages = old.pages.map((p) => ({
        ...p,
        messages: (p.messages ?? []).map((m) =>
          m.message_id === targetMsgId
            ? {
                ...m,
                __offline: {
                  ...m.__offline!,
                  status: "failed" as const,
                  error,
                },
              }
            : m,
        ),
      }));
      return { ...old, pages };
    },
  );
}
```

#### 3.5.1 Failure Classification

Not all failures are permanent. The flush loop should classify errors:

```typescript
function isTransientError(error: unknown): boolean {
  if (error instanceof ApiError) {
    // Network errors, server errors, rate limiting
    if (error.status === 0 || error.status >= 500 || error.status === 429) return true;
    // Auth errors (session expired) -- may recover after re-auth
    if (error.status === 401) return true;
  }
  // Fetch failures (network error, DNS failure, etc.)
  if (error instanceof TypeError && error.message.includes("fetch")) return true;
  return false;
}

function isPermanentError(error: unknown): boolean {
  if (error instanceof ApiError) {
    // Client errors that won't succeed on retry
    if (error.status === 400 || error.status === 403 || error.status === 404 ||
        error.status === 409 || error.status === 413 || error.status === 422) return true;
  }
  return false;
}
```

For transient errors, the message stays in the queue with `__status: "pending"` and will
retry on the next online event. For permanent errors, the message is marked as
`__status: "failed"` with the error message, and the user must decide to retry or discard.

#### 3.5.2 Maximum Retry Count

After `MAX_RETRIES` (default: 3) transient failures, the message is promoted to
`"failed"` status:

```typescript
const MAX_RETRIES = 3;

// In the flush loop:
try {
  await dispatchAction(action);
  // success...
} catch (error) {
  const retryCount = action.__retryCount ?? 0;
  if (isTransientError(error) && retryCount < MAX_RETRIES) {
    updateActionStatus(action.id, "pending");
    // Will retry on next flush cycle
  } else {
    const errorMsg = error instanceof Error ? error.message : "Unknown error";
    updateActionStatus(action.id, "failed", errorMsg);
    markOfflineMessageFailed(queryClient, action.id, errorMsg);
  }
}
```

### 3.6 Retry and Discard Handlers

In `MessageBubble`, the "Retry" and "Discard" buttons for failed messages:

```typescript
const handleRetry = () => {
  if (!msg.__offline) return;
  const queueId = msg.__offline.queueId;

  // Re-enqueue the action (move from dead-letter back to queue)
  retryDeadLetter(queueId);

  // Update the optimistic message status back to "pending"
  updateOfflineMessageStatus(queryClient, queueId, "pending");

  toast.info("Message re-queued — will send when online");
};

const handleDiscard = () => {
  if (!msg.__offline) return;
  const queueId = msg.__offline.queueId;

  // Remove from dead-letter
  discardDeadLetter(queueId);

  // Remove the optimistic message from the React Query cache
  removeOptimisticMessage(queryClient, convoId, msg.message_id);

  toast.info("Queued message discarded");
};
```

#### 3.6.1 `removeOptimisticMessage` Implementation

```typescript
export function removeOptimisticMessage(
  queryClient: QueryClient,
  conversationId: string,
  messageId: string,
) {
  queryClient.setQueryData<InfiniteData<MessagesPage>>(
    ["messages", conversationId],
    (old) => {
      if (!old?.pages) return old;
      return {
        ...old,
        pages: old.pages.map((page) => ({
          ...page,
          messages: (page.messages ?? []).filter(
            (m) => m.message_id !== messageId,
          ),
        })),
      };
    },
  );

  // Also update the conversations sidebar if the discarded message was the last message
  queryClient.invalidateQueries({ queryKey: ["conversations"] });
}
```

#### 3.6.2 `updateOfflineMessageStatus` Implementation

```typescript
export function updateOfflineMessageStatus(
  queryClient: QueryClient,
  queueId: string,
  status: "pending" | "sending" | "failed",
  error?: string,
) {
  const targetMsgId = `optimistic-offline-${queueId}`;

  queryClient.setQueriesData<InfiniteData<MessagesPage>>(
    { queryKey: ["messages"] },
    (old) => {
      if (!old?.pages) return old;
      let found = false;
      const pages = old.pages.map((p) => ({
        ...p,
        messages: (p.messages ?? []).map((m) => {
          if (m.message_id === targetMsgId) {
            found = true;
            return {
              ...m,
              __offline: {
                ...m.__offline!,
                status,
                ...(error !== undefined ? { error } : {}),
              },
            };
          }
          return m;
        }),
      }));
      // Only return new object if we found and updated the target
      return found ? { ...old, pages } : old;
    },
  );
}
```

#### 3.6.3 `removeOfflineField` Implementation

After a successful flush, remove the `__offline` field entirely so the message renders
as a normal sent message during the brief window before the refetch arrives:

```typescript
export function removeOfflineField(
  queryClient: QueryClient,
  queueId: string,
) {
  const targetMsgId = `optimistic-offline-${queueId}`;

  queryClient.setQueriesData<InfiniteData<MessagesPage>>(
    { queryKey: ["messages"] },
    (old) => {
      if (!old?.pages) return old;
      let found = false;
      const pages = old.pages.map((p) => ({
        ...p,
        messages: (p.messages ?? []).map((m) => {
          if (m.message_id === targetMsgId) {
            found = true;
            const { __offline, ...rest } = m;
            return rest;
          }
          return m;
        }),
      }));
      return found ? { ...old, pages } : old;
    },
  );
}
```

### 3.7 Optimistic Feed Post

For feed posts, create a similar optimistic injection in `FeedTimeline.tsx`:

```typescript
// In FeedTimeline component, after the useFeedTimelineQuery for the feed
const offlineQueue = useOfflineStore((s) => s.queue);
const offlinePosts = offlineQueue
  .filter((a) => a.type === "create_post")
  .map((a) => ({
    post_id: `optimistic-post-${a.id}`,
    body: (a.payload as CreatePostReq).body_plain ?? (a.payload as CreatePostReq).body ?? "",
    body_format: (a.payload as CreatePostReq).body_format ?? "plain",
    image_urls: (a.payload as CreatePostReq).image_urls ?? [],
    created_at: new Date(a.enqueuedAt).toISOString(),
    author_id: userId ?? "",
    like_count: 0,
    comment_count: 0,
    __offline: {
      queueId: a.id,
      status: "pending" as const,
      enqueuedAt: a.enqueuedAt,
    },
  }));

// Prepend offline posts to the feed list
const allPosts = [...offlinePosts, ...(feedData?.pages.flatMap((p) => p.items) ?? [])];
```

#### 3.7.1 Full FeedTimeline Modification

The complete modification to `FeedTimeline.tsx`:

```typescript
import { useOfflineStore } from "@/stores/offlineStore";
import { useAuthStore } from "@/stores/authStore";
import type { CreatePostReq, FeedPost } from "@/api/types";

export function FeedTimeline({ showComposer = false, ... }: FeedTimelineProps) {
  const feedQuery = useFeedTimelineQuery({ authorId, q, from, to, hasMedia, cursor });
  const userId = useAuthStore((s) => s.userId);
  const offlineQueue = useOfflineStore((s) => s.queue);

  // Build optimistic posts from offline queue
  const offlinePosts = useMemo((): FeedPost[] => {
    return offlineQueue
      .filter((a) => a.type === "create_post")
      .map((a) => {
        const payload = a.payload as CreatePostReq;
        return {
          post_id: `optimistic-post-${a.id}`,
          author_id: userId ?? "",
          body: payload.body_plain ?? payload.body ?? "",
          body_plain: payload.body_plain,
          body_markdown: payload.body_markdown,
          body_rich: payload.body_rich,
          body_format: payload.body_format ?? "plain",
          image_urls: payload.image_urls ?? [],
          file_attachments: [],
          unlock_price_cents: payload.unlock_price_cents ?? null,
          like_count: 0,
          comment_count: 0,
          tip_total_cents: 0,
          reactions_counts: {},
          my_reactions: [],
          created_at: new Date(a.enqueuedAt).toISOString(),
          status: "published",  // show as published for display purposes
          __offline: {
            queueId: a.id,
            status: (a.__status ?? "pending") as "pending" | "sending" | "failed",
            error: a.__error,
            enqueuedAt: a.enqueuedAt,
          },
        };
      });
  }, [offlineQueue, userId]);

  // Merge server posts with offline optimistic posts
  const serverPosts = useMemo(
    () => mergeFeedPages((feedQuery.data?.pages ?? []) as any),
    [feedQuery.data?.pages],
  );
  const allPosts = useMemo(
    () => [...offlinePosts, ...serverPosts],
    [offlinePosts, serverPosts],
  );

  // ... rest of component unchanged ...
}
```

#### 3.7.2 Offline Post with Markdown/Rich Content

When the queued post has `body_format: "markdown"` or `body_format: "rich"`, the
`PostCard` uses the `RichContentRenderer` component to render the content. The optimistic
post includes the `body_markdown` or `body_rich` fields from the payload, which
`RichContentRenderer` can render client-side without any server processing.

For markdown posts, the server normally converts `body_markdown` to `body_markdown_html`.
The optimistic post will NOT have `body_markdown_html`, so `RichContentRenderer` must
fall back to raw markdown rendering (which it already does when `body_markdown_html` is
absent).

#### 3.7.3 Offline Post with Video

If the queued post has a `video_id`, the optimistic post should show a video placeholder:

```typescript
// In the optimistic post construction:
...(payload.video_id
  ? {
      video: {
        video_id: payload.video_id,
        title: "Pending video",
        thumbnail_url: null,
        duration_seconds: null,
        hls_manifest_url: null,
        playback_token: null,
        playback_expires_at: null,
      },
    }
  : {}),
```

The `VideoPostPlayer` component in `PostCard` should handle the case where
`hls_manifest_url` is null by showing a placeholder card instead of a broken player.

### 3.8 `PostCard` Pending State

Extend `PostCard` to show the offline indicator:

```typescript
{post.__offline && (
  <div className="flex items-center gap-1 text-xs text-muted-foreground border-t pt-2 mt-2">
    {post.__offline.status === "pending" && (
      <>
        <Clock className="h-3 w-3 animate-pulse" />
        <span>Waiting to publish...</span>
      </>
    )}
    {post.__offline.status === "sending" && (
      <>
        <Loader2 className="h-3 w-3 animate-spin" />
        <span>Publishing...</span>
      </>
    )}
    {post.__offline.status === "failed" && (
      <>
        <AlertCircle className="h-3 w-3 text-destructive" />
        <span className="text-destructive">{post.__offline.error ?? "Failed to publish"}</span>
        <Button variant="ghost" size="sm" onClick={() => retryDeadLetter(post.__offline!.queueId)}>
          Retry
        </Button>
        <Button variant="ghost" size="sm" onClick={() => discardDeadLetter(post.__offline!.queueId)}>
          Discard
        </Button>
      </>
    )}
  </div>
)}
```

#### 3.8.1 PostCard Action Disabling for Offline Posts

When `post.__offline` is present, disable interactive elements:

```typescript
// In PostCard component, around the action buttons area:

const isOfflinePost = !!post.__offline;

// Like button
<Button
  variant="ghost"
  size="sm"
  onClick={() => likeMutation.mutate()}
  disabled={isOfflinePost || likeMutation.isPending}
>
  <Heart className={cn("h-4 w-4", post.liked_by_me && "fill-current text-red-500")} />
  {post.like_count}
</Button>

// Comment button
<Button
  variant="ghost"
  size="sm"
  onClick={() => setShowComments(!showComments)}
  disabled={isOfflinePost}
>
  <MessageCircle className="h-4 w-4" />
  {post.comment_count}
</Button>

// Tip, Share, Bookmark — all disabled when offline
```

#### 3.8.2 PostCard Opacity for Offline Posts

Apply reduced opacity to the entire card when offline:

```typescript
<Card className={cn(
  "overflow-hidden",
  post.__offline && "opacity-70",
  post.__offline?.status === "failed" && "ring-1 ring-destructive/30",
)}>
```

#### 3.8.3 PostCard Timestamp for Offline Posts

The `formatRelative` function (lines 51-63 of `PostCard.tsx`) handles ISO date strings.
For offline posts with `created_at` set to `new Date(enqueuedAt).toISOString()`, this
will show "Just now" (if `diffMin < 1`), which is the expected display for a just-queued
post.

### 3.9 Restoring Optimistic Items After Page Reload

When the user reloads while offline, the React Query cache is empty but the offline store
persists in `localStorage`. The optimistic items must be re-injected into the UI.

Create a hook `useOfflineOptimisticRestore`:

```typescript
export function useOfflineOptimisticRestore(queryClient: QueryClient) {
  const queue = useOfflineStore((s) => s.queue);
  const isOnline = useOfflineStore((s) => s.isOnline);
  const userId = useAuthStore((s) => s.userId);
  const hasRestored = React.useRef(false);

  React.useEffect(() => {
    if (hasRestored.current || isOnline || queue.length === 0) return;
    hasRestored.current = true;

    for (const action of queue) {
      if (action.type === "send_message") {
        const { conversationId, req } = action.payload;
        const optimistic: Message = {
          message_id: `optimistic-offline-${action.id}`,
          conversation_id: conversationId,
          sender_id: userId ?? "",
          kind: "text",
          text: req.text ?? "",
          created_at: action.enqueuedAt / 1000,
          reactions_counts: {},
          __offline: {
            queueId: action.id,
            status: "pending",
            enqueuedAt: action.enqueuedAt,
          },
        };
        queryClient.setQueryData<InfiniteData<MessagesPage>>(
          ["messages", conversationId],
          (old) => {
            if (!old?.pages.length) {
              return {
                pages: [{ messages: [optimistic], next_cursor: undefined }],
                pageParams: [undefined],
              };
            }
            const pages = old.pages.map((p, i) =>
              i === 0 ? { ...p, messages: [optimistic, ...(p.messages ?? [])] } : p,
            );
            return { ...old, pages };
          },
        );
      }
    }
  }, [queue, isOnline, userId, queryClient]);
}
```

Mount in `AppShell` alongside `OfflineQueueFlusher`.

#### 3.9.1 Restoration for Feed Posts

Feed posts do not need explicit restoration into the React Query cache because the
`FeedTimeline` component reads directly from `useOfflineStore((s) => s.queue)` and builds
the `offlinePosts` array on every render (see section 3.7.1). After a page reload, the
Zustand store hydrates from localStorage, and the `offlinePosts` array is rebuilt
automatically.

Messages, however, need restoration because they are injected into the React Query
infinite query cache, which is not persisted. The `useOfflineOptimisticRestore` hook
handles this.

#### 3.9.2 Restoration Edge Cases

**Case 1: User reloads while online, then goes offline**
- `hasRestored.current` is `true` (set on first mount)
- The effect guard `isOnline || queue.length === 0` skips restoration
- If the user then goes offline and queues a new message, the online-enqueue path creates
  the optimistic message normally

**Case 2: User reloads while offline, queue has messages for multiple conversations**
- The restoration loop iterates all queue entries and injects each into its respective
  conversation's cache
- If a conversation's cache does not exist (user hasn't opened it), a new pages structure
  is created with just the optimistic message
- When the user navigates to that conversation, the existing cache has the optimistic
  message; the `useMessagesQuery` will also fetch from the server (if possible) and merge

**Case 3: User reloads while offline, then goes online before navigating**
- Restoration runs (injects optimistic messages)
- Then `useOfflineQueue` flush runs (sends messages, removes from queue)
- The `removeOfflineField` and `invalidateQueries` calls clean up the optimistic messages
- The user sees the transition from pending to sent

**Case 4: Queue has failed items after page reload**
- The restoration hook restores with `status: "pending"` (from the queue entry)
- However, the queue entry may have `__status: "failed"`. Use the stored status:

```typescript
__offline: {
  queueId: action.id,
  status: (action.__status ?? "pending") as "pending" | "sending" | "failed",
  error: action.__error,
  enqueuedAt: action.enqueuedAt,
},
```

#### 3.9.3 Preventing Duplicate Restoration

The `hasRestored.current` ref prevents double-restoration on React strict mode double-mount
or on dependency changes. However, if the queue changes (new items added while offline),
the effect needs to handle them. Use a `Set` to track which queue IDs have been restored:

```typescript
const restoredIds = React.useRef(new Set<string>());

React.useEffect(() => {
  if (isOnline || queue.length === 0) return;

  for (const action of queue) {
    if (restoredIds.current.has(action.id)) continue;
    restoredIds.current.add(action.id);

    if (action.type === "send_message") {
      // ... inject optimistic message ...
    }
  }
}, [queue, isOnline, userId, queryClient]);
```

### 3.10 Queue Status Synchronization

The offline store, the React Query cache, and the IndexedDB sync queue (from PWA-004) must
stay synchronized. The state flow:

```
User sends offline
    |
    v
offlineStore.addToQueue() ──> localStorage
    |
    v
Inject optimistic msg ──────> React Query cache
    |
    v
Write to IndexedDB sync_queue (PWA-004)
    |
    v
Register Background Sync
    |
    ........ (offline) ........
    |
    v (online)
SW sync event fires
    |
    v
fetch() succeeds
    |
    v
Remove from IndexedDB
    |
    v
postMessage("sync-item-success", { id })
    |
    v
Main thread: removeFromQueue(id) ──> localStorage
    |
    v
Remove __offline from optimistic msg ──> React Query
    |
    v
invalidateQueries() ──> real msg replaces optimistic
```

#### 3.10.1 Service Worker postMessage Handling

The main thread listens for messages from the service worker:

```typescript
// In a new hook: useServiceWorkerSync.ts
// Mounted in AppShell

export function useServiceWorkerSync() {
  const removeFromQueue = useOfflineStore((s) => s.removeFromQueue);
  const updateActionStatus = useOfflineStore((s) => s.updateActionStatus);
  const queryClient = useQueryClient();

  React.useEffect(() => {
    const handler = (event: MessageEvent) => {
      const { type, id, error } = event.data ?? {};

      if (type === "sync-item-success") {
        removeFromQueue(id);
        removeOfflineField(queryClient, id);
        // Invalidation happens in batch after all items are processed
      }

      if (type === "sync-item-failure") {
        updateActionStatus(id, "failed", error ?? "Background sync failed");
        markOfflineMessageFailed(queryClient, id, error ?? "Background sync failed");
      }

      if (type === "sync-batch-complete") {
        queryClient.invalidateQueries({ queryKey: ["messages"] });
        queryClient.invalidateQueries({ queryKey: ["conversations"] });
        invalidateFeedCaches(queryClient);
      }
    };

    navigator.serviceWorker?.addEventListener("message", handler);
    return () => {
      navigator.serviceWorker?.removeEventListener("message", handler);
    };
  }, [removeFromQueue, updateActionStatus, queryClient]);
}
```

#### 3.10.2 Conflict Resolution: SW Flush vs. Main Thread Flush

Both the service worker (Background Sync from PWA-004) and the main thread
(`useOfflineQueue`) can attempt to flush the queue when connectivity returns. This creates
a potential double-send. The resolution strategy:

1. **SW has priority**: If Background Sync is registered and the SW is active, the main
   thread flush should detect this and skip items that the SW is handling.
2. **Idempotent backend**: The backend should accept duplicate messages gracefully. For
   text messages, the backend can use a client-generated idempotency key
   (`X-Idempotency-Key` header) to deduplicate.
3. **Simple approach**: Disable main thread flush when SW sync is registered. The
   `useOfflineQueue` checks `navigator.serviceWorker?.controller` and skips if a sync
   registration exists.

For the initial implementation, use the simple approach: main thread flush is the only
path. SW Background Sync integration comes from PWA-004 and plugs in via postMessage.

### 3.11 Accessibility Considerations

#### 3.11.1 ARIA Attributes for Offline Status

```typescript
// On the message bubble wrapper
<div
  role="listitem"
  aria-label={
    message.__offline?.status === "pending"
      ? `Queued message: ${message.text}. Will send when online.`
      : message.__offline?.status === "sending"
      ? `Sending message: ${message.text}`
      : message.__offline?.status === "failed"
      ? `Failed to send message: ${message.text}. ${message.__offline.error ?? ""}`
      : undefined
  }
>
```

#### 3.11.2 Live Region for Status Changes

Use an `aria-live` region to announce status transitions to screen readers:

```typescript
// In ConversationView, add a visually hidden live region
<div
  role="status"
  aria-live="polite"
  className="sr-only"
  ref={offlineStatusAnnouncerRef}
/>

// Update the announcer when a message status changes
useEffect(() => {
  const failedMessages = allMessages.filter(
    (m) => m.__offline?.status === "failed",
  );
  if (failedMessages.length > 0 && offlineStatusAnnouncerRef.current) {
    offlineStatusAnnouncerRef.current.textContent =
      `${failedMessages.length} message${failedMessages.length > 1 ? "s" : ""} failed to send. Use retry or discard to resolve.`;
  }
}, [allMessages]);
```

#### 3.11.3 Focus Management for Retry/Discard

After clicking "Discard", focus should move to the previous message or the compose bar:

```typescript
const handleDiscard = (msg: Message) => {
  // ... remove message ...

  // Move focus to compose bar
  const composeInput = document.querySelector<HTMLTextAreaElement>(
    '[placeholder*="type a message" i]',
  );
  composeInput?.focus();
};
```

---

## 4. Implementation Plan

### 4.1 New Files

| File | Purpose |
|------|---------|
| `frontend/src/hooks/useOfflineOptimisticRestore.ts` | Restore optimistic items from queue after reload |
| `frontend/src/lib/offlineMessageHelpers.ts` | Helpers: `markOfflineMessageFailed`, `updateOfflineMessageStatus`, `removeOptimisticMessage`, `removeOfflineField`, `isOfflineOptimistic`, `isOptimisticMessageId` |
| `frontend/src/hooks/useServiceWorkerSync.ts` | Listen for SW postMessage events from PWA-004 Background Sync |

### 4.2 Modified Files

| File | Changes |
|------|---------|
| `frontend/src/api/types.ts` | Add `__offline` optional field to `Message` type (line 987) and `FeedPost` type (line 1927) |
| `frontend/src/pages/messages/ConversationView.tsx` | Inject optimistic message on offline enqueue (lines 1028-1033); add deduplication guard |
| `frontend/src/pages/messages/MessageBubble.tsx` | Add `OfflineStatusBadge` component; add opacity/ring classes; disable hover toolbar for offline messages; add retry/discard handlers |
| `frontend/src/pages/feed/FeedTimeline.tsx` | Import offline store; build `offlinePosts` array; prepend to `allPosts` |
| `frontend/src/pages/feed/PostCard.tsx` | Add offline status indicator; disable actions for offline posts; add opacity class |
| `frontend/src/pages/feed/CreatePost.tsx` | Keep `resetComposer()` call (content is captured in queue); optionally show "queued" toast instead of "will publish" |
| `frontend/src/stores/offlineStore.ts` | Add `addToQueueWithId()`, `updateActionStatus()`, `retryAction()` methods; extend action types with `__status`, `__error`, `__retryCount` |
| `frontend/src/hooks/useOfflineQueue.ts` | On flush: update status to "sending" per item; on success: call `removeOfflineField`; on failure: call `markOfflineMessageFailed`; classify transient vs permanent errors |
| `frontend/src/components/layout/AppShell.tsx` | Mount `useOfflineOptimisticRestore` and `useServiceWorkerSync` hooks |
| `frontend/src/components/shared/OfflineBanner.tsx` | Show failed count badge; progress during flush |

### 4.3 Implementation Phases

1. **Phase 1 -- Message type extension + bubble rendering** (2 hours)
   - Add `__offline` field to `Message` type
   - Create `OfflineStatusBadge` component in `MessageBubble.tsx`
   - Add opacity and animation styles for pending messages
   - Test: manually inject an optimistic offline message and verify rendering

2. **Phase 2 -- Offline enqueue injection** (2 hours)
   - Modify `ConversationView.tsx` offline path to create optimistic message
   - Add `addToQueueWithId()` to `offlineStore` so the queue ID is known before injection
   - Verify: send message while offline, see it inline with pending badge

3. **Phase 3 -- Flush success transition** (2 hours)
   - Modify `useOfflineQueue` `flush` success path to remove `__offline` from the
     optimistic message in the React Query cache
   - Invalidate queries to replace optimistic with real server message
   - Create `offlineMessageHelpers.ts` with `updateOfflineMessageStatus` and
     `removeOptimisticMessage`
   - Test: send offline, come online, verify transition from pending to sent

4. **Phase 4 -- Failure + retry/discard** (1.5 hours)
   - Implement `markOfflineMessageFailed` to set `__offline.status = "failed"`
   - Wire failure from `useOfflineQueue` and SW postMessage to the helper
   - Add retry and discard buttons in `OfflineStatusBadge`
   - Test: mock server error, verify red error state with retry/discard buttons

5. **Phase 5 -- Feed post optimistic** (2 hours)
   - Modify `FeedTimeline.tsx` to read offline queue and prepend optimistic posts
   - Add offline indicator to `PostCard`
   - Handle flush success (remove optimistic, invalidate feed queries)
   - Test: create post offline, verify it appears in feed with pending badge

6. **Phase 6 -- Restore after reload** (1 hour)
   - Create `useOfflineOptimisticRestore` hook
   - Mount in `AppShell`
   - Test: send offline, reload page (still offline), verify message re-appears

7. **Phase 7 -- Accessibility + polish** (1 hour)
   - Add ARIA attributes to offline status indicators
   - Add live region announcements for state transitions
   - Add focus management for retry/discard
   - Test with screen reader (VoiceOver/NVDA)

8. **Phase 8 -- SW sync integration** (1 hour)
   - Create `useServiceWorkerSync` hook
   - Wire postMessage events from PWA-004 to offline helpers
   - Test: full round-trip with Background Sync

---

## 5. Testing Strategy

### 5.1 E2E Test Plan (`frontend/e2e/pwa-optimistic-ui.spec.ts`)

**Section 102: Offline Message Optimistic Display (8 tests)**

```typescript
import { test, expect, type Page, type BrowserContext } from "@playwright/test";

// ── Test helpers ──────────────────────────────────────────────────

const sessions: Record<string, { session_id: string; csrf_token: string; access_token: string }> = {};

async function injectAuth(page: Page, identity: string) {
  const s = sessions[identity];
  if (!s) throw new Error(`No session for ${identity}`);
  await page.context().addCookies([
    { name: "ui_session", value: s.session_id, domain: "localhost", path: "/" },
    { name: "ui_csrf", value: s.csrf_token, domain: "localhost", path: "/" },
    { name: "ui_access_token", value: s.access_token, domain: "localhost", path: "/" },
  ]);
}

async function setupDmConversation(page: Page, identity: string): Promise<string> {
  // Navigate to messages and open/create DM with Bob
  await injectAuth(page, identity);
  await page.goto("/messages");
  // ... DM setup logic ...
  return convoId;
}

// ── Tests ──────────────────────────────────────────────────────────

test.describe("102. Offline Message Optimistic Display", () => {
  test("102.1 offline message appears inline with pending badge", async ({ page }) => {
    await injectAuth(page, "alice");
    await page.goto("/messages");
    // Navigate to a conversation with Bob
    // ... open DM ...

    // Go offline
    await page.context().setOffline(true);

    // Send a message
    const testMsg = `Offline opt test ${Date.now()}`;
    await page.getByPlaceholder(/type a message/i).fill(testMsg);
    await page.getByRole("button", { name: /send/i }).click();

    // Verify message appears in conversation
    await expect(page.locator("p").filter({ hasText: testMsg })).toBeVisible();

    // Verify pending badge is visible
    await expect(page.getByText(/sending when online/i)).toBeVisible();

    await page.context().setOffline(false);
  });

  test("102.2 offline message has reduced opacity", async ({ page }) => {
    await injectAuth(page, "alice");
    await page.goto("/messages");
    // ... setup ...

    await page.context().setOffline(true);
    const testMsg = `Opacity test ${Date.now()}`;
    await page.getByPlaceholder(/type a message/i).fill(testMsg);
    await page.getByRole("button", { name: /send/i }).click();

    // Check opacity class on the message bubble
    const bubble = page.locator("p").filter({ hasText: testMsg }).locator("../..");
    await expect(bubble).toHaveClass(/opacity-7/);

    await page.context().setOffline(false);
  });

  test("102.3 offline message transitions to sent when online", async ({ page }) => {
    await injectAuth(page, "alice");
    await page.goto("/messages");
    // ... setup DM, go offline, send message ...

    const testMsg = `Transition test ${Date.now()}`;
    await page.context().setOffline(true);
    await page.getByPlaceholder(/type a message/i).fill(testMsg);
    await page.getByRole("button", { name: /send/i }).click();

    // Verify pending
    await expect(page.getByText(/sending when online/i)).toBeVisible();

    // Come back online
    await page.context().setOffline(false);

    // Wait for the pending badge to disappear (flush + refetch)
    await expect(page.getByText(/sending when online/i)).not.toBeVisible({ timeout: 15000 });

    // Message text should still be visible (now from server)
    await expect(page.locator("p").filter({ hasText: testMsg })).toBeVisible();

    // Opacity should be restored to full
    const bubble = page.locator("p").filter({ hasText: testMsg }).locator("../..");
    await expect(bubble).not.toHaveClass(/opacity-7/);
  });

  test("102.4 multiple offline messages appear in order", async ({ page }) => {
    await injectAuth(page, "alice");
    await page.goto("/messages");
    // ... setup ...

    await page.context().setOffline(true);

    const ts = Date.now();
    // Send three messages
    for (const suffix of ["first", "second", "third"]) {
      const text = `Order ${suffix} ${ts}`;
      await page.getByPlaceholder(/type a message/i).fill(text);
      await page.getByRole("button", { name: /send/i }).click();
      await page.waitForTimeout(100);
    }

    // All three should appear in order (first at top, third at bottom)
    const bubbles = page.locator("p").filter({ hasText: new RegExp(`Order .+ ${ts}`) });
    await expect(bubbles).toHaveCount(3);
    const texts = await bubbles.allTextContents();
    expect(texts[0]).toContain("first");
    expect(texts[1]).toContain("second");
    expect(texts[2]).toContain("third");

    // All should have pending badges
    const badges = page.getByText(/sending when online/i);
    await expect(badges).toHaveCount(3);

    await page.context().setOffline(false);
  });

  test("102.5 offline message persists after page reload", async ({ page }) => {
    await injectAuth(page, "alice");
    await page.goto("/messages");
    // ... setup + open DM ...

    const testMsg = `Reload test ${Date.now()}`;
    await page.context().setOffline(true);
    await page.getByPlaceholder(/type a message/i).fill(testMsg);
    await page.getByRole("button", { name: /send/i }).click();

    // Verify it appears
    await expect(page.locator("p").filter({ hasText: testMsg })).toBeVisible();

    // Reload while offline
    await page.reload();
    await page.waitForTimeout(2000);

    // Navigate back to the conversation
    // ... re-open DM ...

    // The message should re-appear from the persisted queue
    await expect(page.locator("p").filter({ hasText: testMsg })).toBeVisible();
    await expect(page.getByText(/sending when online/i)).toBeVisible();

    await page.context().setOffline(false);
  });

  test("102.6 offline message shows sending state during flush", async ({ page }) => {
    await injectAuth(page, "alice");
    await page.goto("/messages");
    // ... setup + open DM ...

    const testMsg = `Sending state test ${Date.now()}`;
    await page.context().setOffline(true);
    await page.getByPlaceholder(/type a message/i).fill(testMsg);
    await page.getByRole("button", { name: /send/i }).click();

    // Verify pending
    await expect(page.getByText(/sending when online/i)).toBeVisible();

    // Intercept the message POST to delay it
    await page.route("**/messaging/conversations/*/messages", async (route) => {
      await new Promise((r) => setTimeout(r, 2000));
      await route.continue();
    });

    // Come back online
    await page.context().setOffline(false);

    // Should briefly show "Sending..." with spinner
    await expect(page.getByText(/^Sending\.\.\.$/)).toBeVisible({ timeout: 5000 });

    // Then transition to sent (after the delayed response)
    await expect(page.getByText(/^Sending\.\.\.$/)).not.toBeVisible({ timeout: 10000 });
    await expect(page.locator("p").filter({ hasText: testMsg })).toBeVisible();
  });

  test("102.7 offline message hover toolbar is hidden", async ({ page }) => {
    await injectAuth(page, "alice");
    await page.goto("/messages");
    // ... setup + open DM ...

    const testMsg = `Toolbar test ${Date.now()}`;
    await page.context().setOffline(true);
    await page.getByPlaceholder(/type a message/i).fill(testMsg);
    await page.getByRole("button", { name: /send/i }).click();

    // Hover over the offline message
    const bubble = page.locator("p").filter({ hasText: testMsg });
    await bubble.hover();

    // The reply, react, and more actions buttons should NOT appear
    await expect(page.getByRole("button", { name: /react/i })).not.toBeVisible();
    await expect(page.getByRole("button", { name: /reply/i })).not.toBeVisible();
    await expect(page.getByRole("button", { name: /message actions/i })).not.toBeVisible();

    await page.context().setOffline(false);
  });

  test("102.8 offline message with reply shows reply preview", async ({ page }) => {
    await injectAuth(page, "alice");
    await page.goto("/messages");
    // ... setup + open DM with existing messages ...

    // Click reply on an existing message from Bob
    const bobMsg = page.locator("p").filter({ hasText: /bob.*message/i }).first();
    await bobMsg.hover();
    await page.getByRole("button", { name: /reply/i }).click();

    // Go offline and send the reply
    await page.context().setOffline(true);
    const replyText = `Offline reply ${Date.now()}`;
    await page.getByPlaceholder(/type a message/i).fill(replyText);
    await page.getByRole("button", { name: /send/i }).click();

    // The reply should appear with a reply preview
    await expect(page.locator("p").filter({ hasText: replyText })).toBeVisible();
    // Should show reply-to indicator
    // The reply preview text depends on the original message content

    await page.context().setOffline(false);
  });
});
```

**Section 103: Failed Message UI (5 tests)**

```typescript
test.describe("103. Failed Message UI", () => {
  test("103.1 failed message shows error badge with retry/discard", async ({ page }) => {
    await injectAuth(page, "alice");
    await page.goto("/messages");
    // ... setup DM ...

    const testMsg = `Fail test ${Date.now()}`;

    // Go offline, send a message
    await page.context().setOffline(true);
    await page.getByPlaceholder(/type a message/i).fill(testMsg);
    await page.getByRole("button", { name: /send/i }).click();

    // Verify pending
    await expect(page.locator("p").filter({ hasText: testMsg })).toBeVisible();

    // Intercept message POST to return 400 (permanent failure)
    await page.route("**/messaging/conversations/*/messages", (route) => {
      route.fulfill({
        status: 400,
        contentType: "application/json",
        body: JSON.stringify({ detail: "Message content rejected" }),
      });
    });

    // Come back online (triggers flush, which hits 400)
    await page.context().setOffline(false);

    // Verify error badge appears
    await expect(page.getByText(/failed to send/i)).toBeVisible({ timeout: 15000 });
    await expect(page.getByRole("button", { name: /retry/i })).toBeVisible();
    await expect(page.getByRole("button", { name: /discard/i })).toBeVisible();

    // Message text should still be visible (not removed)
    await expect(page.locator("p").filter({ hasText: testMsg })).toBeVisible();

    // Message should have a red ring
    const bubble = page.locator("p").filter({ hasText: testMsg }).locator("../..");
    await expect(bubble).toHaveClass(/ring-destructive/);
  });

  test("103.2 retry moves failed message back to pending", async ({ page }) => {
    // ... setup failed message from 103.1 ...

    // Unblock the API route for retry
    await page.unroute("**/messaging/conversations/*/messages");

    // Click retry
    await page.getByRole("button", { name: /retry/i }).click();

    // Should show pending state again (not failed)
    await expect(page.getByText(/sending when online/i)).toBeVisible();
    await expect(page.getByText(/failed to send/i)).not.toBeVisible();

    // Toast should confirm
    await expect(page.getByText(/re-queued/i)).toBeVisible();
  });

  test("103.3 discard removes the message from the conversation", async ({ page }) => {
    // ... setup failed message ...

    const testMsg = `Discard test ${Date.now()}`;
    // ... go offline, send, go online with blocked route, wait for failure ...

    await page.getByRole("button", { name: /discard/i }).click();

    // Message should be removed from the conversation
    await expect(page.locator("p").filter({ hasText: testMsg })).not.toBeVisible();

    // Toast should confirm
    await expect(page.getByText(/discarded/i)).toBeVisible();
  });

  test("103.4 multiple failed messages each have retry/discard", async ({ page }) => {
    // ... setup two failed messages ...

    const retryButtons = page.getByRole("button", { name: /retry/i });
    const discardButtons = page.getByRole("button", { name: /discard/i });

    await expect(retryButtons).toHaveCount(2);
    await expect(discardButtons).toHaveCount(2);

    // Discard the first, retry the second
    await discardButtons.first().click();
    await expect(retryButtons).toHaveCount(1);
    await expect(discardButtons).toHaveCount(1);
  });

  test("103.5 failed message error text shows server error", async ({ page }) => {
    // ... setup with specific error message ...

    await page.route("**/messaging/conversations/*/messages", (route) => {
      route.fulfill({
        status: 422,
        contentType: "application/json",
        body: JSON.stringify({ detail: "Message text exceeds maximum length" }),
      });
    });

    // ... go online to trigger flush ...

    // Error text should show the specific server error
    await expect(
      page.getByText(/message text exceeds maximum length/i),
    ).toBeVisible({ timeout: 15000 });
  });
});
```

**Section 104: Offline Feed Post Optimistic (6 tests)**

```typescript
test.describe("104. Offline Feed Post Optimistic", () => {
  test("104.1 offline post appears at top of feed with pending badge", async ({ page }) => {
    await injectAuth(page, "alice");
    await page.goto("/feed");

    await page.context().setOffline(true);

    const testPost = `Offline post ${Date.now()}`;
    const composer = page.getByPlaceholder(/what.*mind|write.*post/i);
    if (await composer.isVisible({ timeout: 3000 }).catch(() => false)) {
      await composer.fill(testPost);
      await page.getByRole("button", { name: /post|publish/i }).click();

      // Post should appear in the feed
      await expect(page.getByText(testPost)).toBeVisible();
      await expect(page.getByText(/waiting to publish/i)).toBeVisible();
    }

    await page.context().setOffline(false);
  });

  test("104.2 offline post transitions to published when online", async ({ page }) => {
    // ... setup offline post, come back online ...
    // Verify "waiting to publish" disappears
    await expect(page.getByText(/waiting to publish/i)).not.toBeVisible({ timeout: 10000 });
  });

  test("104.3 offline post has reduced opacity", async ({ page }) => {
    await injectAuth(page, "alice");
    await page.goto("/feed");

    await page.context().setOffline(true);
    const testPost = `Opacity post test ${Date.now()}`;
    // ... fill composer and submit ...

    // Check the card has reduced opacity
    const card = page.getByText(testPost).locator("ancestor::div[class*='opacity']");
    await expect(card).toBeVisible();

    await page.context().setOffline(false);
  });

  test("104.4 offline post like button is disabled", async ({ page }) => {
    await injectAuth(page, "alice");
    await page.goto("/feed");

    await page.context().setOffline(true);
    const testPost = `Like disabled test ${Date.now()}`;
    // ... fill composer and submit ...

    // Find the like button near the offline post
    const postCard = page.getByText(testPost).locator("ancestor::article, ancestor::div[class*='card']");
    const likeButton = postCard.getByRole("button", { name: /like|heart/i }).first();
    await expect(likeButton).toBeDisabled();

    await page.context().setOffline(false);
  });

  test("104.5 offline post persists after page reload", async ({ page }) => {
    await injectAuth(page, "alice");
    await page.goto("/feed");

    await page.context().setOffline(true);
    const testPost = `Reload post test ${Date.now()}`;
    // ... fill composer and submit ...

    await expect(page.getByText(testPost)).toBeVisible();

    // Reload while offline
    await page.reload();
    await page.waitForTimeout(2000);

    // Post should re-appear (from offline store hydration)
    await expect(page.getByText(testPost)).toBeVisible();
    await expect(page.getByText(/waiting to publish/i)).toBeVisible();

    await page.context().setOffline(false);
  });

  test("104.6 offline post composer resets after queueing", async ({ page }) => {
    await injectAuth(page, "alice");
    await page.goto("/feed");

    await page.context().setOffline(true);
    const testPost = `Composer reset test ${Date.now()}`;
    const composer = page.getByPlaceholder(/what.*mind|write.*post/i);
    await composer.fill(testPost);
    await page.getByRole("button", { name: /post|publish/i }).click();

    // Composer should be empty (content captured in queue)
    await expect(composer).toHaveValue("");

    // But the post should appear in the feed
    await expect(page.getByText(testPost)).toBeVisible();

    await page.context().setOffline(false);
  });
});
```

**Section 105: Offline Encrypted Message Optimistic (3 tests)**

```typescript
test.describe("105. Offline Encrypted Message Optimistic", () => {
  test("105.1 encrypted offline message shows 'Encrypted message' with pending badge", async ({ page }) => {
    await injectAuth(page, "alice");
    await page.goto("/messages");
    // ... setup DM, enable encryption ...

    await page.context().setOffline(true);

    // Send an encrypted message
    // ... toggle encryption, type message, send ...

    // Should show "Encrypted message" text (not the actual text)
    await expect(page.getByText(/encrypted message/i)).toBeVisible();
    // Should also show pending badge
    await expect(page.getByText(/sending when online/i)).toBeVisible();

    await page.context().setOffline(false);
  });

  test("105.2 encrypted offline message transitions to sent", async ({ page }) => {
    // ... similar to 102.3 but with encryption ...
    // Verify the encrypted message stays encrypted after flush
    await expect(page.getByText(/encrypted message/i)).toBeVisible();
    await expect(page.getByText(/sending when online/i)).not.toBeVisible({ timeout: 15000 });
  });

  test("105.3 encrypted offline message with lock shows both badges", async ({ page }) => {
    // ... send encrypted + locked message while offline ...
    // Should show both lock badge and pending badge
    await expect(page.getByText(/locked/i)).toBeVisible();
    await expect(page.getByText(/sending when online/i)).toBeVisible();
  });
});
```

**Section 106: Offline Queue Banner Integration (3 tests)**

```typescript
test.describe("106. Offline Queue Banner Integration", () => {
  test("106.1 banner shows queue count when messages queued offline", async ({ page }) => {
    await injectAuth(page, "alice");
    await page.goto("/messages");

    await page.context().setOffline(true);

    // Banner should appear
    await expect(page.getByText(/you're offline/i)).toBeVisible();

    // Send two messages
    for (let i = 0; i < 2; i++) {
      await page.getByPlaceholder(/type a message/i).fill(`Banner test ${i} ${Date.now()}`);
      await page.getByRole("button", { name: /send/i }).click();
      await page.waitForTimeout(100);
    }

    // Banner should show "2 queued"
    await expect(page.getByText(/2 queued/)).toBeVisible();

    await page.context().setOffline(false);
  });

  test("106.2 banner count decreases as items flush", async ({ page }) => {
    // ... setup 3 queued messages ...
    // Go online
    await page.context().setOffline(false);

    // Banner should eventually disappear (all items flushed)
    await expect(page.getByText(/queued/)).not.toBeVisible({ timeout: 15000 });
  });

  test("106.3 banner shows failed count", async ({ page }) => {
    // ... setup 2 messages, block API, go online ...
    // Should show "2 failed"
    await expect(page.getByText(/failed/)).toBeVisible({ timeout: 15000 });
  });
});
```

**Section 107: Group Chat Offline Optimistic (3 tests)**

```typescript
test.describe("107. Group Chat Offline Optimistic", () => {
  test("107.1 offline message in group chat shows pending badge", async ({ page }) => {
    await injectAuth(page, "alice");
    await page.goto("/messages");
    // ... navigate to group chat ...

    await page.context().setOffline(true);
    const testMsg = `Group offline test ${Date.now()}`;
    await page.getByPlaceholder(/type a message/i).fill(testMsg);
    await page.getByRole("button", { name: /send/i }).click();

    await expect(page.locator("p").filter({ hasText: testMsg })).toBeVisible();
    await expect(page.getByText(/sending when online/i)).toBeVisible();

    await page.context().setOffline(false);
  });

  test("107.2 group offline message transitions to sent when online", async ({ page }) => {
    // ... similar to DM transition test ...
  });

  test("107.3 multiple group offline messages appear in chronological order", async ({ page }) => {
    // ... similar to 102.4 but in group chat ...
  });
});
```

**Section 108: Sidebar Preview for Offline Messages (2 tests)**

```typescript
test.describe("108. Sidebar Preview for Offline Messages", () => {
  test("108.1 sidebar shows offline message text as preview", async ({ page }) => {
    await injectAuth(page, "alice");
    await page.goto("/messages");

    await page.context().setOffline(true);

    // Navigate to DM, send a message
    const testMsg = `Sidebar preview test ${Date.now()}`;
    // ... navigate to DM, send message ...

    // Go back to conversation list
    if (await page.getByRole("button", { name: /back/i }).isVisible()) {
      await page.getByRole("button", { name: /back/i }).click();
    }

    // Sidebar should show the message text as preview
    await expect(page.getByText(testMsg).first()).toBeVisible();

    await page.context().setOffline(false);
  });

  test("108.2 sidebar preview updates after flush", async ({ page }) => {
    // ... send offline, go online, verify sidebar preview still shows ...
    // After flush, the real last_message should replace the optimistic one
  });
});
```

### 5.2 Unit Tests

- `frontend/src/lib/__tests__/offlineMessageHelpers.test.ts`:

```typescript
import { describe, it, expect, vi } from "vitest";
import { QueryClient } from "@tanstack/react-query";
import {
  markOfflineMessageFailed,
  updateOfflineMessageStatus,
  removeOptimisticMessage,
  removeOfflineField,
  isOfflineOptimistic,
  isOptimisticMessageId,
  isOfflineOptimisticMessageId,
} from "../offlineMessageHelpers";

describe("offlineMessageHelpers", () => {
  describe("isOfflineOptimistic", () => {
    it("returns true for messages with __offline field", () => {
      expect(isOfflineOptimistic({ __offline: { queueId: "x", status: "pending", enqueuedAt: 0 } })).toBe(true);
    });
    it("returns false for messages without __offline field", () => {
      expect(isOfflineOptimistic({})).toBe(false);
    });
  });

  describe("isOptimisticMessageId", () => {
    it("matches optimistic- prefix", () => {
      expect(isOptimisticMessageId("optimistic-12345")).toBe(true);
      expect(isOptimisticMessageId("optimistic-offline-abc")).toBe(true);
      expect(isOptimisticMessageId("m_abc123")).toBe(false);
    });
  });

  describe("isOfflineOptimisticMessageId", () => {
    it("matches optimistic-offline- prefix", () => {
      expect(isOfflineOptimisticMessageId("optimistic-offline-abc")).toBe(true);
      expect(isOfflineOptimisticMessageId("optimistic-12345")).toBe(false);
    });
  });

  describe("markOfflineMessageFailed", () => {
    it("updates status to failed with error message", () => {
      const qc = new QueryClient();
      const queueId = "offline-123-abc";
      const msgId = `optimistic-offline-${queueId}`;

      // Seed cache with an optimistic message
      qc.setQueryData(["messages", "conv1"], {
        pages: [{
          messages: [{
            message_id: msgId,
            conversation_id: "conv1",
            sender_id: "alice",
            kind: "text",
            text: "Hello",
            created_at: 1000,
            reactions_counts: {},
            __offline: { queueId, status: "sending", enqueuedAt: 1000 },
          }],
          next_cursor: undefined,
        }],
        pageParams: [undefined],
      });

      markOfflineMessageFailed(qc, queueId, "Server rejected");

      const data = qc.getQueryData(["messages", "conv1"]) as any;
      const msg = data.pages[0].messages[0];
      expect(msg.__offline.status).toBe("failed");
      expect(msg.__offline.error).toBe("Server rejected");
    });
  });

  describe("updateOfflineMessageStatus", () => {
    it("updates status from pending to sending", () => {
      const qc = new QueryClient();
      const queueId = "offline-456-def";
      const msgId = `optimistic-offline-${queueId}`;

      qc.setQueryData(["messages", "conv2"], {
        pages: [{
          messages: [{
            message_id: msgId,
            conversation_id: "conv2",
            sender_id: "alice",
            kind: "text",
            text: "Test",
            created_at: 2000,
            reactions_counts: {},
            __offline: { queueId, status: "pending", enqueuedAt: 2000 },
          }],
        }],
        pageParams: [undefined],
      });

      updateOfflineMessageStatus(qc, queueId, "sending");

      const data = qc.getQueryData(["messages", "conv2"]) as any;
      expect(data.pages[0].messages[0].__offline.status).toBe("sending");
    });
  });

  describe("removeOptimisticMessage", () => {
    it("removes the optimistic message from the cache", () => {
      const qc = new QueryClient();
      qc.setQueryData(["messages", "conv3"], {
        pages: [{
          messages: [
            { message_id: "optimistic-offline-id1", text: "Offline msg", __offline: { queueId: "id1", status: "failed", enqueuedAt: 0 } },
            { message_id: "m_real_msg", text: "Real msg" },
          ],
        }],
        pageParams: [undefined],
      });

      removeOptimisticMessage(qc, "conv3", "optimistic-offline-id1");

      const data = qc.getQueryData(["messages", "conv3"]) as any;
      expect(data.pages[0].messages).toHaveLength(1);
      expect(data.pages[0].messages[0].message_id).toBe("m_real_msg");
    });
  });

  describe("removeOfflineField", () => {
    it("removes __offline field, leaving rest of message intact", () => {
      const qc = new QueryClient();
      const queueId = "offline-789-ghi";
      const msgId = `optimistic-offline-${queueId}`;

      qc.setQueryData(["messages", "conv4"], {
        pages: [{
          messages: [{
            message_id: msgId,
            text: "Sent successfully",
            __offline: { queueId, status: "sending", enqueuedAt: 3000 },
          }],
        }],
        pageParams: [undefined],
      });

      removeOfflineField(qc, queueId);

      const data = qc.getQueryData(["messages", "conv4"]) as any;
      const msg = data.pages[0].messages[0];
      expect(msg.__offline).toBeUndefined();
      expect(msg.text).toBe("Sent successfully");
    });
  });
});
```

- `frontend/src/hooks/__tests__/useOfflineOptimisticRestore.test.tsx`:

```typescript
import { describe, it, expect, vi, beforeEach } from "vitest";
import { renderHook } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useOfflineOptimisticRestore } from "../useOfflineOptimisticRestore";
import { useOfflineStore } from "@/stores/offlineStore";
import { useAuthStore } from "@/stores/authStore";

function createWrapper(qc: QueryClient) {
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={qc}>{children}</QueryClientProvider>
  );
}

describe("useOfflineOptimisticRestore", () => {
  let qc: QueryClient;

  beforeEach(() => {
    qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    // Reset stores
    useOfflineStore.setState({ queue: [], isOnline: false });
    useAuthStore.setState({ userId: "alice" });
  });

  it("injects optimistic messages from queue into React Query cache", () => {
    useOfflineStore.setState({
      queue: [
        {
          id: "offline-1-abc",
          type: "send_message",
          enqueuedAt: 1000000,
          payload: {
            conversationId: "conv-1",
            req: { text: "Hello from offline" },
          },
        },
      ],
      isOnline: false,
    });

    renderHook(() => useOfflineOptimisticRestore(qc), {
      wrapper: createWrapper(qc),
    });

    const data = qc.getQueryData(["messages", "conv-1"]) as any;
    expect(data).toBeDefined();
    expect(data.pages[0].messages).toHaveLength(1);
    expect(data.pages[0].messages[0].text).toBe("Hello from offline");
    expect(data.pages[0].messages[0].__offline.status).toBe("pending");
  });

  it("does not inject when online", () => {
    useOfflineStore.setState({
      queue: [
        {
          id: "offline-2-def",
          type: "send_message",
          enqueuedAt: 2000000,
          payload: {
            conversationId: "conv-2",
            req: { text: "Should not appear" },
          },
        },
      ],
      isOnline: true,  // ONLINE
    });

    renderHook(() => useOfflineOptimisticRestore(qc), {
      wrapper: createWrapper(qc),
    });

    const data = qc.getQueryData(["messages", "conv-2"]);
    expect(data).toBeUndefined();
  });

  it("does not duplicate on re-render", () => {
    useOfflineStore.setState({
      queue: [
        {
          id: "offline-3-ghi",
          type: "send_message",
          enqueuedAt: 3000000,
          payload: {
            conversationId: "conv-3",
            req: { text: "No duplicates" },
          },
        },
      ],
      isOnline: false,
    });

    const { rerender } = renderHook(() => useOfflineOptimisticRestore(qc), {
      wrapper: createWrapper(qc),
    });

    // Re-render multiple times
    rerender();
    rerender();

    const data = qc.getQueryData(["messages", "conv-3"]) as any;
    expect(data.pages[0].messages).toHaveLength(1);
  });

  it("handles multiple messages across different conversations", () => {
    useOfflineStore.setState({
      queue: [
        {
          id: "offline-4a",
          type: "send_message",
          enqueuedAt: 4000000,
          payload: { conversationId: "conv-a", req: { text: "Msg A" } },
        },
        {
          id: "offline-4b",
          type: "send_message",
          enqueuedAt: 4000001,
          payload: { conversationId: "conv-b", req: { text: "Msg B" } },
        },
      ],
      isOnline: false,
    });

    renderHook(() => useOfflineOptimisticRestore(qc), {
      wrapper: createWrapper(qc),
    });

    const dataA = qc.getQueryData(["messages", "conv-a"]) as any;
    const dataB = qc.getQueryData(["messages", "conv-b"]) as any;
    expect(dataA.pages[0].messages[0].text).toBe("Msg A");
    expect(dataB.pages[0].messages[0].text).toBe("Msg B");
  });

  it("restores failed items with correct status", () => {
    useOfflineStore.setState({
      queue: [
        {
          id: "offline-5-jkl",
          type: "send_message",
          enqueuedAt: 5000000,
          __status: "failed",
          __error: "Server rejected",
          payload: { conversationId: "conv-5", req: { text: "Failed msg" } },
        },
      ],
      isOnline: false,
    });

    renderHook(() => useOfflineOptimisticRestore(qc), {
      wrapper: createWrapper(qc),
    });

    const data = qc.getQueryData(["messages", "conv-5"]) as any;
    expect(data.pages[0].messages[0].__offline.status).toBe("failed");
    expect(data.pages[0].messages[0].__offline.error).toBe("Server rejected");
  });
});
```

- `frontend/src/stores/__tests__/offlineStore.test.ts`:

```typescript
import { describe, it, expect, beforeEach } from "vitest";
import { useOfflineStore } from "../offlineStore";

describe("offlineStore extensions", () => {
  beforeEach(() => {
    useOfflineStore.setState({ queue: [], isOnline: true });
  });

  describe("addToQueueWithId", () => {
    it("adds an action with the specified ID", () => {
      useOfflineStore.getState().addToQueueWithId("custom-id-123", {
        type: "send_message",
        payload: { conversationId: "conv1", req: { text: "Hello" } },
      });

      const queue = useOfflineStore.getState().queue;
      expect(queue).toHaveLength(1);
      expect(queue[0].id).toBe("custom-id-123");
      expect(queue[0].type).toBe("send_message");
    });
  });

  describe("updateActionStatus", () => {
    it("updates status and error for a specific action", () => {
      useOfflineStore.getState().addToQueueWithId("status-test", {
        type: "send_message",
        payload: { conversationId: "conv1", req: { text: "Hello" } },
      });

      useOfflineStore.getState().updateActionStatus("status-test", "failed", "Network error");

      const action = useOfflineStore.getState().queue[0];
      expect(action.__status).toBe("failed");
      expect(action.__error).toBe("Network error");
    });
  });

  describe("retryAction", () => {
    it("resets status to pending and increments retry count", () => {
      useOfflineStore.getState().addToQueueWithId("retry-test", {
        type: "send_message",
        payload: { conversationId: "conv1", req: { text: "Hello" } },
      });

      useOfflineStore.getState().updateActionStatus("retry-test", "failed", "Error");
      useOfflineStore.getState().retryAction("retry-test");

      const action = useOfflineStore.getState().queue[0];
      expect(action.__status).toBe("pending");
      expect(action.__error).toBeUndefined();
      expect(action.__retryCount).toBe(1);
    });

    it("increments retry count on each retry", () => {
      useOfflineStore.getState().addToQueueWithId("retry-count", {
        type: "send_message",
        payload: { conversationId: "conv1", req: { text: "Hello" } },
      });

      useOfflineStore.getState().retryAction("retry-count");
      useOfflineStore.getState().retryAction("retry-count");
      useOfflineStore.getState().retryAction("retry-count");

      const action = useOfflineStore.getState().queue[0];
      expect(action.__retryCount).toBe(3);
    });
  });
});
```

### 5.3 Visual Regression Tests

Add visual snapshot tests for the offline message states using Playwright's screenshot
comparison:

```typescript
test("visual: pending message bubble appearance", async ({ page }) => {
  // ... setup offline message ...
  const bubble = page.locator("p").filter({ hasText: testMsg }).locator("../..");
  await expect(bubble).toHaveScreenshot("pending-message-bubble.png");
});

test("visual: failed message bubble appearance", async ({ page }) => {
  // ... setup failed message ...
  const bubble = page.locator("p").filter({ hasText: testMsg }).locator("../..");
  await expect(bubble).toHaveScreenshot("failed-message-bubble.png");
});
```

### 5.4 Manual Testing Checklist

| Scenario | Steps | Expected Result |
|----------|-------|-----------------|
| Basic offline message | Go offline -> Send message -> Observe | Message appears with clock icon, reduced opacity |
| Multiple offline messages | Go offline -> Send 3 messages -> Observe | All 3 appear in order with pending badges |
| Reconnect flush | Offline -> Send -> Go online | Pending badge disappears, message stays |
| Flush failure | Offline -> Send -> Block API -> Go online | Red error with retry/discard buttons |
| Retry after failure | Fail state -> Click Retry -> Unblock API | Returns to pending, then sends on next flush |
| Discard after failure | Fail state -> Click Discard | Message removed from conversation |
| Page reload while offline | Offline -> Send -> Reload | Message re-appears from localStorage |
| Page reload then online | Offline -> Send -> Reload -> Go online | Message appears, then flushes successfully |
| Feed post offline | Go offline -> Create post -> Observe feed | Post appears at top with "Waiting to publish" |
| Feed post flush | Offline post -> Go online | "Waiting" badge disappears |
| Encrypted message offline | Offline -> Enable encryption -> Send | Shows "Encrypted message" + pending badge |
| Group chat offline | Open group -> Go offline -> Send | Pending badge appears in group |
| Reply while offline | Reply to existing message -> Go offline -> Send | Reply preview shows correctly |
| Sidebar preview | Offline -> Send -> Navigate to convo list | Sidebar shows the offline message text |
| Banner queue count | Offline -> Send 3 messages | Banner shows "3 queued" |

---

## 6. Edge Cases & Gotchas

### 6.1 Optimistic Message ID Collisions

The optimistic message ID format `optimistic-offline-${queueId}` uses the same queue ID
that is stored in the offline store. Since queue IDs include `Date.now()` and a random
string (line 52 of `offlineStore.ts`), collisions are extremely unlikely. However, if two
messages are queued within the same millisecond, the random suffix prevents collisions.

#### 6.1.1 Theoretical Collision Analysis

The ID format is: `offline-<timestamp_ms>-<random_base36>`

Where `Math.random().toString(36).slice(2)` produces ~10.7 characters of randomness
(~55 bits of entropy). Combined with the millisecond timestamp, the probability of
collision is approximately 2^(-55) per millisecond, which is negligible.

However, in automated tests that loop rapidly, `Date.now()` may return the same value for
consecutive calls. The random suffix handles this case.

### 6.2 React Query Cache vs. Offline Store as Source of Truth

The offline store (`localStorage`) is the persistent source of truth. The React Query cache
is in-memory and ephemeral. After a page reload:
- The offline store is hydrated from localStorage (Zustand persist middleware).
- The React Query cache is empty.
- The `useOfflineOptimisticRestore` hook reads the store and re-injects optimistic items
  into the query cache.

If the store and cache diverge (e.g., the flush succeeds but the cache update fails), the
next query invalidation will reconcile by fetching fresh data from the server.

#### 6.2.1 Divergence Scenario: Tab Backgrounded During Flush

If the user backgrounds the tab during flush:
1. `useOfflineQueue` starts flushing (tab was in foreground).
2. User switches to another tab.
3. Fetch completes but the `removeOfflineField` call may not execute immediately
   (React state updates are batched and may be deferred in background tabs).
4. The `removeFromQueue` call updates localStorage (Zustand persist is synchronous).
5. User returns to tab: React re-renders, `useOfflineOptimisticRestore` sees empty queue,
   but the React Query cache still has the `__offline` field on the message.

**Mitigation**: The `invalidateQueries` call (step 6 in the flush) triggers a refetch
that replaces the entire messages page. Even if `removeOfflineField` was deferred, the
refetch will provide the real message (without `__offline`), reconciling the cache.

### 6.3 Conversation Not Yet Loaded

If the user sends a message to a conversation that has not been loaded into the React Query
cache (e.g., they reload and navigate directly to `/messages`), the `setQueryData` call
finds no existing data for `["messages", conversationId]`. The `useOfflineOptimisticRestore`
hook handles this by creating a new pages structure with just the optimistic message.

#### 6.3.1 Lazy Loading Interaction

When the user navigates to the conversation, `useMessagesQuery` fires a GET request (or
uses the cached data if available). The cached data now contains only the optimistic
message(s). The GET request will also return real messages from the server (if online) or
fail (if offline).

**If offline**: The GET fails, and the cached data (optimistic messages only) is displayed.
The user sees their queued messages and an empty conversation otherwise. When they go
online, the GET succeeds and the optimistic messages are merged with real data.

**If online**: The GET succeeds and `invalidateQueries` replaces the cache. The optimistic
messages may briefly appear, then be replaced by the server response. If the flush has
already succeeded, the real message replaces the optimistic one seamlessly.

### 6.4 Multiple Offline Messages to Different Conversations

Each optimistic message is injected into the correct conversation's query cache using
`["messages", conversationId]`. The `allMessages` memo in `ConversationView` only renders
messages for the currently open conversation. Messages to other conversations appear in
those conversations when navigated to.

#### 6.4.1 Navigation Between Conversations While Offline

If the user navigates between conversations while offline:
1. Conversation A: Send message, optimistic injected into `["messages", "conv-A"]`
2. Navigate to Conversation B: `["messages", "conv-B"]` is fetched (may fail if offline)
3. Send message to B: optimistic injected into `["messages", "conv-B"]`
4. Navigate back to A: `["messages", "conv-A"]` cache still has the optimistic message

This works correctly because React Query caches are per-query-key and independent.

### 6.5 Feed Post Without Image URLs

Offline-queued posts may reference `image_urls` that point to server-side URLs. If the
images were uploaded before going offline, the URLs are valid. If the user composed a post
with images that were mid-upload when connectivity was lost, the `image_urls` may be empty
or incomplete. The optimistic post card should handle missing images gracefully.

#### 6.5.1 Partial Image Upload Recovery

The `CreatePost` component uploads images via `uploadPostImage` (line 694) before the
post is submitted. If the user goes offline mid-upload:
- The upload fails with a network error.
- The `imageUrls` state may have some successful URLs but not all.
- The offline-queued post includes only the successfully uploaded URLs.

The optimistic `PostCard` should render whatever images are available and show a
placeholder for missing ones:

```typescript
{post.__offline && post.image_urls?.some((url) => url.startsWith("blob:")) && (
  <p className="text-xs text-muted-foreground italic">
    Some images may not be available until online
  </p>
)}
```

### 6.6 Encrypted Messages

If the queued message has `encryption` envelope data, the optimistic message shows
"Encrypted message" (same as the online optimistic path at line 221 of
`ConversationView.tsx`). The `__offline` badge appears alongside the encryption indicator.

### 6.7 Strict Mode Violations in MessageBubble

Adding the `OfflineStatusBadge` inside the bubble may cause Playwright `getByText`
strict-mode violations if "Sending when online" text appears in multiple queued messages.
Tests should scope assertions using the message text as an anchor:
```typescript
page.locator("p").filter({ hasText: testMsg }).locator("..").getByText(/sending when online/i)
```

#### 6.7.1 Additional Playwright Strict Mode Considerations

The "Retry" and "Discard" buttons also appear once per failed message. When multiple
messages fail, `getByRole("button", { name: /retry/i })` matches multiple elements.
Tests should scope to a specific message's bubble:

```typescript
const failedBubble = page.locator("p").filter({ hasText: specificTestMsg }).locator("../..");
const retryBtn = failedBubble.getByRole("button", { name: /retry/i });
await retryBtn.click();
```

### 6.8 localStorage Storage Limits

The offline store is persisted to `localStorage`, which typically has a 5MB limit per
origin. Each queued message action is approximately 200-500 bytes (mostly the text
content). At 500 bytes per message, localStorage can hold approximately 10,000 queued
messages before hitting the limit.

However, if the user queues very long messages (e.g., 10KB each), the limit could be
reached with as few as 500 messages. The `addToQueue` method should check available space:

```typescript
addToQueueWithId: (id, action) => {
  try {
    set((s) => ({
      queue: [
        ...s.queue,
        { ...action, id, enqueuedAt: Date.now() } as OfflineAction,
      ],
    }));
  } catch (e) {
    if (e instanceof DOMException && e.name === "QuotaExceededError") {
      toast.error("Offline queue is full. Please go online to send pending messages.");
      throw e;
    }
    throw e;
  }
},
```

### 6.9 Concurrent Tabs

If the user has multiple tabs open and goes offline in both:
1. Tab A: queues message to conv-1
2. Tab B: queues message to conv-2

Both tabs write to the same `localStorage` key (`offline-store`). Zustand's persist
middleware does not handle cross-tab synchronization natively. The last write wins, which
could cause one tab's queue entries to overwrite the other's.

**Mitigation**: Use the `storage` event listener to synchronize across tabs:

```typescript
// In offlineStore.ts, add cross-tab sync
if (typeof window !== "undefined") {
  window.addEventListener("storage", (e) => {
    if (e.key === "offline-store" && e.newValue) {
      try {
        const parsed = JSON.parse(e.newValue);
        if (parsed?.state?.queue) {
          useOfflineStore.setState({ queue: parsed.state.queue });
        }
      } catch {
        // Ignore parse errors
      }
    }
  });
}
```

### 6.10 View-Once and Expiring Messages Queued Offline

If the user sends a view-once message (`view_once: true`) or an expiring message
(`expires_in_seconds: N`) while offline, the optimistic message should NOT show these
special behaviors client-side (since the server hasn't validated or started the timers).

- **View-once**: The optimistic message should show the text normally (it's the sender's
  own message, and senders always see view-once content).
- **Expiring**: The `expires_at` field is computed server-side at send time. The optimistic
  message has no `expires_at`, so the countdown timer does not start. After flush, the real
  message from the server includes `expires_at` and the timer begins.

### 6.11 Lock Price Queued Offline

If the user sends a locked message (`lock_price_cents > 0`) while offline, the optimistic
message shows the lock badge (sender view) with the price. However, the lock is not
enforceable until the server receives the message. If the recipient happens to see the
conversation before the flush completes, they will not see the locked message (it does not
exist on the server yet).

### 6.12 Tip Attached to Offline Message

If the user attaches a tip (`tip_amount_cents > 0`) to an offline message, the tip
billing entry is NOT created until the message is flushed. The optimistic message can show
the tip amount badge, but the billing ledger update happens server-side on flush.

### 6.13 Thread/Reply Context for Offline Messages

When replying to a message while offline, the `reply_to_message_id` and thread linkage
fields are included in the queued payload. The optimistic message renders with the reply
preview correctly because:
1. The `messageById` map in `ConversationView` includes the replied-to message (it's in
   the cached data).
2. The `MessageBubble` looks up `replyToMessage` via `messageById.get(msg.reply_to_message_id)`.

Edge case: If the replied-to message was itself an optimistic offline message, the lookup
still works because optimistic messages are in the `allMessages` array and thus in
`messageById`.

### 6.14 Offline Queue Ordering vs. Server Ordering

Messages are queued with `enqueuedAt` timestamps and flushed in FIFO order. The server
assigns `created_at` timestamps at receive time. If the flush takes several seconds (e.g.,
3 messages flushed sequentially with 1-second network round trips), the server timestamps
will differ from the queued timestamps.

This means the final message order (after server response) may differ slightly from the
optimistic order. In practice, this is imperceptible because all flushed messages are from
the same user and sent within seconds of each other.

### 6.15 Offline Banner Visibility While Online with Failed Items

After going online and flushing, if some items fail, the offline banner should remain
visible to show the failed count, even though the user is online. The banner condition
changes from `if (!offline) return null` to `if (!offline && failedCount === 0) return null`.

---

## 7. Security Considerations

### 7.1 Optimistic Messages and Data Integrity

Optimistic messages are client-side fabrications that have not been validated by the
backend. They are only shown to the sender on the sender's device. Other users never see
optimistic messages. The backend validates all fields when the message is actually sent
during flush.

#### 7.1.1 Validation at Flush Time

The backend's `send_text_message` endpoint performs these validations:
- **Authentication**: `require_ui_session` verifies the session cookie and CSRF token.
- **Authorization**: Checks that the sender is a participant in the conversation.
- **Content validation**: Checks text length limits, encryption envelope format, etc.
- **Rate limiting**: Prevents message spam.
- **Content moderation**: Checks for banned content patterns.

All of these validations occur at flush time. The optimistic message bypasses none of them.

### 7.2 Queue Tampering

If a malicious actor modifies the `localStorage` offline store to inject arbitrary
message text, the optimistic message appears only on the tampered device. When flushed,
the backend applies its normal validation (auth, CSRF, content moderation). A tampered
payload that fails validation goes to the dead-letter queue, not to the server.

#### 7.2.1 XSS Risk in Optimistic Message Text

The message text is rendered via React's `{message.text}` inside a `<p>` element, which
automatically escapes HTML entities. There is no `dangerouslySetInnerHTML` in the text
rendering path. Rich text posts use `RichContentRenderer` which sanitizes HTML.

Even if a malicious payload is injected into localStorage with `<script>` tags, React's
JSX escaping prevents execution.

#### 7.2.2 localStorage Eviction by Other Origins

On some browsers, localStorage entries can be evicted under storage pressure. If the
offline store is evicted between enqueue and flush, the queued messages are lost. The user
sees the optimistic messages disappear after reload (because the store is empty).

**Mitigation**: Consider using IndexedDB for the offline queue (more storage, less likely
to be evicted). This is deferred to PWA-004.

### 7.3 Failed Message Content Visibility

Failed messages remain visible in the conversation UI with their full text. This is the
user's own composed content on their own device -- no additional exposure risk. The "Retry"
action re-sends the exact same payload; "Discard" removes it permanently.

### 7.4 Offline Post with Locked Content

If the user creates a post with `unlock_price_cents` while offline, the optimistic post
shows the lock indicator. When flushed, the backend validates the lock price. If the
backend rejects the lock configuration, the post goes to dead-letter. The user can then
modify and retry (future enhancement) or discard.

### 7.5 Session Expiry During Offline Period

If the user's session expires while they are offline, the queued messages will fail to
flush with a 401 error when connectivity returns. The flush error handler should detect
401 responses and redirect to the login page:

```typescript
if (error instanceof ApiError && error.status === 401) {
  // Session expired — all remaining items will also fail
  // Do not mark as failed (misleading); instead, notify user to re-authenticate
  toast.error("Session expired. Please log in again to send queued messages.");
  // Do not clear the queue — messages should persist across re-login
  break; // Stop processing remaining items
}
```

### 7.6 CSRF Token Validity

The CSRF token is embedded in the session cookie and validated on non-GET requests.
If the CSRF token expires or changes during the offline period, the flush will fail with
a 403 CSRF error. The error handler should treat this as a session issue:

```typescript
if (error instanceof ApiError && error.status === 403) {
  // CSRF validation failed — session may be stale
  toast.error("Session validation failed. Please refresh the page.");
  break;
}
```

### 7.7 Privacy: Queued Message Persistence

Queued messages persist in localStorage indefinitely until flushed or discarded. On shared
devices, a subsequent user could potentially read the previous user's queued messages by
inspecting localStorage.

**Mitigation**: The existing logout flow should clear the offline store:

```typescript
// In the logout handler (authStore or wherever logout is implemented):
useOfflineStore.getState().clearQueue();
localStorage.removeItem("offline-store");
```

---

## 8. Performance Considerations

### 8.1 React Query Cache Size

Each optimistic message adds to the React Query cache. If the user queues many messages
(e.g., 50 messages across 10 conversations while offline), the cache grows proportionally.
This is a small overhead compared to the existing cache content (which already stores
hundreds of messages per conversation).

### 8.2 Zustand Store Reactivity

The `FeedTimeline` component subscribes to `useOfflineStore((s) => s.queue)`. When any
queue entry changes (e.g., status update from "pending" to "sending"), the entire
`offlinePosts` computation re-runs. This is acceptable because:
- The queue is typically small (< 50 items).
- The computation is O(N) where N is the queue size.
- React's reconciliation handles the re-render efficiently (only changed posts update).

For very large queues (> 100 items), consider memoizing the `offlinePosts` computation
with a stable selector that only recomputes when the relevant queue entries change.

### 8.3 Animation Performance

The `animate-pulse` class on the clock icon uses CSS `@keyframes pulse`, which animates
`opacity`. This is GPU-accelerated (compositor-only) and does not cause layout thrashing.

The `animate-spin` class on the `Loader2` icon uses CSS `@keyframes spin`, which animates
`transform: rotate()`. This is also GPU-accelerated.

### 8.4 Optimistic Message Creation Cost

Creating an optimistic message and calling `queryClient.setQueryData` is synchronous and
fast (< 1ms). The subsequent React re-render takes 5-15ms depending on the conversation
size. This is well within the 16ms frame budget for 60fps.

---

## 9. Future Enhancements

### 9.1 Offline Image Queueing

Store image `File` objects in IndexedDB alongside the queue entry. On flush, reconstruct
the `FormData` and upload. Show a placeholder thumbnail (from `URL.createObjectURL`) in
the optimistic message.

### 9.2 Offline Message Editing

Allow editing the text of a queued message before it is flushed. Update both the offline
store and the React Query cache.

### 9.3 Offline Reactions

Queue reactions (emoji add/remove) and tips when offline. These are lightweight payloads
that can be queued alongside messages.

### 9.4 Background Sync Priority

When multiple items are queued, prioritize messages over feed posts (messages are more
time-sensitive). Within messages, prioritize by conversation (active conversation first).

### 9.5 Offline Queue Management UI

A dedicated "Pending Queue" page that shows all queued items with their status, allows
bulk retry/discard, and provides queue size information.

### 9.6 Optimistic Read Receipts

When the user reads a message while offline, queue the read receipt and show it as sent
when online.

---

## Appendix A: File Reference

| Existing File | Relevance |
|---------------|-----------|
| `frontend/src/pages/messages/ConversationView.tsx` | Online optimistic pattern (lines 207-269); offline enqueue (lines 1028-1033); allMessages memo (lines 112-123); message rendering loop (lines 990-1011); ComposeBar wiring (lines 1019-1061) |
| `frontend/src/pages/messages/MessageBubble.tsx` | Message rendering (lines 315-2019); hover toolbar (lines 702-821); content rendering (lines 840-1190); needs OfflineStatusBadge |
| `frontend/src/pages/messages/ComposeBar.tsx` | ComposeBar interface (lines 32-60); send button and input |
| `frontend/src/pages/feed/CreatePost.tsx` | Offline post enqueue (lines 635-654); composer state; content payload construction |
| `frontend/src/pages/feed/FeedPage.tsx` | Feed page layout (19 lines) |
| `frontend/src/pages/feed/FeedTimeline.tsx` | Feed list rendering (131 lines); allPosts assembly; PostCard mapping; needs optimistic post injection |
| `frontend/src/pages/feed/NewsFeed.tsx` | Wrapper around FeedTimeline (13 lines) |
| `frontend/src/pages/feed/PostCard.tsx` | Post card rendering (881 lines); action buttons; lock/unlock; needs offline indicator + action disabling |
| `frontend/src/stores/offlineStore.ts` | Queue store (69 lines); needs `addToQueueWithId()`, `updateActionStatus()`, `retryAction()` |
| `frontend/src/hooks/useOfflineQueue.ts` | Flush hook (96 lines); needs per-item status updates and error classification |
| `frontend/src/api/types.ts` | `Message` type (lines 882-987); `FeedPost` type (lines 1867-1927); `SendTextMessageReq` (lines 1003-1018); `CreatePostReq` (lines 1958-1982); need `__offline` field |
| `frontend/src/components/shared/OfflineBanner.tsx` | Shows queue count (33 lines); needs failed count badge |
| `frontend/src/components/layout/AppShell.tsx` | Renders OfflineBanner + OfflineQueueFlusher (78+ lines); needs OfflineOptimisticRestorer |
| `frontend/src/lib/feedCacheInvalidation.ts` | `invalidateFeedCaches()` utility |
| `frontend/src/lib/feedPagination.ts` | `mergeFeedPages()` utility; deduplicates by post_id |
| `frontend/src/lib/feedQueryKeys.ts` | Feed query key factory |
| `frontend/src/hooks/useFeedTimelineQuery.ts` | Feed infinite query hook |
| `frontend/src/main.tsx` | QueryClient; boot sequence |
| `frontend/src/api/endpoints/messaging.ts` | `sendTextMessage()` function signature |
| `frontend/src/api/endpoints/newsfeed.ts` | `createPost()` function signature |

## Appendix B: Dependencies & Risks

| Risk | Mitigation |
|------|------------|
| Optimistic message shape mismatches real `Message` type | Use same fields as online optimistic (line 216-227); TypeScript catches shape errors |
| Page reload loses React Query cache | `useOfflineOptimisticRestore` re-injects from persisted queue |
| Flush success but query invalidation fails | Stale optimistic message stays until next manual refresh; no data loss |
| Multiple offline messages cause strict-mode Playwright violations | Scope assertions using unique message text anchors |
| Feed post optimistic shows incomplete data (no author avatar, timestamps) | Use current user data from authStore; show "Just now" for timestamp |
| Encrypted message queued offline shows empty text | Consistent with online optimistic path (line 221: `payload.encryption ? "" : ...`) |
| Image messages not queued (limitation) | Show toast "Images cannot be sent while offline" instead of silently failing |
| localStorage evicted under storage pressure | Queue entries lost; user must re-type. Future: use IndexedDB. |
| Session expires during offline period | 401 on flush; notify user to re-authenticate; keep queue across re-login |
| CSRF token changes during offline period | 403 on flush; notify user to refresh; keep queue |
| Concurrent tabs overwrite localStorage | Add `storage` event listener for cross-tab synchronization |
| Retry creates duplicate messages on server | Add `X-Idempotency-Key` header with queue ID to deduplicate server-side |
| View-once message queued offline | Sender always sees own view-once content; no special handling needed |
| Expiring message queued offline | No client-side timer until server assigns `expires_at` on flush |

## Appendix C: Glossary

| Term | Definition |
|------|-----------|
| **Optimistic UI** | Displaying a result in the UI before server confirmation, assuming success |
| **Offline queue** | The Zustand-persisted array of `OfflineAction` entries in localStorage |
| **Dead letter** | A failed queue entry that has exhausted retries and requires user intervention |
| **Flush** | The process of sending all queued actions to the server when connectivity returns |
| **Queue ID** | The unique identifier for each queued action, format: `offline-<timestamp>-<random>` |
| **Optimistic message ID** | The `message_id` of an optimistic message, format: `optimistic-offline-<queueId>` |
| **Background Sync** | Web API (from PWA-004) that allows the service worker to retry failed requests |
| **React Query cache** | In-memory data store managed by `@tanstack/react-query` |
| **Zustand persist** | Middleware that serializes Zustand store state to localStorage |
| **InfiniteData** | React Query's data structure for `useInfiniteQuery`, containing `pages` array |
| **MessagesPage** | `{ messages: Message[]; next_cursor?: string }` -- one page of messages |
| **FeedPage** | `{ items: FeedPost[]; next_cursor?: string }` -- one page of feed posts |
