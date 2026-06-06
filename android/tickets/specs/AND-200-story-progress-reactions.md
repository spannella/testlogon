---
id: AND-200
title: Story progress + reactions
milestone: M4
epic: E27
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-199]
blocks: []
---

# AND-200 — Story progress + reactions

## 1. Overview & Goal

AND-199 delivered the Stories tray and a full-screen viewer that opens a user's
story ring and auto-advances between segments. AND-200 layers the *interaction*
surface on top of that viewer: a per-segment **progress bar**, **tap/swipe
navigation** (tap-right = next, tap-left = previous, swipe-down = dismiss,
long-press = pause), **view tracking** (`POST /ui/stories/{story_id}/view`), and
an **inline reaction + reply composer** that lets the viewer fire a quick emoji
reaction or send a free-text reply to the story author.

The goal is a viewer that feels like a first-party Stories experience: smooth,
gesture-driven segment playback with deterministic progress animation, and a
reaction/reply path that produces optimistic UI immediately while the network
call settles in the background. The scope is the `feature-stories` viewer
internals only; it reuses the data layer, models, and `StoryViewerViewModel`
introduced by AND-199 and extends them rather than replacing them.

Out of scope: the tray/ring rendering and story fetch (AND-199), story creation
/ upload, highlights management (`/ui/stories/{story_id}/highlight`), and the
viewers list (`/ui/stories/{story_id}/viewers`, future ticket). Those are named
where relevant below.

## 2. Context & References

- **Module:** `feature-stories` (depends on `core-data`, `core-network`,
  `core-model`, `core-ui`). Namespace `com.testlogon.android.feature.stories`.
- **Web reference:** `src/api/endpoints/stories.ts` (the `stories.ts`
  named in AND-199 scope) and shared types in `src/api/types.ts`; the viewer
  screen is `src/pages/feed/StoryViewer.tsx`.
  The web app records views via `POST /ui/stories/{story_id}/view` (verified).
  **CORRECTION (was wrong):** the web app does **not** send story reactions or
  replies at all — `StoryViewer.tsx` exposes only progress bars, prev/pause/next
  tap zones, and (for owners) a view-count + viewers panel. There is **no**
  dedicated `/ui/stories/{id}/react` route in the backend OpenAPI (verified). The
  reaction/reply composer in this ticket is therefore an **Android-original**
  feature with **no web precedent** — its wire contract is an unverified
  assumption (see §16 / OQ-1), not a mirror of the web client.
- **Predecessor:** AND-199 (Stories tray + viewer) owns `StoryRepository`,
  `StoryViewerScreen`, `StoryViewerViewModel`, `StoryUiModel`, `StorySegment`,
  and the auto-advance timer. AND-200 extends these types.
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Media3/ExoPlayer 1.4 for
  video segments, Coil for image segments, Hilt (KSP), Coroutines/Flow,
  Retrofit 2.11 + Moshi 1.15. minSdk 24 / targetSdk 35.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000`
  (plaintext HTTP, unreliable — ~20s timeouts, bounded retry for idempotent
  GETs only). Cookie-based session + `X-CSRF-Token`.

## 3. Functional Requirements

FR-1 **Segment progress bar.** The top of the viewer shows N equal-width
segments (one per story media item for the active author). The active segment
fills left-to-right over its `durationMs`; completed segments are fully filled;
future segments are empty. The bar respects pause/resume and seeks.

FR-2 **Auto-advance with progress.** When the active segment's progress reaches
1.0, the viewer advances to the next segment. After the last segment of the
current author, the viewer advances to the next author in the tray order (data
provided by AND-199); after the last author, it dismisses.

FR-3 **Tap navigation.** Tap on the right third of the screen = next segment;
tap on the left third = previous segment. Previous from the first segment of an
author moves to the previous author's last segment; previous from the very
first segment restarts the current segment.

FR-4 **Pause.** Press-and-hold (long press) anywhere on the media area pauses
progress and any video playback and hides chrome (progress bar + composer);
release resumes. Tapping the reply field also pauses until the field loses
focus / the reply is sent.

FR-5 **Swipe-to-dismiss.** A downward vertical drag past a threshold (≥ 120 dp
or fling) dismisses the viewer and returns to the tray.

FR-6 **View tracking.** On first display of a segment (per app session), fire
`POST /ui/stories/{story_id}/view` exactly once per `story_id`. De-dupe by
`story_id` so re-viewing within the session does not re-POST. Failure is
silent (fire-and-forget; no UI impact).

FR-7 **Quick reactions.** A row of emoji reactions (default set: ❤️ 😂 😮 😢 👏
🔥) is available at the bottom. Tapping one sends a reaction reply to the story
author and shows an optimistic confirmation (floating emoji + brief toast),
then collapses. The viewer pauses while the reaction row is expanded.

FR-8 **Text reply.** A single-line `TextField` ("Reply to story…") lets the
viewer send a free-text reply to the author. Sending pauses progress, clears
the field, shows "Sent" confirmation, and resumes. Empty/whitespace replies are
disabled.

FR-9 **Own-story suppression.** When viewing the current user's own story
(`StoryUiModel.isOwner == true`), the reaction/reply composer is replaced by a
viewers-count affordance (count only; the viewers list screen is a future
ticket). Reactions/replies cannot be sent to oneself.

FR-10 **State preservation.** Progress position survives configuration changes
(rotation) and process-death restore of the active author/segment index.

## 4. Technical Design

### 4.1 State

Extend the AND-199 `StoryViewerUiState` rather than create a parallel one:

```kotlin
data class StoryViewerUiState(
    val authors: List<StoryAuthorUiModel> = emptyList(), // from AND-199
    val authorIndex: Int = 0,
    val segmentIndex: Int = 0,
    val progress: Float = 0f,            // 0f..1f for active segment
    val isPaused: Boolean = false,
    val composer: ComposerState = ComposerState(),
    val transient: TransientEvent? = null, // one-shot, e.g. ReactionSent
) {
    val currentAuthor get() = authors.getOrNull(authorIndex)
    val currentSegment get() = currentAuthor?.segments?.getOrNull(segmentIndex)
}

data class ComposerState(
    val replyText: String = "",
    val reactionsExpanded: Boolean = false,
    val sending: Boolean = false,
    val sendError: String? = null,
)

sealed interface TransientEvent {
    data class ReactionSent(val emoji: String) : TransientEvent
    data object ReplySent : TransientEvent
    data object Dismiss : TransientEvent
}
```

### 4.2 ViewModel

`StoryViewerViewModel` (Hilt `@HiltViewModel`, already created in AND-199) gains:

```kotlin
fun onSegmentDisplayed()          // triggers recordView (de-duped)
fun next()                        // FR-2/FR-3
fun previous()                    // FR-3
fun seekToProgress(p: Float)      // internal, from progress driver
fun setPaused(paused: Boolean)    // FR-4
fun onReplyTextChange(text: String)
fun onReactionsToggle(expanded: Boolean)
fun sendReaction(emoji: String)   // FR-7
fun sendReply(text: String)       // FR-8
fun consumeTransient()
```

**Progress driver.** A single coroutine in `viewModelScope` advances
`progress` using a frame clock rather than a fixed tick, so animation stays
smooth and pause is exact:

```kotlin
private fun startProgressLoop() {
    progressJob?.cancel()
    progressJob = viewModelScope.launch {
        var last = withFrameNanos { it }
        while (isActive) {
            val now = withFrameNanos { it }
            val dtMs = (now - last) / 1_000_000f
            last = now
            val seg = state.value.currentSegment ?: break
            if (!state.value.isPaused && !state.value.composer.reactionsExpanded) {
                val delta = dtMs / seg.durationMs
                val p = (state.value.progress + delta)
                if (p >= 1f) { next() } else update { it.copy(progress = p) }
            }
        }
    }
}
```

Video segments (Media3) use the player position as the progress source instead
of the wall clock; the ViewModel observes `Player.Listener` events and the
ExoPlayer instance is owned by AND-199's media controller. Image segments use
the loop above with a default `durationMs = 5_000`.

### 4.3 Compose UI

`StoryViewerScreen` (extends AND-199) adds:

```kotlin
@Composable fun SegmentProgressBar(
    segmentCount: Int, activeIndex: Int, activeProgress: Float,
    modifier: Modifier = Modifier,
)

@Composable fun StoryGestureLayer(
    onTapLeft: () -> Unit, onTapRight: () -> Unit,
    onPauseChange: (Boolean) -> Unit, onDismiss: () -> Unit,
    content: @Composable () -> Unit,
)

@Composable fun StoryComposer(
    state: ComposerState, isOwner: Boolean, viewerCount: Int?,
    onTextChange: (String) -> Unit, onReactionsToggle: (Boolean) -> Unit,
    onReaction: (String) -> Unit, onSend: (String) -> Unit,
)
```

Gestures: `StoryGestureLayer` uses `Modifier.pointerInput` —
`detectTapGestures(onTap = {pos -> left/right by pos.x}, onLongPress = pause,
onPress = { awaitRelease(); resume })` plus a `detectVerticalDragGestures` for
swipe-down dismiss. The composer overlays the bottom; expanding the reaction
row or focusing the field calls `setPaused(true)`.

`SegmentProgressBar` renders `Row` of `LinearProgressIndicator`-style bars; the
active bar's value is `activeProgress`, driven by the StateFlow so it is frame
accurate. Chrome (bar + composer) animates out with `AnimatedVisibility` while
long-press is held.

## 5. API Contract

### 5.1 Record view (idempotent intent, FR-6)

```
POST /ui/stories/{story_id}/view
Headers: X-CSRF-Token: <ui_csrf>, Cookie: <session>, Authorization: Bearer <token>
Body: (none — OpenAPI req= empty)
200 -> StoryViewResp { ok: boolean, already_viewed: boolean }   (422 -> HTTPValidationError)
```

**CORRECTION (was wrong):** the 200 body is **not** an untyped `{}`. Per
`src/api/types.ts: StoryViewResp` it is `{ ok, already_viewed }`. The client may
ignore it for fire-and-forget, but `already_viewed` is a real server-side
de-dupe signal that complements the in-session client de-dupe (FR-6).

`StoryApi.recordView(storyId): ApiResult<Unit>` — fire-and-forget; not retried.

### 5.2 Reactions & replies (FR-7 / FR-8)

There is **no** `/ui/stories/{id}/react` endpoint in the OpenAPI (verified).
There is also **no web precedent** for story reactions/replies — the web viewer
does not implement them (see §2 correction). The "send via messaging DM" design
is an Android-original choice; its body shape below is an **unverified assumption**
gated by OQ-1, **not** a confirmed contract.

The plan routes both through a single repository method that (1) resolves or
creates the DM with the author, then (2) posts a message. The **verified** primitives are:

```
# 1. Resolve / create the author DM (verified):
POST /messaging/conversations/dm/find-or-create
  req  = FindOrCreateDmIn { user_id: "<author_id>" }      # only field; required
  200 -> ConversationOut   (422 -> HTTPValidationError)
  Headers: X-CSRF-Token, Cookie, Authorization: Bearer

# 2a. Reply = a normal text message (verified endpoint + schema):
POST /messaging/conversations/{conversation_id}/messages
  req  = SendTextMessageIn { text: "<reply>" (1..4000) }   # see CORRECTION below
  200 -> MessageOut { message_id, conversation_id, sender_id, created_at, kind, text, ... }

# 2b. Reaction — TWO candidate mechanisms, neither story-scoped (OQ-1 must pick one):
#   (i)  send the emoji as a text message  -> SendTextMessageIn { text: "🔥" }
#   (ii) react to an existing message      -> POST .../messages/{message_id}/reactions
#        req = ReactIn { emoji: "🔥" (1..64), action: "add"|"remove" (default add) }
#        (note: reacts to a *message*, not to a story — there is no story-react route)
```

**CORRECTION (was wrong):** `SendTextMessageIn` has **no** `context` object and
**no** `is_reaction` field (verified against the schema). The previously specced
body `{ text, context: { story_id, is_reaction } }` is fabricated and will 422 /
silently drop those keys. The real schema fields are `text` (1..4000), `body`,
`reply_to_message_id`, `parent_message_id`, `thread_id`, `view_once`, etc. — none
carries story context. Consequently the story↔message linkage (how the author
knows a reply pertains to a given story) is **unresolved** and is the core of
OQ-1; do not ship §5.2 until the backend confirms a real mechanism.

If the messaging conversation with the author does not yet exist the repository
resolves/creates it first via `dm/find-or-create` (above). Until OQ-1 is
resolved the repository exposes:

```kotlin
suspend fun reactToStory(storyId: String, authorId: String, emoji: String): ApiResult<Unit>
suspend fun replyToStory(storyId: String, authorId: String, text: String): ApiResult<Unit>
```

The viewer depends only on these two methods, so the wire detail is isolated to
`core-data` and can change without touching `feature-stories`.

### 5.3 ApiResult mapping

All calls return `ApiResult<T>` (core-network). FastAPI `detail` is mapped by
the shared interceptor exactly as the web `normalizeErrorDetail`
(`src/api/client.ts`): `string` -> message; `[{msg}]` -> joined `msg` values;
`{code,...}` -> coded error (e.g. `role_required`, `geo_blocked`). 401 triggers
the single `POST /ui/session/refresh` + retry already implemented in the OkHttp
authenticator (shared infra) — verified against `client.ts` (`refreshSession`,
single in-flight `refreshPromise`, one retry, logout on second 401).

Note: the web client additionally sends `Authorization: Bearer <accessToken>`
alongside the cookie + `X-CSRF-Token` (`client.ts` lines 158-171); the messaging
endpoints list `authorization` + `X-SESSION-ID` params in the OpenAPI index, so
the Android messaging calls (§5.2) should attach the bearer token too, not rely
on the cookie alone.

## 6. Data & State Management

- **Source of truth:** `StoryViewerViewModel.uiState: StateFlow<StoryViewerUiState>`.
- **Models (extend AND-199):** `StorySegment(storyId, mediaUrl, mediaType,
  durationMs)`; `StoryAuthorUiModel(authorId, displayName, avatarUrl,
  segments, isOwner, viewerCount)`. Verified field mapping from
  `src/api/types.ts: Story`: `storyId<-story_id`, `mediaUrl<-media_url`,
  `mediaType<-media_type ("image"|"video")`, `durationMs<-duration_seconds*1000`.
  `viewerCount` is per-segment on the server (`Story.view_count`), not per-author;
  the owner affordance shows the **active segment's** `view_count`, matching the
  web (`StoryViewer.tsx` shows `currentStory.view_count`). `isOwner` is derived by
  comparing `Story.author_id` to the current user (web compares to `authStore.userId`).
- **View de-dupe:** `viewedStoryIds: MutableSet<String>` held in the ViewModel
  for session-scoped de-dupe (FR-6). No persistence required — re-viewing
  across app restarts may re-POST and that is acceptable (server is idempotent
  per user/story/day).
- **No Room caching for this ticket.** Story content caching is AND-199's
  concern; AND-200 adds no new tables. Replies/reactions are not cached.
- **SavedStateHandle:** persist `authorIndex` and `segmentIndex` for
  process-death restore (FR-10). `progress` resets to 0f on restore (segment
  replays from start — acceptable and simpler than persisting sub-segment
  position).
- **Optimistic UI:** reactions/replies update `composer`/`transient`
  immediately on tap; on `ApiResult.Error` the optimistic state is rolled back
  and `composer.sendError` is set (FR-7/FR-8 error path, §7).

## 7. Error Handling & Resilience

| Case | Behavior |
|------|----------|
| `recordView` fails / times out | Silent; no UI, no retry (FR-6). |
| Reply/reaction `Error` | Roll back optimistic confirmation, surface `composer.sendError` as an inline snackbar "Couldn't send — tap to retry"; restore text for replies so the user can resend. |
| 401 on any call | Handled by shared authenticator (refresh once, retry). On second 401 the call returns `Error`; reply path shows retry, view path stays silent. |
| Network offline | Reply/reaction disabled with "You're offline" helper; viewer playback continues (content already loaded for visible segment). |
| Media segment load failure (Coil/ExoPlayer) | Show a per-segment error placeholder and auto-advance after 2s rather than stalling the bar. |
| Slow author switch (next author not yet loaded) | Show a thin indeterminate bar at top; pause progress until first segment ready, then resume. |

Timeouts follow the global OkHttp config (~20s). No call here is auto-retried
except the GET-only backoff in shared infra — reactions/replies/views are POSTs
and are **never** auto-retried (avoids duplicate sends).

## 8. Security & Privacy

- All requests carry the session cookie and the `X-CSRF-Token` header (echoed
  from the `ui_csrf` cookie); the persistent cookie jar from core-network is
  reused — no new auth surface.
- The dev backend is plaintext HTTP; cleartext is permitted only for the dev
  host via the existing network-security-config. No story media URLs or reply
  text are logged (see §10).
- Reactions/replies are author-directed DMs; the viewer must not send to itself
  (FR-9 enforces server-side too, but client suppresses the composer).
- No PII is persisted to disk by this ticket (no Room, no DataStore writes).
  Reply draft text lives only in in-memory `ComposerState`.

## 9. Accessibility & i18n

- Progress bar exposes `Modifier.progressSemantics(progress)` and a content
  description "Story segment {n} of {N}".
- Tap zones: provide explicit `Role.Button` semantics actions
  "Next segment" / "Previous segment" so TalkBack users navigate without
  guessing tap regions; long-press pause has a semantics action "Pause story".
- Reaction emojis have content descriptions ("React with heart", etc.); the
  reply field has a labelled `TextField` and an explicit send button (TalkBack
  cannot use IME send reliably).
- Honor reduced-motion: when `Settings.Global.ANIMATOR_DURATION_SCALE == 0`,
  the bar still advances (time-based) but skips the floating-emoji animation.
- All strings (`reply_hint`, `react_with_*`, `story_segment_progress`,
  `offline_cannot_send`, `reply_send_failed`) live in `feature-stories`
  `strings.xml`; no hardcoded UI text. RTL handled by `Row` + start/end
  padding; tap-left/tap-right map to physical screen sides (not start/end) so
  navigation direction is consistent across locales.

## 10. Telemetry & Logging

- Analytics events (via the shared analytics facade, no-op until its ticket):
  `story_segment_viewed{author_id, segment_index, story_id}`,
  `story_completed{author_id}`, `story_reaction_sent{emoji}`,
  `story_reply_sent{}`, `story_dismissed{method=swipe|back|end}`.
- Logs use the core logging tag `Stories`; **never** log reply text, emoji
  payloads tied to a user, media URLs, or `story_id` at INFO. Errors log only
  the mapped `ApiResult.Error` code + HTTP status.
- View-tracking failures are logged at DEBUG only.

## 11. Testing Strategy

**Unit (core-testing, JUnit + Turbine + coroutines-test):**
- Progress loop advances `progress` deterministically with a `TestScope`
  virtual clock; reaching 1.0 calls `next()`.
- `next()` / `previous()` cross author boundaries correctly; previous from
  first-of-first restarts segment.
- `onSegmentDisplayed()` POSTs view once per `story_id`; second call is a no-op
  (verify `viewedStoryIds`).
- `sendReaction` / `sendReply`: optimistic state set immediately; on
  `ApiResult.Error` rolled back and `sendError` populated; whitespace reply is
  rejected without a network call.
- `isOwner == true` suppresses composer and never calls reply/reaction.
- Pause: `setPaused(true)` and `reactionsExpanded == true` both halt progress.

**Compose UI tests (`createComposeRule`):**
- Tap right third invokes next; tap left invokes previous (assert via fake VM).
- Long-press hides chrome and pauses; release resumes.
- Swipe-down past threshold emits `Dismiss`.
- Reaction tap shows confirmation and collapses; reply send clears field.
- Progress semantics and content descriptions present (TalkBack assertions).

**Repository test:** `reactToStory`/`replyToStory` build correct request and
map `detail` error variants; MockWebServer asserts `X-CSRF-Token` header
present and POSTs are not retried on 5xx.

## 12. Dependencies & Sequencing

- **Depends on AND-199** (Stories tray + viewer) — provides `StoryRepository`,
  `StoryViewerScreen`/`ViewModel`, models, ExoPlayer/Coil media wiring, and
  tray ordering. This ticket cannot start until AND-199's viewer renders a
  single segment.
- Transitively depends on AND-168 (via AND-199) and the shared core-network
  cookie/CSRF/refresh infrastructure.
- **Blocks:** none listed. The viewers-list screen (consumes `viewerCount`
  surfaced here and `/ui/stories/{story_id}/viewers`) is a separate future
  ticket and is *not* a hard blocker of AND-200.
- Sibling AND-201 (Gallery) is independent.

## 13. Risks & Open Questions

- **OQ-1 (blocking detail):** confirm the exact reaction/reply wire contract.
  OpenAPI has no story-react route; web sends via messaging DMs. Verify the
  conversation-resolution + message body (`context.story_id`,
  `context.is_reaction`) against the live messaging API before wiring §5.2. The
  `feature-stories` interface (`reactToStory`/`replyToStory`) insulates the UI
  regardless of outcome.
- **OQ-2 (mostly resolved):** segment duration. **Verified** against
  `src/pages/feed/StoryViewer.tsx` + `src/api/types.ts: Story`: the GET response
  is typed (`Story.duration_seconds?: number`), and the web viewer uses
  `duration_seconds * 1000` **only for `media_type === "video"`**, otherwise a
  fixed `SLIDE_DURATION_MS = 5000` (so images always run 5s on web even if
  `duration_seconds` is set). Android should match this rule, or deliberately
  honor `duration_seconds` for images too — that single behavioral choice is the
  only open part of OQ-2. `CreateStoryReq.duration_seconds` is the create-side
  field; range bound (1–300) is not enforced in `types.ts` and is unverified here.
- **R-1:** unreliable dev host may make author-switch loads slow; mitigated by
  the indeterminate-bar/pause-until-ready behavior (§7).
- **R-2:** frame-clock progress + ExoPlayer position must not double-drive the
  bar for video segments; the ViewModel must pick exactly one source per
  segment type. Covered by unit tests.
- **R-3:** duplicate reactions from rapid taps — debounce the reaction row
  (ignore taps while `composer.sending`).

## 14. Acceptance Criteria

AC-1 (FR-1/FR-2) Progress bar shows one filled segment per story item; the
active segment fills smoothly and auto-advances at completion; the last segment
of the last author dismisses the viewer.

AC-2 (FR-3) Tapping the right third advances; tapping the left third goes back,
crossing author boundaries per FR-3.

AC-3 (FR-4) Long-press pauses progress and video and hides chrome; release
resumes from the same position.

AC-4 (FR-5) Swipe-down past threshold dismisses to the tray.

AC-5 (FR-6) Viewing a segment fires `POST /ui/stories/{story_id}/view` exactly
once per `story_id` per session; failures are silent.

AC-6 (FR-7) Tapping a reaction emoji shows immediate confirmation and sends the
reaction; on failure the confirmation rolls back and a retry affordance appears.

AC-7 (FR-8) Sending a non-empty reply clears the field, shows "Sent", pauses
then resumes; empty replies cannot be sent.

AC-8 (FR-9) Viewing one's own story shows a viewer count and no composer.

AC-9 (FR-10) Rotation and process-death restore the active author/segment.

AC-10 All §11 unit and Compose tests pass; package is
`com.testlogon.android.feature.stories`.

Backlog acceptance ("Progress + reactions work") is satisfied by AC-1–AC-8.

## 15. Definition of Done

- All §14 acceptance criteria met and demoed against the dev backend.
- Code merged to `android-port` under `android/feature-stories/` with package
  `com.testlogon.android.feature.stories`; builds with AGP 8.7.3 / Gradle 8.9 /
  JDK 17.
- ViewModel exposes `StateFlow<StoryViewerUiState>`; all network calls return
  `ApiResult<T>`; FastAPI `detail` mapping reused.
- Unit + Compose test suites (§11) green in CI; no new lint/detekt regressions.
- No PII/media-URL/reply-text logging; cleartext limited to the dev host.
- OQ-1 resolved (reaction/reply wire contract confirmed) and §5.2 updated to
  match before merge; OQ-2 noted in code if unresolved.
- Strings externalized; TalkBack pass on the viewer; RTL spot-checked.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer.

1. **`POST /ui/stories/{story_id}/view` records a view** — **Verified.**
   OpenAPI `POST /ui/stories/{story_id}/view`
   (op `record_view_endpoint_ui_stories__story_id__view_post`, req empty,
   resp `200`/`422:HTTPValidationError`); frontend
   `src/api/endpoints/stories.ts: recordStoryView`.

2. **The view 200 body is untyped `{}`** — **Corrected.** It is
   `src/api/types.ts: StoryViewResp { ok: boolean, already_viewed: boolean }`.
   Spec §5.1 corrected.

3. **View de-dupe is a session-scoped client `Set<story_id>`, fire-and-forget** —
   **Verified.** `src/pages/feed/StoryViewer.tsx` (`viewedSetRef = useRef(new
   Set<string>())`, `viewMut.mutate` with no error UI).

4. **There is no `/ui/stories/{id}/react` route** — **Verified.** Absent from
   `reference/openapi.index.txt` (only `/view`, `/viewers`, `/highlight`,
   `/highlights/*`, CRUD exist, lines 1899-1910).

5. **The web app sends story reactions/replies via messaging DMs** —
   **Corrected (was false).** The web viewer `src/pages/feed/StoryViewer.tsx`
   implements **no** reactions and **no** replies — only progress, prev/pause/next
   tap zones, owner view-count, and a viewers panel. Reactions/replies are an
   Android-original feature with no web precedent.

6. **Reaction/reply message body `{ text, context:{ story_id, is_reaction } }`** —
   **Corrected → Unverified-assumption.** OpenAPI
   `components.schemas.SendTextMessageIn` has **no** `context` and **no**
   `is_reaction` fields (fields are `text` 1..4000, `body`, `reply_to_message_id`,
   `parent_message_id`, `thread_id`, `view_once`, …). The story↔message linkage is
   unresolved (OQ-1).

7. **`POST /messaging/conversations/{conversation_id}/messages` is the send-text
   endpoint** — **Verified.** OpenAPI line 333
   (op `send_text_message_...`, req `SendTextMessageIn`, resp `200:MessageOut`).

8. **DM is resolved/created before messaging** — **Verified primitive.** OpenAPI
   `POST /messaging/conversations/dm/find-or-create`
   (req `FindOrCreateDmIn { user_id }`, resp `200:ConversationOut`, line 314).
   That this is the right call *for stories* is an assumption (OQ-1).

9. **Message-reaction alternative `ReactIn`** — **Verified primitive.** OpenAPI
   `POST /messaging/conversations/{conversation_id}/messages/{message_id}/reactions`
   (req `ReactIn { emoji 1..64, action add|remove }`, line 358). Reacts to a
   *message*, not a story.

10. **`MessageOut` carries `message_id` + `created_at`** — **Verified.**
    `components.schemas.MessageOut` required:
    `conversation_id, message_id, sender_id, created_at, kind` (+ `text`).

11. **Auth: session cookie + `X-CSRF-Token` from `ui_csrf` cookie** —
    **Verified.** `src/api/client.ts` (`getCookie("ui_csrf")` →
    `headers.set("X-CSRF-Token", …)`, `credentials: "include"`). Note the web
    client **also** sends `Authorization: Bearer <accessToken>`; messaging
    endpoints list `authorization`/`X-SESSION-ID` params — §5.3 updated.

12. **401 → single `POST /ui/session/refresh` then one retry** — **Verified.**
    `src/api/client.ts` (`refreshSession()` POSTs `/ui/session/refresh`; single
    in-flight `refreshPromise`; retries once; `logout` on second 401).

13. **FastAPI `detail` mapping (string / `[{msg}]` / coded `{code}`)** —
    **Verified.** `src/api/client.ts: normalizeErrorDetail` + `mapAuthorizationError`.

14. **Validation errors are `422:HTTPValidationError`** — **Verified.** All
    `/ui/stories/*` and `/messaging/.../messages` rows in the index include
    `422:HTTPValidationError`.

15. **Image segment default duration = 5000 ms; video uses `duration_seconds`** —
    **Verified.** `src/pages/feed/StoryViewer.tsx` (`SLIDE_DURATION_MS = 5000`;
    `media_type === "video" && duration_seconds ? duration_seconds*1000 : 5000`).
    `src/api/types.ts: Story.duration_seconds?: number`.

16. **`Story` model fields used by segments** — **Verified.**
    `src/api/types.ts: Story` (`story_id, author_id, media_type "image"|"video",
    media_url, duration_seconds?, view_count, …`).

17. **Owner detection / owner-only view count** — **Verified.**
    `src/pages/feed/StoryViewer.tsx` (`isOwn = currentStory.author_id ===
    currentUser`; owner UI shows `currentStory.view_count` + `ViewersPanel` via
    `getStoryViewers`). Spec FR-9 "viewers list is a future ticket" is an Android
    scoping choice (the route `GET /ui/stories/{story_id}/viewers` exists, line 1910).

18. **Web tap zones are prev / pause / next (3 equal thirds), pause = middle tap** —
    **Verified.** `src/pages/feed/StoryViewer.tsx` (three `w-1/3` buttons:
    `goPrev`, toggle pause, `goNext`). Android's choice of left/right thirds + long-
    press-to-pause + swipe-to-dismiss differs from web; this is an intentional
    mobile-native deviation (unverified-assumption as a UX claim, not a contract).

19. **Compose / Media3 / Coil / Hilt framework choices** —
    **Unverified-assumption (framework ref).** Not derivable from backend or web
    sources; standard Android stack. Refs: Media3 ExoPlayer
    https://developer.android.com/media/media3/exoplayer ; Compose pointerInput /
    `detectTapGestures` https://developer.android.com/develop/ui/compose/touch-input/pointer-input/tap-and-press ;
    `withFrameNanos` https://developer.android.com/reference/kotlin/androidx/compose/runtime/package-summary#withFrameNanos ;
    `SavedStateHandle` https://developer.android.com/topic/libraries/architecture/viewmodel/viewmodel-savedstate ;
    `progressSemantics` https://developer.android.com/reference/kotlin/androidx/compose/foundation/package-summary#(androidx.compose.ui.Modifier).progressSemantics(kotlin.Float,kotlin.ranges.ClosedFloatingPointRange,kotlin.Int) .

20. **Dev host `http://18.222.237.167:8000`, plaintext HTTP, ~20s timeouts** —
    **Unverified-assumption.** Carried from AND-199 / project infra; not present in
    the OpenAPI/frontend sources provided.

### Corrections made

- **§2** — removed the false claim that the web app sends story reactions/replies
  via messaging DMs; clarified the web viewer has no such feature and that the
  composer is Android-original. Fixed frontend paths (`src/...` not `frontend/src/...`).
- **§5.1** — view response corrected from untyped `{}` to
  `StoryViewResp { ok, already_viewed }`; added `Authorization: Bearer`.
- **§5.2** — removed the fabricated `SendTextMessageIn` body (`context`,
  `is_reaction` do not exist); replaced with verified primitives
  (`dm/find-or-create` → `FindOrCreateDmIn`; `messages` → `SendTextMessageIn`;
  message reactions → `ReactIn`) and flagged the story↔message linkage as the
  unresolved core of OQ-1.
- **§5.3** — tied error mapping to `normalizeErrorDetail`; noted the bearer token.
- **§6** — added verified `Story`→model field mapping; clarified `viewerCount`
  comes from per-segment `Story.view_count` and `isOwner` from `author_id`.
- **§13 OQ-2** — marked mostly-resolved: duration is typed and the web rule
  (5s images / `duration_seconds` for video) is verified.

### Open assumptions

- **OQ-1 (blocking):** the entire reaction/reply wire contract. No web precedent,
  no story-context field in `SendTextMessageIn`, no story-react route. How a
  reply/reaction is associated with a story server-side is unknown and must be
  confirmed with the backend before §5.2 ships.
- **Reaction mechanism choice:** text-message emoji vs. `ReactIn` on a message —
  both exist but neither is story-scoped; backend must specify.
- **Image-duration policy:** match web (force 5s for images) vs. honor
  `duration_seconds` for images — product decision, not a contract.
- **Android UX gestures** (left/right thirds, long-press pause, swipe-dismiss)
  deviate from the web's prev/pause/next thirds — intentional, unverifiable from sources.
- **Framework stack & dev-host/transport** facts (§19, §20 above) are not in the
  provided authoritative sources.

## 17. Test Plan

Test targets: **JVM** = JVM unit/Robolectric (local, no device); **emu35** =
headless emulator AVD `test35` (x86_64, API 35); **A15** = physical Samsung Galaxy
A15 5G (SM-A156U, serial R5CX821TA9R, API 34, arm64-v8a). Prefer **A15** for real
hardware/playback/biometric behavior; **emu35** is fine for fast Compose/UI suites.

### TC-AND-200-01 — Progress loop advances and auto-advances (happy path)
- **Type:** unit (Turbine + coroutines-test virtual clock). **Target:** JVM.
- **Preconditions:** ViewModel seeded with one author, 3 image segments
  (`durationMs=5000`), not paused.
- **Steps:** Start progress loop; advance virtual time by `durationMs` for segment 0.
- **Expected:** `progress` rises 0→1 then `next()` fires; `segmentIndex` becomes 1,
  `progress` resets to 0. After the last segment of the last author a `Dismiss`
  transient is emitted.
- **Traces:** AC-1.

### TC-AND-200-02 — Tap navigation incl. author-boundary crossing
- **Type:** unit. **Target:** JVM.
- **Preconditions:** Two authors, 2 segments each; positioned at author0/segment0.
- **Steps:** Call `previous()` (first-of-first); then `next()` ×2 to cross into
  author1; then `previous()` from author1/segment0.
- **Expected:** first `previous()` restarts segment0 (no author change); crossing
  forward moves to author1/segment0; backward from author1/segment0 lands on
  author0's **last** segment.
- **Traces:** AC-2.

### TC-AND-200-03 — Pause halts progress (long-press and reactions-expanded)
- **Type:** unit. **Target:** JVM.
- **Preconditions:** Running progress loop mid-segment.
- **Steps:** `setPaused(true)`; advance virtual clock; assert no progress change;
  `setPaused(false)`; separately set `reactionsExpanded=true` and advance clock.
- **Expected:** progress is frozen in both paused and `reactionsExpanded` states
  and resumes from the same value on release; video playback paused too.
- **Traces:** AC-3, AC-6 (pause-while-expanded).

### TC-AND-200-04 — View recorded exactly once per story_id per session
- **Type:** contract/MockWebServer. **Target:** JVM.
- **Preconditions:** MockWebServer returns `200 {"ok":true,"already_viewed":false}`
  for `POST /ui/stories/{id}/view`.
- **Steps:** `onSegmentDisplayed()` for story A; navigate away and back to A;
  call again.
- **Expected:** exactly **one** `POST /ui/stories/A/view` is issued; request carries
  `X-CSRF-Token`; second display is a no-op (`viewedStoryIds` de-dupe). Response
  body parses to `StoryViewResp` but is ignored.
- **Traces:** AC-5.

### TC-AND-200-05 — View failure is silent and not retried
- **Type:** contract/MockWebServer. **Target:** JVM.
- **Preconditions:** MockWebServer returns `500` then would return `200`.
- **Steps:** `onSegmentDisplayed()`; observe requests and UI state.
- **Expected:** exactly **one** POST (no auto-retry); no error surfaced to UI;
  failure logged at DEBUG only; playback continues.
- **Traces:** AC-5.

### TC-AND-200-06 — Reply happy path: DM resolve then send (contract)
- **Type:** contract/MockWebServer. **Target:** JVM.
- **Preconditions:** MockWebServer: `POST /messaging/conversations/dm/find-or-create`
  → `200 ConversationOut{conversation_id:"c1"}`; `POST
  /messaging/conversations/c1/messages` → `200 MessageOut{message_id,created_at,...}`.
- **Steps:** `replyToStory(storyId, authorId, "hi")`.
- **Expected:** request 1 body = `{"user_id":"<authorId>"}` (FindOrCreateDmIn);
  request 2 body contains `text:"hi"` (1..4000) and **no** `context`/`is_reaction`
  keys; both carry `X-CSRF-Token` (+ bearer); returns `ApiResult.Success`;
  optimistic "Sent" then resume.
- **Traces:** AC-7.

### TC-AND-200-07 — Reply/reaction validation + error-shape mapping & rollback
- **Type:** contract/MockWebServer. **Target:** JVM.
- **Preconditions:** Cases: (a) `422` body
  `{"detail":[{"msg":"text too long","loc":[...]}]}`; (b) `403`
  `{"detail":{"code":"role_required"}}`; (c) whitespace-only reply.
- **Steps:** Attempt send for each.
- **Expected:** (a) maps to "text too long" via `[{msg}]` rule; (b) maps the coded
  message; both roll back optimistic confirmation and set `composer.sendError`,
  restoring reply text for resend; (c) is rejected client-side with **no** network
  call (empty/whitespace disabled).
- **Traces:** AC-6, AC-7.

### TC-AND-200-08 — POSTs are never auto-retried (no duplicate sends)
- **Type:** contract/MockWebServer. **Target:** JVM.
- **Preconditions:** `messages` endpoint returns `503`.
- **Steps:** `replyToStory(...)` once; rapid double-tap a reaction while
  `composer.sending`.
- **Expected:** exactly one `messages` POST per user action (no GET-style backoff
  on POST); the second rapid reaction tap is debounced (R-3).
- **Traces:** AC-6, AC-7.

### TC-AND-200-09 — 401 refresh-then-retry once
- **Type:** contract/MockWebServer. **Target:** JVM.
- **Preconditions:** `messages` returns `401`, then `POST /ui/session/refresh`
  → `200`, then retried `messages` → `200`.
- **Steps:** `replyToStory(...)`.
- **Expected:** exactly one refresh call; original request retried once and
  succeeds; on a second consecutive `401` the call returns `ApiResult.Error` and
  the reply path shows the retry affordance (view path would stay silent).
- **Traces:** AC-5, AC-6, AC-7.

### TC-AND-200-10 — Own-story suppresses composer, shows view count
- **Type:** Compose-UI. **Target:** emu35.
- **Preconditions:** Fake VM state `isOwner=true`, `viewerCount=42`.
- **Steps:** Render `StoryComposer`/viewer; attempt to find reaction row & reply
  field.
- **Expected:** no reply field / reaction row; a "42 views" affordance is shown;
  `sendReaction`/`sendReply` are never invokable. (Matches web owner UI.)
- **Traces:** AC-8.

### TC-AND-200-11 — Gestures: tap zones, long-press pause/chrome, swipe-dismiss
- **Type:** Compose-UI. **Target:** emu35.
- **Preconditions:** Fake VM capturing callbacks.
- **Steps:** Tap right third; tap left third; long-press media then release; drag
  down past 120 dp.
- **Expected:** right→`next`, left→`previous`; long-press sets paused + hides
  chrome (bar + composer) via `AnimatedVisibility`, release resumes; downward drag
  past threshold emits `Dismiss`.
- **Traces:** AC-2, AC-3, AC-4.

### TC-AND-200-12 — Reaction & reply UI feedback
- **Type:** Compose-UI. **Target:** emu35.
- **Preconditions:** Fake VM, online.
- **Steps:** Expand reaction row (asserts pause), tap ❤️; type a reply and send.
- **Expected:** reaction shows optimistic floating-emoji + brief confirmation then
  collapses; reply send clears field, shows "Sent", pauses then resumes; empty
  reply's send button is disabled.
- **Traces:** AC-6, AC-7.

### TC-AND-200-13 — Accessibility: semantics & content descriptions
- **Type:** Compose-UI (TalkBack/semantics assertions). **Target:** emu35.
- **Preconditions:** Viewer rendered with N segments.
- **Steps:** Assert semantics tree.
- **Expected:** progress bar exposes `progressSemantics` + "Story segment {n} of
  {N}"; explicit `Role.Button` actions "Next segment"/"Previous segment"/"Pause
  story"; reaction emojis have content descriptions; reply field is labelled with a
  discrete send button. With `ANIMATOR_DURATION_SCALE==0` the bar still advances
  but skips the floating-emoji animation.
- **Traces:** AC-3, AC-6, AC-7, AC-10.

### TC-AND-200-14 — State preservation across rotation & process death
- **Type:** instrumented/e2e. **Target:** emu35.
- **Preconditions:** Viewer at author1/segment2.
- **Steps:** Rotate device; then simulate process death/restore
  (`SavedStateHandle`).
- **Expected:** `authorIndex`/`segmentIndex` preserved; `progress` resets to 0
  (segment replays from start, per design); composer draft is **not** persisted
  (in-memory only, security §8).
- **Traces:** AC-9.

### TC-AND-200-15 — Offline path: composer disabled, playback continues
- **Type:** instrumented/e2e. **Target:** **A15** (real radio toggle).
- **Preconditions:** A current segment already loaded; toggle airplane mode on.
- **Steps:** Attempt reaction and reply while offline; then restore network.
- **Expected:** reaction/reply disabled with "You're offline" helper and **no**
  network attempt; visible segment keeps playing; on reconnect, sending works.
  Run on A15 because real connectivity-loss/restore (and arm64/API-34 behavior)
  differs from the emulator's simulated network.
- **Traces:** AC-6, AC-7 (offline error path), AC-1 (playback continuity).

### TC-AND-200-16 — Real video segment progress source (ExoPlayer position)
- **Type:** instrumented/e2e. **Target:** **A15** (real Media3 playback).
- **Preconditions:** Author with a video segment (`media_type="video"`,
  `duration_seconds` set).
- **Steps:** Play the video segment to completion on the physical device.
- **Expected:** the bar is driven by the **player position** (not the wall-clock
  frame loop) for video; exactly one progress source is active (R-2); auto-advance
  fires at media end; image segments still use the 5s frame loop. Must run on A15
  to exercise real arm64 Media3 decode/timing rather than emulated playback.
- **Traces:** AC-1, AC-3.

### Coverage matrix (§14 AC → TCs)

| AC | Covered by |
|----|------------|
| AC-1 (progress + auto-advance + final dismiss) | TC-01, TC-15, TC-16 |
| AC-2 (tap navigation incl. author boundaries) | TC-02, TC-11 |
| AC-3 (long-press pause + hide chrome + resume) | TC-03, TC-11, TC-13, TC-16 |
| AC-4 (swipe-to-dismiss) | TC-11 |
| AC-5 (view once per story_id; silent failure) | TC-04, TC-05, TC-09 |
| AC-6 (reaction optimistic + rollback/retry) | TC-03, TC-07, TC-08, TC-09, TC-12, TC-13, TC-15 |
| AC-7 (reply send/clear/Sent; empty disabled) | TC-06, TC-07, TC-08, TC-09, TC-12, TC-13, TC-15 |
| AC-8 (own-story: view count, no composer) | TC-10 |
| AC-9 (rotation + process-death restore) | TC-14 |
| AC-10 (test suites pass; correct package) | TC-13 + all unit/UI suites (TC-01–TC-13) |
