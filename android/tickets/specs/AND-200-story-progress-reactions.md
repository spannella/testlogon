---
id: AND-200
title: Story progress + reactions
milestone: M4
epic: E27
priority: P2
size: M
status: draft
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
- **Web reference:** `frontend/src/api/endpoints/stories.ts` (the `stories.ts`
  named in AND-199 scope) and shared types in `frontend/src/api/types.ts`.
  The web app records views via `POST /ui/stories/{id}/view` and sends story
  reactions/replies through the messaging/DM endpoints — there is **no**
  dedicated `/ui/stories/{id}/react` route in the backend OpenAPI
  (`/openapi.json`). Android mirrors this.
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
Headers: X-CSRF-Token: <ui_csrf>, Cookie: <session>
Body: (none)
200 -> {} (untyped; ignored)
```

`StoryApi.recordView(storyId): ApiResult<Unit>` — fire-and-forget; not retried.

### 5.2 Reactions & replies (FR-7 / FR-8)

There is **no** `/ui/stories/{id}/react` endpoint in `/openapi.json`. Per the
web reference, story reactions/replies are author-directed messages sent over
the messaging (DM) channel keyed by the story. The Android client routes both
through a single repository method that posts a DM referencing the story:

```
POST /messaging/conversations/{conversation_id}/messages
Headers: X-CSRF-Token, Cookie
Body (reply):    { "text": "<reply>", "context": { "story_id": "<id>" } }
Body (reaction): { "text": "<emoji>", "context": { "story_id": "<id>",
                                                    "is_reaction": true } }
200 -> { "message_id": "...", "created_at": "..." } (shape per messaging API)
```

If the messaging conversation with the author does not yet exist the repository
resolves/creates it first (existing `core-data` messaging helper). **Open
question OQ-1** confirms the exact body contract against the live messaging API
before implementation; until then the repository exposes:

```kotlin
suspend fun reactToStory(storyId: String, authorId: String, emoji: String): ApiResult<Unit>
suspend fun replyToStory(storyId: String, authorId: String, text: String): ApiResult<Unit>
```

The viewer depends only on these two methods, so the wire detail is isolated to
`core-data` and can change without touching `feature-stories`.

### 5.3 ApiResult mapping

All calls return `ApiResult<T>` (core-network). FastAPI `detail` is mapped by
the shared interceptor: `string` -> message; `[{msg}]` -> first `msg`;
`{code,...}` -> coded error. 401 triggers the single
`POST /ui/session/refresh` + retry already implemented in the OkHttp
authenticator (shared infra).

## 6. Data & State Management

- **Source of truth:** `StoryViewerViewModel.uiState: StateFlow<StoryViewerUiState>`.
- **Models (extend AND-199):** `StorySegment(storyId, mediaUrl, mediaType,
  durationMs)`; `StoryAuthorUiModel(authorId, displayName, avatarUrl,
  segments, isOwner, viewerCount)`.
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
- **OQ-2:** image segment default duration — backend `CreateStoryRequest`
  allows `duration_seconds` (1–300). Default to 5s when null; confirm the
  `/ui/stories/...` GET actually returns per-story duration in its (untyped)
  response so the bar timing matches the author's intent.
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
