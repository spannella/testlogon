---
id: AND-176
title: Share / bookmark from feed
milestone: M4
epic: E24
priority: P1
size: M
status: draft
depends_on: [AND-099, AND-092]
blocks: []
---

# AND-176 — Share / bookmark from feed

## 1. Overview & Goal

Add two per-post affordances to the feed: a **bookmark/save toggle** and a
**share action** that opens the Android system share sheet. Both actions are
surfaced directly on the post item (`PostItem`, AND-099) so a user can save or
share without navigating into a detail screen.

The save toggle must be **optimistic** and reconcile against the backend
bookmark endpoints owned by the Saved/Bookmarks feature (AND-092). Tapping
share builds a canonical post URL and hands it to `ACTION_SEND` via a Compose
`LocalContext` intent launcher.

Done means: tapping the bookmark icon flips its state instantly and persists
server-side (surviving scroll/recycle and process death via the saved-items
cache); tapping share opens the OS chooser with a resolvable deep link and
plain-text fallback. No new screens are introduced — this ticket adds row-level
controls and the wiring beneath them.

Module home: `feature-feed` for the UI binding; the bookmark domain logic and
repository live in `feature-saved` / `core-data` (shared with AND-092). Package
base everywhere: `com.testlogon.android`.

## 2. Context & References

- **AND-099 — Post item composable** (P0, dependency): provides `PostItem` and
  its action-row slot. This ticket adds the bookmark + share controls into that
  row. We extend, not rewrite, `PostItem`.
- **AND-092 — Saved / bookmarks** (P1, dependency): owns the saved/bookmarks
  API surface (`bookmarks.ts` web equivalent), the Saved screen, and the
  `BookmarkRepository`. This ticket is the **feed-side entry point** that toggles
  bookmark state through that same repository so the Saved screen stays
  consistent. AND-092 owns persistence + the list screen; AND-176 owns the feed
  toggle and share.
- Web reference: `frontend/src/api/endpoints/bookmarks.ts`,
  `frontend/src/api/types.ts` for the `Bookmark` / `Post` shapes and the share
  URL convention.
- OpenAPI: `http://18.222.237.167:8000/openapi.json` — confirm exact bookmark
  paths/verbs at implementation time; treat below as the contract derived from
  the web client.
- Auth: cookie-based session + `X-CSRF-Token` (echoed `ui_csrf` cookie). Mutating
  bookmark calls (POST/DELETE) require the CSRF header and the persistent cookie
  jar; on 401 the network layer performs one `POST /ui/session/refresh` + retry.

## 3. Functional Requirements

FR-1. Each `PostItem` in the feed renders a **bookmark toggle** (outline icon
when not saved, filled when saved) and a **share button** in the action row.

FR-2. Tapping the bookmark toggle **optimistically** flips the visual state and
issues the corresponding `POST` (save) or `DELETE` (unsave) bookmark request.

FR-3. On bookmark request failure the UI **reverts** to the prior state and
surfaces a transient, non-blocking snackbar ("Couldn't save post. Retry.") with
a retry affordance for the same post.

FR-4. Bookmark state is **sourced from the saved-items cache** (Room, shared
with AND-092) so a post already saved elsewhere renders as saved in the feed,
and a feed save appears on the Saved screen without manual refresh.

FR-5. Tapping share opens the **system share sheet** (`Intent.ACTION_SEND`,
`text/plain`) containing a canonical post URL and, when available, the post
title/author as the share subject.

FR-6. Bookmark and share controls must be **disabled/no-op for logged-out
state**; bookmark requires an authenticated session, share does not require auth
but still needs a resolvable URL.

FR-7. Rapid repeated taps on the bookmark toggle must be **debounced/serialized**
per post so the final committed state matches the last user intent (no
save/unsave race).

FR-8. State must **survive list recycling and process death**: a saved post
re-rendered after scroll, configuration change, or restart shows the saved icon.

## 4. Technical Design

### 4.1 Layering

```
feature-feed (UI: PostItem action row, FeedViewModel wiring)
   -> feature-saved/core-data (BookmarkRepository — shared with AND-092)
        -> core-network (BookmarkApi, Retrofit)
   -> core-ui (ShareLauncher, icons, snackbar host)
```

### 4.2 UI surface (feature-feed)

Extend the `PostItem` action row (AND-099) with a stateless, hoisted control
block. State is passed in; events are emitted up.

```kotlin
@Composable
fun PostActionRow(
    isBookmarked: Boolean,
    isBookmarkPending: Boolean,
    onToggleBookmark: () -> Unit,
    onShare: () -> Unit,
    modifier: Modifier = Modifier,
)
```

```kotlin
@Composable
fun BookmarkToggle(
    checked: Boolean,
    enabled: Boolean,
    onCheckedChange: (Boolean) -> Unit,
) {
    IconToggleButton(checked = checked, enabled = enabled, onCheckedChange = onCheckedChange) {
        Icon(
            imageVector = if (checked) Icons.Filled.Bookmark else Icons.Outlined.BookmarkBorder,
            contentDescription = if (checked)
                stringResource(R.string.feed_remove_bookmark)
            else stringResource(R.string.feed_add_bookmark),
        )
    }
}
```

### 4.3 Share (core-ui)

Share is a side-effecting platform call; wrap it so it is testable and not
called directly from the composable body.

```kotlin
class ShareLauncher @Inject constructor() {
    fun share(context: Context, content: ShareContent) {
        val send = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_TEXT, content.url)
            content.subject?.let { putExtra(Intent.EXTRA_SUBJECT, it) }
        }
        context.startActivity(
            Intent.createChooser(send, context.getString(R.string.feed_share_chooser_title))
        )
    }
}

data class ShareContent(val url: String, val subject: String?)
```

```kotlin
object PostShare {
    private const val WEB_BASE = "https://app.testlogon.com" // canonical web origin
    fun urlFor(postId: String): String = "$WEB_BASE/p/$postId"
    fun subjectFor(post: PostUiModel): String? =
        post.authorDisplayName?.let { "Post by $it on TestLogon" }
}
```

In the feed screen the share callback resolves `LocalContext.current`:

```kotlin
val context = LocalContext.current
PostActionRow(
    /* ... */
    onShare = { shareLauncher.share(context, ShareContent(PostShare.urlFor(post.id), PostShare.subjectFor(post))) },
)
```

### 4.4 ViewModel wiring (feature-feed)

```kotlin
@HiltViewModel
class FeedViewModel @Inject constructor(
    private val bookmarkRepository: BookmarkRepository,
) : ViewModel() {

    // post.id -> in-flight toggle job, for serialization/debounce
    private val toggleJobs = mutableMapOf<String, Job>()

    fun onToggleBookmark(postId: String, desired: Boolean) {
        toggleJobs.remove(postId)?.cancel()
        toggleJobs[postId] = viewModelScope.launch {
            when (val r = bookmarkRepository.setBookmarked(postId, desired)) {
                is ApiResult.Success -> { /* cache already updated optimistically */ }
                is ApiResult.Failure -> emitRevertAndSnackbar(postId, !desired, r.error)
            }
        }
    }
}
```

The repository (shared with AND-092) is the single writer of bookmark state:

```kotlin
interface BookmarkRepository {
    /** Reactive saved-state for a post, backed by Room cache. */
    fun observeBookmarked(postId: String): Flow<Boolean>
    /** Optimistic write to cache, then network reconcile. */
    suspend fun setBookmarked(postId: String, bookmarked: Boolean): ApiResult<Unit>
}
```

Optimistic flow inside `setBookmarked`: (1) upsert/delete the local
`BookmarkEntity` so `observeBookmarked` emits immediately; (2) call the network;
(3) on failure roll the cache row back and return `ApiResult.Failure`.

## 5. API Contract

Bookmark endpoints are derived from the web `bookmarks.ts` client and are owned
by AND-092; AND-176 consumes them. Confirm exact paths against `/openapi.json`.

**Save a post**

```
POST /ui/bookmarks
Headers: X-CSRF-Token: <ui_csrf>; Cookie: <session>
Body: { "post_id": "<postId>" }
-> 200 { "id": "bm_123", "post_id": "<postId>", "created_at": "2026-06-05T12:00:00Z" }
```

**Unsave a post**

```
DELETE /ui/bookmarks/{post_id}
Headers: X-CSRF-Token: <ui_csrf>; Cookie: <session>
-> 204 No Content   (or 200 { "ok": true })
```

**List saved (read by AND-092; used here to seed cache)**

```
GET /ui/bookmarks?cursor=<c>&limit=20  -> 200 { "items": [Bookmark], "next_cursor": "..." }
```

Retrofit interface (in core-network, shared):

```kotlin
interface BookmarkApi {
    @POST("ui/bookmarks")
    suspend fun add(@Body body: AddBookmarkRequest): Response<BookmarkDto>

    @DELETE("ui/bookmarks/{postId}")
    suspend fun remove(@Path("postId") postId: String): Response<Unit>
}

@JsonClass(generateAdapter = true)
data class AddBookmarkRequest(@Json(name = "post_id") val postId: String)

@JsonClass(generateAdapter = true)
data class BookmarkDto(
    val id: String,
    @Json(name = "post_id") val postId: String,
    @Json(name = "created_at") val createdAt: String?,
)
```

FastAPI `detail` errors are normalized by the shared mapper:
`string | [{msg}] | {code,...}` -> domain `AppError`. A `409` on add (already
bookmarked) and `404` on delete (not bookmarked) are treated as **idempotent
success** (the desired end-state already holds) rather than failures.

Share has **no API contract** — it is a pure client-side Android intent.

## 6. Data & State Management

- **Room (core-data), shared with AND-092**: `BookmarkEntity(postId: String PK,
  bookmarkId: String?, createdAt: Long?, syncState: enum{SYNCED, PENDING_ADD,
  PENDING_REMOVE})`. Optimistic toggles set `PENDING_*`; success -> `SYNCED`;
  failure -> rollback (delete pending-add row / restore removed row).
- **Read path**: `FeedViewModel` joins each post with `observeBookmarked(postId)`
  so the UI is driven by cache, not by transient view state. This satisfies FR-4
  and FR-8 (recycle/process-death survival).
- **UiState**: `FeedUiState` gains no new top-level field; per-post bookmark and
  pending flags are projected onto each `PostUiModel`:

```kotlin
data class PostUiModel(
    val id: String,
    val authorDisplayName: String?,
    val isBookmarked: Boolean = false,
    val isBookmarkPending: Boolean = false,
    /* ...AND-099 fields... */
)
```

- **Serialization** (FR-7): per-`postId` job map in the ViewModel; a new toggle
  cancels the prior in-flight job, so only the last intent is committed.
- **DataStore** is not used here; bookmark truth is the Room cache reconciled
  with the server. No prefs are added.

## 7. Error Handling & Resilience

- **Optimistic + rollback**: cache flips immediately; network failure reverts the
  cache row and emits a one-shot snackbar event (`SnackbarEvent.BookmarkFailed(postId)`)
  consumed by the feed screen with a Retry action that re-invokes
  `onToggleBookmark(postId, desired)`.
- **Idempotency**: bookmark mutations are NOT retried automatically (POST/DELETE
  are not idempotent GETs per project policy). Only the `GET /ui/bookmarks`
  seed list is eligible for bounded-backoff retry on the unreliable dev host.
- **409/404 reconciliation**: add->409 and delete->404 mean the server already
  matches desired state; mark `SYNCED`, no snackbar.
- **401**: handled by the OkHttp authenticator (single `POST /ui/session/refresh`
  + retry). If refresh fails, the toggle reverts and the user is treated as
  logged-out (FR-6).
- **Timeouts**: ~20s OkHttp timeout; a timed-out toggle reverts and offers retry.
- **Share**: wrap `startActivity` in try/catch for `ActivityNotFoundException`
  (no share target) — show a snackbar and, as fallback, copy the URL to the
  clipboard.
- **Offline**: toggles still flip the cache and stay `PENDING_*`; FR-3 snackbar
  notes "Saved locally, will sync" only if a background sync exists in AND-092,
  otherwise it reverts and reports offline. Default: revert + offline snackbar.

## 8. Security & Privacy

- All bookmark mutations send the `X-CSRF-Token` header from the `ui_csrf` cookie
  via the shared OkHttp interceptor; requests use the persistent cookie jar.
  No bookmark call may be made without an authenticated session (FR-6).
- The share URL contains only the **public post id** (`/p/{postId}`); no session
  token, cookie, CSRF value, user id, or auth material is ever placed in
  `EXTRA_TEXT`/`EXTRA_SUBJECT`. This is asserted by a unit test.
- Share uses `Intent.createChooser` (system chooser) rather than a hardcoded
  target, avoiding leaking content to a privileged app implicitly.
- Cleartext: the dev backend is plaintext HTTP; share URLs use the canonical
  **HTTPS** web origin, independent of the dev API host.

## 9. Accessibility & i18n

- `BookmarkToggle` exposes a state-dependent `contentDescription`
  ("Add bookmark" / "Remove bookmark") and reports toggle state to TalkBack via
  `IconToggleButton` (role = switch/toggle, checked state announced).
- Share button `contentDescription` = "Share post".
- Touch targets >= 48dp; icons meet Material 3 contrast in light/dark themes.
- All user-facing strings are in `strings.xml`:
  `feed_add_bookmark`, `feed_remove_bookmark`, `feed_share`,
  `feed_share_chooser_title`, `feed_bookmark_failed`, `feed_bookmark_retry`,
  `feed_share_no_target`. No hardcoded literals in composables.
- Snackbar messages are translatable; chooser title is localized.

## 10. Telemetry & Logging

- Analytics events (via the project analytics facade): `bookmark_add`,
  `bookmark_remove`, `bookmark_failed` (with normalized error code),
  `post_share_opened` — each with `post_id` and `source = "feed"`. No PII or
  post content in event params.
- Logging: Timber `d` for optimistic flip + reconcile result; `w` on rollback
  with the mapped `AppError` code (never log cookies/CSRF/full bodies).
- Verify analytics in debug via a no-op/test analytics sink in `core-testing`.

## 11. Testing Strategy

- **Unit (core-data / feature-saved)**: `BookmarkRepository.setBookmarked`
  optimistic upsert; rollback on network failure; 409/404 treated as success;
  serialization (last-write-wins) when two toggles race. Use a fake
  `BookmarkApi` + in-memory Room.
- **Unit (feature-feed)**: `FeedViewModel.onToggleBookmark` emits pending then
  settled state; failure emits revert + `SnackbarEvent.BookmarkFailed`; retry
  re-invokes the call. Coroutine test dispatcher.
- **Unit (core-ui)**: `PostShare.urlFor`/`subjectFor` shape; assert URL contains
  no auth material; `ShareLauncher` builds an `ACTION_SEND`/`text/plain` intent
  (Robolectric `ShadowApplication.getNextStartedActivity`).
- **Compose UI test**: `BookmarkToggle` shows outline->filled on tap; correct
  `contentDescription` per state; disabled when logged out; share button click
  invokes `onShare`.
- **Acceptance mapping**: "Save toggles" -> repo + ViewModel + Compose tests
  above; "share opens sheet" -> Robolectric intent assertion + Compose click test.
- **core-testing** fixtures: `FakeBookmarkRepository`, sample `PostUiModel`s,
  `TestShareLauncher` recording the last `ShareContent`.

## 12. Dependencies & Sequencing

- **Depends on AND-099** (Post item composable, P0): the action-row slot must
  exist before bookmark/share controls can be placed. Hard dependency.
- **Depends on AND-092** (Saved / bookmarks, P1): `BookmarkRepository`,
  `BookmarkApi`, `BookmarkEntity`, and the saved-items Room cache are owned by
  AND-092 and reused here. AND-176 must not fork these — if AND-092 lands first,
  AND-176 only wires the feed surface; if developed in parallel, the repository
  interface (Section 4.4) is the agreed contract.
- Blocks: none currently.
- Sequencing: implement after AND-099 is mergeable and the AND-092 repository
  interface is frozen. Share (Sections 4.3, 8) has no upstream dependency and can
  proceed independently.

## 13. Risks & Open Questions

- **R1 — Canonical share URL**: `WEB_BASE`/path (`/p/{id}`) is assumed from the
  web app; confirm the actual public post route and whether IDs are slugs.
  *Open:* is there a server-issued share/short URL endpoint? Default to
  client-built URL until confirmed.
- **R2 — Endpoint shape**: bookmark add/remove verbs and the unsave path
  (`DELETE /ui/bookmarks/{post_id}` vs `DELETE /ui/bookmarks/{bookmark_id}`)
  must be verified against `/openapi.json`; affects whether we need the
  `bookmarkId` from the add response.
- **R3 — Offline policy**: whether AND-092 provides background bookmark sync
  decides FR-3 wording (queue vs revert). Default: revert + offline snackbar.
- **R4 — Shared ownership**: schema/interface drift between AND-092 and AND-176
  during parallel work. Mitigation: freeze `BookmarkRepository` contract first.
- **R5 — Idempotent re-tap during in-flight**: covered by job serialization, but
  needs explicit test for the unsave-then-save sequence within one debounce.

## 14. Acceptance Criteria

AC-1 (Save toggles): Tapping the bookmark icon on a feed post flips it from
outline to filled (and back) immediately; the change persists server-side and is
visible on the Saved screen (AND-092) without manual refresh.

AC-2 (Persistence/recycle): A saved post still shows the filled icon after
scrolling it off/on screen, after a configuration change, and after process
death + restart (cache-driven).

AC-3 (Failure revert): When the bookmark network call fails, the icon reverts to
its prior state and a snackbar with a working Retry is shown; Retry re-issues the
toggle.

AC-4 (Idempotent server state): An add returning 409 or a delete returning 404 is
treated as success with no error snackbar.

AC-5 (Share opens sheet): Tapping share opens the Android system chooser with
`ACTION_SEND`/`text/plain`, containing a resolvable post URL and (when known) an
author subject; no auth material appears in the shared text.

AC-6 (Logged-out): When unauthenticated, the bookmark toggle is disabled/no-op;
share still functions with a valid URL.

AC-7 (a11y): Bookmark and share controls have correct, state-aware
`contentDescription`s, announce toggle state to TalkBack, and meet 48dp targets.

AC-8 (Tested): The bookmark toggle/unsave behavior is covered by automated tests
(repository, ViewModel, Compose) and the share intent by a Robolectric test.

## 15. Definition of Done

- Bookmark toggle + share button implemented in `PostItem`'s action row
  (`feature-feed`), wired to the shared `BookmarkRepository` and `ShareLauncher`.
- Optimistic toggle with rollback, per-post serialization, and cache-driven state
  implemented; AC-1..AC-8 all pass.
- `BookmarkApi`/DTOs reused from (or aligned with) AND-092; CSRF + cookie jar +
  401-refresh path exercised.
- All strings localized; no hardcoded user-facing text; package base
  `com.testlogon.android` throughout.
- Unit, Compose, and Robolectric tests added and green in CI; analytics events
  emitted and verified via the test sink.
- No auth material in share payloads (asserted by test); Timber logs scrub
  secrets.
- Code reviewed and merged to `android-port`; ktlint/detekt clean; no new
  lint-baseline regressions.
