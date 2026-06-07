---
id: AND-176
title: Share / bookmark from feed
milestone: M4
epic: E24
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
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

> **Review note (platform divergence):** The web reference does NOT use a system
> share sheet or a public canonical URL. Web "share" (`src/pages/feed/SharePostDialog.tsx`)
> opens an **in-app dialog that DMs the post to a conversation** via
> `sendTextMessage(..., { preview: { url: "/posts/{post_id}", ... } })`. This
> Android ticket deliberately chooses the native OS share sheet instead — an
> accepted platform divergence, not a contract match. The web's internal post
> path is `/posts/{post_id}` (see §16 corrections), not `/p/{postId}`.

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
- Web reference: `src/api/endpoints/bookmarks.ts`, `src/api/types.ts` for the
  `BookmarkItem` / `FeedPost` shapes; `src/pages/feed/PostCard.tsx` and
  `src/pages/feed/SharePostDialog.tsx` for feed action-row behavior. **Note:** the
  DTO is `BookmarkItem` (keyed by `content_type`+`content_id`), not a `Bookmark`
  with a `post_id` — see §5 and §16. There is no web "share URL convention";
  share is in-app DM (see §1 review note).
- OpenAPI (verified for this review): bookmark endpoints live under `/ui/bookmarks`
  and `/ui/bookmark-collections`. Verified operations:
  `POST /ui/bookmarks` (`create_bookmark`, req `CreateBookmarkRequest`, resp 201),
  `DELETE /ui/bookmarks/{content_type}/{content_id}` (`delete_bookmark`, resp 200),
  `GET /ui/bookmarks` (`list_bookmarks`, resp 200),
  `GET /ui/bookmarks/status?ids=` (`bookmark_status`, resp 200).
- Auth: cookie-based session + `X-CSRF-Token` echoed from the `ui_csrf` cookie
  (verified in `src/api/client.ts`). Mutating bookmark calls (POST/DELETE) require
  the CSRF header and the persistent cookie jar. **Correction:** the web does not
  use an OkHttp authenticator — `client.ts` retries once on 401 *only if the user
  was already authenticated*, via a single in-flight `POST /ui/session/refresh`
  promise, then replays the request; on refresh failure it logs out. The Android
  401-refresh-retry is a faithful port of that behavior. The web client also
  attaches `Authorization: Bearer <accessToken>` (from the auth store) in addition
  to the CSRF header; the Android port should carry the equivalent bearer/session.

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
    // WEB_BASE is an UNVERIFIED assumption — no public origin appears in OpenAPI
    // or the web client. The web's internal post route is "/posts/{post_id}"
    // (src/pages/feed/SharePostDialog.tsx), NOT "/p/{postId}". Use the verified
    // web path segment; confirm the public origin before launch (R1).
    private const val WEB_BASE = "https://app.testlogon.com" // ASSUMED canonical origin
    fun urlFor(postId: String): String = "$WEB_BASE/posts/$postId"
    // NOTE: FeedPost in the web contract has NO author_display_name — only
    // author_id (src/api/types.ts: FeedPost). authorDisplayName here must be
    // supplied by the Android PostUiModel from a profile source, or fall back to
    // author_id; do not assume the feed payload carries it.
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

Bookmark endpoints are owned by AND-092; AND-176 consumes them. The shapes below
are **verified** against OpenAPI (`openapi.index.txt` / `openapi.pretty.json`) and
`src/api/endpoints/bookmarks.ts`. Corrections from the prior draft are flagged.

> **Corrected:** the prior draft used `{post_id}` bodies/paths and a `BookmarkDto`
> with `id`/`post_id`. The real contract is keyed by `content_type` + `content_id`.
> Posts use `content_type = "post"` (enum: `post | video`).

**Save a post** — `POST /ui/bookmarks` (`create_bookmark`, resp **201**)

```
POST /ui/bookmarks
Headers: X-CSRF-Token: <ui_csrf>; Cookie: <session>
Body (CreateBookmarkRequest):
  { "content_type": "post", "content_id": "<postId>", "collection_id": "default" }
  # content_id required (1..64, ^[a-zA-Z0-9_]+$); content_type defaults "post";
  # collection_id optional, defaults "default".
-> 201 { "ok": true, "content_type": "post", "content_id": "<postId>",
         "collection_id": "default", "created_at": "2026-06-06T12:00:00Z" }
```

**Unsave a post** — `DELETE /ui/bookmarks/{content_type}/{content_id}`
(`delete_bookmark`, resp **200**)

```
DELETE /ui/bookmarks/post/<postId>
Headers: X-CSRF-Token: <ui_csrf>; Cookie: <session>
-> 200 { "ok": true }
```

> **Corrected:** path is `/ui/bookmarks/{content_type}/{content_id}` (two segments),
> not `/ui/bookmarks/{post_id}`; and success is **200 `{ "ok": true }`**, not 204.
> This means R2 is RESOLVED: unsave keys off `(content_type, content_id)`, so the
> `bookmarkId` from the add response is NOT needed for delete.

**List saved (read by AND-092; used here to seed cache)** — `GET /ui/bookmarks`

```
GET /ui/bookmarks?cursor=<c>&limit=20&content_type=post&collection_id=<id>
-> 200 { "bookmarks": [BookmarkItem], "next_cursor": "...", "total_count": N }
# BookmarkItem: { content_type, content_id, collection_id, created_at,
#   content_preview: { author_id, author_display_name?, body_snippet?,
#                      image_url?, like_count? } }
```

> **Corrected:** list response wrapper is `{ bookmarks, next_cursor, total_count }`
> (not `{ items, next_cursor }`), and elements are `BookmarkItem` (not `Bookmark`).

**Bookmark status (batch presence check)** — `GET /ui/bookmarks/status?ids=`
(`bookmark_status`, resp **200**) — NEW, not in prior draft

```
GET /ui/bookmarks/status?ids=<id1>,<id2>,...
-> 200 { "statuses": { "<id1>": true, "<id2>": false } }
```

> This endpoint lets the feed seed per-post saved-state cheaply for visible posts
> without paging the whole saved list — recommended for FR-4/FR-8 hydration.

Retrofit interface (in core-network, shared):

```kotlin
interface BookmarkApi {
    @POST("ui/bookmarks")
    suspend fun add(@Body body: CreateBookmarkRequest): Response<BookmarkResponse>

    @DELETE("ui/bookmarks/{contentType}/{contentId}")
    suspend fun remove(
        @Path("contentType") contentType: String,   // "post"
        @Path("contentId") contentId: String,
    ): Response<OkResponse>

    @GET("ui/bookmarks/status")
    suspend fun status(@Query("ids") ids: String): Response<BookmarkStatusResponse>
}

@JsonClass(generateAdapter = true)
data class CreateBookmarkRequest(
    @Json(name = "content_type") val contentType: String = "post",
    @Json(name = "content_id") val contentId: String,
    @Json(name = "collection_id") val collectionId: String? = "default",
)

@JsonClass(generateAdapter = true)
data class BookmarkResponse(
    val ok: Boolean,
    @Json(name = "content_type") val contentType: String,
    @Json(name = "content_id") val contentId: String,
    @Json(name = "collection_id") val collectionId: String?,
    @Json(name = "created_at") val createdAt: String?,
)

@JsonClass(generateAdapter = true)
data class OkResponse(val ok: Boolean)

@JsonClass(generateAdapter = true)
data class BookmarkStatusResponse(val statuses: Map<String, Boolean>)
```

FastAPI `detail` errors are normalized by the shared mapper:
`string | [{msg}] | {code,...}` -> domain `AppError` (this matches
`normalizeErrorDetail` in `src/api/client.ts`). Note all bookmark ops also list a
**422 `HTTPValidationError`** response (e.g. malformed `content_id` against the
`^[a-zA-Z0-9_]+$` pattern). The web's documented idempotency handling
(`src/pages/feed/PostCard.tsx`): a **409** on add (already bookmarked) is treated
as success (`setIsBookmarked(true)`), and a **404** on delete (already removed) is
treated as success (`setIsBookmarked(false)`) — the desired end-state already
holds. The Android port mirrors this.

Share has **no API contract** — it is a pure client-side Android intent.

## 6. Data & State Management

- **Room (core-data), shared with AND-092**: `BookmarkEntity(contentId: String PK,
  contentType: String = "post", collectionId: String?, createdAt: Long?,
  syncState: enum{SYNCED, PENDING_ADD, PENDING_REMOVE})`. Optimistic toggles set
  `PENDING_*`; success -> `SYNCED`; failure -> rollback (delete pending-add row /
  restore removed row). **Corrected:** there is no server `bookmarkId` to store —
  the add response is `{ ok, content_type, content_id, collection_id, created_at }`
  and delete keys off `(content_type, content_id)`, so the entity is keyed by
  `contentId` (the postId for feed posts) + `contentType`, with `collectionId`.
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

- **R1 — Canonical share URL** *(partially clarified)*: the web app has NO public
  share URL — its share is an in-app DM, and its internal post route is
  `/posts/{post_id}` (corrected from `/p/{id}`). No server-issued share/short URL
  endpoint exists in OpenAPI. `WEB_BASE` (public origin) remains an unverified
  assumption; confirm the actual public origin and whether IDs are slugs before
  launch. Default to client-built `WEB_BASE/posts/{postId}` until confirmed.
- **R2 — Endpoint shape** *(RESOLVED in this review)*: verified against OpenAPI.
  Add = `POST /ui/bookmarks` (201, `CreateBookmarkRequest` keyed by
  `content_type`+`content_id`); unsave = `DELETE /ui/bookmarks/{content_type}/{content_id}`
  (200 `{ok:true}`). No `bookmarkId` is needed — delete keys off the content tuple.
  See §5 and §16.
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the authoritative source pointer.

1. **Save endpoint is `POST /ui/bookmarks`.** VERIFIED.
   Source: OpenAPI `POST /ui/bookmarks` (op `create_bookmark_ui_bookmarks_post`);
   `src/api/endpoints/bookmarks.ts: createBookmark`.
2. **Save request body shape.** CORRECTED — was `{ "post_id" }`; actual is
   `CreateBookmarkRequest { content_type ("post"|"video", default "post"),
   content_id (required, 1..64, ^[a-zA-Z0-9_]+$), collection_id (default "default") }`.
   Source: `components.schemas.CreateBookmarkRequest` in `openapi.pretty.json`;
   `src/api/endpoints/bookmarks.ts: createBookmark`.
3. **Save success status / response body.** CORRECTED — was `200 {id,post_id,created_at}`;
   actual is **201** with `{ ok, content_type, content_id, collection_id, created_at }`.
   Source: OpenAPI `POST /ui/bookmarks` resp `201`; `src/api/endpoints/bookmarks.ts: createBookmark`
   return type.
4. **Unsave endpoint path.** CORRECTED — was `DELETE /ui/bookmarks/{post_id}`;
   actual is `DELETE /ui/bookmarks/{content_type}/{content_id}`.
   Source: OpenAPI `DELETE /ui/bookmarks/{content_type}/{content_id}`
   (op `delete_bookmark_ui_bookmarks__content_type___content_id__delete`);
   `src/api/endpoints/bookmarks.ts: removeBookmark`.
5. **Unsave success status / body.** CORRECTED — was `204 No Content`; actual is
   **200** `{ ok: true }`. Source: OpenAPI resp `200`;
   `src/api/endpoints/bookmarks.ts: removeBookmark` (`api.del<{ ok: boolean }>`).
6. **List saved endpoint + wrapper.** CORRECTED — was `{ items, next_cursor }`;
   actual is `GET /ui/bookmarks` -> `{ bookmarks: BookmarkItem[], next_cursor?, total_count }`
   with params `limit,cursor,content_type,collection_id`.
   Source: OpenAPI `GET /ui/bookmarks` (op `list_bookmarks_ui_bookmarks_get`);
   `src/api/endpoints/bookmarks.ts: BookmarkListResponse / getBookmarks`.
7. **Batch presence endpoint `GET /ui/bookmarks/status?ids=` -> `{ statuses: {id:bool} }`.**
   VERIFIED (newly surfaced; absent from prior draft). Source: OpenAPI
   `GET /ui/bookmarks/status` (op `bookmark_status_ui_bookmarks_status_get`, param `ids`);
   `src/api/endpoints/bookmarks.ts: getBookmarkStatus`.
8. **DTO is keyed by `content_type`+`content_id`, not a `Bookmark`/`post_id`.**
   CORRECTED. Source: `src/api/endpoints/bookmarks.ts: BookmarkItem`
   (`content_type, content_id, collection_id, created_at, content_preview{...}`).
9. **409-on-add and 404-on-delete treated as idempotent success.** VERIFIED.
   Source: `src/pages/feed/PostCard.tsx: bookmarkMutation.onError` (status 409 ->
   `setIsBookmarked(true)`; 404 -> `setIsBookmarked(false)`). Note: server's normal
   error envelope per op is **422 HTTPValidationError**; 409/404 are runtime conflict
   states handled client-side, not declared response codes in OpenAPI.
10. **Auth = cookie session + `X-CSRF-Token` from `ui_csrf` cookie on mutations.**
    VERIFIED. Source: `src/api/client.ts` (`getCookie("ui_csrf")` ->
    `headers.set("X-CSRF-Token", csrf)`; `credentials: "include"`).
11. **401 -> single `POST /ui/session/refresh` + one retry.** VERIFIED, with nuance.
    CORRECTED framing — it is not an "OkHttp authenticator"; the web does a single
    in-flight `refreshPromise` and ONLY refreshes if `isAuthenticated` was already
    true, else propagates 401; on refresh failure -> `logout`. Source:
    `src/api/client.ts: refreshSession` + the `res.status === 401` block; OpenAPI
    `POST /ui/session/refresh` (op `ui_session_refresh_ui_session_refresh_post`, resp 200).
12. **Web client also sends `Authorization: Bearer <accessToken>`.** VERIFIED (added).
    Source: `src/api/client.ts` (`headers.set("Authorization", \`Bearer ${accessToken}\`)`).
13. **Error normalization `string | [{msg}] | {code,...}` -> message.** VERIFIED.
    Source: `src/api/client.ts: normalizeErrorDetail` and `mapAuthorizationError`.
14. **Web "share" opens a system share sheet with a canonical `/p/{postId}` URL.**
    CORRECTED — web share is an IN-APP DM, not a system sheet; internal route is
    `/posts/{post_id}` (NOT `/p/{postId}`). The Android system-share-sheet design is
    an accepted platform divergence. Source: `src/pages/feed/SharePostDialog.tsx`
    (`sendTextMessage(..., { preview: { url: \`/posts/${post.post_id}\`, ... } })`);
    `src/pages/feed/PostCard.tsx` (share button opens `SharePostDialog`).
15. **Public web origin `https://app.testlogon.com`.** UNVERIFIED-ASSUMPTION.
    No public origin appears in OpenAPI or the web client (`VITE_API_BASE_URL` is
    env-injected and points at the dev API host). Must confirm before launch (R1).
16. **`FeedPost` carries an author display name for the share subject.**
    UNVERIFIED-ASSUMPTION (effectively CORRECTED) — `FeedPost` has only `author_id`,
    no `author_display_name`; the web feed renders `author_id` as the name.
    `author_display_name` only appears nested in `BookmarkItem.content_preview`.
    The Android `PostUiModel.authorDisplayName` must come from a profile source or
    fall back to `author_id`. Source: `src/api/types.ts: FeedPost`;
    `src/pages/feed/PostCard.tsx` (renders `{post.author_id}`).
17. **No server-issued share/short-URL endpoint exists.** VERIFIED (absence).
    Source: grep of `openapi.index.txt` for `share` returns only broadcast-clip
    share-recording and messaging file/video/calendar-share message endpoints — none
    mints a public post URL.
18. **Share via `Intent.ACTION_SEND` + `Intent.createChooser`, `text/plain`.**
    VERIFIED (framework ref). Source: Android docs —
    https://developer.android.com/training/sharing/send (Sharsheet / ACTION_SEND).
19. **`IconToggleButton` announces checked/toggle state to TalkBack; 48dp targets.**
    VERIFIED (framework ref). Source: Material 3 Compose
    https://developer.android.com/jetpack/compose/components/button#icon-button and
    accessibility minimum touch target
    https://developer.android.com/develop/ui/compose/accessibility.
20. **`ActivityNotFoundException` possible when no share target / no `startActivity` resolver.**
    VERIFIED (framework ref). Source: Android docs
    https://developer.android.com/reference/android/content/ActivityNotFoundException.

### Corrections made

- C1 (§5): Save body `{post_id}` -> `CreateBookmarkRequest {content_type, content_id, collection_id}`.
- C2 (§5): Save response `200 {id,post_id,created_at}` -> `201 {ok,content_type,content_id,collection_id,created_at}`.
- C3 (§5): Unsave path `/ui/bookmarks/{post_id}` -> `/ui/bookmarks/{content_type}/{content_id}`.
- C4 (§5): Unsave success `204` -> `200 {ok:true}`.
- C5 (§5): List wrapper `{items,next_cursor}` -> `{bookmarks,next_cursor,total_count}`; element `Bookmark` -> `BookmarkItem`.
- C6 (§5): Added the previously-missing `GET /ui/bookmarks/status?ids=` endpoint.
- C7 (§5 Retrofit): `AddBookmarkRequest`/`BookmarkDto` replaced with verified
  `CreateBookmarkRequest`/`BookmarkResponse`/`OkResponse`/`BookmarkStatusResponse`;
  `remove(postId)` -> `remove(contentType, contentId)`.
- C8 (§6): `BookmarkEntity` re-keyed `postId`+`bookmarkId` -> `contentId`+`contentType`+`collectionId`
  (no server bookmarkId exists).
- C9 (§2, §1, §4.3, §13/R1): Share corrected — web is in-app DM, internal route
  `/posts/{post_id}` not `/p/{postId}`; Android native share-sheet noted as a
  deliberate divergence; share-URL path segment fixed to `/posts/`.
- C10 (§2): 401 handling reframed from "OkHttp authenticator" to the web's actual
  single-in-flight-refresh-if-already-authenticated behavior; added the
  `Authorization: Bearer` header fact.
- C11 (§13/R2): marked RESOLVED with verified shapes.

### Open assumptions

- **OA-1 — Public share origin (`WEB_BASE`).** Unverifiable from sources: no public
  origin in OpenAPI; the web injects `VITE_API_BASE_URL` at build time pointing at
  the dev API. The `/posts/{post_id}` path segment is verified, the host is not.
  Why: deployment/DNS config is outside the provided artifacts.
- **OA-2 — Resolvability of the shared URL on a logged-out device.** AC-5 requires a
  "resolvable" URL; whether `/posts/{post_id}` is publicly viewable without auth
  cannot be confirmed (no public post-fetch route was verified). Why: no public
  unauthenticated post endpoint appears in OpenAPI.
- **OA-3 — Author display name on the feed.** `FeedPost` lacks `author_display_name`;
  the share subject depends on an Android-side profile join or `author_id` fallback.
  Why: the web feed contract simply does not carry it.
- **OA-4 — AND-092 background sync existence.** The offline "Saved locally, will sync"
  wording (§7) depends on whether AND-092 ships background bookmark sync. Default
  remains revert + offline snackbar. Why: AND-092 internals are not in scope here.
- **OA-5 — Logged-out bookmark gating in the web.** The web `PostCard` does not
  visibly disable the bookmark button when logged out (FR-6 is an Android product
  decision, not a verified web behavior). Why: web relies on the 401 path rather
  than pre-disabling.

## 17. Test Plan

Test target legend: **JVM** = JVM unit/Robolectric (local, no device);
**emu35** = headless emulator AVD `test35` (x86_64, Android 15 / API 35);
**A15** = physical Samsung Galaxy A15 5G (SM-A156U, Android 14 / API 34, arm64-v8a).
Most cases here are non-hardware and run on JVM or emu35; the OS share-chooser
real-target case is called out for the physical device.

- **TC-AND-176-01** — Type: unit (JVM). Target: `BookmarkRepository.setBookmarked`.
  Preconditions: in-memory Room empty; fake `BookmarkApi` returns 201
  `{ok:true,...}` for add. Steps: call `setBookmarked(postId,true)`; collect
  `observeBookmarked(postId)`. Expected: emits `true` immediately (optimistic
  upsert, `PENDING_ADD`), then settles `SYNCED`; fake API received
  `CreateBookmarkRequest(content_type="post", content_id=postId)`; result
  `ApiResult.Success`. Traces: AC-1.
- **TC-AND-176-02** — Type: unit (JVM). Target: `BookmarkRepository.setBookmarked`
  (unsave). Preconditions: row exists `SYNCED`; fake API returns 200 `{ok:true}`
  for `DELETE /ui/bookmarks/post/{id}`. Steps: `setBookmarked(postId,false)`.
  Expected: cache flips to absent immediately; DELETE called with path segments
  `("post", postId)`; settles success. Traces: AC-1.
- **TC-AND-176-03** — Type: unit (JVM). Target: `setBookmarked` rollback.
  Preconditions: fake API returns network failure / non-2xx on add. Steps:
  `setBookmarked(postId,true)`. Expected: `observeBookmarked` emits `true` then
  reverts to `false`; returns `ApiResult.Failure`; no orphan `PENDING_ADD` row.
  Traces: AC-3.
- **TC-AND-176-04** — Type: contract/MockWebServer (JVM). Target: `BookmarkApi` +
  Moshi adapters + CSRF interceptor. Preconditions: MockWebServer enqueues add
  201 and delete 200; a `ui_csrf` cookie present in the jar. Steps: call `add`
  then `remove`. Expected: add request is `POST /ui/bookmarks` with JSON
  `{"content_type":"post","content_id":...,"collection_id":...}` and header
  `X-CSRF-Token`; remove is `DELETE /ui/bookmarks/post/{id}`; both parse
  (`BookmarkResponse.ok==true`, `OkResponse.ok==true`). Verifies C1-C5/C7.
  Traces: AC-1.
- **TC-AND-176-05** — Type: contract/MockWebServer (JVM). Target: idempotency
  mapping. Preconditions: MockWebServer returns 409 for add, 404 for delete.
  Steps: toggle save (409) and unsave (404). Expected: both treated as success,
  cache reaches desired state, NO `SnackbarEvent.BookmarkFailed` emitted.
  Traces: AC-4.
- **TC-AND-176-06** — Type: contract/MockWebServer (JVM). Target: 422 validation
  error. Preconditions: server returns 422 `HTTPValidationError` (e.g. malformed
  `content_id`). Steps: `setBookmarked`. Expected: mapped to `AppError`, cache
  rolled back, `BookmarkFailed` snackbar event emitted. Traces: AC-3.
- **TC-AND-176-07** — Type: contract/MockWebServer (JVM). Target: 401 refresh +
  retry. Preconditions: authenticated session; server returns 401 once, then
  `POST /ui/session/refresh` 200, then add succeeds on replay. Steps:
  `setBookmarked(postId,true)`. Expected: exactly one refresh call, original
  request replayed once, final success. Sub-case: refresh fails -> toggle reverts
  and user treated as logged-out (FR-6). Traces: AC-1, AC-6.
- **TC-AND-176-08** — Type: unit (JVM). Target: `FeedViewModel.onToggleBookmark`
  serialization. Preconditions: coroutine test dispatcher; fake repo with
  controllable delay. Steps: fire toggle true then false then true rapidly for the
  same postId. Expected: prior in-flight jobs cancelled; only the last intent
  (`true`) commits; final state matches last tap (last-write-wins). Traces: AC-1.
- **TC-AND-176-09** — Type: unit (JVM). Target: `PostShare` + share-payload safety.
  Steps: `PostShare.urlFor(postId)` and `subjectFor(model)`. Expected: URL equals
  `https://app.testlogon.com/posts/{postId}` (path `/posts/`, not `/p/`); asserts
  URL/subject contain NO cookie, session token, `ui_csrf`, CSRF value, bearer, or
  user id. Traces: AC-5 (security), AC-8.
- **TC-AND-176-10** — Type: integration/Robolectric (JVM). Target: `ShareLauncher`.
  Preconditions: Robolectric context. Steps: call `share(context, ShareContent)`.
  Expected: a started activity is an `ACTION_SEND` chooser, inner intent
  `type=="text/plain"`, `EXTRA_TEXT==url`, `EXTRA_SUBJECT==subject` when present
  (`ShadowApplication.getNextStartedActivity`). Traces: AC-5, AC-8.
- **TC-AND-176-11** — Type: Compose-UI (emu35). Target: `BookmarkToggle` /
  `PostActionRow`. Steps: render unsaved; tap; render saved; tap share. Expected:
  icon goes outline->filled on tap and invokes `onCheckedChange(true)`;
  `contentDescription` switches "Add bookmark"->"Remove bookmark"; share click
  invokes `onShare`. Traces: AC-1, AC-5.
- **TC-AND-176-12** — Type: Compose-UI/accessibility (emu35). Target:
  `BookmarkToggle`, share button. Steps: assert semantics. Expected: toggle exposes
  Switch/Toggleable role with checked state announced to TalkBack; both controls
  >= 48dp touch targets; share `contentDescription=="Share post"`; no hardcoded
  literals (all from `strings.xml`). Traces: AC-7.
- **TC-AND-176-13** — Type: Compose-UI (emu35). Target: logged-out gating. Steps:
  render `PostActionRow` with `enabled=false` (unauthenticated). Expected: bookmark
  toggle disabled / no-op (no `onCheckedChange`); share button still enabled and
  invokes `onShare` with a valid URL. Traces: AC-6.
- **TC-AND-176-14** — Type: instrumented/e2e (emu35). Target: cache-driven
  persistence. Steps: save a post; scroll it off and back; trigger configuration
  change (rotation); kill + relaunch process. Expected: the post shows the filled
  icon in all three cases (state sourced from Room, not transient view state).
  Traces: AC-2, AC-8.
- **TC-AND-176-15** — Type: instrumented/e2e (emu35). Target: offline toggle path.
  Preconditions: airplane mode / no connectivity (or flaky-dev-host simulated
  failure). Steps: tap bookmark. Expected (default policy): optimistic flip then
  revert with an offline/failed snackbar carrying a working Retry; Retry re-invokes
  the toggle. Traces: AC-3.
- **TC-AND-176-16** — Type: manual/instrumented, **MUST run on physical device A15**.
  Target: real OS share chooser. Rationale: the system Sharesheet, installed share
  targets, and `ActivityNotFoundException` fallback behave differently on a real
  device than the emulator's sparse app set; also validates arm64/API-34. Steps:
  tap share on a feed post; pick a target (e.g. messaging/email); separately,
  uninstall/disable share targets to exercise the no-target path. Expected: chooser
  appears with the post URL + subject; on no target, the clipboard-copy fallback
  fires with the `feed_share_no_target` snackbar; shared text contains no auth
  material. Traces: AC-5.

### Coverage matrix

| AC | Covered by |
|----|------------|
| AC-1 (save toggles + persists) | TC-01, TC-02, TC-04, TC-07, TC-08, TC-11 |
| AC-2 (persist/recycle/process-death) | TC-14 |
| AC-3 (failure revert + retry) | TC-03, TC-06, TC-15 |
| AC-4 (409/404 idempotent) | TC-05 |
| AC-5 (share opens sheet, no auth leak) | TC-09, TC-10, TC-11, TC-16 |
| AC-6 (logged-out gating) | TC-07, TC-13 |
| AC-7 (accessibility) | TC-12 |
| AC-8 (tested: repo/VM/Compose/Robolectric) | TC-09, TC-10, TC-14 (plus TC-01..08, 11) |
