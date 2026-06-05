---
id: AND-174
title: Comments
milestone: M4
epic: E24
priority: P1
size: L
status: draft
depends_on: [AND-100]
blocks: []
---

# AND-174 — Comments

## 1. Overview & Goal

Add a comments surface to the post detail screen for the TestLogon Android app:
a Paging 3 backed comment list, a composer to **add** a top-level comment, and
**replies** to existing comments where the backend supports threading. The list
paginates from the FastAPI backend, a posted comment **appears immediately**
(optimistic insert) and is reconciled against the server response, and the
new comment count is reflected on the post.

This ticket owns the `feature-comments` surface that is hosted by AND-100's
post detail screen: the `CommentsApi` consumption, `CommentsRepository`,
`CommentsPagingSource`, `CommentsViewModel`, and the Compose UI for the list +
composer + (conditional) reply affordance. It does **not** own the post body /
media rendering (AND-100), nor the like/unlike interaction (AND-173), nor the
report/moderation flow (separate ticket).

Success means: from a post detail screen a signed-in user sees existing comments
load page-by-page, types and posts a comment that appears at the top of the list
without a manual refresh, can reply to a comment when threading is available,
and can scroll to load older comments. Failures (the unreliable dev host) surface
retriable inline states and the optimistic comment is rolled back or marked
"failed — retry" on a post error.

## 2. Context & References

- **Module:** `feature-comments` (new), depending on `core-network`,
  `core-model`, `core-data`, `core-ui`, `core-testing`. Namespace
  `com.testlogon.android.feature.comments`.
- **Host (AND-100):** the post detail screen renders the post and then embeds the
  comments section. AND-100 supplies the `postId` and a deep-link entry point;
  this ticket plugs `CommentsSection(postId)` beneath the post body.
- **Adjacent (E24):** AND-173 (like/unlike, optimistic) establishes the optimistic
  update + reconcile pattern reused here; AND-176 (share/bookmark) and AND-175
  (hide/not-interested) are sibling interactions and do not depend on this ticket.
- **Auth:** comments are a cookie-authenticated surface. All requests ride the
  persistent cookie jar + `X-CSRF-Token` header from the session stack (AND-011,
  AND-012, AND-027). Mutations (POST/DELETE) require the CSRF header. On `401`,
  the shared OkHttp authenticator performs a single `POST /ui/session/refresh`
  then retries once; this code must treat a persisting `401` as terminal.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000`
  (plaintext HTTP, unreliable; design for ~20s timeouts, bounded backoff for
  idempotent GETs only). OpenAPI at `/openapi.json`. Web reference:
  `frontend/src/api/endpoints/comments.ts` (or `postComments.ts`), shared types
  in `frontend/src/api/types.ts`. **Exact paths/params and the existence of
  reply threading MUST be confirmed against `/openapi.json` and the web app
  during implementation** — see §13 OQ-1/OQ-2.
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Paging 3 (`paging-runtime` +
  `paging-compose`), Hilt (KSP), Coroutines/Flow, Retrofit 2.11 / OkHttp 4.12 /
  Moshi 1.15. minSdk 24, compile/target 35, JDK 17.

## 3. Functional Requirements

FR-1. **Comment list.** The comments section loads the post's comments
page-by-page (newest-first by default). A footer spinner shows while
`loadState.append is LoadState.Loading`; older comments append on scroll.

FR-2. **Initial load / empty.** While the first page loads on an empty list,
show an inline loading row. When refresh succeeds with zero comments, show an
empty state ("No comments yet — be the first").

FR-3. **Add comment.** A composer (multiline `TextField` + Send button) posts a
top-level comment. Send is disabled while the trimmed text is empty or a post is
in flight. On send the comment is **optimistically inserted** at the top of the
list and the input clears.

FR-4. **Optimistic reconcile.** When the server returns the created comment, the
optimistic placeholder is replaced by the server entity (real id, server
timestamp). On failure the placeholder is marked **failed** with an inline
**Retry** / **Discard** affordance; the list is never silently desynced.

FR-5. **Replies (conditional).** If the backend exposes reply support
(`parent_id` / a replies endpoint), each comment shows a **Reply** action that
opens the composer in reply mode (parent context shown). Replies render as a
nested/indented thread (one level) under the parent. If the backend does not
support replies, the Reply affordance is hidden and this requirement is
satisfied as N/A (gated by a single `repliesSupported` capability flag).

FR-6. **Reply paging.** Where a comment has more replies than the inlined preview
count, a "View N more replies" control loads additional replies for that thread
(a secondary paged/limited fetch). One level of nesting only.

FR-7. **Comment count.** Posting a top-level comment increments the post's
displayed comment count (exposed to AND-100 host via a callback/shared state);
posting a reply increments the parent's reply count.

FR-8. **Delete own comment (if supported).** If the backend allows it, the
author may delete their own comment via an overflow action with a confirm
dialog; on success the row is removed (optimistically) and reconciled.

FR-9. **Refresh.** Pull-to-refresh (or a refresh action) re-loads from page one;
in-flight optimistic comments are preserved across refresh until reconciled.

FR-10. **State preservation.** Scroll position, the `PagingData` stream, and
composer draft survive configuration change and in-session back navigation
(`cachedIn(viewModelScope)` + `rememberSaveable` draft).

## 4. Technical Design

### 4.1 Layering

```
CommentsSection (Composable)          feature-comments/ui   (embedded by AND-100)
  -> CommentsViewModel (Hilt)         feature-comments/ui
       -> CommentsRepository          core-data / feature-comments/data
            -> CommentsPagingSource   feature-comments/data
            -> CommentsApi (Retrofit) core-network
```

### 4.2 Model (core-model)

```kotlin
data class Comment(
    val id: String,
    val postId: String,
    val parentId: String?,            // null => top-level
    val author: CommentAuthor,
    val body: String,
    val createdAt: Instant,
    val replyCount: Int,
    val canDelete: Boolean,           // server-asserted permission
    val pending: Boolean = false,     // optimistic, not yet reconciled
    val failed: Boolean = false,      // post failed; show Retry/Discard
    val localKey: String = id,        // stable diff key; uuid for optimistic
)

data class CommentAuthor(
    val id: String,
    val displayName: String,
    val avatarUrl: String?,
)
```

### 4.3 PagingSource

Cursor-paginated, newest-first, forward-only (older on append).

```kotlin
class CommentsPagingSource(
    private val repository: CommentsRepository,
    private val postId: String,
    private val parentId: String?,    // null => top-level list; set => replies
) : PagingSource<String, Comment>() {

    override suspend fun load(
        params: LoadParams<String>,
    ): LoadResult<String, Comment> = when (
        val result = repository.getComments(
            postId = postId,
            parentId = parentId,
            cursor = params.key,        // null => first page
            limit = params.loadSize,
        )
    ) {
        is ApiResult.Success -> LoadResult.Page(
            data = result.data.items,
            prevKey = null,
            nextKey = result.data.nextCursor,
        )
        is ApiResult.Failure -> LoadResult.Error(result.toThrowable())
    }

    override fun getRefreshKey(state: PagingState<String, Comment>): String? = null
}
```

### 4.4 Repository

```kotlin
interface CommentsRepository {
    suspend fun getComments(
        postId: String,
        parentId: String?,
        cursor: String?,
        limit: Int,
    ): ApiResult<CommentPage>

    suspend fun addComment(
        postId: String,
        body: String,
        parentId: String?,            // null => top-level, set => reply
    ): ApiResult<Comment>

    suspend fun deleteComment(commentId: String): ApiResult<Unit>

    val repliesSupported: Boolean      // capability, derived once from OpenAPI/config
}

data class CommentPage(val items: List<Comment>, val nextCursor: String?)
```

`ApiResult.toThrowable()` (core-network) maps a typed failure into a
`CommentException(message, isRetryable)`. The repository maps DTOs (§5) to
domain `Comment`. Mutations are **not** retried automatically (non-idempotent);
GET pages benefit from the shared idempotent-GET backoff interceptor.

### 4.5 ViewModel

Paged list is exposed as `PagingData`; optimistic + failed comments are held in a
side `StateFlow` and merged into the rendered stream so the differ stays stable.

```kotlin
@HiltViewModel
class CommentsViewModel @Inject constructor(
    private val repository: CommentsRepository,
    savedState: SavedStateHandle,
) : ViewModel() {

    private val postId: String = checkNotNull(savedState["postId"])

    val repliesSupported: Boolean get() = repository.repliesSupported

    // Locally-originated comments (optimistic/failed) merged ahead of the server page.
    private val _pending = MutableStateFlow<List<Comment>>(emptyList())

    private val pager: Flow<PagingData<Comment>> = Pager(
        config = PagingConfig(
            pageSize = 20,
            initialLoadSize = 20,
            prefetchDistance = 5,
            enablePlaceholders = false,
        ),
        pagingSourceFactory = { CommentsPagingSource(repository, postId, parentId = null) },
    ).flow.cachedIn(viewModelScope)

    val comments: Flow<PagingData<Comment>> =
        combine(pager, _pending) { page, pending ->
            // Prepend not-yet-reconciled local comments; drop ones now present server-side.
            pending.foldRight(page) { c, acc -> acc.insertHeaderItem(item = c) }
        }

    val composer: StateFlow<ComposerState> = MutableStateFlow(ComposerState())

    fun onBodyChange(text: String)
    fun startReply(parent: Comment)        // no-op if !repliesSupported
    fun cancelReply()
    fun send()                             // posts top-level or reply per composer.replyTo
    fun retry(localKey: String)            // re-post a failed optimistic comment
    fun discard(localKey: String)
    fun delete(comment: Comment)

    data class ComposerState(
        val text: String = "",
        val replyTo: Comment? = null,
        val sending: Boolean = false,
        val canSend: Boolean = false,
    )
}
```

`send()` flow: build an optimistic `Comment(id = uuid, pending = true,
localKey = uuid, body = trimmed, parentId = replyTo?.id)`, push into `_pending`,
clear composer text, call `repository.addComment(...)`. On `Success`, remove the
optimistic entry from `_pending` and `refresh()` the relevant `LazyPagingItems`
(or surgically replace) so the server entity lands in its canonical position; on
`Failure`, set `pending = false, failed = true` on that `_pending` entry.

### 4.6 Compose host

```kotlin
@Composable
fun CommentsSection(
    postId: String,
    viewModel: CommentsViewModel = hiltViewModel(),
    onCommentCountChanged: (delta: Int) -> Unit,   // notifies AND-100 host
    modifier: Modifier = Modifier,
)

@Composable private fun CommentRow(
    comment: Comment,
    repliesSupported: Boolean,
    onReply: (Comment) -> Unit,
    onRetry: (String) -> Unit,
    onDiscard: (String) -> Unit,
    onDelete: (Comment) -> Unit,
    onViewReplies: (Comment) -> Unit,
)

@Composable private fun CommentComposer(
    state: CommentsViewModel.ComposerState,
    onBodyChange: (String) -> Unit,
    onSend: () -> Unit,
    onCancelReply: () -> Unit,
)

@Composable private fun CommentsEmpty()
@Composable private fun CommentsFooterLoading()
@Composable private fun CommentsFooterError(message: String, onRetry: () -> Unit)
```

`CommentsSection` collects `comments.collectAsLazyPagingItems()`, renders rows
keyed by `items.itemKey { it.localKey }`, an append footer that switches on
`loadState.append` (Loading/Error), and a sticky/bottom `CommentComposer`. The
composer pins to the bottom and respects IME insets (`imePadding()`). Reply mode
shows a "Replying to @name" chip with a cancel (X). Pending rows render dimmed
with a small progress glyph; failed rows show inline Retry / Discard.

### 4.7 Hilt wiring

`CommentsRepository` impl is bound in a `@Module @InstallIn(SingletonComponent)`;
`CommentsApi` is provided from the shared Retrofit instance (core-network).
`CommentsPagingSource` is constructed by the `pagingSourceFactory` lambda, not
injected, so its lifetime matches each `Pager` invalidation.

## 5. API Contract

Consumes the comments endpoints; **authoritative shapes/paths must be confirmed
against `/openapi.json` and `frontend/src/api/endpoints/comments.ts`.** Assumed
contract below; deviations are contained to the repository mapping layer.

**List (GET, idempotent):**

```
GET /ui/posts/{post_id}/comments?limit=20
GET /ui/posts/{post_id}/comments?limit=20&cursor=<opaque>
GET /ui/comments/{comment_id}/replies?limit=20&cursor=<opaque>   # if threaded
Cookie: <session cookies>
X-CSRF-Token: <ui_csrf value>
```

**Response 200** (`CommentPageDto`):

```json
{
  "items": [
    {
      "id": "cmt_01HZ...",
      "post_id": "post_01HZ...",
      "parent_id": null,
      "author": { "id": "usr_123", "display_name": "Jane", "avatar_url": "https://..." },
      "body": "great post",
      "created_at": "2026-06-05T12:00:00Z",
      "reply_count": 2,
      "can_delete": true
    }
  ],
  "next_cursor": "eyJvZmZzZXQiOjIwfQ==",
  "has_more": true
}
```

**Add (POST, non-idempotent, requires CSRF):**

```
POST /ui/posts/{post_id}/comments
Content-Type: application/json
X-CSRF-Token: <ui_csrf value>

{ "body": "great post", "parent_id": null }
```

**Response 201** — single `CommentDto` (same shape as an `items[]` element).

**Delete (DELETE, requires CSRF, if supported):**

```
DELETE /ui/comments/{comment_id}
X-CSRF-Token: <ui_csrf value>
```

`204 No Content` on success.

- `next_cursor == null` (or `has_more == false`) => `nextKey == null` =>
  `endOfPaginationReached`.
- **Errors.** FastAPI `detail` may be `string | [{msg}] | {code,...}`; mapping is
  owned by core-network (AND-015). Relevant here: `401` => single
  refresh-then-retry (then terminal); `403` (CSRF/permission) => non-retryable
  user-facing error; `404` (post/comment gone) => non-retryable; `422`
  (validation, e.g. empty/too-long body) => field error on the composer; `5xx` /
  timeout => retryable.

## 6. Data & State Management

- **Source of truth (list):** `Flow<PagingData<Comment>>` from `Pager`,
  `cachedIn(viewModelScope)`, merged with the optimistic `_pending` list via
  `insertHeaderItem`. Re-collection on recomposition/navigation does not refetch.
- **Optimistic store:** `MutableStateFlow<List<Comment>>` for not-yet-reconciled
  comments (pending + failed). Reconciliation removes the entry on success and
  flips `failed = true` on error.
- **Composer:** `StateFlow<ComposerState>`; draft text persisted via
  `rememberSaveable` (or `SavedStateHandle`) so it survives config change.
- **Keys:** `items.itemKey { it.localKey }` — optimistic comments use a generated
  UUID so they keep stable identity until replaced by the server `id`.
- **Comment count:** propagated to the AND-100 host through
  `onCommentCountChanged(delta)`; not persisted by this ticket.
- **Caching:** online-only. No Room `RemoteMediator` here; offline comment cache
  is out of scope (deferrable to E24 follow-up if required).
- **Pagination params:** `cursor: String?`, `limit = pageSize = 20`,
  forward-only (`prevKey` always null); replies use a separate
  `CommentsPagingSource(parentId = <id>)` instance per expanded thread.

## 7. Error Handling & Resilience

- **Timeouts:** OkHttp call timeout ~20s (core-network). Surfaces as
  `LoadResult.Error` (list) or `ApiResult.Failure` (mutation).
- **Idempotent GET retry:** comment list/replies GETs use the shared bounded
  backoff interceptor for idempotent GETs. Paging `retry()` is wired to footer
  and full-section error controls.
- **Mutations not auto-retried:** add/delete are non-idempotent — no network-layer
  retry; retry is **user-initiated** only (avoids duplicate comments on the flaky
  host). To further guard duplicates, send a client `Idempotency-Key` header if
  the backend honors one (confirm; see §13 OQ-3).
- **Optimistic failure:** failed comment stays visible, flagged, with Retry /
  Discard. Retry re-issues `addComment` with the same body; Discard removes it.
- **Append failure:** keep loaded comments; show footer error + Retry. Never clear
  the list on append failure.
- **Refresh failure:** with content present, preserve items + transient error;
  on an empty list show an inline retriable error (not the empty state).
- **401 loop guard:** rely on the interceptor's single-refresh contract; a
  persisting `401` is terminal (do not loop against the dev host).
- **422 validation:** map to a composer-level inline error (e.g. "Comment is too
  long"); do not insert an optimistic row for an invalid body.
- **Empty vs error:** empty state only when refresh is `NotLoading`,
  `endOfPaginationReached`, `itemCount == 0`, and `_pending` is empty.

## 8. Security & Privacy

- All requests are cookie-authenticated over the shared persistent cookie jar;
  mutations send the `X-CSRF-Token` header echoed from the `ui_csrf` cookie. This
  ticket adds no new auth handling and must not bypass the shared OkHttp client.
- **CSRF on mutations is mandatory** — POST/DELETE without the header will (and
  should) be rejected; surfaced as a non-retryable `403`.
- **Permissions are server-asserted:** delete is only offered when
  `can_delete == true`; the client never assumes deletability and always honors a
  server `403`.
- No session cookies, CSRF token, or comment bodies are logged (see §10).
- Dev backend is **plaintext HTTP** (dev-only posture); production must be HTTPS,
  with `usesCleartextTraffic` gated to debug/dev flavors (owned by build/network
  tickets).
- **User-generated content:** comment bodies are rendered as plain text (no HTML/
  markdown interpretation) to avoid injection/spoofing; URLs are not
  auto-linkified in this ticket. No PII persisted to disk (no Room mediator).

## 9. Accessibility & i18n

- All user-facing strings are `stringResource`-backed in
  `feature-comments/res/values/strings.xml`; no hardcoded literals. Keys:
  `comments_empty`, `comments_loading`, `comments_error_generic`,
  `comments_retry`, `comments_send`, `comments_input_hint`,
  `comments_reply_action`, `comments_replying_to`, `comments_view_more_replies`,
  `comments_delete`, `comments_delete_confirm`, `comments_pending`,
  `comments_failed`, `comments_discard`.
- Send / Reply / Retry / Delete controls have ≥48x48dp touch targets and content
  descriptions. The composer `TextField` has a label/hint and announces character
  limit errors via `semantics { error(...) }`.
- Pending rows expose a state description ("Sending"); failed rows ("Failed to
  post — double tap to retry").
- Reply nesting is conveyed to TalkBack via semantics (e.g. "Reply to @name"),
  not by indentation alone.
- RTL: layout uses start/end padding and `Modifier` directional insets; nesting
  indent mirrors in RTL. IME handling via `imePadding()`.
- Timestamps localized via `DateUtils.getRelativeTimeSpanString` / `java.time`
  formatting with the device locale.

## 10. Telemetry & Logging

- Structured debug logs (Timber, debug builds only):
  `comments_list_load{stage,success,count,durationMs}`,
  `comments_post_start{isReply}`, `comments_post_result{success,httpStatus}`,
  `comments_delete_result{success}`, `comments_load_error{type,httpStatus}`.
  **No comment bodies, author identifiers, cookies, CSRF tokens, or cursors** are
  logged (cursors logged as a presence boolean only).
- Analytics (if the core analytics facade is available): `comment_added`,
  `comment_reply_added`, `comment_post_failed{errorType}`, `comment_deleted`,
  `comments_viewed`, `comments_load_failed{stage,errorType}`. Counts/flags only;
  no content.
- Load-state transitions are observable via the Paging `LoadState` API for tests;
  no bespoke telemetry surface is required for acceptance.

## 11. Testing Strategy

**Unit — `CommentsPagingSource` (JUnit + coroutines-test/Turbine):**
- `load(key == null)` success returns `LoadResult.Page` with correct `data`,
  `prevKey == null`, `nextKey == next_cursor`.
- `next_cursor == null` => `nextKey == null` (end of pagination).
- `ApiResult.Failure` => `LoadResult.Error` with a retryable `CommentException`.
- `getRefreshKey` returns null.

**Unit — `CommentsViewModel` optimistic logic:**
- `send()` inserts a `pending` comment at the head and clears the composer.
- On `addComment` success, the pending entry is removed and the server comment is
  reflected (via refresh/replace).
- On `addComment` failure, the entry flips to `failed`; `retry(localKey)`
  re-issues and `discard(localKey)` removes it.
- `startReply`/`cancelReply` toggle `replyTo`; `send()` in reply mode sets
  `parent_id`. When `repliesSupported == false`, `startReply` is a no-op.
- `canSend` is false for blank/whitespace and while `sending`.
- `onCommentCountChanged` deltas: +1 on top-level success, parent reply-count
  increment on reply success, -1 on delete success.

**Integration — repository + MockWebServer (core-network rig, AND-046):**
- Two-page list sequence (`next_cursor` then null) drives append then
  `endOfPaginationReached`.
- `POST` returns `201` with the created comment; mapping to domain `Comment` is
  asserted.
- `POST` returns `422` => field error; `403` => non-retryable; `5xx`/timeout =>
  retryable failure; no auto-retry of the POST is performed.
- `401` then post-refresh `200` succeeds for a GET; persistent `401` => terminal.
- `DELETE` `204` success; `403` honored.

**Paging differ test:** `PagingData.asSnapshot { }` for the two-page sequence
equals concatenated items; with one optimistic header item present, the snapshot
includes it at index 0.

**Compose UI (`createComposeRule`, AND-046 fakes):**
- Empty result shows empty state (not error).
- Typing enables Send; tapping Send shows the optimistic row immediately and
  clears input.
- Simulated post failure shows the failed row with Retry/Discard; Retry re-posts.
- Append-error footer shows Retry and calls `retry()`.
- Reply action (when supported) opens reply mode with the "Replying to" chip;
  hidden when `repliesSupported == false`.

**Manual / live backend (acceptance):** against `http://18.222.237.167:8000`,
signed in, on a post detail screen: existing comments load and paginate, a posted
comment appears at the top and persists across refresh, a reply posts under its
parent (if supported).

## 12. Dependencies & Sequencing

- **Hard dependency — AND-100 (Post detail screen):** provides the host screen,
  `postId`, and deep-link entry where `CommentsSection(postId)` is embedded; must
  land first.
- **Transitive:** core-network session stack — persistent cookie jar (AND-011),
  CSRF interceptor (AND-012), 401-refresh authenticator (AND-013), `ApiResult` +
  detail mapping (AND-015, AND-018), idempotent-GET backoff (AND-016) — all in
  place by M1. core-ui state composables (AND-021) and MockWebServer harness
  (AND-046).
- **Pattern reuse — AND-173 (like/unlike):** the optimistic-update + reconcile
  approach mirrors AND-173; align on the shared helper if one exists.
- **Blocks:** none in the current backlog.
- **Sequencing:** AND-100 -> **AND-174**. Reply support (FR-5/FR-6) is gated on a
  backend capability confirmation (§13) and may ship behind the
  `repliesSupported` flag without blocking the top-level comment feature.

## 13. Risks & Open Questions

- **OQ-1 (paths/params):** exact comment endpoint paths and pagination param
  names (`cursor` vs `after`, `limit` vs `page_size`) are unconfirmed — verify
  against `/openapi.json` and `frontend/src/api/endpoints/comments.ts`. This spec
  assumes `GET /ui/posts/{post_id}/comments?limit=&cursor=` and
  `POST /ui/posts/{post_id}/comments`.
- **OQ-2 (reply threading):** whether the backend supports replies at all, and if
  so via `parent_id` on the same collection vs a dedicated
  `/comments/{id}/replies` endpoint, and how many nesting levels. The
  `repliesSupported` capability flag isolates this; default assumption is
  single-level replies. *(Source scope: "+ replies if supported".)*
- **OQ-3 (idempotency):** does add-comment accept an `Idempotency-Key` header to
  dedupe retries against the flaky host? If not, user-initiated retry risks a
  duplicate; mitigate by disabling Retry while a re-post is in flight.
- **OQ-4 (ordering):** newest-first vs oldest-first default, and where a new
  comment should appear; this spec assumes newest-first with new comments at the
  top. Confirm with web reference.
- **OQ-5 (count source):** whether the post's comment count is authoritative from
  the post DTO (AND-100) or must be derived; the `onCommentCountChanged` delta
  contract assumes the host owns the displayed count.
- **Risk-1 (flaky dev host):** ~20s timeouts slow manual acceptance and may cause
  intermittent optimistic-post failures; mitigated by clear failed-row UX and
  user-initiated retry. No unbounded Paging-level retries.
- **Risk-2 (reconcile dupes):** if the server comment arrives via refresh while
  the optimistic header is still present, the `localKey`/server-`id` swap must
  drop the optimistic entry to avoid a visible duplicate; covered by ViewModel
  reconcile tests.

## 14. Acceptance Criteria

AC-1. On a post detail screen, a signed-in user sees existing comments load and
**paginate** (append on scroll) until `next_cursor` is null. *(maps to source
Acceptance: "paginates")*

AC-2. Posting a comment makes it **appear** at the top of the list immediately
(optimistic) and it **persists** after a pull-to-refresh (server-reconciled).
*(maps to: "Comment posts + appears")*

AC-3. A failed post shows the comment as failed with **Retry** and **Discard**;
Retry re-posts successfully and Discard removes it. The list never silently
desyncs.

AC-4. Where the backend supports replies, a **Reply** action posts a reply under
its parent and increments the parent's reply count; where unsupported, the Reply
affordance is absent (gated by `repliesSupported`). *(maps to: "+ replies if
supported")*

AC-5. A successful empty post shows the empty state, distinct from an error
state; an append failure shows a retriable footer without clearing loaded items.

AC-6. Posting a top-level comment increments the post's displayed comment count
via `onCommentCountChanged(+1)`; deleting (if supported) decrements it.

AC-7. Composer draft, scroll position, and loaded pages survive configuration
change and in-session back navigation (no refetch on return).

AC-8. Unit tests (`CommentsPagingSource`, ViewModel optimistic logic), an
`asSnapshot` differ test, MockWebServer integration (list/append/POST/401-
refresh/422/403/5xx), and Compose tests (empty/post/failed-retry/append-error/
reply-mode) all pass.

## 15. Definition of Done

- `feature-comments` module created with `CommentsApi` consumption,
  `CommentsRepository` (+impl), `CommentsPagingSource`, `CommentsViewModel`, and
  `CommentsSection` + `CommentRow`/`CommentComposer`/state composables; package
  `com.testlogon.android.feature.comments`.
- `CommentsSection(postId, onCommentCountChanged)` embedded in AND-100's post
  detail screen; no DTO/Retrofit duplication of the shared session stack.
- All FR-1..FR-10 implemented; AC-1..AC-8 verified. Reply support shipped behind
  `repliesSupported` (active if the backend supports it, otherwise cleanly hidden).
- Optimistic add + reconcile + failed-retry/discard implemented; mutations send
  CSRF and are not auto-retried.
- All user-facing strings externalized; a11y semantics, touch targets, and IME
  handling in place.
- No sensitive data logged; uses the shared cookie/CSRF OkHttp client only.
- Unit + integration + Compose tests added and green in CI;
  `./gradlew :feature-comments:test :feature-comments:connectedDebugAndroidTest`
  (or instrumented equivalent) passes.
- Lint/detekt clean; merged to `android-port` with a passing review against this
  spec; OQ-1..OQ-5 resolved (or explicitly deferred with the capability flag) in
  the PR description.
