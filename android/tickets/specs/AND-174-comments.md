---
id: AND-174
title: Comments
milestone: M4
epic: E24
priority: P1
size: L
status: reviewed
reviewed_on: 2026-06-06
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
- **Auth:** comments ride the shared session transport. **Corrected against
  `src/api/client.ts`:** the web client sends BOTH an `Authorization: Bearer
  <accessToken>` header (from the auth store) AND session cookies
  (`credentials: "include"`), plus `X-CSRF-Token` echoed from the `ui_csrf`
  cookie on every request, plus an optional `X-IMPERSONATION-TOKEN`. The original
  "cookie-authenticated only" framing was incomplete — Android must replicate the
  Bearer + cookie + CSRF combination via the shared OkHttp stack (AND-011,
  AND-012, AND-027). The CSRF header is present on all requests (not only
  mutations) in the web client, though it is only enforced server-side on
  mutations. On `401` (when authenticated), the shared OkHttp authenticator
  performs a single `POST /ui/session/refresh` then retries once
  (**verified — `src/api/client.ts: refreshSession`/`api`**); a persisting `401`
  is terminal and triggers logout.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000`
  (plaintext HTTP, unreliable; design for ~20s timeouts, bounded backoff for
  idempotent GETs only). OpenAPI at `/openapi.json`. **Corrected web reference:**
  comment endpoints live in `frontend/src/api/endpoints/newsfeed.ts` (not a
  dedicated `comments.ts`/`postComments.ts`); the comment DTO is `FeedComment` in
  `frontend/src/api/types.ts`; the rendered UI is
  `frontend/src/pages/feed/CommentsThread.tsx`. Paths/params and reply behavior
  have now been verified against the OpenAPI index and the web source — see §16
  for the exact citations and corrections (OQ-1/OQ-2 in §13 are now resolved).
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

FR-5. **Replies (conditional).** **Verified caveat:** the backend *data model*
supports a parent pointer — `parent_comment_id` exists on both
`CreateCommentRequest` and `CommentResponse` (verified schemas) — so a reply CAN
be created and is returned with its parent id. **However, there is NO dedicated
replies endpoint and the web reference renders comments FLAT** (it
`flatMap`s all pages into one list keyed by `comment_id` and exposes no Reply
affordance — see `CommentsThread.tsx`). Therefore: gate threaded reply UI behind
the `repliesSupported` capability flag, default **OFF** to match web behavior. If
turned on, replies post with `parent_comment_id` set and render as a single-level
indented thread; the client must group by `parent_comment_id` itself from the
same flat collection (no server-side thread grouping exists). When off, the Reply
affordance is hidden and FR-5 is satisfied as N/A.

FR-6. **Reply paging.** **Corrected:** there is **no separate replies/`View N
more replies` endpoint** — replies arrive interleaved in the same
`/posts/{post_id}/comments` page stream and are distinguished only by
`parent_comment_id`. A per-thread secondary fetch is **not possible** against
this backend. If reply UI is enabled, "more replies" must be satisfied by loading
more of the flat list, not a thread-scoped fetch. This sub-requirement is
otherwise **deferred** (no backend support).

FR-7. **Comment count.** Posting a top-level comment increments the post's
displayed comment count (exposed to AND-100 host via a callback/shared state).
**Corrected:** there is **no `reply_count` field** on the comment DTO, so a
parent's reply count cannot be incremented from server data — if reply UI is
enabled, any reply tally must be computed client-side from grouped
`parent_comment_id` values. The web app invalidates both `["comments", postId]`
and `["feed"]` queries on post/delete so the post-level count refreshes from the
post DTO; Android's `onCommentCountChanged(delta)` is the optimistic equivalent
until the host refetches the post.

FR-8. **Delete own comment.** **Corrected (now confirmed supported):** delete is
available via `DELETE /posts/{post_id}/comments/{comment_id}`. The author may
delete their own comment via an overflow action with a confirm dialog. **There is
no server `can_delete` flag** — eligibility is derived client-side as
`authorId == currentUserId` (web: `isOwn`). The dialog copy mirrors web ("This
comment will be permanently deleted."). On success the row is removed; the web
shows a `deleted: true` tombstone ("Comment deleted") for already-deleted rows
that arrive in a page, which the Android list should also handle.

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

> **Corrected to match the real `CommentResponse`/`FeedComment` wire shape**
> (verified `GET/POST /posts/{post_id}/comments`, schema
> `components.schemas.CommentResponse`, and `src/api/types.ts: FeedComment`).
> Differences from the original draft: the server field is `comment_id` (not
> `id`); the parent pointer is `parent_comment_id` (not `parent_id`); there is
> **no nested `author` object** — only a flat `author_id: String` (no
> `display_name`/`avatar_url` on the comment DTO); there is **no `reply_count`**
> and **no `can_delete`** field. Deletability is derived client-side from
> `author_id == currentUserId` (web does `isOwn = comment.author_id === userId`),
> not server-asserted. The DTO also carries `created_at`, optional `updated_at`
> (presence => "edited"), `deleted: Boolean`, `version`, `tip_total_cents`, and
> rich/markdown/gif/sticker body variants (out of scope for this ticket — render
> `body` as plain text; treat unknown `kind` gracefully).

```kotlin
data class Comment(
    val id: String,                   // maps from DTO `comment_id`
    val postId: String,               // `post_id`
    val parentId: String?,            // `parent_comment_id`; null => top-level
    val authorId: String,             // `author_id` (no nested author DTO exists)
    val body: String,                 // `body` (plain text rendering this ticket)
    val createdAt: Instant,           // `created_at`
    val updatedAt: Instant?,          // `updated_at`; non-null => show "(edited)"
    val deleted: Boolean = false,     // `deleted`; render "Comment deleted" tombstone
    val tipTotalCents: Int = 0,       // `tip_total_cents`
    val canDelete: Boolean = false,   // DERIVED: authorId == currentUserId (no server field)
    val pending: Boolean = false,     // optimistic, not yet reconciled (client-only)
    val failed: Boolean = false,      // post failed; show Retry/Discard (client-only)
    val localKey: String = id,        // stable diff key; uuid for optimistic
)
```

> Display name / avatar are **not** available from the comment DTO. If the UI
> needs them it must resolve `authorId` via a separate profile lookup (the web
> reference simply renders `author_id` initials and the id itself). Showing the
> raw `authorId` for the first cut is acceptable; richer author display is an
> open assumption (see §16) and may need a profile-batch endpoint owned elsewhere.

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

Consumes the comments endpoints. **The contract below has been verified against
the OpenAPI index and `src/api/endpoints/newsfeed.ts` / `src/api/types.ts`.** The
original draft contained several path/method/status/field errors; they are
corrected here and audited in §16. Deviations stay contained to the repository
mapping layer.

> **Path correction:** endpoints are **un-prefixed** `/posts/...` — there is **no
> `/ui/` prefix** on the comment routes, and there is **no `/ui/comments/...` or
> `/comments/{id}/replies` route**. (verified OpenAPI index lines 501-503.)

**List (GET, idempotent):**

```
GET /posts/{post_id}/comments
GET /posts/{post_id}/comments?cursor=<opaque>
GET /posts/{post_id}/comments?limit=20&cursor=<opaque>
Authorization: Bearer <accessToken>
Cookie: <session cookies>
X-CSRF-Token: <ui_csrf value>
```

> `op=list_comments_posts__post_id__comments_get`; query params `limit`, `cursor`
> are supported (verified). Note the web client only sends `cursor` (no `limit`),
> letting the server default the page size — Android may send `limit=20` since the
> param exists, but must not assume the server honors it; treat the returned
> `items.size` as authoritative, not the requested `limit`.

**Response 200** — `{ items: CommentResponse[]; next_cursor?: string }`. There is
**no `has_more` field** (the web type is `{ items: FeedComment[]; next_cursor?:
string }`); end-of-pagination is purely `next_cursor == null/absent`.

```json
{
  "items": [
    {
      "comment_id": "cmt_01HZ...",
      "post_id": "post_01HZ...",
      "parent_comment_id": null,
      "author_id": "usr_123",
      "body": "great post",
      "body_format": "plain",
      "created_at": "2026-06-05T12:00:00Z",
      "updated_at": null,
      "deleted": false,
      "version": 1,
      "tip_total_cents": 0
    }
  ],
  "next_cursor": "eyJvZmZzZXQiOjIwfQ=="
}
```

> Corrected fields: `comment_id` (not `id`); `parent_comment_id` (not
> `parent_id`); flat `author_id` (no nested `author`/`display_name`/`avatar_url`);
> **no `reply_count`**; **no `can_delete`**. `body` is nullable on the wire
> (`anyOf string|null`) — map null to empty string. Rich/markdown/gif/sticker
> fields exist but are out of scope (render `body` plain).

**Add (POST, non-idempotent, requires CSRF):**

```
POST /posts/{post_id}/comments
Content-Type: application/json
Authorization: Bearer <accessToken>
X-CSRF-Token: <ui_csrf value>

{ "body": "great post", "parent_comment_id": null }
```

> Request schema `CreateCommentRequest`; the reply field is **`parent_comment_id`**
> (not `parent_id`). Web sends `{ kind: "text", ...buildContentPayload(...) }`;
> for a plain comment Android may send just `{ "body": "...", "parent_comment_id":
> null }` (kind defaults to text). **Response is `200`, not `201`** —
> `resp=200:CommentResponse` (verified OpenAPI index line 502; the web mutation
> `createComment` returns `FeedComment`). Body of the response is a single
> `CommentResponse` (same shape as an `items[]` element).

**Delete (DELETE, requires CSRF):**

```
DELETE /posts/{post_id}/comments/{comment_id}
Authorization: Bearer <accessToken>
X-CSRF-Token: <ui_csrf value>
```

> **Corrected path and status:** the route is
> `DELETE /posts/{post_id}/comments/{comment_id}` (post-scoped, NOT
> `/ui/comments/{comment_id}`), and it returns **`200`**, not `204` (OpenAPI index
> line 503: `resp=200:`; the web `deleteComment` expects a `{ ok: boolean }` JSON
> body). Map a 200 with `{ok:true}` (or any 2xx) to `ApiResult.Success(Unit)`.

> **Edit (PATCH) also exists** (`PATCH /posts/{post_id}/comments/{comment_id}`,
> req `EditCommentRequest`, resp `200:CommentResponse`) — the web app exposes
> inline edit. It is **out of scope** for AND-174 (this ticket is list + add +
> delete + conditional reply) but is noted so the repository can grow an `edit`
> method later without a contract surprise.

- `next_cursor == null`/absent => `nextKey == null` => `endOfPaginationReached`.
- **Errors.** FastAPI `detail` may be `string | [{msg}] | {code,...}`; the web
  `normalizeErrorDetail` (in `src/api/client.ts`) handles all three shapes and
  also maps a `{code: ...}` object to friendly text — Android's core-network
  mapping (AND-015) should mirror this. **Schema note:** the comment routes only
  *declare* `200` and `422:HTTPValidationError` in OpenAPI; `401`/`403`/`404`/`5xx`
  are produced by shared middleware (not per-route schema) and are handled
  transport-wide by the client. Relevant mappings: `401` => single
  refresh-then-retry then terminal (verified `client.ts`); `403` (CSRF/permission;
  the client special-cases a `geo_blocked` code) => non-retryable user-facing
  error; `404` (post/comment gone) => non-retryable; `422` (validation, e.g.
  empty/too-long body) => field error on the composer; `5xx` / timeout / network
  (`ApiError(0)`) => retryable.

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
- `POST` returns `200` with the created comment (NOT 201); mapping to domain
  `Comment` is asserted.
- `POST` returns `422` => field error; `403` => non-retryable; `5xx`/timeout =>
  retryable failure; no auto-retry of the POST is performed.
- `401` then post-refresh `200` succeeds for a GET; persistent `401` => terminal.
- `DELETE` `200` (body `{ok:true}`) success (NOT 204); `403` honored.

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

- **OQ-1 (paths/params): RESOLVED.** Endpoints are `GET/POST
  /posts/{post_id}/comments` and `DELETE/PATCH
  /posts/{post_id}/comments/{comment_id}` with **no `/ui/` prefix**; pagination
  params are `limit` + `cursor` (verified OpenAPI index 501-503, `newsfeed.ts`).
  See §5 and §16.
- **OQ-2 (reply threading): RESOLVED (mostly negative).** The wire has a
  `parent_comment_id` field on request and response, but there is **no replies
  endpoint and no thread rendering in the web reference** (flat list, no Reply
  affordance, no `reply_count`). Ship threaded reply UI behind `repliesSupported`
  defaulting **OFF** to match web; if enabled, group single-level by
  `parent_comment_id` client-side. One remaining unknown is logged in §16 Open
  assumptions (round-trip persistence of `parent_comment_id`, not exercised by
  web). *(Source scope: "+ replies if supported".)*
- **OQ-3 (idempotency):** does add-comment accept an `Idempotency-Key` header to
  dedupe retries against the flaky host? If not, user-initiated retry risks a
  duplicate; mitigate by disabling Retry while a re-post is in flight.
- **OQ-4 (ordering): PARTIALLY RESOLVED.** The web reference does **not** sort or
  reverse client-side — it renders `pages.flatMap(p => p.items)` in server order
  and relies on `invalidateQueries` (refetch) after a post, so a new comment
  appears wherever the server places it on refetch, not necessarily at index 0.
  The server's default ordering is **not documented in OpenAPI** (still an
  assumption — see §16). Android's optimistic-top-insert is a deliberate UX
  divergence from web (see §16 Divergences); after reconcile/refresh the row
  settles into server order.
- **OQ-5 (count source): RESOLVED.** The post DTO (AND-100) owns the displayed
  count; the web invalidates the `["feed"]` query after post/delete so the count
  refreshes from the post. `onCommentCountChanged(delta)` is the optimistic stand-in
  until the host refetches. The comment DTO has no count field of its own.
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

AC-4. With `repliesSupported` enabled, a **Reply** action posts a reply with
`parent_comment_id` set and the reply renders grouped (single level) under its
parent; any reply tally is computed client-side (no server `reply_count` exists).
With the flag OFF (the default, matching web), the Reply affordance is absent and
the requirement is satisfied as N/A. *(maps to: "+ replies if supported")*

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

## 16. Citations & Assumption Audit

Each key technical claim, its VERDICT (Verified / Corrected / Unverified-assumption),
and the exact source pointer.

1. **List endpoint is `GET /posts/{post_id}/comments` with `limit`+`cursor`
   params.** VERDICT: Corrected (draft said `GET /ui/posts/{post_id}/comments`).
   SOURCE: OpenAPI `GET /posts/{post_id}/comments`
   (`op=list_comments_posts__post_id__comments_get`, params `post_id,limit,cursor`);
   `src/api/endpoints/newsfeed.ts: getComments`.
2. **Add endpoint is `POST /posts/{post_id}/comments`, request
   `CreateCommentRequest`, response `200:CommentResponse`.** VERDICT: Corrected
   (draft said `POST /ui/posts/...` and `201`). SOURCE: OpenAPI
   `POST /posts/{post_id}/comments`
   (`op=create_comment_posts__post_id__comments_post`,
   `req=CreateCommentRequest | resp=200:CommentResponse`);
   `src/api/endpoints/newsfeed.ts: createComment`.
3. **Delete endpoint is `DELETE /posts/{post_id}/comments/{comment_id}`,
   response `200` (body `{ok:true}`).** VERDICT: Corrected (draft said
   `DELETE /ui/comments/{comment_id}` returning `204`). SOURCE: OpenAPI
   `DELETE /posts/{post_id}/comments/{comment_id}`
   (`op=delete_comment_posts__post_id__comments__comment_id__delete | resp=200:`);
   `src/api/endpoints/newsfeed.ts: deleteComment` (returns `{ ok: boolean }`).
4. **No `/ui/` prefix and no dedicated replies endpoint
   (`/comments/{id}/replies`) exists.** VERDICT: Corrected. SOURCE: OpenAPI index
   lines 501-505 (only `/posts/{post_id}/comments[...]` routes; the only
   `/ui/.../comments/...` route is `moderate`, and `/ui/videos/{video_id}/comments`
   is a separate *video* comments feature, not post comments).
5. **Comment DTO field names are `comment_id`, `post_id`, `parent_comment_id`,
   `author_id`, `body`, `created_at`, `updated_at`, `deleted`, `version`,
   `tip_total_cents` (plus body/markdown/gif/sticker variants).** VERDICT:
   Corrected (draft used `id`, `parent_id`, nested `author{display_name,avatar_url}`).
   SOURCE: schema `components.schemas.CommentResponse`; `src/api/types.ts:
   FeedComment`.
6. **No `reply_count` field and no `can_delete` field on the comment DTO.**
   VERDICT: Corrected (draft modeled both). SOURCE: full property list of
   `components.schemas.CommentResponse` (no such keys); deletability in web is
   derived `isOwn = comment.author_id === userId`
   (`src/pages/feed/CommentsThread.tsx`).
7. **Reply create field is `parent_comment_id` (not `parent_id`).** VERDICT:
   Corrected. SOURCE: schema `components.schemas.CreateCommentRequest`
   (`parent_comment_id` present); `src/api/types.ts: CreateCommentReq`.
8. **List response is `{ items, next_cursor? }` with NO `has_more` field; end of
   pagination = `next_cursor` null/absent.** VERDICT: Corrected (draft included
   `has_more`). SOURCE: `src/api/endpoints/newsfeed.ts: getComments` return type
   `{ items: FeedComment[]; next_cursor?: string }`;
   `src/pages/feed/CommentsThread.tsx` `getNextPageParam: (lastPage) =>
   lastPage.next_cursor`.
9. **CSRF: `X-CSRF-Token` echoed from the `ui_csrf` cookie, sent on every
   request.** VERDICT: Verified (draft said mutations-only; web sends it on all
   requests, enforced server-side on mutations). SOURCE: `src/api/client.ts`
   (`getCookie("ui_csrf")` -> `headers.set("X-CSRF-Token", csrf)`).
10. **Transport also sends `Authorization: Bearer <accessToken>` and includes
    cookies (`credentials: "include"`), plus optional `X-IMPERSONATION-TOKEN`.**
    VERDICT: Corrected (draft framed the surface as cookie-only). SOURCE:
    `src/api/client.ts: api` (sets `Authorization`, `X-IMPERSONATION-TOKEN`,
    `credentials: "include"`).
11. **401 handling: single `POST /ui/session/refresh` then exactly one retry; a
    persisting 401 logs out (terminal).** VERDICT: Verified. SOURCE:
    `src/api/client.ts: refreshSession` and the `res.status === 401` branch in
    `api`.
12. **FastAPI `detail` may be `string | [{msg}] | {code,...}` and must be
    normalized.** VERDICT: Verified. SOURCE: `src/api/client.ts:
    normalizeErrorDetail` / `mapAuthorizationError`.
13. **Only `200` and `422:HTTPValidationError` are schema-declared on the comment
    routes; 401/403/404/5xx are middleware-level.** VERDICT: Verified. SOURCE:
    OpenAPI index lines 501-503 (`resp=200:...;422:HTTPValidationError`);
    transport handling in `src/api/client.ts`.
14. **An edit endpoint exists: `PATCH /posts/{post_id}/comments/{comment_id}`
    (`EditCommentRequest` -> `200:CommentResponse`).** VERDICT: Verified
    (out of scope, noted for forward-compat). SOURCE: OpenAPI index line 504;
    `src/api/endpoints/newsfeed.ts: editComment`.
15. **A comment-tip endpoint exists: `POST
    /posts/{post_id}/comments/{comment_id}/tip`.** VERDICT: Verified (out of scope;
    relevant only because `tip_total_cents` appears on the DTO). SOURCE: OpenAPI
    index line 505; `src/api/endpoints/newsfeed.ts: tipPost`.
16. **Web does NOT optimistically insert; it refetches via `invalidateQueries`
    after a successful post/delete and renders comments flat in server order.**
    VERDICT: Verified (Android's optimistic-insert + top-placement is a deliberate
    divergence, not the web contract). SOURCE: `src/pages/feed/CommentsThread.tsx`
    (`sendMutation.onSuccess -> invalidateQueries(["comments", postId])`,
    `allComments = pages.flatMap(p => p.items)`).
17. **Deleted comments may arrive in a page as `deleted: true` and render as a
    "Comment deleted" tombstone.** VERDICT: Verified. SOURCE:
    `src/pages/feed/CommentsThread.tsx` (`if (comment.deleted) return <tombstone>`).
18. **Stack/framework choices (Paging 3 `cachedIn`, `collectAsLazyPagingItems`,
    `itemKey`, `insertHeaderItem`, `imePadding`, Compose Material 3, Hilt KSP).**
    VERDICT: Unverified-assumption (framework refs, not backend contract).
    SOURCE: framework ref — Android Paging
    (https://developer.android.com/topic/libraries/architecture/paging/v3-paged-data),
    Compose Paging
    (https://developer.android.com/jetpack/compose/lists#paging),
    window-insets/IME (https://developer.android.com/develop/ui/compose/layouts/insets).

### Corrections made

- §2 Auth: reframed from "cookie-authenticated only" to Bearer token + cookies +
  `X-CSRF-Token` (+ optional impersonation), per `src/api/client.ts`.
- §2 Backend: web reference file is `endpoints/newsfeed.ts` (not `comments.ts`);
  DTO is `FeedComment`; UI is `CommentsThread.tsx`.
- §4.2 Model: field renames (`id`->`comment_id`, `parent_id`->`parent_comment_id`),
  removed nested `author`/`display_name`/`avatar_url`, removed server `reply_count`
  and `can_delete`; added `authorId`, `updatedAt`, `deleted`, `tipTotalCents`;
  `canDelete` now documented as client-derived.
- §5 API contract: corrected all paths (dropped `/ui/`), POST status `201`->`200`,
  DELETE path + status `204`->`200`, removed `/comments/{id}/replies`, removed
  `has_more`, corrected request/response field names, documented the PATCH edit
  endpoint and `200`-with-`422` schema reality.
- FR-5/FR-6/FR-7/FR-8: corrected reply support (data-model only, no endpoint/thread
  rendering, no `reply_count`), corrected delete (now confirmed; client-derived
  ownership; tombstone handling).
- §11 testing + AC-4: status codes `201`->`200`, `204`->`200`; AC-4 reworded off
  the non-existent `reply_count`.
- §13 OQ-1/OQ-2/OQ-4/OQ-5: marked resolved with the verified facts.

### Open assumptions

- **Server default comment ordering** (newest-first vs oldest-first) is NOT
  documented in OpenAPI and the web does not sort client-side — unverifiable from
  the sources. Android assumes newest-first for the optimistic top-insert UX, but
  must tolerate either and let the server order win after reconcile/refresh.
- **Round-trip of `parent_comment_id`** — the schema accepts it on create and
  returns it on read, but the web reference never sends or renders it, so actual
  server persistence/threading behavior is unexercised by the reference. Treated
  as an assumption; the `repliesSupported` flag (default OFF) isolates the risk.
- **`Idempotency-Key` support on POST** (OQ-3) — no evidence in OpenAPI params or
  `client.ts`; assume NOT supported and mitigate duplicate-on-retry by disabling
  Retry while a re-post is in flight.
- **Author display name/avatar** — not available on the comment DTO; resolving
  them requires a separate profile lookup not specified here. Assumption: render
  `author_id` (web behavior) until a profile-batch source is provided.
- **`limit` honored by the server** — the param is declared but the web client
  never sends it; whether the server clamps/ignores a client `limit` is unverified.
  Treat `items.size` (and `next_cursor`) as authoritative.

## 17. Test Plan

Test target legend: JVM = JVM unit/Robolectric (local, no device); MWS =
contract test on MockWebServer (JVM); EMU = headless emulator AVD `test35`
(x86_64, Android 15 / API 35) for Compose-UI/instrumented; DEV = physical Samsung
Galaxy A15 5G (SM-A156U, Android 14 / API 34, arm64-v8a) for real-network /
real-hardware / ABI-API-skew cases; MAN = manual against the live dev host.

- **TC-AND-174-01 — Paging happy path (two pages -> end).**
  Type: contract/MockWebServer. Target: MWS (JVM).
  Preconditions: MockWebServer enqueues page 1 `{items:[20], next_cursor:"c2"}`
  then page 2 `{items:[5], next_cursor:null}` for `GET /posts/{id}/comments`.
  Steps: drive `CommentsPagingSource.load(key=null)` then `load(key="c2")` (or
  `Pager` via `asSnapshot`). Expected: page 1 `nextKey=="c2"`,
  `prevKey==null`; page 2 `nextKey==null` (`endOfPaginationReached`); request paths
  are exactly `/posts/{id}/comments` and `/posts/{id}/comments?cursor=c2` (no `/ui/`).
  Traces: AC-1, AC-8.

- **TC-AND-174-02 — DTO mapping (real `CommentResponse` shape).**
  Type: contract/MockWebServer. Target: MWS (JVM).
  Preconditions: enqueue a page whose item uses `comment_id`, `author_id`,
  `parent_comment_id`, `created_at`, `updated_at`, `deleted`, `tip_total_cents`,
  nullable `body`. Steps: load page; map to domain `Comment`. Expected:
  `id==comment_id`, `parentId==parent_comment_id`, `authorId==author_id`, null
  `body`->"", `updatedAt` parsed, `deleted` honored; no crash on unknown
  `kind`/rich fields. Traces: AC-1, AC-8.

- **TC-AND-174-03 — Optimistic add success + reconcile.**
  Type: unit. Target: JVM.
  Preconditions: ViewModel with a fake repo returning `Success(comment)` from
  `addComment`. Steps: `onBodyChange("hi")`, `send()`. Expected: a `pending`
  comment is inserted at head and composer text clears immediately; on success the
  pending entry is removed from `_pending` and a refresh/replace is triggered so the
  server entity lands; `onCommentCountChanged(+1)` fired exactly once. Traces:
  AC-2, AC-6, AC-8.

- **TC-AND-174-04 — Add POST returns 200 (not 201) and is mapped.**
  Type: contract/MockWebServer. Target: MWS (JVM).
  Preconditions: enqueue `200` with a single `CommentResponse` body for
  `POST /posts/{id}/comments`. Steps: call `repository.addComment(postId,"hi",null)`.
  Expected: `ApiResult.Success`; request body is `{"body":"hi","parent_comment_id":null}`;
  `X-CSRF-Token` header present; a `200` (not just `201`) is accepted. Traces:
  AC-2, AC-8.

- **TC-AND-174-05 — Optimistic add failure -> failed row -> Retry/Discard.**
  Type: unit. Target: JVM.
  Preconditions: fake repo returns `Failure(retryable)` then `Success` on retry.
  Steps: `send()`; observe failed flip; `retry(localKey)`; then a second case
  `discard(localKey)`. Expected: after failure the entry has `pending=false,
  failed=true` and remains visible; `retry` re-issues `addComment` with the same
  body and on success reconciles; `discard` removes the entry; list never silently
  desyncs. Traces: AC-3, AC-8.

- **TC-AND-174-06 — 422 validation maps to composer field error (no optimistic
  row).** Type: contract/MockWebServer. Target: MWS (JVM).
  Preconditions: enqueue `422` `{"detail":[{"msg":"Comment is too long"}]}` for the
  POST. Steps: send an over-long body. Expected: no optimistic row is inserted for
  an invalid body / it is rolled back; a composer-level inline error surfaces the
  normalized `detail` message; POST is not auto-retried. Traces: AC-3, AC-5, AC-8.

- **TC-AND-174-07 — 403 (CSRF/permission) is non-retryable; 5xx/timeout
  retryable; POST never auto-retried.** Type: contract/MockWebServer. Target: MWS
  (JVM). Preconditions: three sub-cases — `403`, `503`, and a socket timeout on
  `POST`. Steps: attempt add in each. Expected: `403` -> non-retryable failure
  (failed row, no network retry); `503`/timeout -> retryable failure; in all cases
  the network layer issues exactly one POST (no automatic re-post). Traces: AC-3,
  AC-8.

- **TC-AND-174-08 — 401 single-refresh-then-retry on a GET; persistent 401
  terminal.** Type: contract/MockWebServer. Target: MWS (JVM).
  Preconditions: GET list returns `401`, then `POST /ui/session/refresh` returns
  `200`, then the retried GET returns `200`; second sub-case keeps returning `401`.
  Steps: trigger a list load. Expected: exactly one refresh call and one retry;
  success surfaces on the happy sub-case; the persistent-`401` sub-case ends
  terminal (no loop) and signals logout. Traces: AC-1, AC-8.

- **TC-AND-174-09 — Delete success (200 / `{ok:true}`) and 403 honored.**
  Type: contract/MockWebServer. Target: MWS (JVM).
  Preconditions: enqueue `200 {"ok":true}` for
  `DELETE /posts/{id}/comments/{cid}`; second sub-case `403`. Steps: call
  `repository.deleteComment` for an own comment. Expected: `200` -> `Success(Unit)`
  and the row is removed (optimistically) then reconciled; path has no `/ui/`
  prefix and `X-CSRF-Token` is present; `403` -> non-retryable, row restored;
  `onCommentCountChanged(-1)` only on success. Traces: AC-6, AC-8 (delete behavior
  of FR-8).

- **TC-AND-174-10 — Paging differ snapshot incl. optimistic header.**
  Type: integration (Paging `asSnapshot`). Target: JVM.
  Preconditions: two-page fake source; one pending optimistic comment in `_pending`.
  Steps: collect `comments.asSnapshot`. Expected: snapshot equals concatenated
  server items with the optimistic comment at index 0 (stable `localKey`); after
  reconcile the duplicate does not appear (Risk-2). Traces: AC-1, AC-2, AC-8.

- **TC-AND-174-11 — Compose: empty vs append-error vs post UX.**
  Type: Compose-UI. Target: EMU (test35).
  Preconditions: fakes for (a) empty success, (b) append error, (c) post failure.
  Steps/Expected: (a) zero comments + `endOfPaginationReached` shows the empty state,
  not an error; (b) append failure keeps loaded items and shows a footer Retry that
  calls `retry()`; (c) typing enables Send, Send shows the dimmed pending row and
  clears input, simulated failure shows Retry/Discard. Traces: AC-2, AC-3, AC-5,
  AC-7 (no refetch), AC-8.

- **TC-AND-174-12 — Compose: reply affordance gated by `repliesSupported`.**
  Type: Compose-UI. Target: EMU (test35).
  Preconditions: render once with `repliesSupported=false` (default), once `true`.
  Steps/Expected: with false, no Reply control is present anywhere (`onClick`-free,
  matches web); with true, Reply opens reply mode with a "Replying to" chip and a
  cancel (X), and a sent reply carries `parent_comment_id`. Traces: AC-4, AC-8.

- **TC-AND-174-13 — Accessibility: touch targets, semantics, IME.**
  Type: Compose-UI / instrumented (TalkBack semantics assertions). Target: EMU
  (test35). Preconditions: list with one pending and one failed row + composer.
  Steps: assert content descriptions on Send/Reply/Retry/Delete; ≥48x48dp targets;
  pending row state-description "Sending"; failed row "Failed to post — double tap
  to retry"; composer announces a `422` char-limit error via `semantics{error()}`;
  `imePadding` keeps the composer above the keyboard. Expected: all assertions pass;
  externalized strings (no hardcoded literals). Traces: AC-8 (a11y per §9).

- **TC-AND-174-14 — State preservation across config change / back nav.**
  Type: instrumented. Target: EMU (test35).
  Preconditions: loaded list, scrolled, with a composer draft. Steps: rotate
  device and navigate back-then-forward in-session. Expected: scroll position, the
  cached `PagingData` (no refetch — assert no new GET fires), and the composer
  draft all survive (`cachedIn` + `rememberSaveable`). Traces: AC-7, AC-8.

- **TC-AND-174-15 — Live flaky-host / offline acceptance + ABI/API skew.**
  Type: manual + instrumented/e2e. Target: DEV (physical SM-A156U) — MUST run on
  the physical device: real network against `http://18.222.237.167:8000` exercises
  the ~20s timeout/intermittent-failure path and validates arm64-v8a / API-34
  behavior vs the x86_64 / API-35 emulator. Preconditions: signed-in user, real
  post detail screen; for offline, toggle airplane mode mid-send. Steps: load +
  paginate comments; post a comment and confirm it appears and persists across
  pull-to-refresh; force a timeout/offline send and confirm the failed-row UX +
  user-initiated Retry (no duplicate created); delete an own comment. Expected:
  all behaviors per AC-1/2/3/5/6 on real hardware; cleartext HTTP only on the
  dev/debug flavor. Traces: AC-1, AC-2, AC-3, AC-5, AC-6.

### Coverage matrix

| AC | Covered by |
| --- | --- |
| AC-1 (load + paginate to `next_cursor==null`) | TC-01, TC-02, TC-08, TC-10, TC-15 |
| AC-2 (optimistic appear + persists after refresh) | TC-03, TC-04, TC-10, TC-11, TC-15 |
| AC-3 (failed post: Retry/Discard, no desync) | TC-05, TC-06, TC-07, TC-11, TC-15 |
| AC-4 (reply gated by `repliesSupported`) | TC-12 |
| AC-5 (empty vs error; append error retriable) | TC-06, TC-11, TC-15 |
| AC-6 (count delta on add/delete) | TC-03, TC-09, TC-15 |
| AC-7 (draft/scroll/pages survive; no refetch) | TC-11, TC-14 |
| AC-8 (unit/differ/MWS/Compose suites green) | TC-01..TC-14 |
