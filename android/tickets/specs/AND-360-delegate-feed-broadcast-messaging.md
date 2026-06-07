---
id: AND-360
title: Delegate feed/broadcast/messaging
milestone: M7
epic: E46
priority: P2
size: L
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-359]
blocks: []
---

# AND-360 — Delegate feed/broadcast/messaging

## 1. Overview & Goal

This ticket makes the **delegate (manage-as-creator) mode** functional across the three highest-value content surfaces of the TestLogon native Android app: the **feed**, **broadcast (live)**, and **messaging** routes. AND-359 delivers the delegation *primitive* — the `delegates` API, the act of entering/exiting "manage-as-creator" mode, and the global `managingCreator` flag in the auth store. AND-360 consumes that primitive: when a delegate has assumed a creator's context, the feed/broadcast/messaging features must operate **on behalf of that creator**, scoped to exactly the permissions the delegation grants, and the UI must make the delegated context unambiguous and reversible.

The backlog scope is "delegate feed/broadcast/messaging routes" with the acceptance "delegate can act in delegated surfaces." Concretely, AND-360 wires the existing feature modules (`feature-feed`, `feature-broadcast`, `feature-messaging`) to (a) read the active managed-creator id from the auth store, (b) route in-scope reads/writes to the backend's **dedicated delegate endpoint families** (`/ui/newsfeed/delegate/{creator_id}/…`, `/messaging/delegate/{creator_id}/…`, `/ui/broadcast/delegate/{creator_id}/…`), where the managed `creator_id` is a **path segment** (CORRECTED — there is no on-behalf-of *header*; see §5), (c) filter the surfaced actions to the delegation's permission scopes, and (d) render a persistent "managing <creator>" affordance with a one-tap exit. Success = a delegate who has entered manage-as-creator mode for creator C can author/cancel content in C's feed, run/operate C's broadcast surfaces, and read and reply to C's conversations — and is blocked, gracefully, from any action C has not delegated to them.

Building new feed/broadcast/messaging screens is **out of scope** — those are owned by their epics (feed E15/AND-097–104, broadcast E40 viewer/host families, messaging E22 AND-120+). AND-360 is the **delegation-overlay integration layer** over those features.

## 2. Context & References

- **Backlog:** AND-360, Feature, P2, Deps **AND-359**. Scope: "Delegate feed/broadcast/messaging routes." Acceptance: "Delegate can act in delegated surfaces."
- **Dependency AND-359 (Delegates / delegation API):** Provides `delegates.ts` parity (`DelegatesApi`), the manage-as-creator enter/exit flow, and the auth-store `managingCreator` state. AND-360 **must not** redefine the delegation model or the enter/exit flow; it reads the context AND-359 publishes. AND-359 transitively depends on AND-027 (auth/session endpoints + interceptor chain).
- **Web parity (VERIFIED):** Web `delegates.ts` (`src/api/endpoints/delegates.ts`), plus dedicated `delegateFeed.ts` and `delegateBroadcast.ts`; shared types in `src/api/types.ts`. CORRECTED: the web app does **not** inject the managed-creator id into the *self* feed/broadcast/messaging calls. Instead it calls **separate delegate endpoint functions** (`createDelegatedPost(creatorId, …)`, `sendDelegatedMessage(creatorId, conversationId, …)`, `startBroadcast(creatorId, sessionId)`, etc.) whose paths embed `creator_id`. The auth store (`src/stores/authStore.ts`) holds only `managingCreatorId` and `managingCreatorName` (two strings) — **not** a rich `{handle, displayName, scopes}` object. Android must mirror this path-based routing, not a header.
- **Feature modules consumed:** `feature-feed` (AND-097–104), `feature-broadcast` (host/viewer families, e.g. AND-278–287, AND-307–318), `feature-messaging` (AND-120–160). AND-360 extends their ViewModels/repositories with a delegation-context input rather than forking them.
- **Auth model (CORRECTED):** The web client (`src/api/client.ts`) is **not** purely cookie-based. Every request carries **three** auth artifacts: (1) `Authorization: Bearer <accessToken>` from the auth store, (2) the `ui_csrf` cookie echoed as the `X-CSRF-Token` header, and (3) cookies via `credentials: "include"`. On a `401` for an authenticated user it calls `POST /ui/session/refresh` **once** (de-duplicated via a shared `refreshPromise`) and retries the original request; a second `401` logs out. The Android `Authenticator`/interceptor design (single-shot refresh + retry) is a reasonable framework mapping of this behaviour and is an Android implementation choice, not a literal web artifact. NOTE: on any `401` the web also clears the impersonation store (`useImpersonationStore.getState().clear()`). Delegation does **not** create a second session — it is the same delegate session calling delegate-scoped paths.
- **Backend:** FastAPI + DynamoDB at dev host `http://18.222.237.167:8000` (plaintext HTTP, unreliable; ~20s timeouts, bounded backoff for idempotent GETs only, offline/stale states). OpenAPI at `/openapi.json`. R1 RESOLVED: the attribution transport is a **dedicated delegate path family with `creator_id` as a path segment** (not a header, not a query flag). Delegate endpoints also accept optional `user_sub` (query), `X-SESSION-ID` (header), and `X-IMPERSONATION-TOKEN` (header) params; the impersonation token is for admin support flows, **not** delegation.
- **Module layering:** `app -> feature-feed/feature-broadcast/feature-messaging -> core-network/core-model/core-data/core-ui/core-testing`. The delegation context type and interceptor live in `core-data`/`core-network` so all three features share one source of truth.
- **Stack pins:** Kotlin 2.0.21, Compose + Material 3, Navigation-Compose, Hilt (KSP), Retrofit 2.11 + OkHttp 4.12 + Moshi 1.15, Coroutines/Flow, Paging 3. minSdk 24 / compileSdk-targetSdk 35. Namespace base `com.testlogon.android`.

## 3. Functional Requirements

FR-1. **Read active delegation context.** All three features observe the auth-store managing-creator state published by AND-359. CORRECTED: the web auth store exposes only `managingCreatorId` + `managingCreatorName` (two nullable strings), so the per-creator **permission set is NOT in the auth store** — it is read from `GET /ui/delegates/managed` (`ManagedCreatorOut.permissions: string[]`, filtered to `status == "active"`). The Android `DelegationContext` may aggregate id + name + the resolved permission list, but the permissions must be sourced from `managed`, not assumed present alongside the id. When the managing id is null, every feature behaves exactly as in self mode (no regression).

FR-2. **Scope-gated actions.** Each delegated surface filters its action set to the granted permissions. CORRECTED scope vocabulary (VERIFIED against `src/pages/delegates/DelegatesPage.tsx: ALL_PERMISSIONS` and OpenAPI endpoint descriptions): the real permission strings are `chat_read`, `chat_respond`, `feed_read`, `feed_post`, `feed_moderate`, `broadcast_moderate`, `broadcast_control` — **not** `FEED_PUBLISH`/`MESSAGING_SEND`/`BROADCAST_OPERATE`. Mapping: messaging read = `chat_read`, messaging send/reply = `chat_respond` (OpenAPI: "requires chat_respond"); feed read = `feed_read`, feed create/edit/delete = `feed_post`, comment moderation = `feed_moderate`; broadcast chat moderation (mute/ban/pin/delete/announce) = `broadcast_moderate`, broadcast control (start/stop/schedule) = `broadcast_control`. An action whose permission is absent is **hidden** where it is a primary affordance, or **disabled with an explanatory tooltip/snackbar** where hiding would confuse layout.

FR-3. **Delegate-path routing.** While a managing creator is set, feed/broadcast/messaging in-scope reads/writes are routed to the delegate endpoint families (`/ui/newsfeed/delegate/{creator_id}/…`, `/messaging/delegate/{creator_id}/…`, `/ui/broadcast/delegate/{creator_id}/…`) per §5. CORRECTED: attribution is the path, not a header; these are **distinct endpoints** from the self-mode feed/messaging/broadcast endpoints, so the delegate sees and mutates the **creator's** data via the dedicated routes.

FR-4. **Feed delegation.** A delegate with `feed_post` can create/edit/delete posts in the managed creator's feed via `POST/PUT/DELETE /ui/newsfeed/delegate/{creator_id}/posts[/{post_id}]`. ADDED (verified): the creator may set `require_post_approval` (`FeedDelegationSettingsOut`), in which case a delegate-created post enters a **draft/approval workflow** (`approval_status` on `DelegatedPostOut`) and is approved/rejected by the creator via the `drafts/{post_id}/approve|reject` endpoints — the delegate cannot self-approve (those endpoints are "creator only"). The feed list is read via `GET /ui/newsfeed/delegate/{creator_id}/posts?limit=` (a plain array, not a paged envelope; cursoring is via `limit`/`before` on the messaging/feed read endpoints). Without `feed_post`, authoring entry points are hidden; read (with `feed_read`) remains available.

FR-5. **Broadcast delegation.** A delegate with `broadcast_control` can start/stop/schedule the managed creator's sessions (`/ui/broadcast/delegate/{creator_id}/sessions/{sid}/start|stop`, `…/sessions/schedule`); a delegate with `broadcast_moderate` can mute/ban/unban viewers, delete/pin chat, post announcements, and manage moderators on the creator's sessions. Without these permissions the broadcast surface is read/viewer-only. NOTE: there is **no** `broadcast_operate`/`broadcast_publish` permission in the backend — those two were invented by the draft.

FR-6. **Messaging delegation.** A delegate with `chat_read` sees the managed creator's conversation list and threads (`GET /messaging/delegate/{creator_id}/conversations[/{cid}/messages]`); with `chat_respond` they can send a reply (`POST …/messages`, body `DelegatedSendMessageIn` = `{ text, reply_to_message_id? }`). Outbound messages are attributed to the creator server-side; the response carries `sent_by_delegate`, `delegate_display_name`, `delegate_tag`. ADDED (verified): for encrypted conversations the message may carry `delegate_cannot_decrypt: true` — a delegate may be unable to read E2E-encrypted content even with `chat_read`; the UI must handle this state. The composer shows an "as <creator>" badge. Without `chat_respond`, the composer is disabled with an explanatory state.

FR-7. **Persistent context banner.** While in delegate mode, every delegated route renders a persistent `DelegationBanner` with an **Exit** action that calls AND-359's exit flow and returns to self context. CORRECTED copy: the web banner text is "**Managing @{creator}**" (not "Acting as"); align Android copy to "Managing @{handle}" for parity (or document the deliberate divergence). The web banner is dismissible only via Exit and also offers a creator-switcher dropdown when the delegate manages multiple creators with `chat_read`. The banner uses a distinct color role so the delegate cannot mistake whose account they are operating.

FR-8. **Context-change safety.** Entering or exiting delegate mode invalidates feed/messaging paging and broadcast session state so stale (self vs creator) data never bleeds across contexts. In-flight composes (post draft, message draft) are discarded or clearly re-scoped on context change with a confirm prompt if non-empty.

FR-9. **Authorization failures are graceful.** A `403` from the backend (delegation revoked mid-session, scope insufficient, or creator disabled the delegate) surfaces a clear message and triggers a re-fetch of the delegation context from AND-359; if the delegation is gone, the app auto-exits delegate mode and returns the user to self context.

FR-10. **No self/creator data leakage in caches.** Cached reads (Room/DataStore where used by the three features) are keyed by the effective acting identity so a delegate's view of a creator never overwrites the delegate's own cached self data, and vice versa.

## 4. Technical Design

Shared delegation plumbing lives in `core-data`/`core-network`; per-feature wiring lives in each feature package.

### 4.1 Delegation context (shared, published by AND-359)

```kotlin
// core-model — CORRECTED: permission strings + name source match the backend.
// `managingCreatorName` is the only display field the web stores; there is no
// separate handle vs displayName. Permissions come from ManagedCreatorOut.permissions.
data class DelegationContext(
    val creatorId: String,            // managingCreatorId (auth store)
    val creatorName: String?,         // managingCreatorName (auth store; may be null)
    val permissions: Set<DelegatePermission>, // from GET /ui/delegates/managed
)

// CORRECTED enum: real server strings (DelegatesPage.tsx ALL_PERMISSIONS).
enum class DelegatePermission(val wire: String) {
    CHAT_READ("chat_read"),
    CHAT_RESPOND("chat_respond"),
    FEED_READ("feed_read"),
    FEED_POST("feed_post"),
    FEED_MODERATE("feed_moderate"),
    BROADCAST_MODERATE("broadcast_moderate"),
    BROADCAST_CONTROL("broadcast_control"),
    UNKNOWN("");                       // forward-compat for unmapped server strings
    companion object {
        fun from(s: String) = entries.firstOrNull { it.wire == s } ?: UNKNOWN
    }
}
```

```kotlin
// core-data — owned by AND-359, consumed here
interface DelegationStore {
    /** null = self mode; non-null = manage-as-creator. */
    val managingCreator: StateFlow<DelegationContext?>
    suspend fun enter(creatorId: String): ApiResult<DelegationContext> // AND-359
    suspend fun exit()                                                  // AND-359
    suspend fun refresh(): ApiResult<DelegationContext?>               // re-validate
}

// CORRECTED to real permissions.
fun DelegationContext?.canPostFeed()        = this?.permissions?.contains(DelegatePermission.FEED_POST) == true
fun DelegationContext?.canRespondMessages() = this?.permissions?.contains(DelegatePermission.CHAT_RESPOND) == true
fun DelegationContext?.canControlBroadcast()= this?.permissions?.contains(DelegatePermission.BROADCAST_CONTROL) == true
fun DelegationContext?.canModerateBroadcast()=this?.permissions?.contains(DelegatePermission.BROADCAST_MODERATE) == true
```

### 4.2 Delegate API surface (core-network) — CORRECTED design

R1 is RESOLVED: there is **no on-behalf-of header**. Attribution is carried by **separate delegate endpoints whose path contains `{creator_id}`**. Therefore the original "single OkHttp interceptor that stamps `X-On-Behalf-Of`" design is **dropped**. Instead Android defines dedicated Retrofit interfaces (parity with `delegateFeed.ts` / `delegateBroadcast.ts` / the chat-delegation block of `delegates.ts`) and the feature repositories choose self vs delegate endpoints based on `managingCreatorId`.

```kotlin
// core-network — delegate Retrofit surfaces (creator_id is a @Path).
interface DelegateFeedApi {
    @POST("ui/newsfeed/delegate/{creatorId}/posts")
    suspend fun createPost(@Path("creatorId") creatorId: String,
                           @Body body: DelegatedPostCreateIn): DelegatedPostOut // 201
    @GET("ui/newsfeed/delegate/{creatorId}/posts")
    suspend fun listPosts(@Path("creatorId") creatorId: String,
                          @Query("limit") limit: Int = 50): List<DelegatedPostOut>
    @DELETE("ui/newsfeed/delegate/{creatorId}/posts/{postId}")
    suspend fun deletePost(@Path("creatorId") c: String, @Path("postId") p: String)
}

interface DelegateMessagingApi {
    @GET("messaging/delegate/{creatorId}/conversations")
    suspend fun conversations(@Path("creatorId") c: String): List<DelegatedConversation>
    @POST("messaging/delegate/{creatorId}/conversations/{cid}/messages")
    suspend fun send(@Path("creatorId") c: String, @Path("cid") cid: String,
                     @Body body: DelegatedSendMessageIn): DelegatedMessageOut
}
// DelegateBroadcastApi mirrors /ui/broadcast/delegate/{creatorId}/sessions/...
```

A repository helper resolves the acting identity:

```kotlin
val actingCreatorId: String? get() = delegation.managingCreatorId.value // null ⇒ self
```

CSRF (`X-CSRF-Token`) and `Authorization: Bearer` are applied by the **existing** core-network interceptors to *all* requests (delegate paths included); the 401→`/ui/session/refresh`→retry `Authenticator` already covers delegate calls because they share the client. No new header interceptor is introduced by AND-360.

### 4.3 Per-feature ViewModel wiring

Each feature's existing ViewModel gains a delegation input. Pattern (feed shown; broadcast/messaging analogous):

```kotlin
@HiltViewModel
class FeedViewModel @Inject constructor(
    private val feedRepo: FeedRepository,
    private val delegation: DelegationStore,
) : ViewModel() {

    private val ctx: StateFlow<DelegationContext?> = delegation.managingCreator

    // Re-key the pager on context change so self/creator feeds never mix.
    // When actingAs != null the repo hits the /ui/newsfeed/delegate/{id}/posts
    // endpoint; when null it hits the self feed endpoint.
    val posts: Flow<PagingData<PostUi>> = ctx
        .flatMapLatest { dc -> feedRepo.feedPager(actingAs = dc?.creatorId) }
        .cachedIn(viewModelScope)

    val delegationUi: StateFlow<DelegationUiState> = ctx
        .map { dc ->
            DelegationUiState(
                banner = dc?.let { BannerState(it.creatorName ?: it.creatorId) },
                canPublish = dc.canPostFeed() || dc == null, // self always can
                isDelegated = dc != null,
            )
        }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), DelegationUiState())

    fun exitDelegation() = viewModelScope.launch { delegation.exit() }
}

data class DelegationUiState(
    val banner: BannerState? = null,
    val canPublish: Boolean = true,
    val isDelegated: Boolean = false,
)
data class BannerState(val creatorHandle: String)
```

Messaging re-keys its conversation pager on `actingAs` (and switches to `DelegateMessagingApi`); broadcast re-derives control visibility from `canControlBroadcast()` and moderation visibility from `canModerateBroadcast()`. The composer/authoring entry points in each feature read the feature-specific `canX` flag for visibility/enablement.

### 4.4 UI overlay (core-ui)

```kotlin
@Composable
fun DelegationBanner(
    state: BannerState,
    onExit: () -> Unit,
    modifier: Modifier = Modifier,
)
```

A slim Material 3 surface pinned to the top of each delegated screen (`tertiaryContainer` color role), text "Managing @{creatorName}" (CORRECTED for web parity — web uses "Managing @…"), trailing **Exit** `TextButton`, `Modifier.semantics { liveRegion = LiveRegionMode.Polite }`. Optional trailing creator-switcher dropdown when the delegate manages >1 creator (web parity, `DelegateBanner.tsx`). Hosted by each feature screen's `Scaffold` `topBar` slot (or stacked above it). Non-dismissible by swipe; only Exit removes it (by exiting delegate mode).

### 4.5 Routing & navigation

No new routes. Delegated state is global, so the existing feed/broadcast/messaging destinations render their delegated variants based on `DelegationStore`. On `exit()` the user remains on the current route but it re-renders in self context (data invalidated per §6). The "Enter delegate mode" entry point is owned by AND-359 (delegate management UI); AND-360 only consumes the resulting state.

## 5. API Contract

CORRECTED: AND-360 introduces no new *backend* endpoints, but it does **not** reuse the self-mode endpoints with an added header. It consumes a **dedicated family of delegate endpoints** (already in the backend) whose paths embed `{creator_id}`. The contract this ticket owns on the Android side is wiring those endpoints and gating them by permission.

**Verified delegate endpoints (OpenAPI index):**
- Feed: `POST /ui/newsfeed/delegate/{creator_id}/posts` (req `DelegatedPostCreateIn`, **resp 201 `DelegatedPostOut`**), `GET …/posts`, `PUT …/posts/{post_id}` (`DelegatedPostEditIn`), `DELETE …/posts/{post_id}`, `…/posts/{post_id}/comments/{comment_id}/moderate` (`CommentModerationIn`), `…/drafts`, `…/drafts/{post_id}/approve|reject` (`DraftApprovalIn`, **creator only**), `…/analytics`, `…/audit`, `…/settings` (GET/PUT).
- Messaging: `GET /messaging/delegate/{creator_id}/conversations`, `GET …/conversations/{conversation_id}/messages` (params `limit`, `before`), `POST …/conversations/{conversation_id}/messages` (req `DelegatedSendMessageIn`, resp `DelegatedMessageOut`), `GET …/audit`.
- Broadcast: `POST /ui/broadcast/delegate/{creator_id}/sessions/schedule|{sid}/start|{sid}/stop`, `…/{sid}/mute|ban|announcement`, `DELETE …/{sid}/ban/{uid}`, `…/{sid}/chat/{mid}[/pin]`, `…/{sid}/moderator/register`, `GET …/{sid}/moderators|bans|moderation-log`.
- Common params on delegate endpoints: `creator_id` (path), optional `user_sub` (query), optional `X-SESSION-ID` and `X-IMPERSONATION-TOKEN` (headers). `X-IMPERSONATION-TOKEN` is admin-support impersonation, **not** delegation.

**Delegation context source (CORRECTED):** there is no `GET /delegates/me`. The managed-creator list and per-creator permissions come from `GET /ui/delegates/managed` → `ManagedCreatorOut[]`:
```json
{
  "creator_id": "usr_creatorC",
  "permissions": ["chat_read", "chat_respond", "feed_post", "broadcast_moderate"],
  "preset": "...",
  "status": "active",
  "label": "Creator C",
  "accepted_at": 0
}
```
There is no `creator_handle` / `creator_display_name`; the display string is `label` (and the auth store mirrors it as `managingCreatorName`). Map by `@Json` snake_case → camelCase; unknown permission strings → `DelegatePermission.UNKNOWN` (never crash).

**Example delegated call (feed create — VERIFIED path/method/code):**
```
POST /ui/newsfeed/delegate/usr_creatorC/posts
Authorization: Bearer <accessToken>
X-CSRF-Token: <ui_csrf>
Content-Type: application/json
{ "text": "...", "image_url": null, "lock_price_cents": 0, "tags": [], "scheduled_at": null }
→ 201 DelegatedPostOut { post_id, author_id, status, posted_by_delegate, approval_status, ... }
```

**Error envelope (FastAPI, VERIFIED in `client.ts`):** `{"detail": "..."}`, or a validation array `{"detail": [{"loc": [...], "msg": "...", "type": "..."}]}`, or a structured object `{"detail": {"code": "...", ...}}`. The web normalizes arrays by joining `msg` fields, and maps `detail.code` values (e.g. `role_required_scope` with `required_scope`, `geo_blocked`). Delegation-relevant codes:
- `403` — permission insufficient / delegation revoked → §7 graceful refresh/auto-exit (web shows a toast and throws `ApiError(403)`; supports a `silent403` opt-out).
- `404` — managed creator unknown/disabled → exit delegate mode.
- `422 HTTPValidationError` — the actual validation error code on these endpoints (NOT 400); surfaced via the array-of-`msg` normalizer.
- `409` — domain conflict on the underlying action (passed through).
All map through the shared `ApiResult` (`Success | Error(detail) | NetworkError`) error mapper in `core-network`.

## 6. Data & State Management

- **Single source of truth for context:** `DelegationStore.managingCreator: StateFlow<DelegationContext?>` (AND-359), where the id+name originate from the persisted auth-store fields `managingCreatorId`/`managingCreatorName` (VERIFIED shape) and the permission set is hydrated from `GET /ui/delegates/managed`. All three features observe it; none cache their own copy. NOTE: the web persists `userId/accessToken/isAuthenticated/logoutReason` but **not** `managingCreatorId` (it is excluded from `partialize`), so on web the managing context is lost on reload; Android may choose to persist it but **must** re-validate via `managed` on cold start (see process-death below).
- **Acting-identity cache keying:** any Room/DataStore reads used by feed/broadcast/messaging are keyed by an `actingId = managingCreator?.creatorId ?: selfUserId`. This guarantees FR-10 (no self/creator leakage). Cache entries written under a creator context are namespaced and are not surfaced in self mode.
- **Pager invalidation on context change:** feed and messaging pagers are built inside `flatMapLatest(managingCreator)`, so entering/exiting delegate mode tears down the old `PagingSource` and rebuilds it for the new `actingAs`. Broadcast operate-state is re-derived from the new context.
- **Draft handling (FR-8):** in-progress post/message drafts are held in the owning feature ViewModel `SavedStateHandle`. On a context change with a non-empty draft, the feature prompts ("Discard draft for previous context?") before re-scoping; empty drafts are silently dropped.
- **No persisted delegate session:** the cookie jar is unchanged; delegation is a per-request attribution, not a second login. Exiting delegate mode requires no cookie mutation.
- **Process death:** `managingCreator` is restored by AND-359 on cold start and re-validated via `DelegationStore.refresh()`; until validation completes, delegated surfaces show a brief loading/validating state rather than acting on possibly-stale scopes.

## 7. Error Handling & Resilience

- **Timeouts/retry:** rely on `core-network`'s ~20s call timeout. **Idempotent GETs** (delegate feed/conversation/broadcast reads) keep the shared bounded backoff (2 retries, 500ms→2s, jitter). **POSTs** (create post, send, control/moderate) are non-idempotent → no auto-retry; user-initiated retry only. CORRECTED: there is no on-behalf-of header to reapply — the `creator_id` lives in the request *path*, so it is intrinsically preserved across retries.
- **401:** shared single-shot `/ui/session/refresh` + retry of the (same delegate-path) request. CORRECTED: nothing extra to re-stamp; note the web also clears the impersonation store on 401 — Android should treat impersonation and delegation as independent.
- **403 / revoked delegation (FR-9):** on a delegate `403`/`404`, re-fetch `GET /ui/delegates/managed`. If the creator is no longer present (or `status != "active"`), auto-exit delegate mode, show "Your access to @creatorC ended," and re-render the current route in self context. A permission-specific 403 (action not delegated) disables that action and explains, without exiting the whole mode. The server may return `detail.code` (e.g. `role_required_scope`); surface its `required_scope` if present.
- **Permission drift:** if the re-fetched `ManagedCreatorOut.permissions` is a reduced set, the UI updates affordances immediately (an action that was visible becomes hidden/disabled) rather than letting the user hit a server 403.
- **Offline:** delegated reads fall back to acting-identity-keyed cached/stale data with the offline banner; delegated writes are blocked with a "no connection" snackbar before issuing.
- **Context-change races:** `flatMapLatest` cancels in-flight delegated loads when the context changes, preventing a creator-scoped response from landing in a self-scoped UI.

## 8. Security & Privacy

- **Server is the authority.** Client scope gating (FR-2) is UX only; the backend independently enforces delegation and scope on every delegated call. The client never assumes an action will succeed because a scope flag is set.
- **CSRF:** all delegated writes carry `X-CSRF-Token` (echoed `ui_csrf`) and `Authorization: Bearer` via the shared interceptors (VERIFIED in `client.ts`). CORRECTED: there is no `X-On-Behalf-Of`; attribution is the delegate path.
- **No privilege escalation client-side:** routing to a delegate path cannot grant permissions — the backend enforces them. Unknown server permission strings map to `UNKNOWN` and grant nothing.
- **Audit clarity:** the persistent banner (FR-7) and per-composer "as <creator>" badge ensure the delegate always knows whose data they affect, reducing accidental cross-account actions (a privacy/safety control).
- **Data isolation:** acting-identity cache keying (§6) prevents a delegate's device from co-mingling a creator's private feed/messages with the delegate's own cached data; creator-context caches are cleared on exit.
- **PII/logging:** never log message text, post bodies, recipient/creator identifiers beyond the opaque `creator_id` needed for debugging attribution; the messaging-body redaction from AND-160 applies. Dev host is plaintext HTTP; production HTTPS is mandatory (cleartext is dev-flavor only, owned by `core-network`).

## 9. Accessibility & i18n

- All strings in feature/`core-ui` `strings.xml`: banner text ("Acting as %1$s"), Exit, "as <creator>" composer badge, scope-denied explanations, revoked-delegation messages, discard-draft prompt. No hardcoded text.
- **Banner semantics:** `liveRegion = Polite` so screen readers announce entering/exiting delegate mode; Exit button has a content description and a ≥48dp target.
- **Disabled actions:** scope-denied affordances expose `stateDescription` (e.g. "Disabled — not permitted for this creator") rather than silently inert controls.
- **Color independence:** the banner's distinct color role is reinforced by the explicit "Acting as" text and an icon, so the delegated state is perceivable without color.
- **RTL / dynamic type:** banner and badges use start/end padding and scalable typography; handle text truncates with ellipsis but remains fully readable to TalkBack.

## 10. Telemetry & Logging

- **Analytics (shared facade):** `delegation_surface_entered` (params: `surface` ∈ feed|broadcast|messaging, `scope_count`), `delegation_action_attempted` (`surface`, `action`, `has_scope`), `delegation_action_denied_local` (scope-gated), `delegation_action_403` (`error_code`), `delegation_auto_exit` (`reason` ∈ revoked|not_found), `delegation_exit_manual`. No content, no recipient/creator PII beyond opaque `creator_id` hashed if the facade requires user-level params.
- **Logging:** debug-only OkHttp logging with bodies redacted; the `creator_id` path segment (an opaque id) may appear in debug logs as part of the request line. CORRECTED: there is no `X-On-Behalf-Of` header. No message text or post bodies at any level.
- **Crash reporting:** delegation mapping/refresh failures are caught into `ApiResult`; an unexpected mapping error reports a non-fatal with endpoint name + "delegation-context" tag only.

## 11. Testing Strategy

- **Delegate routing (unit + MockWebServer):** CORRECTED — with `managingCreatorId` set, assert in-scope feed/messaging/broadcast calls go to the `…/delegate/{creator_id}/…` paths (path contains the creator id), and self-mode calls go to the self endpoints; assert `X-CSRF-Token` + `Authorization: Bearer` present on both; assert the delegate path is preserved across a simulated 401→refresh→retry. (No `X-On-Behalf-Of` exists to assert.)
- **Permission gating (ViewModel, Turbine):** for each feature ViewModel, `canPostFeed`/`canRespondMessages`/`canControlBroadcast`/`canModerateBroadcast` derive correctly from permission sets including `UNKNOWN`; self mode (null context) grants self defaults; a reduced permission set flips affordance flags.
- **Context invalidation:** entering/exiting delegate mode triggers pager rebuild (assert `flatMapLatest` produces a new `PagingData` stream and old creator data does not appear in self mode).
- **Graceful 403/revocation (MockWebServer):** a delegated call returns `403`; assert a `GET /ui/delegates/managed` re-fetch is triggered and, when the creator is absent/inactive, the ViewModel emits auto-exit and reverts to self UI.
- **Cache keying:** delegated read writes under `actingId=creatorId`; self read under `selfUserId`; assert no cross-read.
- **Compose UI tests:** `DelegationBanner` renders with handle and Exit; Exit invokes exit; scope-denied composer is disabled with explanation; non-delegated mode shows no banner; messaging composer shows "as <creator>" badge only in delegate+send mode.
- **Coverage:** the delegate API surfaces, per-feature delegation wiring, and permission helpers ≥ 80% line coverage; the acceptance flow ("delegate can act in delegated surfaces") covered end-to-end against MockWebServer for at least one action per surface (feed create `feed_post`, messaging send `chat_respond`, broadcast control `broadcast_control`).

## 12. Dependencies & Sequencing

- **Hard dependency:** **AND-359** (delegates API + manage-as-creator mode + `managingCreator` store). AND-360 cannot start its scope/attribution wiring until AND-359 publishes `DelegationStore`/`DelegationContext`. AND-359 → AND-027 (auth/session + interceptor chain).
- **Feature prerequisites:** the feed (AND-097–104), messaging (AND-120+, incl. send AND-124 and conversation list/thread AND-121/123), and broadcast (viewer AND-278–287 and/or host AND-307–318) surfaces must exist to be delegated. AND-360 integrates with whatever of these has landed; surfaces not yet built are wired when they arrive (documented as partial in §13).
- **Platform deps (in place):** `core-network` cookie jar + CSRF + Bearer + 401-refresh interceptors (delegate calls reuse this chain unchanged; CORRECTED — no new delegation interceptor), Paging 3, analytics facade, Navigation-Compose host, `core-ui` theming.
- **Blocks:** none recorded in backlog.
- **Sequencing within ticket:** (1) delegate Retrofit surfaces (`DelegateFeedApi`/`DelegateMessagingApi`/`DelegateBroadcastApi`) + permission helpers + routing tests (CORRECTED — no interceptor/tag work); (2) `DelegationBanner` in `core-ui`; (3) feed delegation wiring + tests; (4) messaging delegation wiring + tests; (5) broadcast delegation wiring + tests; (6) cross-surface context-change/invalidation + 403 auto-exit + Compose UI tests; (7) accessibility + telemetry pass.

## 13. Risks & Open Questions

- **R1 — Attribution transport. RESOLVED (was primary).** Verified against OpenAPI + `delegateFeed.ts`/`delegateBroadcast.ts`/`delegates.ts`: attribution is **dedicated delegate endpoint paths with `{creator_id}` as a path segment** — NOT a header and NOT a query flag. No interceptor stamping is needed (see §4.2). Residual: confirm the `user_sub` query param and `X-SESSION-ID` header are not required by the dev backend for cookie+Bearer sessions (they are optional in the schema).
- **R2 — Permission vocabulary. RESOLVED.** Verified strings: `chat_read`, `chat_respond`, `feed_read`, `feed_post`, `feed_moderate`, `broadcast_moderate`, `broadcast_control` (`DelegatesPage.tsx: ALL_PERMISSIONS`; OpenAPI "requires chat_read/chat_respond"). The draft's `FEED_PUBLISH`/`MESSAGING_SEND`/`BROADCAST_OPERATE`/`BROADCAST_PUBLISH` do not exist. `UNKNOWN` keeps forward-compat. Open: the exact `preset` keys (`GET /ui/delegates/presets`) are not enumerated here.
- **R3 — Surface availability at integration time.** Some broadcast/host tickets may not have landed when AND-360 runs. *Mitigation:* wire whatever exists; gate not-yet-built surfaces behind their feature flags and document the residual integration as a follow-up.
- **R4 — Revocation timeliness.** Mid-session revocation is only detected on the next call's `403` (no push). *Open question:* is there a delegation event over the SSE stream (AND-143) we should subscribe to for proactive exit? If yes, add a listener; if no, the `403`-driven auto-exit (FR-9) is the contract.
- **R5 — Cache leakage subtlety.** Acting-identity keying must cover every cached read in all three features; a missed key would leak creator data into self view. *Mitigation:* centralize the `actingId` accessor and audit each feature's DAO/DataStore reads during wiring; covered by cache-keying tests.
- **R6 — Unreliable dev host** makes delegated end-to-end QA flaky; mitigated by timeouts, offline states, and MockWebServer-based automated coverage.

## 14. Acceptance Criteria

AC-1. While a managing creator is set, feed/broadcast/messaging surfaces show the **managed creator's** data and issue in-scope calls to the **delegate endpoint paths** (`…/delegate/{creator_id}/…`, verified transport per R1) carrying `X-CSRF-Token` + `Authorization: Bearer` on writes. *(FR-1, FR-3, §5)*
AC-2. A delegate with `feed_post` can create/delete a post in the creator's feed (and, when `require_post_approval` is set, the post enters the creator's draft-approval queue); without `feed_post`, authoring entry points are hidden while `feed_read` keeps read available. *(FR-4, FR-2)*
AC-3. A delegate with `chat_read` sees the creator's conversations/threads and with `chat_respond` can send a reply attributed to the creator (composer shows "as <creator>"); without `chat_respond` the composer is disabled with explanation; `delegate_cannot_decrypt` messages render an undecryptable state. *(FR-6, FR-2)*
AC-4. A delegate with `broadcast_control` can start/stop/schedule the creator's broadcast and with `broadcast_moderate` can moderate chat (mute/ban/pin/announce); without either, the surface is read/viewer-only. *(FR-5, FR-2)*
AC-5. Every delegated route shows the persistent "Managing @creator" banner with a working Exit that returns to self context and re-renders in self data. *(FR-7)*
AC-6. Entering/exiting delegate mode invalidates feed/messaging paging and broadcast state so self and creator data never co-mingle, including in caches. *(FR-8, FR-10)*
AC-7. A `403`/revocation on a delegate call triggers a `GET /ui/delegates/managed` re-validation; if the creator is gone/inactive the app auto-exits to self context with a clear message; a permission-specific denial disables only that action. *(FR-9, §7)*
AC-8. Idempotent delegate GETs retain bounded retry; delegate POSTs never auto-retry; the delegate path (and thus attribution) is intrinsically preserved on refreshed retries. *(§7)*
AC-9. Tests: delegate routing, permission gating, context invalidation, 403 auto-exit, and one action per surface (feed create `feed_post`, messaging send `chat_respond`, broadcast control `broadcast_control`) pass against MockWebServer at ≥80% coverage on the delegation wiring. *(§11)*

## 15. Definition of Done

- Delegate Retrofit surfaces (`DelegateFeedApi`/`DelegateMessagingApi`/`DelegateBroadcastApi`) implemented in `core-network`, routing in-scope calls to the `…/delegate/{creator_id}/…` paths (R1-confirmed); CSRF + Bearer applied by the existing interceptors; delegate path preserved across refreshed retries. (No `X-On-Behalf-Of` interceptor — that draft design is dropped.)
- `feature-feed`, `feature-broadcast`, and `feature-messaging` ViewModels consume `DelegationStore.managingCreator`, re-key their pagers/state on context change, and gate post/respond/control/moderate affordances by permission (`UNKNOWN` grants nothing).
- `DelegationBanner` in `core-ui` rendered on every delegated route with a working Exit; messaging composer shows the "as <creator>" badge in delegate+send mode.
- `403`/revocation auto-exit + scope-drift handling implemented; acting-identity cache keying applied across all three features with no self/creator leakage.
- All nine acceptance criteria demonstrably met; interceptor, ViewModel (Turbine), invalidation, 403 auto-exit, cache-keying, and Compose UI tests green at ≥80% coverage on delegation wiring; one end-to-end action per surface passes against MockWebServer.
- No hardcoded strings; accessibility (live-region banner, ≥48dp Exit, disabled-state descriptions, RTL, dynamic type) verified; telemetry emitted without logging post/message content or creator/recipient PII.
- Open questions R1 (transport = delegate paths) and R2 (permission vocabulary) RESOLVED per §16; R3–R5 resolved against `/openapi.json` / `delegates.ts` (or explicitly documented as deferred) before merge; ktlint/detekt clean; builds on `android-port` with AGP 8.7.3 / Gradle 8.9 / JDK 17.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer. Paths are relative to `reference/` unless noted.

1. **Attribution transport is a header `X-On-Behalf-Of`.** VERDICT: **Corrected → delegate path family.** The backend exposes dedicated delegate endpoints with `{creator_id}` as a path segment; no on-behalf-of header exists. SOURCE: OpenAPI `POST /ui/newsfeed/delegate/{creator_id}/posts`, `POST /messaging/delegate/{creator_id}/conversations/{conversation_id}/messages`, `POST /ui/broadcast/delegate/{creator_id}/sessions/{sid}/start`; `src/api/endpoints/delegateFeed.ts: createDelegatedPost`, `src/api/endpoints/delegateBroadcast.ts: startBroadcast`, `src/api/endpoints/delegates.ts: sendDelegatedMessage`.
2. **The web client injects no `X-On-Behalf-Of` anywhere.** VERDICT: **Verified.** The only delegation-ish header is `X-IMPERSONATION-TOKEN` (admin impersonation, separate store), plus `X-CSRF-Token` and `Authorization: Bearer`. SOURCE: `src/api/client.ts` (lines ~157–171).
3. **Auth is cookie-only session.** VERDICT: **Corrected.** Requests carry `Authorization: Bearer <accessToken>` (auth store) + `X-CSRF-Token` (`ui_csrf` cookie) + cookies via `credentials:"include"`. SOURCE: `src/api/client.ts: api()`; `src/stores/authStore.ts: accessToken`.
4. **401 → single-shot `/ui/session/refresh` then retry.** VERDICT: **Verified.** De-duplicated via shared `refreshPromise`; second 401 logs out; impersonation store cleared on 401. SOURCE: `src/api/client.ts: refreshSession`, `refreshPromise`.
5. **`managingCreator` carries `{creatorId, creatorHandle, creatorDisplayName, scopes}`.** VERDICT: **Corrected.** The auth store holds only `managingCreatorId` and `managingCreatorName` (two nullable strings); there is no handle vs displayName, and no scopes in the store. SOURCE: `src/stores/authStore.ts` (lines 14–24, 67–71).
6. **Per-creator permissions come from the auth store / `GET /delegates/me`.** VERDICT: **Corrected.** Permissions come from `GET /ui/delegates/managed` → `ManagedCreatorOut.permissions: string[]` (filtered to `status=="active"`); there is no `/delegates/me`. SOURCE: OpenAPI `GET /ui/delegates/managed` (resp `ManagedCreatorOut`); `src/api/types.ts: ManagedCreatorOut`; `src/pages/messages/DelegateBanner.tsx` (filters on `permissions.includes("chat_read")`).
7. **Scope vocabulary `FEED_PUBLISH / FEED_MODERATE / MESSAGING_READ / MESSAGING_SEND / BROADCAST_OPERATE / BROADCAST_PUBLISH`.** VERDICT: **Corrected.** Real strings: `chat_read`, `chat_respond`, `feed_read`, `feed_post`, `feed_moderate`, `broadcast_moderate`, `broadcast_control`. SOURCE: `src/pages/delegates/DelegatesPage.tsx: ALL_PERMISSIONS` (lines 61–69); OpenAPI descriptions "requires chat_read"/"requires chat_respond".
8. **Messaging send permission = `messaging_send`.** VERDICT: **Corrected → `chat_respond`.** SOURCE: OpenAPI `POST /messaging/delegate/{creator_id}/conversations/{conversation_id}/messages` description "Send a message as the creator via delegation (requires chat_respond)."
9. **Send-message request shape.** VERDICT: **Verified.** `DelegatedSendMessageIn` = `{ text, reply_to_message_id? }`; resp `DelegatedMessageOut`. SOURCE: OpenAPI `req=DelegatedSendMessageIn resp=200:DelegatedMessageOut`; `src/api/types.ts: DelegatedSendMessageReq`, `DelegatedMessage`.
10. **Feed create request/response.** VERDICT: **Verified + augmented.** `DelegatedPostCreateIn` = `{ text, image_url?, lock_price_cents?, tags?, scheduled_at? }`; **resp is 201 `DelegatedPostOut`** (not 200). SOURCE: OpenAPI `POST /ui/newsfeed/delegate/{creator_id}/posts | resp=201:DelegatedPostOut`; `src/api/types.ts: DelegatedPostCreateReq`, `DelegatedPostOut`.
11. **Feed draft/approval workflow exists.** VERDICT: **Verified (added; draft omitted it).** When `require_post_approval`, delegate posts require creator approval via `…/drafts/{post_id}/approve|reject` (DraftApprovalIn) which are "creator only"; `DelegatedPostOut.approval_status`. SOURCE: OpenAPI `…/drafts/{post_id}/approve|reject`; descriptions "(creator only)"; `src/api/types.ts: FeedDelegationSettingsOut.require_post_approval`, `DelegatedPostOut.approval_status`.
12. **Delegate messages may be undecryptable (`delegate_cannot_decrypt`).** VERDICT: **Verified (added).** SOURCE: `src/api/types.ts: DelegatedMessage.delegate_cannot_decrypt`.
13. **Banner copy "Acting as @{creator}".** VERDICT: **Corrected → "Managing @{creator}".** Web banner reads "Managing @{name}" and offers a creator-switcher dropdown + Exit. SOURCE: `src/pages/messages/DelegateBanner.tsx` (lines 44–82).
14. **Broadcast operate endpoints.** VERDICT: **Verified.** Start/stop/schedule + mute/ban/unban/announce/pin/delete-chat/moderator-register/list under `/ui/broadcast/delegate/{creator_id}/sessions/...`. SOURCE: OpenAPI `…/sessions/{sid}/start|stop|mute|ban|announcement|chat/{mid}[/pin]|moderator/register|moderators|bans`; `src/api/endpoints/delegateBroadcast.ts`.
15. **Error envelope shape + validation code.** VERDICT: **Verified/refined.** `{"detail": str | [{loc,msg,type}] | {code,...}}`; validation responses are **422 `HTTPValidationError`** (not 400); the web normalizes arrays via `msg` and maps `detail.code` (e.g. `role_required_scope`, `geo_blocked`). SOURCE: `src/api/client.ts: normalizeErrorDetail`, `mapAuthorizationError`; OpenAPI `resp=...;422:HTTPValidationError`.
16. **Delegate-list management endpoints.** VERDICT: **Verified.** `GET/POST /ui/delegates`, `…/{delegate_id}` GET/DELETE, `…/{delegate_id}/permissions` PUT, `…/managed`, `…/invites`, `…/invites/{creator_id}/respond`, `…/settings`, `…/presets`, `…/audit`. SOURCE: OpenAPI lines 1398–1409; `src/api/endpoints/delegates.ts`.
17. **Feed/conversation reads are plain arrays (no paging envelope).** VERDICT: **Verified-with-caveat.** `listDelegatedPosts`/`listDelegatedConversations` return arrays; cursoring on messages is `limit`/`before`. Paging 3 must build a cursor `PagingSource` over these, not consume a server page object. SOURCE: `src/api/endpoints/delegateFeed.ts: listDelegatedPosts`, `src/api/endpoints/delegates.ts: listDelegatedMessages`.
18. **Optional `user_sub` query + `X-SESSION-ID` header on delegate endpoints.** VERDICT: **Verified (both optional).** SOURCE: OpenAPI `params=creator_id,user_sub,X-SESSION-ID,X-IMPERSONATION-TOKEN` on the delegate paths; OpenAPI `create_post` parameter block.
19. **Framework: single-shot `Authenticator` + OkHttp/Retrofit/Moshi/Paging 3 mapping.** VERDICT: **Unverified-assumption (framework ref).** This is an Android implementation mapping of the web's refresh-once-retry logic; not a literal web artifact. framework ref: OkHttp `Authenticator` (https://square.github.io/okhttp/), Paging 3 `RemoteMediator`/`PagingSource` (https://developer.android.com/topic/libraries/architecture/paging/v3-overview).
20. **Accessibility: live-region banner, ≥48dp targets, stateDescription.** VERDICT: **Unverified-assumption (framework ref).** Not in web source; Android-platform requirement. framework ref: Compose semantics `liveRegion` / accessibility (https://developer.android.com/develop/ui/compose/accessibility).

### Corrections made
- C1 — Replaced the `X-On-Behalf-Of` header transport (and the `DelegationInterceptor`/`DelegateAware` tag design) with the verified **delegate path family** (`…/delegate/{creator_id}/…`) and dedicated Retrofit surfaces (§1, §2, §4.2, §5, §7, §8, §10, §13-R1, §14, §15).
- C2 — Replaced the invented scope enum with the real permission strings `chat_read`/`chat_respond`/`feed_read`/`feed_post`/`feed_moderate`/`broadcast_moderate`/`broadcast_control` (§3-FR2, §4.1, §4.3, §5, §11, §13-R2, §14, §15).
- C3 — Corrected `managingCreator` to the real two-string auth-store shape and sourced permissions from `GET /ui/delegates/managed` (no `/delegates/me`) (§2, §3-FR1, §4.1, §5, §6).
- C4 — Corrected the auth model from "cookie-only" to Bearer + CSRF + cookies (§2, §8).
- C5 — Corrected banner copy "Acting as" → "Managing" and added the creator-switcher (§3-FR7, §4.4).
- C6 — Added the feed draft/approval workflow and the messaging `delegate_cannot_decrypt` state, both previously missing (§3-FR4, §3-FR6, §14).
- C7 — Corrected feed-create response code to 201 and validation errors to 422 `HTTPValidationError` (§5).

### Open assumptions
- OA1 — Whether the dev backend requires `user_sub`/`X-SESSION-ID` in addition to cookie+Bearer for delegate calls (schema marks them optional; not exercised in the reference web flow). Unverifiable without hitting the live dev host.
- OA2 — Exact `preset` keys returned by `GET /ui/delegates/presets` (web fetches them dynamically; no static list in source).
- OA3 — Whether mid-session revocation is pushed over SSE (AND-143) for proactive exit, vs. detected only on the next 403. No delegation-event subscription found in the reference source; treated as 403-driven (R4).
- OA4 — Android-framework choices (Authenticator, Paging 3 cursor source, Compose accessibility) are platform mappings, not web-verifiable (citations 19–20).

## 17. Test Plan

Targets: **JVM** = JVM/Robolectric unit; **emu35** = headless AVD `test35` (x86_64, API 35); **A15** = physical Samsung Galaxy A15 5G (SM-A156U, API 34, arm64). Use A15 only where real hardware/ABI/API-34 behavior matters; everything else runs on JVM or emu35.

- **TC-AND-360-01** — Type: contract/MockWebServer. Target: JVM. Pre: `managingCreatorId="usr_creatorC"`, permissions include `feed_post`. Steps: trigger feed-create; capture the recorded request. Expected: method `POST`, path `/ui/newsfeed/delegate/usr_creatorC/posts`, headers include `X-CSRF-Token` and `Authorization: Bearer`, body matches `DelegatedPostCreateIn`; **no** `X-On-Behalf-Of` header present; response 201 `DelegatedPostOut` parses (incl. `approval_status`). Traces: AC-1, AC-2.
- **TC-AND-360-02** — Type: unit. Target: JVM. Pre: permission set `["chat_read"]` plus an unknown string `"foo_bar"`. Steps: map to `DelegatePermission`, evaluate `canPostFeed/canRespondMessages/canControlBroadcast`. Expected: unknown → `UNKNOWN` (grants nothing); `canRespondMessages=false` (only `chat_read`); self mode (null ctx) grants self defaults. Traces: AC-2, AC-3, AC-9.
- **TC-AND-360-03** — Type: contract/MockWebServer. Target: JVM. Pre: managing creator set, permissions include `chat_respond`. Steps: send a reply in conversation `cnv1`. Expected: `POST /messaging/delegate/usr_creatorC/conversations/cnv1/messages` with body `{text, reply_to_message_id?}`; resp `DelegatedMessageOut` exposes `sent_by_delegate`/`delegate_display_name`. Traces: AC-3, AC-9.
- **TC-AND-360-04** — Type: Compose-UI. Target: emu35. Pre: managing creator set, permissions = `["chat_read"]` (no `chat_respond`). Steps: open a delegated thread. Expected: composer disabled with explanatory `stateDescription`; thread list visible; banner shows "Managing @…". Traces: AC-3, AC-5.
- **TC-AND-360-05** — Type: Compose-UI. Target: emu35. Pre: managing creator set, permissions include `chat_respond`; one message has `delegate_cannot_decrypt=true`. Steps: render thread. Expected: undecryptable message renders an explicit "can't be decrypted" state (not blank/crash); composer shows "as @creator" badge. Traces: AC-3.
- **TC-AND-360-06** — Type: contract/MockWebServer. Target: JVM. Pre: managing creator set, permissions include `broadcast_control`. Steps: start broadcast for session `s1`. Expected: `POST /ui/broadcast/delegate/usr_creatorC/sessions/s1/start`; success body parses. Then without `broadcast_control`: control affordances hidden, surface read-only. Traces: AC-4, AC-9.
- **TC-AND-360-07** — Type: integration (Turbine ViewModel + MockWebServer). Target: JVM. Pre: feed pager active for self, then enter delegate mode. Steps: emit context change; collect `PagingData`. Expected: pager rebuilds via `flatMapLatest` to the delegate posts endpoint; prior self items do not appear in delegated stream and vice-versa on exit. Traces: AC-6.
- **TC-AND-360-08** — Type: unit. Target: JVM. Pre: write a cached read under `actingId=creatorId`, and a self read under `selfUserId`. Steps: read each context. Expected: no cross-read; exiting delegate mode does not surface creator-keyed cache in self view. Traces: AC-6.
- **TC-AND-360-09** — Type: integration (MockWebServer). Target: JVM. Pre: managing creator set. Steps: a delegate call returns `403`; queue `GET /ui/delegates/managed` returning a list **without** `usr_creatorC` (or `status!="active"`). Expected: app auto-exits delegate mode, emits "access ended" message, re-renders self context. Traces: AC-7.
- **TC-AND-360-10** — Type: integration (MockWebServer). Target: JVM. Pre: managing creator set. Steps: delegate call returns `403` but `managed` still lists the creator with **reduced** permissions (drops `feed_post`). Expected: only the post affordance is disabled/hidden; delegate mode stays active. Traces: AC-7.
- **TC-AND-360-11** — Type: contract/MockWebServer. Target: JVM. Pre: managing creator set; idempotent delegate GET and non-idempotent delegate POST. Steps: GET fails twice then succeeds; POST fails once. Expected: GET retried with bounded backoff (≤2) and the delegate path unchanged; POST not auto-retried; on a simulated 401 the request is retried after `/ui/session/refresh` with the same delegate path. Traces: AC-1, AC-8.
- **TC-AND-360-12** — Type: contract/MockWebServer. Target: JVM. Pre: managing creator set. Steps: delegate POST returns `422` with `{"detail":[{"loc":["body","text"],"msg":"field required","type":"value_error.missing"}]}`. Expected: `ApiResult.Error` carries the joined `msg`; no auto-exit (validation, not auth). Traces: AC-7 (error mapping), AC-9.
- **TC-AND-360-13** — Type: Compose-UI / accessibility. Target: emu35. Pre: managing creator set. Steps: render any delegated route; inspect banner semantics. Expected: banner has `liveRegion=Polite`, Exit has content description + ≥48dp target; entering/exiting announced; banner perceivable without color (text+icon). Tapping Exit invokes `exit()` and removes the banner. Traces: AC-5.
- **TC-AND-360-14** — Type: instrumented/e2e. Target: **A15 (physical)** — must run on arm64/API-34 to catch ABI- and API-level differences from the emulator. Pre: real session against MockWebServer or dev host; managing creator with `feed_post`+`chat_respond`+`broadcast_control`. Steps: end-to-end one action per surface (create post, send message, start broadcast) then Exit. Expected: each call hits its delegate path and succeeds; banner shows throughout; Exit returns to self context. Traces: AC-1, AC-2, AC-3, AC-4, AC-5, AC-9.
- **TC-AND-360-15** — Type: manual. Target: A15 (flaky-dev-host/offline). Pre: dev host `http://18.222.237.167:8000` reachable then toggled offline. Steps: in delegate mode, perform a delegated GET (expect cached/stale + offline banner) and attempt a delegated write while offline. Expected: read falls back to acting-identity-keyed cache with offline banner; write blocked pre-flight with "no connection" snackbar (no partial send). Traces: AC-6 (cache isolation), AC-8.

### Coverage matrix
| AC | Covered by |
|----|------------|
| AC-1 | TC-01, TC-11, TC-14 |
| AC-2 | TC-01, TC-02, TC-14 |
| AC-3 | TC-02, TC-03, TC-04, TC-05, TC-14 |
| AC-4 | TC-06, TC-14 |
| AC-5 | TC-04, TC-13, TC-14 |
| AC-6 | TC-07, TC-08, TC-15 |
| AC-7 | TC-09, TC-10, TC-12 |
| AC-8 | TC-11, TC-15 |
| AC-9 | TC-01, TC-02, TC-03, TC-06, TC-12, TC-14 |
