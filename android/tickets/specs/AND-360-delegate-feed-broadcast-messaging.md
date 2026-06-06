---
id: AND-360
title: Delegate feed/broadcast/messaging
milestone: M7
epic: E46
priority: P2
size: L
status: draft
depends_on: [AND-359]
blocks: []
---

# AND-360 — Delegate feed/broadcast/messaging

## 1. Overview & Goal

This ticket makes the **delegate (manage-as-creator) mode** functional across the three highest-value content surfaces of the TestLogon native Android app: the **feed**, **broadcast (live)**, and **messaging** routes. AND-359 delivers the delegation *primitive* — the `delegates` API, the act of entering/exiting "manage-as-creator" mode, and the global `managingCreator` flag in the auth store. AND-360 consumes that primitive: when a delegate has assumed a creator's context, the feed/broadcast/messaging features must operate **on behalf of that creator**, scoped to exactly the permissions the delegation grants, and the UI must make the delegated context unambiguous and reversible.

The backlog scope is "delegate feed/broadcast/messaging routes" with the acceptance "delegate can act in delegated surfaces." Concretely, AND-360 wires the existing feature modules (`feature-feed`, `feature-broadcast`, `feature-messaging`) to (a) read the active delegation context from the auth store, (b) attach the on-behalf-of creator identity to the relevant requests, (c) filter the surfaced actions to the delegation's permission scopes, and (d) render a persistent "acting as <creator>" affordance with a one-tap exit. Success = a delegate who has entered manage-as-creator mode for creator C can author/cancel content in C's feed, run/operate C's broadcast surfaces, and read and reply to C's conversations — and is blocked, gracefully, from any action C has not delegated to them.

Building new feed/broadcast/messaging screens is **out of scope** — those are owned by their epics (feed E15/AND-097–104, broadcast E40 viewer/host families, messaging E22 AND-120+). AND-360 is the **delegation-overlay integration layer** over those features.

## 2. Context & References

- **Backlog:** AND-360, Feature, P2, Deps **AND-359**. Scope: "Delegate feed/broadcast/messaging routes." Acceptance: "Delegate can act in delegated surfaces."
- **Dependency AND-359 (Delegates / delegation API):** Provides `delegates.ts` parity (`DelegatesApi`), the manage-as-creator enter/exit flow, and the auth-store `managingCreator` state. AND-360 **must not** redefine the delegation model or the enter/exit flow; it reads the context AND-359 publishes. AND-359 transitively depends on AND-027 (auth/session endpoints + interceptor chain).
- **Web parity:** Web `delegates.ts` (`frontend/src/api/endpoints/delegates.ts`), shared types in `frontend/src/api/types.ts`. The web app injects the managed-creator id into feed/broadcast/messaging API calls when `managingCreator` is set; Android mirrors that behaviour.
- **Feature modules consumed:** `feature-feed` (AND-097–104), `feature-broadcast` (host/viewer families, e.g. AND-278–287, AND-307–318), `feature-messaging` (AND-120–160). AND-360 extends their ViewModels/repositories with a delegation-context input rather than forking them.
- **Auth model:** Cookie-based session (`POST /ui/session/start` → MFA → `/ui/session/finalize` → `/ui/me`). Session rides on cookies + the `ui_csrf` cookie echoed as `X-CSRF-Token`; on 401 the shared OkHttp `Authenticator` calls `POST /ui/session/refresh` once then retries. Persistent cookie jar from `core-network`. Delegation does **not** create a second session — it is an attribute applied to the existing delegate session.
- **Backend:** FastAPI + DynamoDB at dev host `http://18.222.237.167:8000` (plaintext HTTP, unreliable; ~20s timeouts, bounded backoff for idempotent GETs only, offline/stale states). OpenAPI at `/openapi.json`. The exact on-behalf-of transport (header vs query vs path) is the primary risk (R1) and must be confirmed against `/openapi.json` and `delegates.ts`.
- **Module layering:** `app -> feature-feed/feature-broadcast/feature-messaging -> core-network/core-model/core-data/core-ui/core-testing`. The delegation context type and interceptor live in `core-data`/`core-network` so all three features share one source of truth.
- **Stack pins:** Kotlin 2.0.21, Compose + Material 3, Navigation-Compose, Hilt (KSP), Retrofit 2.11 + OkHttp 4.12 + Moshi 1.15, Coroutines/Flow, Paging 3. minSdk 24 / compileSdk-targetSdk 35. Namespace base `com.testlogon.android`.

## 3. Functional Requirements

FR-1. **Read active delegation context.** All three features observe the auth-store `managingCreator` state published by AND-359. When non-null it carries `{ creatorId, creatorDisplayName, creatorHandle, scopes: Set<DelegateScope> }`. When null, every feature behaves exactly as in self mode (no regression).

FR-2. **Scope-gated actions.** Each delegated surface filters its action set to the granted scopes. Minimum scope vocabulary (confirm against AND-359 / OpenAPI): `FEED_PUBLISH`, `FEED_MODERATE`, `MESSAGING_SEND`, `MESSAGING_READ`, `BROADCAST_OPERATE`, `BROADCAST_PUBLISH`. An action whose scope is absent is **hidden** where it is a primary affordance, or **disabled with an explanatory tooltip/snackbar** where hiding would confuse layout.

FR-3. **On-behalf-of request attribution.** While `managingCreator` is set, feed/broadcast/messaging API calls in scope are issued on behalf of `creatorId` (transport per §5). Calls are scoped so the delegate sees and mutates the **creator's** data, not their own.

FR-4. **Feed delegation.** A delegate with `FEED_PUBLISH` can create/schedule and delete/cancel posts in the managed creator's feed (reusing AND-099/AND-100/feed authoring flows). The feed list shows the **creator's** feed. Without `FEED_PUBLISH`, authoring entry points are hidden; read remains available.

FR-5. **Broadcast delegation.** A delegate with `BROADCAST_OPERATE` can operate the managed creator's live surfaces exposed in the broadcast feature (e.g. host controls, moderation, goals/products where those tickets exist) on the creator's behalf. Without operate scope, the broadcast surface is read/viewer-only.

FR-6. **Messaging delegation.** A delegate with `MESSAGING_READ` sees the managed creator's conversation list and threads; with `MESSAGING_SEND` they can reply/send. Outbound messages are attributed to the creator server-side; the composer shows an "as <creator>" badge. Without `MESSAGING_SEND`, the composer is disabled with an explanatory state.

FR-7. **Persistent context banner.** While in delegate mode, every delegated route renders a persistent, non-dismissible `DelegationBanner` ("Acting as <creator handle>") with an **Exit** action that calls AND-359's exit flow and returns to self context. The banner uses a distinct color role so the delegate cannot mistake whose account they are operating.

FR-8. **Context-change safety.** Entering or exiting delegate mode invalidates feed/messaging paging and broadcast session state so stale (self vs creator) data never bleeds across contexts. In-flight composes (post draft, message draft) are discarded or clearly re-scoped on context change with a confirm prompt if non-empty.

FR-9. **Authorization failures are graceful.** A `403` from the backend (delegation revoked mid-session, scope insufficient, or creator disabled the delegate) surfaces a clear message and triggers a re-fetch of the delegation context from AND-359; if the delegation is gone, the app auto-exits delegate mode and returns the user to self context.

FR-10. **No self/creator data leakage in caches.** Cached reads (Room/DataStore where used by the three features) are keyed by the effective acting identity so a delegate's view of a creator never overwrites the delegate's own cached self data, and vice versa.

## 4. Technical Design

Shared delegation plumbing lives in `core-data`/`core-network`; per-feature wiring lives in each feature package.

### 4.1 Delegation context (shared, published by AND-359)

```kotlin
// core-model
data class DelegationContext(
    val creatorId: String,
    val creatorHandle: String,
    val creatorDisplayName: String,
    val scopes: Set<DelegateScope>,
)

enum class DelegateScope {
    FEED_PUBLISH, FEED_MODERATE,
    MESSAGING_READ, MESSAGING_SEND,
    BROADCAST_OPERATE, BROADCAST_PUBLISH,
    UNKNOWN; // forward-compat for unmapped server scopes
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

fun DelegationContext?.canPublishFeed() = this?.scopes?.contains(DelegateScope.FEED_PUBLISH) == true
fun DelegationContext?.canSendMessages() = this?.scopes?.contains(DelegateScope.MESSAGING_SEND) == true
fun DelegationContext?.canOperateBroadcast() = this?.scopes?.contains(DelegateScope.BROADCAST_OPERATE) == true
```

### 4.2 On-behalf-of interceptor (core-network)

A single OkHttp interceptor reads the current `DelegationContext` and attaches the on-behalf-of attribution to outbound requests **only when the call opts in** (so self-scoped endpoints like `/ui/me` are never delegated). Opt-in is by Retrofit tag, avoiding fragile path matching.

```kotlin
@JvmInline value class OnBehalfOf(val creatorId: String) // Retrofit tag

class DelegationInterceptor @Inject constructor(
    private val store: DelegationStore,
) : Interceptor {
    override fun intercept(chain: Interceptor.Chain): Response {
        val req = chain.request()
        val wantsDelegation = req.tag(DelegateAware::class.java) != null
        val ctx = store.managingCreator.value
        val out = if (wantsDelegation && ctx != null) {
            req.newBuilder()
                .header("X-On-Behalf-Of", ctx.creatorId) // R1: confirm vs query/path
                .build()
        } else req
        return chain.proceed(out)
    }
}
object DelegateAware // tag marker added to delegated endpoints' @Tag
```

The interceptor is registered in the shared client **after** the CSRF and cookie interceptors and **before** logging, so the attribution header is present on retried (401-refresh) requests too.

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
    val posts: Flow<PagingData<PostUi>> = ctx
        .flatMapLatest { dc -> feedRepo.feedPager(actingAs = dc?.creatorId) }
        .cachedIn(viewModelScope)

    val delegationUi: StateFlow<DelegationUiState> = ctx
        .map { dc ->
            DelegationUiState(
                banner = dc?.let { BannerState(it.creatorHandle) },
                canPublish = dc.canPublishFeed() || dc == null, // self always can
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

Messaging re-keys its conversation pager on `actingAs`; broadcast re-derives operability and host-control visibility from `canOperateBroadcast()`. The composer/authoring entry points in each feature read the feature-specific `canX` flag for visibility/enablement.

### 4.4 UI overlay (core-ui)

```kotlin
@Composable
fun DelegationBanner(
    state: BannerState,
    onExit: () -> Unit,
    modifier: Modifier = Modifier,
)
```

A slim Material 3 surface pinned to the top of each delegated screen (`tertiaryContainer` color role), text "Acting as @{handle}", trailing **Exit** `TextButton`, `Modifier.semantics { liveRegion = LiveRegionMode.Polite }`. Hosted by each feature screen's `Scaffold` `topBar` slot (or stacked above it). Non-dismissible by swipe; only Exit removes it (by exiting delegate mode).

### 4.5 Routing & navigation

No new routes. Delegated state is global, so the existing feed/broadcast/messaging destinations render their delegated variants based on `DelegationStore`. On `exit()` the user remains on the current route but it re-renders in self context (data invalidated per §6). The "Enter delegate mode" entry point is owned by AND-359 (delegate management UI); AND-360 only consumes the resulting state.

## 5. API Contract

AND-360 introduces **no new endpoints**. It applies the AND-359 delegation context to existing feed/broadcast/messaging endpoints (owned by their tickets) via the on-behalf-of attribution. The contract this ticket owns is the **attribution transport** and the **delegation-context shape** it reads.

**Delegation context (read via AND-359, e.g. `GET /delegates/me` or the enter response):**
```json
{
  "creator_id": "usr_creatorC",
  "creator_handle": "creatorC",
  "creator_display_name": "Creator C",
  "scopes": ["feed_publish", "messaging_read", "messaging_send", "broadcast_operate"]
}
```
Mapped by `@Json` snake_case → camelCase; unknown scope strings map to `DelegateScope.UNKNOWN` (never crash).

**On-behalf-of attribution (this ticket's contract — confirm against `/openapi.json` + `delegates.ts`):**
- Preferred: request header `X-On-Behalf-Of: <creator_id>` on delegated feed/broadcast/messaging calls.
- Alternatives to validate: a `?on_behalf_of=<creator_id>` query param, or distinct delegated path prefixes. The chosen transport must be applied uniformly by `DelegationInterceptor`.

**Example delegated call (feed create, owned by feed epic, attributed here):**
```
POST /feed/posts            (or the canonical web path)
X-CSRF-Token: <ui_csrf>
X-On-Behalf-Of: usr_creatorC
{ "...post body owned by feed ticket..." }
```

**Error envelope (FastAPI):** `{"detail": "..."}` or `{"detail": [{"loc": [...], "msg": "...", "type": "..."}]}`. Delegation-relevant codes:
- `403` — delegation revoked, scope insufficient, or attribution rejected → §7 graceful auto-exit/refresh.
- `404` — managed creator unknown/disabled → exit delegate mode.
- `409` — domain conflict on the underlying action (passed through to the owning feature's handling).
All map through the shared `ApiResult` (`Success | Error(detail) | NetworkError`) error mapper in `core-network`.

## 6. Data & State Management

- **Single source of truth for context:** `DelegationStore.managingCreator: StateFlow<DelegationContext?>` (AND-359). All three features observe it; none cache their own copy.
- **Acting-identity cache keying:** any Room/DataStore reads used by feed/broadcast/messaging are keyed by an `actingId = managingCreator?.creatorId ?: selfUserId`. This guarantees FR-10 (no self/creator leakage). Cache entries written under a creator context are namespaced and are not surfaced in self mode.
- **Pager invalidation on context change:** feed and messaging pagers are built inside `flatMapLatest(managingCreator)`, so entering/exiting delegate mode tears down the old `PagingSource` and rebuilds it for the new `actingAs`. Broadcast operate-state is re-derived from the new context.
- **Draft handling (FR-8):** in-progress post/message drafts are held in the owning feature ViewModel `SavedStateHandle`. On a context change with a non-empty draft, the feature prompts ("Discard draft for previous context?") before re-scoping; empty drafts are silently dropped.
- **No persisted delegate session:** the cookie jar is unchanged; delegation is a per-request attribution, not a second login. Exiting delegate mode requires no cookie mutation.
- **Process death:** `managingCreator` is restored by AND-359 on cold start and re-validated via `DelegationStore.refresh()`; until validation completes, delegated surfaces show a brief loading/validating state rather than acting on possibly-stale scopes.

## 7. Error Handling & Resilience

- **Timeouts/retry:** rely on `core-network`'s ~20s call timeout. **Idempotent GETs** (feed list, conversation list, broadcast reads) keep the shared bounded backoff (2 retries, 500ms→2s, jitter). **POSTs** (publish, send, operate) are non-idempotent → no auto-retry; user-initiated retry only. The on-behalf-of header is reapplied on every retry by the interceptor.
- **401:** shared single-shot `/ui/session/refresh` + retry. The refreshed retry still carries `X-On-Behalf-Of`.
- **403 / revoked delegation (FR-9):** on a delegation `403`/`404`, call `DelegationStore.refresh()`. If the delegation no longer exists or the scope is gone, auto-exit delegate mode, show "Your access to @creatorC ended," and re-render the current route in self context. A scope-specific 403 (action not delegated) disables that action and explains, without exiting the whole mode.
- **Scope drift:** if `refresh()` returns a reduced scope set, the UI updates affordances immediately (action that was visible becomes hidden/disabled) rather than letting the user hit a server 403.
- **Offline:** delegated reads fall back to acting-identity-keyed cached/stale data with the offline banner; delegated writes are blocked with a "no connection" snackbar before issuing.
- **Context-change races:** `flatMapLatest` cancels in-flight delegated loads when the context changes, preventing a creator-scoped response from landing in a self-scoped UI.

## 8. Security & Privacy

- **Server is the authority.** Client scope gating (FR-2) is UX only; the backend independently enforces delegation and scope on every delegated call. The client never assumes an action will succeed because a scope flag is set.
- **CSRF:** all delegated writes carry `X-CSRF-Token` (echoed `ui_csrf`) via the shared interceptor, in addition to `X-On-Behalf-Of`.
- **No privilege escalation client-side:** the interceptor only attaches attribution; it cannot grant scopes. Unknown server scopes map to `UNKNOWN` and grant nothing.
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
- **Logging:** debug-only OkHttp logging with bodies redacted; the `X-On-Behalf-Of` header value (an opaque id) may appear at debug only. No message text or post bodies at any level.
- **Crash reporting:** delegation mapping/refresh failures are caught into `ApiResult`; an unexpected mapping error reports a non-fatal with endpoint name + "delegation-context" tag only.

## 11. Testing Strategy

- **Interceptor (unit + MockWebServer):** with `managingCreator` set and a `DelegateAware`-tagged request, assert `X-On-Behalf-Of` is present and equals `creatorId`; with delegation null, header absent; on self-scoped (untagged) requests, header always absent; header persists across a simulated 401→refresh→retry.
- **Scope gating (ViewModel, Turbine):** for each feature ViewModel, `canPublish`/`canSend`/`canOperate` derive correctly from scope sets including `UNKNOWN`; self mode (null context) grants self defaults; entering a context with reduced scopes flips affordance flags.
- **Context invalidation:** entering/exiting delegate mode triggers pager rebuild (assert `flatMapLatest` produces a new `PagingData` stream and old creator data does not appear in self mode).
- **Graceful 403/revocation (MockWebServer):** a delegated call returns `403`; assert `DelegationStore.refresh()` is called and, when refresh returns null, the ViewModel emits auto-exit and reverts to self UI.
- **Cache keying:** delegated read writes under `actingId=creatorId`; self read under `selfUserId`; assert no cross-read.
- **Compose UI tests:** `DelegationBanner` renders with handle and Exit; Exit invokes exit; scope-denied composer is disabled with explanation; non-delegated mode shows no banner; messaging composer shows "as <creator>" badge only in delegate+send mode.
- **Coverage:** `DelegationInterceptor`, the per-feature delegation wiring, and scope helpers ≥ 80% line coverage; the acceptance flow ("delegate can act in delegated surfaces") covered end-to-end against MockWebServer for at least one action per surface (feed publish, messaging send, broadcast operate).

## 12. Dependencies & Sequencing

- **Hard dependency:** **AND-359** (delegates API + manage-as-creator mode + `managingCreator` store). AND-360 cannot start its scope/attribution wiring until AND-359 publishes `DelegationStore`/`DelegationContext`. AND-359 → AND-027 (auth/session + interceptor chain).
- **Feature prerequisites:** the feed (AND-097–104), messaging (AND-120+, incl. send AND-124 and conversation list/thread AND-121/123), and broadcast (viewer AND-278–287 and/or host AND-307–318) surfaces must exist to be delegated. AND-360 integrates with whatever of these has landed; surfaces not yet built are wired when they arrive (documented as partial in §13).
- **Platform deps (in place):** `core-network` cookie jar + CSRF + 401-refresh interceptors (the `DelegationInterceptor` slots into this chain), Paging 3, analytics facade, Navigation-Compose host, `core-ui` theming.
- **Blocks:** none recorded in backlog.
- **Sequencing within ticket:** (1) `DelegationInterceptor` + `DelegateAware` tagging + scope helpers + interceptor tests; (2) `DelegationBanner` in `core-ui`; (3) feed delegation wiring + tests; (4) messaging delegation wiring + tests; (5) broadcast delegation wiring + tests; (6) cross-surface context-change/invalidation + 403 auto-exit + Compose UI tests; (7) accessibility + telemetry pass.

## 13. Risks & Open Questions

- **R1 — Attribution transport unverified (primary).** Whether on-behalf-of is a header (`X-On-Behalf-Of`), a query param (`?on_behalf_of=`), or delegated path prefixes is inferred from the web app. *Mitigation:* confirm against `/openapi.json` + `delegates.ts` in step (1); the interceptor centralizes the choice so only one place changes.
- **R2 — Scope vocabulary.** The exact scope strings and their granularity (single `manage` vs per-surface `feed_publish`/`messaging_send`/`broadcast_operate`) must be confirmed with AND-359. *Open question:* if scopes are coarse, collapse the `canX` helpers to the available granularity; `UNKNOWN` keeps it forward-compatible.
- **R3 — Surface availability at integration time.** Some broadcast/host tickets may not have landed when AND-360 runs. *Mitigation:* wire whatever exists; gate not-yet-built surfaces behind their feature flags and document the residual integration as a follow-up.
- **R4 — Revocation timeliness.** Mid-session revocation is only detected on the next call's `403` (no push). *Open question:* is there a delegation event over the SSE stream (AND-143) we should subscribe to for proactive exit? If yes, add a listener; if no, the `403`-driven auto-exit (FR-9) is the contract.
- **R5 — Cache leakage subtlety.** Acting-identity keying must cover every cached read in all three features; a missed key would leak creator data into self view. *Mitigation:* centralize the `actingId` accessor and audit each feature's DAO/DataStore reads during wiring; covered by cache-keying tests.
- **R6 — Unreliable dev host** makes delegated end-to-end QA flaky; mitigated by timeouts, offline states, and MockWebServer-based automated coverage.

## 14. Acceptance Criteria

AC-1. While `managingCreator` is set, feed/broadcast/messaging surfaces show the **managed creator's** data and issue in-scope calls with the on-behalf-of attribution (verified transport per R1) plus `X-CSRF-Token` on writes. *(FR-1, FR-3, §5)*
AC-2. A delegate with `FEED_PUBLISH` can create/cancel a post in the creator's feed; without it, authoring entry points are hidden while read remains. *(FR-4, FR-2)*
AC-3. A delegate with `MESSAGING_READ` sees the creator's conversations/threads and with `MESSAGING_SEND` can send a reply attributed to the creator (composer shows "as <creator>"); without `MESSAGING_SEND` the composer is disabled with explanation. *(FR-6, FR-2)*
AC-4. A delegate with `BROADCAST_OPERATE` can operate the creator's broadcast surface; without it the surface is read/viewer-only. *(FR-5, FR-2)*
AC-5. Every delegated route shows the persistent "Acting as @creator" banner with a working Exit that returns to self context and re-renders in self data. *(FR-7)*
AC-6. Entering/exiting delegate mode invalidates feed/messaging paging and broadcast state so self and creator data never co-mingle, including in caches. *(FR-8, FR-10)*
AC-7. A `403`/revocation on a delegated call triggers a context re-validation; if the delegation is gone the app auto-exits to self context with a clear message; a scope-specific denial disables only that action. *(FR-9, §7)*
AC-8. Idempotent delegated GETs retain bounded retry; delegated POSTs never auto-retry; the attribution header is present on refreshed retries. *(§7)*
AC-9. Tests: interceptor attribution, scope gating, context invalidation, 403 auto-exit, and one action per surface (feed publish, messaging send, broadcast operate) pass against MockWebServer at ≥80% coverage on the delegation wiring. *(§11)*

## 15. Definition of Done

- `DelegationInterceptor` + `DelegateAware` tagging registered in the `core-network` client chain, applying the (R1-confirmed) on-behalf-of transport to delegated feed/broadcast/messaging calls and to refreshed retries.
- `feature-feed`, `feature-broadcast`, and `feature-messaging` ViewModels consume `DelegationStore.managingCreator`, re-key their pagers/state on context change, and gate authoring/send/operate affordances by scope (`UNKNOWN` grants nothing).
- `DelegationBanner` in `core-ui` rendered on every delegated route with a working Exit; messaging composer shows the "as <creator>" badge in delegate+send mode.
- `403`/revocation auto-exit + scope-drift handling implemented; acting-identity cache keying applied across all three features with no self/creator leakage.
- All nine acceptance criteria demonstrably met; interceptor, ViewModel (Turbine), invalidation, 403 auto-exit, cache-keying, and Compose UI tests green at ≥80% coverage on delegation wiring; one end-to-end action per surface passes against MockWebServer.
- No hardcoded strings; accessibility (live-region banner, ≥48dp Exit, disabled-state descriptions, RTL, dynamic type) verified; telemetry emitted without logging post/message content or creator/recipient PII.
- Open questions R1–R5 resolved against `/openapi.json` / `delegates.ts` (or explicitly documented as deferred) before merge; ktlint/detekt clean; builds on `android-port` with AGP 8.7.3 / Gradle 8.9 / JDK 17.
