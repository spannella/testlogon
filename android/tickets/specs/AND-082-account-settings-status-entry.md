---
id: AND-082
title: Account settings & status entry
milestone: M2
epic: E11
priority: P1
size: M
status: draft
depends_on: [AND-077, AND-043]
blocks: []
---

# AND-082 — Account settings & status entry

## 1. Overview & Goal

This ticket delivers the **Account** subsection of the Settings hub for the TestLogon native Android app. It is the single screen a user reaches from the Settings landing (AND-077) to view their account standing and to launch account-lifecycle journeys that live elsewhere.

The Account screen is intentionally a **read-and-route surface**, not a transactional one. It does three things:

1. Renders the authenticated user's **account status** fetched from `GET /ui/account/status` (state, plan/tier, verification flags, creation date, and any standing flags such as suspension or pending closure).
2. Provides **navigation entries** into adjacent flows owned by other tickets: the active-sessions list (AND-043), account **closure** and **reactivation** (epic E50), and **privacy / data export** (E50 / privacy epic).
3. Wraps every **destructive** entry (closure, data deletion) in a strong, unambiguous confirmation gate before deep-linking to the owning flow, so a misfire from this screen can never start an irreversible action.

The goal is a stable, dependency-light hub row set that surfaces truthful account state and hands off cleanly. No closure, reactivation, or export *execution* logic is implemented here — those are explicit handoffs. Success means: status renders accurately for every documented account state, navigation entries route to the correct destinations (or to placeholder routes when the destination ticket is not yet merged), and destructive entries require an explicit confirm.

## 2. Context & References

- **Module:** `feature-settings` (Gradle module `:feature:settings`), package `com.testlogon.android.feature.settings.account`.
- **Upstream dependency AND-077 (Settings hub IA):** owns the Settings landing and the navigation graph node `settings/account`. This ticket plugs the Account screen into that route. Section/row IA conventions (icon + title + supporting text + trailing chevron, Material 3 `ListItem`) are inherited from AND-077.
- **Upstream dependency AND-043 (Active sessions list + revoke):** owns `GET /ui/sessions` and the sessions UI. This ticket only links to its route (`settings/sessions`); it must not duplicate session-fetch logic.
- **Handoff to epic E50 (account lifecycle):** closure, reactivation, and data-export *flows*. This ticket renders the entry rows and the confirm gate, then deep-links. Destination routes are referenced by stable name and may resolve to a "coming soon" placeholder until E50 lands.
- **Backend:** FastAPI + DynamoDB. Dev host `http://18.222.237.167:8000` (plaintext HTTP, unreliable). OpenAPI at `/openapi.json`. Web reference: `frontend/src/api/endpoints/account.ts` and shared types in `frontend/src/api/types.ts` — mirror field names and the `detail` error shape.
- **Auth:** cookie-based session (`ui_csrf` echoed as `X-CSRF-Token`); `core-network` interceptor handles the single `POST /ui/session/refresh` retry on 401 and the persistent cookie jar. This screen makes only authenticated `GET` requests and inherits that behavior.
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Navigation-Compose, Hilt (KSP), Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15, Room 2.6 + DataStore, Coroutines/Flow. minSdk 24, compileSdk/targetSdk 35, JDK 17, AGP 8.7.3, Gradle 8.9.

## 3. Functional Requirements

FR-1 **Status display.** On entry the screen fetches `GET /ui/account/status` and renders: account state (e.g. `active`, `suspended`, `pending_closure`, `closed`), display name / email, plan/tier label, email-verified and MFA-enabled badges, and account creation date (localized).

FR-2 **State banner.** Non-`active` states render a prominent status banner above the row list: `suspended` (error color, reason text if present), `pending_closure` (warning color, with the scheduled closure date and a "Reactivate" affordance that deep-links to E50 reactivation), and `closed` (informational, with reactivation entry).

FR-3 **Sessions entry.** A row "Active sessions" with supporting text showing the count (`"N active devices"` when known) navigates to `settings/sessions` (AND-043). Count comes from `account/status` if exposed, otherwise the supporting text is omitted (no extra network call from this screen).

FR-4 **Closure entry.** A row "Close account" (destructive styling) opens a strong confirmation dialog; on confirm it deep-links to the E50 closure flow route. The row is hidden/disabled when state is already `closed` or `pending_closure` (in `pending_closure` it is replaced by a "Cancel scheduled closure" entry that also hands off to E50).

FR-5 **Reactivation entry.** Shown only when state is `pending_closure` or `closed`. Deep-links to the E50 reactivation route. Reactivation is *not* treated as destructive (no confirm gate beyond the destination's own).

FR-6 **Privacy / data-export entry.** A row "Privacy & data export" navigates to the privacy/export route (handoff). The "Request data export" sub-action and the "Delete my data" sub-action (destructive) are owned downstream; this screen only routes.

FR-7 **Strong confirm gate.** Every destructive entry (close account, delete data when surfaced here) requires a confirmation dialog before any navigation. The dialog states the consequence in plain language and requires an explicit affirmative tap; the default/focused button is the non-destructive (cancel) action.

FR-8 **Loading / empty / error / offline states.** The screen shows a skeleton while loading, a typed error state with retry for failures, and a stale banner when rendering cached status offline.

FR-9 **Pull-to-refresh** re-fetches status.

## 4. Technical Design

The screen follows the project pattern: a Hilt-injected `ViewModel` exposing `StateFlow<AccountUiState>`, a repository over a Retrofit service returning `ApiResult<T>`, and a stateless Composable driven by the state.

```kotlin
// core-model
data class AccountStatus(
    val accountId: String,
    val state: AccountState,          // ACTIVE, SUSPENDED, PENDING_CLOSURE, CLOSED, UNKNOWN
    val displayName: String?,
    val email: String,
    val emailVerified: Boolean,
    val mfaEnabled: Boolean,
    val planTier: String?,            // e.g. "free", "pro"
    val createdAt: Instant,
    val activeSessionCount: Int?,     // null when backend omits it
    val closureScheduledAt: Instant?, // present iff state == PENDING_CLOSURE
    val suspensionReason: String?,    // present iff state == SUSPENDED
)

enum class AccountState { ACTIVE, SUSPENDED, PENDING_CLOSURE, CLOSED, UNKNOWN }
```

```kotlin
// feature-settings/account
sealed interface AccountUiState {
    data object Loading : AccountUiState
    data class Error(val message: String, val retryable: Boolean) : AccountUiState
    data class Ready(
        val status: AccountStatus,
        val isStale: Boolean,
        val isRefreshing: Boolean,
        val pendingConfirm: DestructiveAction? = null,
    ) : AccountUiState
}

enum class DestructiveAction { CLOSE_ACCOUNT, DELETE_DATA }
```

```kotlin
@HiltViewModel
class AccountViewModel @Inject constructor(
    private val repo: AccountRepository,
    private val nav: SettingsNavRouter,        // from AND-077
) : ViewModel() {
    val uiState: StateFlow<AccountUiState>

    fun refresh()
    fun onSessionsClicked()                    // -> nav.toSessions()  (AND-043)
    fun onPrivacyClicked()                     // -> nav.toPrivacy()
    fun onReactivateClicked()                  // -> nav.toReactivation() (E50)
    fun requestDestructive(action: DestructiveAction)   // sets pendingConfirm
    fun dismissConfirm()
    fun confirmDestructive()                   // -> nav.toClosure()/toDataDeletion() (E50)
}
```

```kotlin
// core-data
interface AccountRepository {
    fun observeStatus(): Flow<ApiResult<AccountStatus>>   // cache-then-network
    suspend fun refreshStatus(): ApiResult<AccountStatus>
}
```

```kotlin
// Composables
@Composable fun AccountScreen(vm: AccountViewModel = hiltViewModel())
@Composable fun AccountScreenContent(
    state: AccountUiState,
    onEvent: (AccountEvent) -> Unit,
)
@Composable private fun AccountStatusBanner(state: AccountState, status: AccountStatus)
@Composable private fun DestructiveConfirmDialog(action: DestructiveAction, onConfirm: () -> Unit, onDismiss: () -> Unit)
```

**Navigation.** AND-077 owns the nav graph. This ticket registers `composable("settings/account") { AccountScreen() }` and consumes a `SettingsNavRouter` interface (provided by AND-077) with methods `toSessions()`, `toPrivacy()`, `toClosure()`, `toReactivation()`, `toDataDeletion()`. Routes that belong to E50 are declared as constants now; if the destination composable is not yet registered, the router resolves to a shared `settings/placeholder?feature={name}` route so navigation never crashes. Reactivation/closure passing of `closureScheduledAt` is via nav arguments where the destination needs it.

**State mapping.** `AccountState.UNKNOWN` is the fallback for any unrecognized backend string (forward compatibility); UNKNOWN renders status fields it has and hides lifecycle actions. Row visibility is computed purely from `AccountState` per FR-4/FR-5.

## 5. API Contract

This screen consumes one endpoint; all lifecycle mutations are out of scope (handed to E50).

**`GET /ui/account/status`** — authenticated (cookies + `X-CSRF-Token`). Idempotent GET, eligible for bounded backoff retry.

Response `200`:
```json
{
  "account_id": "acct_8f3a...",
  "state": "active",
  "display_name": "Sean P.",
  "email": "spannella@gmail.com",
  "email_verified": true,
  "mfa_enabled": true,
  "plan_tier": "pro",
  "created_at": "2024-11-02T14:21:09Z",
  "active_session_count": 3,
  "closure_scheduled_at": null,
  "suspension_reason": null
}
```

`pending_closure` variant:
```json
{ "state": "pending_closure", "closure_scheduled_at": "2026-07-01T00:00:00Z", "...": "..." }
```

Moshi adapter maps snake_case → camelCase; `state` parsed via a custom adapter to `AccountState` (unknown → `UNKNOWN`). Nullable fields (`display_name`, `plan_tier`, `active_session_count`, `closure_scheduled_at`, `suspension_reason`) are optional. Validate exact field names against `/openapi.json` and `frontend/src/api/types.ts` during implementation; adjust the data class if the live schema differs (open question OQ-1).

```kotlin
interface AccountApi {
    @GET("ui/account/status")
    suspend fun getStatus(): Response<AccountStatusDto>
}
```

Error body (FastAPI `detail`, handled by the shared mapper): `string`, `[{ "msg": "..." }]`, or `{ "code": "...", ... }`. Expected non-200s: `401` (interceptor refreshes once then retries; persistent 401 → route to auth), `403`, `5xx` / timeout → `Error(retryable = true)`.

`GET /ui/sessions` is referenced only by name — it is owned by AND-043 and **not** called from this screen.

## 6. Data & State Management

- **Source of truth:** `AccountRepository.observeStatus()` emits cache-then-network. Status is cached in Room (table `account_status`, single row keyed by `account_id`) with a `fetched_at` timestamp so offline/stale UI (FR-8) can render last-known values. TTL for "fresh" is 5 minutes; older cache renders with `isStale = true`.
- **DataStore** is not used here for account data (it holds prefs only); no account PII is persisted to DataStore.
- **StateFlow:** `uiState` is built with `stateIn(viewModelScope, WhileSubscribed(5_000), Loading)`. Network results merge into `Ready` preserving `pendingConfirm` so a config change mid-dialog keeps the confirm visible.
- **Refresh:** `refresh()` sets `isRefreshing = true` on the current `Ready` and calls `refreshStatus()`; on failure while a cached value exists, keep `Ready` and surface a transient snackbar rather than dropping to `Error`.
- **Cache invalidation:** when E50 flows complete a closure/reactivation, they should invalidate this cache; expose `AccountRepository.invalidate()` for that cross-feature contract (consumed by E50, not implemented-against here beyond the method).

## 7. Error Handling & Resilience

- **Timeouts:** inherit the 20s OkHttp timeout for the unreliable dev host. The status GET is idempotent → eligible for the shared bounded-backoff retry (max 2 retries, jittered) on network/5xx.
- **401:** handled by the `core-network` authenticator (single `POST /ui/session/refresh` then retry). Unrecoverable 401 → emit a one-shot nav event to re-auth; do not render stale account state to a logged-out user.
- **Offline / no cache:** `Error(message = "You're offline", retryable = true)` with a Retry button.
- **Offline / with cache:** render `Ready(isStale = true)` plus a dismissible stale banner ("Showing last saved info").
- **Malformed/unknown state:** `AccountState.UNKNOWN` — render available fields, hide lifecycle rows, log a non-fatal.
- **Navigation safety:** destructive deep-links are gated behind `confirmDestructive()`; a missing E50 destination resolves to the placeholder route (no crash). Double-tap on a destructive row is debounced and the confirm dialog is single-instance via `pendingConfirm`.

## 8. Security & Privacy

- Screen renders PII (email, display name, account id). No new persistence beyond the encrypted-at-rest expectations of Room; do **not** log PII (see §10).
- All requests carry session cookies and the `X-CSRF-Token` header via the shared client; this screen adds no auth handling of its own.
- **Destructive-action principle:** this screen never performs closure/deletion; it only routes after an explicit confirm. This keeps the irreversible-action surface concentrated in E50 where re-authentication/step-up can be enforced. The confirm dialog here is a UX guard, not the security boundary.
- Plaintext HTTP dev host is a known dev-only condition; production config must use HTTPS (enforced by network-security config from core-network, not this ticket).
- Screenshots: consider `FLAG_SECURE` is **not** set here (account status is not high-secrecy); revisit if data-export tokens ever render on this screen (they do not — handed to E50).

## 9. Accessibility & i18n

- All rows use Material 3 `ListItem` with merged semantics: `contentDescription` combining title + supporting text; trailing chevron marked decorative.
- Status badges (verified, MFA, state) carry text labels, not color alone (WCAG 1.4.1). Banner colors paired with an icon + text.
- Destructive rows expose `Role.Button` and announce "destructive" via state description; the confirm dialog traps focus, defaults to Cancel, and the destructive button has an explicit `contentDescription`.
- Minimum touch target 48dp; dynamic type / font scaling supported (no fixed-height rows that clip).
- All strings in `feature-settings` `strings.xml`; dates/numbers via `java.time` + `NumberFormat` with locale. No hardcoded user-facing text. RTL-safe (use start/end paddings).

## 10. Telemetry & Logging

- Events (via the shared analytics interface): `account_status_viewed { state }`, `account_status_load_failed { reason }`, `account_row_clicked { row: sessions|privacy|close|reactivate|delete }`, `account_destructive_confirm_shown { action }`, `account_destructive_confirmed { action }`, `account_destructive_cancelled { action }`.
- Never log email, display name, account id, or suspension reason. `state` enum and `reason` (coarse error category) only.
- Non-fatal breadcrumb on `AccountState.UNKNOWN` (include the raw unrecognized string for schema-drift detection — it is not PII).
- Logcat at DEBUG only via the core logging wrapper; no `println`.

## 11. Testing Strategy

**Unit (ViewModel / repository — core-testing):**
- Maps each `state` value to the correct `AccountUiState.Ready` and correct row visibility (active → close shown; pending_closure → reactivate + cancel-closure shown, close hidden; closed → reactivate shown).
- Unknown `state` string → `UNKNOWN`, lifecycle rows hidden, breadcrumb emitted.
- `requestDestructive` sets `pendingConfirm`; `confirmDestructive` triggers exactly one router call; `dismissConfirm` clears it without navigating.
- Error/timeout → `Error(retryable=true)`; cache-present failure → `Ready(isStale=true)` + snackbar.
- 401 path delegates to interceptor (mocked) and emits re-auth event on persistent failure.

**Repository:** MockWebServer for `GET /ui/account/status` — 200 (all states), 401, 500, malformed JSON, timeout; verify cache-then-network and TTL staleness.

**Compose UI tests:**
- Status, badges, and banner render per state (semantics-based assertions).
- Tapping "Close account" shows the confirm dialog; confirm navigates; the destructive nav does **not** fire without confirm (FR-7, key acceptance test).
- Sessions row navigates to `settings/sessions` (router fake records the route).
- Loading skeleton, error+retry, and stale banner render.

**Coverage target:** ViewModel ≥ 85%. All acceptance criteria in §14 have a named test.

## 12. Dependencies & Sequencing

- **Hard deps:** AND-077 (Settings hub IA — provides the route + `SettingsNavRouter`) and AND-043 (Active sessions list — provides the `settings/sessions` destination). Both should merge first; if AND-043 is not yet merged, the sessions row routes to the placeholder.
- **Soft/handoff:** epic E50 owns closure, reactivation, and data-export/deletion execution. This ticket defines the router method contracts (`toClosure`, `toReactivation`, `toDataDeletion`, `toPrivacy`) and placeholder fallback so it can ship independently and E50 wires real destinations later.
- **Backend:** `GET /ui/account/status` must exist and be confirmed against `/openapi.json`.
- **Blocks:** none currently recorded.

## 13. Risks & Open Questions

- **OQ-1:** Exact schema of `GET /ui/account/status` is assumed from the web reference; verify field names/enum values against `/openapi.json` before finalizing the DTO. Risk: schema drift → mapping bugs (mitigated by `UNKNOWN` fallback + breadcrumb).
- **OQ-2:** Does `account/status` actually expose `active_session_count`? If not, the sessions row drops its supporting text (FR-3) — no extra call permitted from this screen.
- **OQ-3:** E50 route names and argument contracts are not yet final; placeholder fallback mitigates, but final wiring is a follow-up.
- **OQ-4:** Whether "cancel scheduled closure" is a distinct E50 route or a parameter of the closure flow — confirm with E50 owner.
- **Risk:** unreliable dev host causing flaky status loads; mitigated by cache-then-network, stale UI, and bounded retry.
- **Risk:** users perceiving the close-account confirm as the actual deletion; mitigated by copy that says the next screen completes the action.

## 14. Acceptance Criteria

AC-1 Account status renders correctly for each documented state (`active`, `suspended`, `pending_closure`, `closed`), including the appropriate state banner and badges. *(Source acceptance: "Account status shows.")*

AC-2 The "Active sessions" row navigates to the AND-043 sessions destination; no session-fetch logic is duplicated here.

AC-3 Every destructive entry (close account; delete data when surfaced) requires a strong confirmation dialog before navigation, and navigation does not occur on cancel/dismiss. *(Source acceptance: "destructive actions deep-link with strong confirms (handoff).")*

AC-4 Closure, reactivation, and privacy/data-export entries deep-link to their destinations (or the placeholder when the E50 destination is not yet registered) without crashing.

AC-5 Lifecycle row visibility matches state (close hidden when already closed/pending; reactivate shown only for pending/closed).

AC-6 Loading, error+retry, offline-with-cache (stale banner), and pull-to-refresh behaviors all function.

AC-7 No PII is written to analytics or logs; `state`/error-category only.

AC-8 All listed strings are localized and the screen passes accessibility checks (labels not color-only, 48dp targets, focus-trapped confirm defaulting to Cancel).

## 15. Definition of Done

- All §14 acceptance criteria met with corresponding automated tests passing in CI.
- `:feature:settings` Account screen registered under `settings/account` and reachable from the Settings hub (AND-077).
- `GET /ui/account/status` DTO verified against `/openapi.json`; mapper handles all states + unknown fallback.
- Unit + repository (MockWebServer) + Compose UI tests merged; ViewModel coverage ≥ 85%.
- Lint, ktlint/detekt, and accessibility scanner clean; no hardcoded user-facing strings.
- Router method contracts for E50 handoffs documented and placeholder fallback verified.
- No PII in logs/telemetry confirmed by review.
- Code reviewed and merged to `android-port`; OQ-1..OQ-4 either resolved or filed as follow-up tickets referencing E50.
