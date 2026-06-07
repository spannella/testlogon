---
id: AND-082
title: Account settings & status entry
milestone: M2
epic: E11
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-077, AND-043]
blocks: []
---

# AND-082 — Account settings & status entry

## 1. Overview & Goal

This ticket delivers the **Account** subsection of the Settings hub for the TestLogon native Android app. It is the single screen a user reaches from the Settings landing (AND-077) to view their account standing and to launch account-lifecycle journeys that live elsewhere.

The Account screen is intentionally a **read-and-route surface**, not a transactional one. It does three things:

1. Renders the authenticated user's **account status** fetched from `GET /ui/account/status`. **[CORRECTED]** The live backend response is intentionally minimal — `{ status, reason?, updated_at?, closed_at? }` (see §5 verified against `frontend/src/api/types.ts: AccountState`) — so this screen surfaces the account **state** string, an optional **reason** (used for suspension), a **last-updated** timestamp, and a **closed-at** timestamp when closed. The richer fields originally drafted here (email, display name, plan/tier, email-verified / MFA badges, creation date, active-session count) are **NOT returned by this endpoint** and have been removed/flagged; any that the screen still wants must come from a different endpoint (out of scope) or be dropped.
2. Provides **navigation entries** into adjacent flows owned by other tickets: the active-sessions list (AND-043), account **closure** and **reactivation** (epic E50), and **privacy / data export** (E50 / privacy epic).
3. Wraps every **destructive** entry (closure, data deletion) in a strong, unambiguous confirmation gate before deep-linking to the owning flow, so a misfire from this screen can never start an irreversible action.

The goal is a stable, dependency-light hub row set that surfaces truthful account state and hands off cleanly. No closure, reactivation, or export *execution* logic is implemented here — those are explicit handoffs. **[NOTE]** The closure/reactivate/suspend endpoints *do* exist on the backend today (`POST /ui/account/closure/start` + `/closure/finalize`, `POST /ui/account/reactivate`, `POST /ui/account/suspend` — verified in OpenAPI and exercised in `frontend/src/pages/settings/Account.tsx`). Routing these mutations to E50 rather than calling them here is an Android-side architecture decision, not a backend limitation. Success means: status renders accurately for every documented account state, navigation entries route to the correct destinations (or to placeholder routes when the destination ticket is not yet merged), and destructive entries require an explicit confirm.

## 2. Context & References

- **Module:** `feature-settings` (Gradle module `:feature:settings`), package `com.testlogon.android.feature.settings.account`.
- **Upstream dependency AND-077 (Settings hub IA):** owns the Settings landing and the navigation graph node `settings/account`. This ticket plugs the Account screen into that route. Section/row IA conventions (icon + title + supporting text + trailing chevron, Material 3 `ListItem`) are inherited from AND-077.
- **Upstream dependency AND-043 (Active sessions list + revoke):** owns `GET /ui/sessions` and the sessions UI. This ticket only links to its route (`settings/sessions`); it must not duplicate session-fetch logic.
- **Handoff to epic E50 (account lifecycle):** closure, reactivation, and data-export *flows*. This ticket renders the entry rows and the confirm gate, then deep-links. Destination routes are referenced by stable name and may resolve to a "coming soon" placeholder until E50 lands.
- **Backend:** FastAPI + DynamoDB. Dev host `http://18.222.237.167:8000` (plaintext HTTP, unreliable). OpenAPI at `/openapi.json`. Web reference: `frontend/src/api/endpoints/account.ts` and shared types in `frontend/src/api/types.ts` — mirror field names and the `detail` error shape.
- **Auth:** cookie-based session (`ui_csrf` echoed as `X-CSRF-Token`); `core-network` interceptor handles the single `POST /ui/session/refresh` retry on 401 and the persistent cookie jar. This screen makes only authenticated `GET` requests and inherits that behavior.
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Navigation-Compose, Hilt (KSP), Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15, Room 2.6 + DataStore, Coroutines/Flow. minSdk 24, compileSdk/targetSdk 35, JDK 17, AGP 8.7.3, Gradle 8.9.

## 3. Functional Requirements

FR-1 **Status display.** **[CORRECTED]** On entry the screen fetches `GET /ui/account/status` and renders the available fields only: account **state** string (verified values: `active`, `suspended`, `closure_pending`, `closed` — see web reference `statusVariant()` in `Account.tsx`), an optional **reason** string (suspension reason), a **last-updated** timestamp (`updated_at`, epoch **seconds**), and a **closed-at** timestamp (`closed_at`, epoch seconds) when present. Display name, email, plan/tier, email-verified / MFA badges, and "creation date" are **not** returned by this endpoint and must NOT be claimed as rendered here; if product still wants them they require a separate profile/me endpoint (out of scope, see OQ-2).

FR-2 **State banner.** **[CORRECTED]** Non-`active` states render a prominent status banner above the row list: `suspended` (warning color in the web ref `statusVariant`, with `reason` text if present), `closure_pending` (danger color; **no scheduled-closure date field exists** in the response — `closed_at` is only populated once `closed` — so the banner shows generic pending-closure copy plus a "Reactivate"/lifecycle affordance handed to E50), and `closed` (danger color, with `closed_at` shown when present and a reactivation entry). Note the backend value is `closure_pending`, NOT `pending_closure`.

FR-3 **Sessions entry.** A row "Active sessions" navigates to `settings/sessions` (AND-043). **[CORRECTED]** `GET /ui/account/status` does **not** expose any session count, so the supporting-text count is **not available from this endpoint**; the row shows a static/secondary label only (no extra network call from this screen). Session data lives behind `GET /ui/sessions` (AND-043).

FR-4 **Closure entry.** A row "Close account" (destructive styling) opens a strong confirmation dialog; on confirm it deep-links to the E50 closure flow route. The row is hidden/disabled when state is already `closed` or `closure_pending` (matching the web ref, which disables the close button for `closed`/`closure_pending`). **[CORRECTED]** There is **no dedicated "cancel scheduled closure" endpoint** in the backend (OpenAPI has only `closure/start`, `closure/finalize`, `reactivate`, `suspend`); a "Cancel scheduled closure" affordance, if surfaced, must hand off to E50 to decide whether that maps to `reactivate` or a future endpoint (see OQ-4). The real web closure flow is a **two-step** `closure/start` → `closure/finalize` with a `challenge_id` step-up; this screen does not implement it (handoff to E50).

FR-5 **Reactivation entry.** **[CORRECTED]** Shown when state is `suspended`, `closure_pending`, or `closed`. (In the web reference, "Reactivate" is the affordance shown for `suspended` accounts and calls `POST /ui/account/reactivate` with an optional `reason`.) On Android this deep-links to the E50 reactivation route. Reactivation is *not* treated as destructive (no confirm gate beyond the destination's own).

FR-6 **Privacy / data-export entry.** A row "Privacy & data export" navigates to the privacy/export route (handoff). The "Request data export" sub-action and the "Delete my data" sub-action (destructive) are owned downstream; this screen only routes.

FR-7 **Strong confirm gate.** Every destructive entry (close account, delete data when surfaced here) requires a confirmation dialog before any navigation. The dialog states the consequence in plain language and requires an explicit affirmative tap; the default/focused button is the non-destructive (cancel) action.

FR-8 **Loading / empty / error / offline states.** The screen shows a skeleton while loading, a typed error state with retry for failures, and a stale banner when rendering cached status offline.

FR-9 **Pull-to-refresh** re-fetches status.

## 4. Technical Design

The screen follows the project pattern: a Hilt-injected `ViewModel` exposing `StateFlow<AccountUiState>`, a repository over a Retrofit service returning `ApiResult<T>`, and a stateless Composable driven by the state.

```kotlin
// core-model
// [CORRECTED] shape mirrors frontend/src/api/types.ts: AccountState
//   { status: string; reason?: string; updated_at?: number; closed_at?: number }
// updated_at / closed_at are epoch SECONDS (web does new Date(updated_at * 1000)).
data class AccountStatus(
    val state: AccountState,          // ACTIVE, SUSPENDED, CLOSURE_PENDING, CLOSED, UNKNOWN
    val reason: String?,              // optional; used for suspension reason
    val updatedAt: Instant?,          // from updated_at (epoch seconds), nullable
    val closedAt: Instant?,           // from closed_at (epoch seconds), present when closed
)
// REMOVED (not in the live response): accountId, displayName, email,
// emailVerified, mfaEnabled, planTier, createdAt, activeSessionCount,
// closureScheduledAt, suspensionReason (folded into `reason`).

enum class AccountState { ACTIVE, SUSPENDED, CLOSURE_PENDING, CLOSED, UNKNOWN }
// Backend strings: "active", "suspended", "closure_pending", "closed" (NOT "pending_closure").
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

**`GET /ui/account/status`** — authenticated (cookies + `X-CSRF-Token`). Idempotent GET, eligible for bounded backoff retry. Verified in OpenAPI: `GET /ui/account/status | op=account_status_ui_account_status_get | resp=200:;422:HTTPValidationError`. Optional params on the endpoint: `user_sub` (query), `X-SESSION-ID` / `X-IMPERSONATION-TOKEN` (headers) — none required for the normal authenticated user; the mobile client does not send them.

**[CORRECTED] Response `200`.** The OpenAPI 200 schema is **untyped** (`"schema": {}`), so the authoritative contract is the web client type `frontend/src/api/types.ts: AccountState`:
```json
{
  "status": "active",
  "reason": null,
  "updated_at": 1730557269,
  "closed_at": null
}
```
- `status` (string, required) — the account state. Known values from `Account.tsx`: `active`, `suspended`, `closed`, `closure_pending`.
- `reason` (string, optional) — present for `suspended` (set via `POST /ui/account/suspend { reason? }`).
- `updated_at` (number, optional) — **epoch seconds**; web renders `new Date(updated_at * 1000)`.
- `closed_at` (number, optional) — **epoch seconds**; populated only when `status == "closed"`.

There is **no** `account_id`, `display_name`, `email`, `email_verified`, `mfa_enabled`, `plan_tier`, `created_at`, `active_session_count`, or `closure_scheduled_at` in this response. The prior draft's rich JSON was an unverified assumption and has been removed.

Moshi: map `status` via a custom adapter to `AccountState` (unknown → `UNKNOWN`); decode `updated_at`/`closed_at` from epoch-seconds longs to `Instant` (`Instant.ofEpochSecond`). Because the 200 schema is untyped server-side (OQ-1), keep the `UNKNOWN` fallback and tolerate additive fields.

```kotlin
@JsonClass(generateAdapter = true)
data class AccountStatusDto(
    @Json(name = "status") val status: String,
    @Json(name = "reason") val reason: String? = null,
    @Json(name = "updated_at") val updatedAt: Long? = null,  // epoch seconds
    @Json(name = "closed_at") val closedAt: Long? = null,    // epoch seconds
)

interface AccountApi {
    @GET("ui/account/status")
    suspend fun getStatus(): Response<AccountStatusDto>
}
```

Error body (FastAPI `detail`, handled by the shared mapper): `string`, `[{ "msg": "..." }]`, or `{ "code": "...", ... }`. **[VERIFIED against `frontend/src/api/client.ts: normalizeErrorDetail`]** — all three shapes are handled there. OpenAPI documents `422:HTTPValidationError` for this endpoint; `401`/`403`/`5xx` are platform-level (not enumerated per-path). Expected non-200s on Android: `401` (authenticator refreshes once via `POST /ui/session/refresh` then retries; persistent 401 → route to auth — matches `client.ts`), `403` → permission/geo error, `422` → validation error (mapped from `detail`), `5xx` / timeout → `Error(retryable = true)`.

`GET /ui/sessions` is referenced only by name — verified to exist (`GET /ui/sessions | op=ui_sessions_ui_sessions_get`), owned by AND-043 and **not** called from this screen.

## 6. Data & State Management

- **Source of truth:** `AccountRepository.observeStatus()` emits cache-then-network. Status is cached in Room (table `account_status`, **single-row** table with a fixed primary key — **[CORRECTED]** the response has no `account_id` to key on; use a constant key, e.g. `id = 0`) with a `fetched_at` timestamp so offline/stale UI (FR-8) can render last-known values. TTL for "fresh" is 5 minutes; older cache renders with `isStale = true`.
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

- **[CORRECTED]** The status endpoint returns no email/display-name/account-id, so this screen renders little-to-no direct PII from `/ui/account/status` (just `state`, a `reason` string that may be user-authored, and timestamps). Treat `reason` as potentially sensitive (free text). No new persistence beyond the encrypted-at-rest expectations of Room; do **not** log `reason` or any account PII (see §10).
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
- Maps each `state` value to the correct `AccountUiState.Ready` and correct row visibility (active → close shown; closure_pending → reactivate + cancel-closure shown, close hidden; closed → reactivate shown; suspended → reactivate shown).
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

- **OQ-1:** **[PARTLY RESOLVED]** Field names/enum values now verified against `frontend/src/api/types.ts: AccountState` and `frontend/src/pages/settings/Account.tsx` (`{ status, reason?, updated_at?, closed_at? }`; states `active|suspended|closed|closure_pending`). Residual risk: the OpenAPI 200 schema for this path is **untyped** (`"schema": {}`), so the server contract is not machine-enforced and could drift; mitigated by `UNKNOWN` fallback + breadcrumb. Confirm with backend whether additional fields are ever returned.
- **OQ-2:** ~~Does `account/status` expose `active_session_count`?~~ **RESOLVED (no).** Verified against `frontend/src/api/types.ts: AccountState` and the OpenAPI untyped 200 — the response is `{ status, reason?, updated_at?, closed_at? }` with no session count and no profile fields. The sessions row therefore has no supporting count (FR-3 updated). If a count is ever required it must come from `GET /ui/sessions` (AND-043) or a profile endpoint — out of scope here.
- **OQ-3:** E50 route names and argument contracts are not yet final; placeholder fallback mitigates, but final wiring is a follow-up.
- **OQ-4:** Whether "cancel scheduled closure" is a distinct E50 route or a parameter of the closure flow — confirm with E50 owner.
- **Risk:** unreliable dev host causing flaky status loads; mitigated by cache-then-network, stale UI, and bounded retry.
- **Risk:** users perceiving the close-account confirm as the actual deletion; mitigated by copy that says the next screen completes the action.

## 14. Acceptance Criteria

AC-1 Account status renders correctly for each documented state (`active`, `suspended`, `closure_pending`, `closed` — **[CORRECTED]** value is `closure_pending`, not `pending_closure`), including the appropriate state banner and the `reason`/`updated_at`/`closed_at` fields when present. (No email/MFA/plan "badges" — those fields are not returned by the endpoint.) *(Source acceptance: "Account status shows.")*

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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer. Sources: OpenAPI index/spec (`reference/openapi.index.txt`, `reference/openapi.pretty.json`) and the frontend reference app (`reference/src/...`).

1. **`GET /ui/account/status` exists and is the status endpoint.** VERIFIED. OpenAPI `GET /ui/account/status` (op=`account_status_ui_account_status_get`); `frontend/src/api/endpoints/account.ts: getAccountStatus`.
2. **Status response shape is `{ status, reason?, updated_at?, closed_at? }`.** CORRECTED (was a rich DTO with email/displayName/plan/badges/createdAt/sessionCount/closureScheduledAt). Source: `frontend/src/api/types.ts: AccountState`. The OpenAPI 200 schema is **untyped** (`"schema": {}` in `openapi.pretty.json` at `/ui/account/status` → responses → 200), so the web type is authoritative.
3. **`updated_at` / `closed_at` are epoch seconds (numbers), not ISO-8601 strings.** CORRECTED. Source: `frontend/src/pages/settings/Account.tsx` renders `new Date(statusQuery.data.updated_at * 1000)` and `closed_at * 1000`.
4. **Account state values are `active`, `suspended`, `closed`, `closure_pending`.** CORRECTED (spec used `pending_closure`). Source: `frontend/src/pages/settings/Account.tsx: statusVariant()` switch + the `closure_pending`/`closed` disabled-button checks.
5. **Status endpoint does NOT return an active-session count.** CORRECTED (resolves OQ-2). Source: `frontend/src/api/types.ts: AccountState` (no such field); session data is `GET /ui/sessions`.
6. **Status endpoint does NOT return email/displayName/plan/email_verified/mfa_enabled/created_at/account_id.** CORRECTED. Source: `frontend/src/api/types.ts: AccountState`.
7. **CSRF: `ui_csrf` cookie echoed as `X-CSRF-Token` header.** VERIFIED. Source: `frontend/src/api/client.ts` (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`). Note: web sets it on every request (incl. GET), matching the spec.
8. **401 handling: single `POST /ui/session/refresh` then one retry; persistent 401 → logout/re-auth.** VERIFIED. Source: `frontend/src/api/client.ts: refreshSession()` + the 401 branch (`refreshPromise`, single retry, `logout("session_expired")`). OpenAPI `POST /ui/session/refresh` (op=`ui_session_refresh_ui_session_refresh_post`).
9. **Error `detail` shapes: `string` | `[{ msg }]` | `{ code, ... }`.** VERIFIED. Source: `frontend/src/api/client.ts: normalizeErrorDetail()` (handles all three) and `mapAuthorizationError()` (object-with-`code`). OpenAPI documents `422:HTTPValidationError` per path.
10. **Network/offline → distinct error (not a thrown HTTP code).** VERIFIED. Source: `frontend/src/api/client.ts` catch → `new ApiError(0, "Network error")`.
11. **`GET /ui/sessions` is the sessions endpoint, owned by AND-043, not called here.** VERIFIED. OpenAPI `GET /ui/sessions` (op=`ui_sessions_ui_sessions_get`).
12. **Closure is a real two-step backend flow with step-up: `closure/start` → `closure/finalize` (challenge_id).** VERIFIED. OpenAPI `POST /ui/account/closure/start` (req empty) and `POST /ui/account/closure/finalize` (req=`AccountClosureFinalizeReq` = `{ challenge_id }`); `frontend/src/api/endpoints/account.ts` (`startAccountClosure` returns `{ auth_required, challenge_id, required_factors }`, `finalizeAccountClosure({ challenge_id })`) and `frontend/src/pages/settings/Account.tsx` two-step UI. The E50 handoff is therefore an Android design choice, not a backend constraint.
13. **`POST /ui/account/reactivate` accepts an optional `reason` (`AccountStatusReq`).** VERIFIED. OpenAPI `POST /ui/account/reactivate` (req=`AccountStatusReq`); `frontend/src/api/types.ts: AccountStatusReq = { reason? }`; `frontend/src/api/endpoints/account.ts: reactivateAccount`.
14. **No dedicated "cancel scheduled closure" endpoint exists.** VERIFIED (resolves OQ-4 direction). Source: OpenAPI lifecycle set is only `closure/start`, `closure/finalize`, `reactivate`, `suspend` (grep `/ui/account/` in `openapi.index.txt`). Any "cancel closure" must map to one of these or a future endpoint (E50 decision).
15. **Privacy / data-export destinations exist.** VERIFIED. OpenAPI `POST /ui/privacy/account-deletion/export` (req=`PrivacyExportRequestIn`, resp `PrivacyExportStatusOut`), `POST /ui/privacy/account-deletion/request` (resp `AccountDeletionStatusOut`), `POST /ui/privacy/delete-account` (req=`DeleteAccountRequestIn`); `frontend/src/api/endpoints/accountDeletion.ts`.
16. **Reactivate affordance in the web app is shown for `suspended`.** VERIFIED. Source: `frontend/src/pages/settings/Account.tsx` (status === "suspended" → "Reactivate Account" button). FR-5 widened accordingly.
17. **Compose/Material 3, Navigation-Compose, Hilt/KSP, Retrofit/OkHttp/Moshi, Room/DataStore stack.** UNVERIFIED-ASSUMPTION (framework ref). Project-level convention inherited from AND-077; not derivable from backend/frontend sources. Android framework refs: Compose `https://developer.android.com/jetpack/compose`, Navigation-Compose `https://developer.android.com/jetpack/compose/navigation`, Room `https://developer.android.com/training/data-storage/room`.
18. **`FLAG_SECURE` not required (low secrecy).** UNVERIFIED-ASSUMPTION (product/security judgement). Framework ref: `https://developer.android.com/reference/android/view/WindowManager.LayoutParams#FLAG_SECURE`.
19. **`SettingsNavRouter` interface + `settings/account` route + placeholder fallback come from AND-077.** UNVERIFIED-ASSUMPTION (cross-ticket contract; AND-077 spec not in these sources).
20. **Bearer token also sent alongside cookies.** NOTE / partly-divergent. `client.ts` sets `Authorization: Bearer` from an auth store in addition to cookies + CSRF; the spec frames auth as cookie-only. On Android the `core-network` layer owns this; treat exact token transport as an AND-077/core-network contract (unverified here).

### Corrections made
- **State value rename:** `pending_closure` → `closure_pending` throughout (FR-2, FR-4, FR-5, §4 enum, §11, AC-1). Backend/web use `closure_pending`.
- **Response schema rewrite (§5, §1, §3, §4):** removed the fabricated rich DTO/JSON; replaced with the real `{ status, reason?, updated_at?, closed_at? }` and an accurate `AccountStatusDto`. Timestamps are epoch **seconds**, not ISO strings.
- **FR-1/FR-2/FR-3:** removed claims of rendering email/display-name/plan/MFA/email-verified badges, creation date, scheduled-closure date, and session count — none are returned by the endpoint.
- **FR-5:** widened reactivation visibility to include `suspended` (matches web).
- **FR-4 / OQ-4:** noted no dedicated "cancel scheduled closure" endpoint; closure is a real two-step `start`→`finalize` step-up flow.
- **§6 cache key:** single-row table cannot key on `account_id` (not returned) → fixed PK constant.
- **§8 privacy:** corrected the "renders PII (email, display name, account id)" claim — the endpoint returns none of those; flagged `reason` as the only sensitive free-text field.
- **OQ-1 / OQ-2:** marked resolved/partly-resolved with sources.

### Open assumptions
- **OQ-1 residual:** OpenAPI 200 schema for `/ui/account/status` is untyped (`{}`); the server contract is not machine-verified and may add fields. Mitigated by `UNKNOWN` + tolerant parsing.
- **AND-077 contract:** `SettingsNavRouter`, the `settings/account` graph node, and the `settings/placeholder?feature=` fallback are assumed from AND-077 (spec not present in sources).
- **E50 routes/args:** closure/reactivation/data-deletion route names and nav-argument contracts are not final (OQ-3); placeholder fallback mitigates.
- **Exact auth transport on Android (cookie-only vs cookie+Bearer):** owned by core-network/AND-077; web uses both. Not verifiable from the provided sources.
- **Android framework choices** (Compose/Hilt/Room/etc.) are conventions, cited to Android docs, not to the backend/frontend sources.

## 17. Test Plan

Test targets: **JVM** = JVM unit/Robolectric (local, no device); **MWS** = contract via MockWebServer (JVM); **emulator(test35)** = headless AVD x86_64 API 35; **device(A15)** = physical Samsung Galaxy A15 5G (SM-A156U, serial R5CX821TA9R), Android 14 / API 34, arm64-v8a. This screen has no camera/biometric/FCM/WebRTC/Telecom needs, so most instrumented work runs on the **emulator**; one ABI/API-parity case is pinned to the **device**.

**TC-AND-082-01** — Type: unit (JVM). Target: `AccountViewModel` mapping. Preconditions: repo fake returns `AccountStatusDto(status="active", reason=null, updatedAt=…, closedAt=null)`. Steps: collect `uiState`. Expected: `Ready(state=ACTIVE)`, close-account row shown, reactivate/cancel-closure rows hidden. Traces: AC-1, AC-5.

**TC-AND-082-02** — Type: unit (JVM). Target: state→row-visibility for all states. Preconditions: parametrize `status` over `active|suspended|closure_pending|closed`. Steps: map each. Expected: active→close shown; suspended→reactivate shown; closure_pending→reactivate + cancel-closure shown, close hidden; closed→reactivate shown, close hidden. Banner color/role matches §FR-2. Traces: AC-1, AC-5.

**TC-AND-082-03** — Type: unit (JVM). Target: unknown-state forward-compat. Preconditions: `status="frozen_pending_review"` (unrecognized). Steps: map. Expected: `state=UNKNOWN`, lifecycle rows hidden, available fields still rendered, non-fatal breadcrumb emitted carrying the raw string. Traces: AC-1, AC-5, AC-7.

**TC-AND-082-04** — Type: contract/MockWebServer (MWS). Target: `AccountApi.getStatus` + Moshi mapping. Preconditions: MWS returns `200 {"status":"suspended","reason":"policy review","updated_at":1730557269}`. Steps: call repo. Expected: DTO maps to `AccountStatus(state=SUSPENDED, reason="policy review", updatedAt=Instant.ofEpochSecond(1730557269), closedAt=null)`; epoch-seconds decoded (not millis). Traces: AC-1.

**TC-AND-082-05** — Type: contract/MockWebServer (MWS). Target: closed-state with `closed_at`. Preconditions: MWS returns `200 {"status":"closed","closed_at":1751328000}`. Steps: call repo. Expected: `state=CLOSED`, `closedAt` populated; close-account row hidden, reactivate shown. Traces: AC-1, AC-5.

**TC-AND-082-06** — Type: contract/MockWebServer (MWS). Target: error mapping (422 + FastAPI detail shapes). Preconditions: MWS returns `422 {"detail":[{"msg":"bad request"}]}`, then a run with `{"detail":"nope"}`, then `{"detail":{"code":"role_required"}}`. Steps: call repo each time. Expected: each maps to a typed `Error` with a human message via the shared mapper (mirrors `normalizeErrorDetail`); no crash on any shape. Traces: AC-6, AC-7.

**TC-AND-082-07** — Type: contract/MockWebServer (MWS). Target: 401 refresh-then-retry. Preconditions: MWS scripts `401`, then (after `POST /ui/session/refresh` → `200`) the retried status `GET` → `200`. Steps: call repo while "authenticated". Expected: exactly one refresh call, original request retried once, success surfaced; on a second persistent `401` a re-auth one-shot event is emitted and stale account state is NOT rendered. Traces: AC-6, AC-7.

**TC-AND-082-08** — Type: contract/MockWebServer (MWS). Target: 5xx/timeout retryability + cache-then-network. Preconditions: warm cache present (Room single-row), MWS returns `500` then a socket timeout. Steps: refresh. Expected: with cache → `Ready(isStale=true)` + transient snackbar (no drop to full Error); with no cache → `Error(retryable=true)`. Bounded backoff (max 2, jittered) observed. Traces: AC-6.

**TC-AND-082-09** — Type: contract/MockWebServer (MWS). Target: malformed JSON tolerance. Preconditions: MWS returns `200 {"status":"active","unexpected_new_field":123}` and separately a body missing `status`. Steps: parse. Expected: additive field ignored (UNKNOWN-tolerant); missing required `status` → typed Error/`UNKNOWN`, breadcrumb, no crash (covers OQ-1 untyped-schema risk). Traces: AC-1, AC-6.

**TC-AND-082-10** — Type: integration (emulator(test35)). Target: offline/flaky-dev-host path end-to-end. Preconditions: seed Room with last-known status, then disable network (airplane mode via adb on emulator). Steps: open Account screen. Expected: cached status renders with a dismissible stale banner ("Showing last saved info"); Retry visible; reconnect + pull-to-refresh fetches fresh. Traces: AC-6.

**TC-AND-082-11** — Type: Compose-UI (emulator(test35)). Target: `AccountScreen` states. Preconditions: drive with `Loading`, `Ready(active)`, `Error(retryable)`. Steps: assert via semantics. Expected: skeleton on Loading; status text + banner + (no profile badges) on Ready; error message + Retry button on Error; pull-to-refresh triggers `refresh()`. Traces: AC-1, AC-6, AC-8.

**TC-AND-082-12** — Type: Compose-UI (emulator(test35)). Target: destructive confirm gate (key security/UX test). Preconditions: `Ready(active)`. Steps: tap "Close account"; assert dialog; (a) tap Cancel/dismiss; (b) re-open and tap Confirm. Expected: dialog appears with plain-language consequence copy; **default/focused button is Cancel**; navigation does NOT fire on cancel/dismiss; fires exactly once on Confirm (router fake records `toClosure`); double-tap debounced (single dialog instance). Traces: AC-3, AC-8.

**TC-AND-082-13** — Type: Compose-UI (emulator(test35)). Target: navigation routing + placeholder fallback. Preconditions: router fake; E50 destinations unregistered. Steps: tap Active sessions, Privacy & data export, Reactivate. Expected: sessions → `settings/sessions`; privacy → privacy/export route; reactivate → E50 reactivation route OR `settings/placeholder?feature=…` when unregistered — never crashes. Traces: AC-2, AC-4.

**TC-AND-082-14** — Type: Compose-UI / accessibility (emulator(test35)). Target: a11y compliance. Preconditions: `Ready(suspended with reason)`. Steps: run accessibility checks + TalkBack semantics assertions. Expected: state/badges conveyed by text+icon, not color alone (WCAG 1.4.1); rows ≥48dp; destructive rows expose `Role.Button` + "destructive" state description; confirm dialog traps focus and defaults to Cancel; font-scaling does not clip. Traces: AC-8.

**TC-AND-082-15** — Type: unit (JVM). Target: telemetry/PII safety. Preconditions: capture analytics + log sink. Steps: drive view, row clicks, destructive confirm shown/confirmed/cancelled, and an UNKNOWN state. Expected: events fire with `state`/`reason`(coarse category)/`row`/`action` only; **no** `reason` free-text, no timestamps-as-PII, no logging of account data; UNKNOWN breadcrumb may include the raw state string (not PII). Traces: AC-7.

**TC-AND-082-16** — Type: instrumented/e2e (device(A15) — MUST run on physical device). Target: ABI/API parity (arm64-v8a, API 34) vs emulator (x86_64, API 35). Preconditions: app installed on SM-A156U via adb. Steps: launch Settings → Account, load status, exercise confirm dialog and one deep-link. Expected: status renders, epoch-seconds dates localize correctly under the device locale/timezone, dialog focus/back behavior correct on API 34, no arm64-specific Moshi/codegen issues. Rationale for device: catches arm64-vs-x86 and API-34-vs-35 differences not visible on the emulator. Traces: AC-1, AC-3, AC-8.

### Coverage matrix

| AC | Covered by |
|----|------------|
| AC-1 (status renders per state) | TC-01, TC-02, TC-03, TC-04, TC-05, TC-09, TC-11, TC-16 |
| AC-2 (sessions row → AND-043, no dup fetch) | TC-13 |
| AC-3 (destructive strong-confirm gate) | TC-12, TC-16 |
| AC-4 (deep-links / placeholder, no crash) | TC-13 |
| AC-5 (lifecycle row visibility per state) | TC-01, TC-02, TC-03, TC-05 |
| AC-6 (loading/error/offline-stale/refresh) | TC-06, TC-08, TC-09, TC-10, TC-11 |
| AC-7 (no PII in logs/telemetry; state/category only) | TC-03, TC-06, TC-07, TC-15 |
| AC-8 (localization + accessibility + Cancel-default confirm) | TC-11, TC-12, TC-14, TC-16 |
