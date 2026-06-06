---
id: AND-388
title: Trust & safety ViewModels
milestone: M8
epic: E50
priority: P1
size: M
status: draft
depends_on: [AND-382]
blocks: []
---

# AND-388 — Trust & safety ViewModels

## 1. Overview & Goal

This ticket delivers the state-holding layer for the TestLogon "trust & safety" surface
area: the ViewModels (plus their `UiState` models and intent surfaces) that drive the
moderation and privacy features of milestone M8 / epic E50. These are the block/unblock
action (AND-382), report flows (AND-383), DMCA takedown submission (AND-384), and
privacy / data-export requests (AND-385).

The scope per the backlog is precisely **State + irreversible-action guards**, with an
acceptance bar of **Unit-tested**. Concretely this ticket ships:

- A shared `IrreversibleActionGuard` confirmation primitive (a small state machine reused
  across all trust & safety actions) so that destructive or irreversible operations
  (block, report-and-block, DMCA submission, account-deletion export/erasure) cannot fire
  without an explicit, typed confirmation step.
- `ReportViewModel`, `DmcaViewModel`, and `PrivacyExportViewModel` — the state owners for
  AND-383/384/385 respectively — each exposing a single `StateFlow<UiState>` and a single
  `onIntent` entry point.
- Consolidation of the block/unblock interaction state introduced inline by AND-382 into a
  reusable `BlockActionDelegate` that the profile and messages ViewModels embed, routed
  through the same guard.

It does **not** ship Composables, navigation, or new endpoints. The screens that host these
ViewModels and their instrumented Compose UI tests are owned by the feature tickets
(AND-382 for block UI, and the report/DMCA/privacy screens defined alongside AND-383/384/385).
The deliverable here is a deterministic, side-effect-free-to-test set of state machines
where, given a sequence of intents and faked repository results, the emitted `UiState`
sequence is fully predictable and exercised by `core-testing` JUnit tests on a `TestDispatcher`.

The animating concern is the **irreversible-action guard**: in a moderation context, an
accidental report, an accidental DMCA filing (which carries legal weight), or an accidental
data-erasure request is materially harmful. Every such action must traverse an explicit
`Idle → Confirming → Submitting → (Submitted | Failed)` lifecycle, and the guard must be
the single, testable choke point for all of them.

## 2. Context & References

- **Repo / branch:** `spannella/testlogon`, Android app under `android/`, branch `android-port`.
- **Namespace:** all packages rooted at `com.testlogon.android`. The shared guard lives in
  `core-ui` (`com.testlogon.android.core.ui.safety`); the feature ViewModels live in their
  respective `feature-*` modules under `com.testlogon.android.feature.<name>.safety`.
- **Module layering:** `app → feature-* → core-* (core-network, core-model, core-ui,
  core-data, core-testing)`. ViewModels expose `StateFlow<UiState>`; network results are
  typed `ApiResult<T>`; FastAPI `detail` error mapping (`string | [{msg}] | {code,...}`)
  is handled in `core-network`.
- **Upstream dependency — AND-382 (Block / unblock):** establishes `BlockApi` (`core-network`),
  `BlockingRepository` (`core-data`), and the `BlockRelationship` / `BlockedUser` models
  (`core-model`), plus the inline block/unblock interaction state. This ticket reuses that
  repository and refactors its interaction state behind `BlockActionDelegate` + the shared
  guard. AND-382 is the declared dependency.
- **Sibling features whose state this ticket owns:**
  - **AND-383 (Report flows):** report user / content / message with reasons; ties to
    AND-163 (report message/conversation). `ReportViewModel` lives here.
  - **AND-384 (DMCA submit):** `dmca.ts` takedown submission. `DmcaViewModel` lives here.
  - **AND-385 (Privacy / data export):** `/ui/privacy/account-deletion/export(+download)`
    and a requests list. `PrivacyExportViewModel` lives here.
- **Web reference:** `frontend/src/api/endpoints/blocking.ts`, `dmca.ts`, the report
  endpoints, and the privacy export endpoints under `frontend/src/api/endpoints/*.ts`;
  shared types in `frontend/src/api/types.ts`. Confirm exact paths against `/openapi.json`
  where the web client and OpenAPI disagree.
- **Backend:** FastAPI + DynamoDB; dev host `http://18.222.237.167:8000` (plaintext HTTP,
  unreliable). Design for ~20s timeouts; bounded backoff retry applies to idempotent GETs
  only (e.g. the export requests list) — never to the mutating POSTs in this ticket.
- **Auth:** cookie-based session; all calls ride the persistent cookie jar and send
  `X-CSRF-Token` on mutating verbs; a single `POST /ui/session/refresh` on 401 then retry,
  handled transparently in `core-network`.
- **Conventions referenced:** `MainDispatcherRule` and Turbine from `core-testing`;
  `UiText` from `core-ui`; injected `@IoDispatcher CoroutineDispatcher`.

## 3. Functional Requirements

**Shared guard**

FR-1. Every irreversible/destructive trust & safety action is gated by an
`IrreversibleActionGuard` that exposes a four-phase lifecycle: `Idle`, `Confirming(action)`,
`Submitting(action)`, terminal `Submitted` or `Failed(error)`. An action can only move
to `Submitting` from `Confirming` via an explicit `confirm()` call; a `request(action)`
call only opens the `Confirming` phase, it never submits.

FR-2. The guard supports a typed "acknowledgement" requirement: actions that the backend
or product marks as legally/contractually significant (DMCA, account-deletion export)
require an `acknowledged = true` flag set during `Confirming` before `confirm()` is accepted;
calling `confirm()` without it leaves the guard in `Confirming` and emits a validation banner.

FR-3. `cancel()` returns the guard to `Idle` from `Confirming` (and is a no-op from any other
phase), discarding the staged action with no side effects.

FR-4. While in `Submitting`, repeated `confirm()` calls are ignored (re-entrancy guard) so a
double-tap cannot submit twice. This is the load-bearing protection against duplicate reports
/ duplicate DMCA filings.

**Report (AND-383)**

FR-5. `ReportViewModel` supports reporting one of three target kinds — `USER`, `CONTENT`
(post/media), or `MESSAGE`/conversation — selected via the target passed at construction or
via an intent. The user picks a `ReportReason` from a server-or-static reason list and may add
optional free-text detail.

FR-6. Submitting a report requires a selected reason; submission flows through the guard
(`Confirming → Submitting`). On success the state is `Submitted` and the UI can show a
confirmation. For a user/message report the ViewModel optionally offers "also block this user",
which, if checked, issues a block via `BlockActionDelegate` after the report succeeds.

FR-7. Reports are effectively idempotent to the user: a duplicate-report rejection from the
backend (e.g. `already_reported`) is surfaced as a benign "Already reported" confirmation,
not a hard error.

**DMCA (AND-384)**

FR-8. `DmcaViewModel` collects the takedown form fields (claimant name, contact email, the
infringing content reference/URL, the original work description, and a sworn-statement /
good-faith acknowledgement checkbox) and validates them client-side before enabling submit.

FR-9. DMCA submission is irreversible and legally significant: it requires the acknowledgement
(FR-2) and traverses the guard. On success the state carries a reference/case id returned by
the backend.

**Privacy / data export (AND-385)**

FR-10. `PrivacyExportViewModel` loads the list of the user's existing export/erasure requests
(`requests`), supports requesting a new account-deletion export, and supports obtaining a
download for a `READY` export.

FR-11. Requesting an export is gated by the guard with acknowledgement (it initiates an
account-deletion data flow). The requests list is refreshable (stale-while-revalidate) and is
the only GET in this ticket eligible for backoff retry.

FR-12. A download intent for a non-`READY` request is rejected locally with a banner; for a
`READY` request it resolves a download URL/token via the repository and emits a one-shot
`DownloadReady(url)` effect the UI consumes.

**Cross-cutting**

FR-13. Every ViewModel exposes exactly one `StateFlow<UiState>` and one `onIntent(intent)`
entry point; the UI cannot mutate state directly. State emissions are distinct (no duplicate
equal emissions).

FR-14. All long-running intents are cancellation-safe and re-entrancy-safe (a second submit
while one is in flight is ignored; a second list refresh cancels/joins rather than racing).

## 4. Technical Design

### 4.1 The shared guard

`IrreversibleActionGuard` is a plain, framework-free state machine in `core-ui` so it is unit
testable without Android and reusable by every ViewModel. It is parameterised by the action
type `A`.

```kotlin
package com.testlogon.android.core.ui.safety

sealed interface GuardPhase<out A> {
    data object Idle : GuardPhase<Nothing>
    data class Confirming<A>(val action: A, val acknowledged: Boolean = false) : GuardPhase<A>
    data class Submitting<A>(val action: A) : GuardPhase<A>
    data object Submitted : GuardPhase<Nothing>
    data class Failed(val error: UiText) : GuardPhase<Nothing>
}

class IrreversibleActionGuard<A>(
    private val requiresAcknowledgement: Boolean = false,
) {
    private val _phase = MutableStateFlow<GuardPhase<A>>(GuardPhase.Idle)
    val phase: StateFlow<GuardPhase<A>> = _phase.asStateFlow()

    fun request(action: A) { _phase.value = GuardPhase.Confirming(action) }

    fun setAcknowledged(value: Boolean) {
        val c = _phase.value as? GuardPhase.Confirming<A> ?: return
        _phase.value = c.copy(acknowledged = value)
    }

    fun cancel() { if (_phase.value is GuardPhase.Confirming<*>) _phase.value = GuardPhase.Idle }

    /** Returns the action to submit, or null if confirmation is not yet valid / already running. */
    fun confirm(): A? {
        val c = _phase.value as? GuardPhase.Confirming<A> ?: return null
        if (requiresAcknowledgement && !c.acknowledged) return null
        _phase.value = GuardPhase.Submitting(c.action)
        return c.action
    }

    fun onSuccess() { _phase.value = GuardPhase.Submitted }
    fun onFailure(error: UiText) { _phase.value = GuardPhase.Failed(error) }
    fun reset() { _phase.value = GuardPhase.Idle }
}
```

The guard owns no coroutines and performs no I/O — the ViewModel calls `confirm()`, and if it
returns a non-null action, launches the repository call and reports `onSuccess`/`onFailure`.
This keeps the destructive-action invariant (FR-1, FR-4) in one ~40-line, exhaustively tested
unit.

### 4.2 ViewModels

Each ViewModel is a Hilt `@HiltViewModel` with a constructor-injected repository and an
injected `@IoDispatcher CoroutineDispatcher` (never hard-coded, so tests substitute a
`TestDispatcher`). Pattern, shown for `ReportViewModel`:

```kotlin
@HiltViewModel
class ReportViewModel @Inject constructor(
    private val reportRepository: ReportRepository,
    private val blocking: BlockActionDelegate,
    @IoDispatcher private val io: CoroutineDispatcher,
    savedState: SavedStateHandle,
) : ViewModel() {

    private val guard = IrreversibleActionGuard<ReportDraft>()
    private val _state = MutableStateFlow(ReportUiState(target = savedState.requireTarget()))
    val state: StateFlow<ReportUiState> = _state.asStateFlow()

    private var submitJob: Job? = null
    init { loadReasons() }

    fun onIntent(intent: ReportIntent) = when (intent) {
        is ReportIntent.SelectReason -> _state.update { it.copy(reason = intent.reason) }
        is ReportIntent.SetDetail    -> _state.update { it.copy(detail = intent.text) }
        is ReportIntent.SetAlsoBlock -> _state.update { it.copy(alsoBlock = intent.value) }
        ReportIntent.Request         -> requestSubmit()
        ReportIntent.Confirm         -> confirmSubmit()
        ReportIntent.Cancel          -> { guard.cancel(); syncGuard() }
        ReportIntent.DismissBanner   -> _state.update { it.copy(banner = null) }
    }

    private fun requestSubmit() {
        val reason = _state.value.reason
            ?: return _state.update { it.copy(banner = UiText.res(R.string.report_pick_reason)) }
        guard.request(ReportDraft(_state.value.target, reason, _state.value.detail)); syncGuard()
    }

    private fun confirmSubmit() {
        val draft = guard.confirm() ?: return syncGuard()  // re-entrancy / validation no-op
        submitJob?.cancel()
        submitJob = viewModelScope.launch(io) {
            when (val r = reportRepository.submit(draft)) {
                is ApiResult.Success -> {
                    if (_state.value.alsoBlock) blocking.block(draft.target.userId)
                    guard.onSuccess()
                }
                is ApiResult.Failure ->
                    if (r.error.code == "already_reported") guard.onSuccess()
                    else guard.onFailure(r.error.toUiText())
            }
            syncGuard()
        }
    }

    private fun syncGuard() { _state.update { it.copy(phase = guard.phase.value) } }
}
```

`DmcaViewModel` and `PrivacyExportViewModel` follow the same shape; their guards are
constructed with `requiresAcknowledgement = true`. `PrivacyExportViewModel` additionally owns
the GET-backed `requests` list with stale-while-revalidate `refresh()` (the only retry-eligible
call) and a one-shot `Channel<DownloadEffect>` for FR-12.

### 4.3 `BlockActionDelegate`

To satisfy "block/unblock embedded in profile/messages" (AND-382) while keeping the guard the
single choke point, the inline block state from AND-382 is refactored into an injectable,
reusable delegate that profile/messages ViewModels (and `ReportViewModel`'s also-block) embed:

```kotlin
class BlockActionDelegate @Inject constructor(
    private val blockingRepository: BlockingRepository,   // from AND-382
    @IoDispatcher private val io: CoroutineDispatcher,
) {
    val guard = IrreversibleActionGuard<BlockAction>()
    suspend fun block(userId: String): ApiResult<Unit> = blockingRepository.block(userId)
    suspend fun unblock(userId: String): ApiResult<Unit> = blockingRepository.unblock(userId)
}
```

This is additive to AND-382 (its repository and models are unchanged); it relocates the
interaction-state into a testable unit shared by all hosts.

## 5. API Contract

This is a state ticket; it defines **no new endpoints**. It consumes repositories that wrap
existing endpoints. Authoritative shapes are the web `frontend/src/api/endpoints/*.ts` files
and `/openapi.json`; confirm before implementation.

**Block / unblock (AND-382, reused):**
`POST /ui/users/{id}/block` and `DELETE /ui/users/{id}/block` (or the path established by
AND-382 / `blocking.ts`). Idempotent from the user's perspective per AND-382.

**Report (AND-383, ties to AND-163):** `POST /ui/reports` with body:

```json
{
  "target_type": "user | content | message",
  "target_id": "usr_… | post_… | msg_…",
  "reason": "harassment",
  "detail": "optional free text"
}
```

→ 201:

```json
{ "id": "rpt_01HF…", "status": "received", "created_at": "2026-06-05T14:21:09Z" }
```

Duplicate → 409 `{ "detail": { "code": "already_reported" } }` (treated as benign, FR-7).
Reason list: `GET /ui/reports/reasons` → `[{ "key": "harassment", "label": "Harassment" }, …]`
(if absent, fall back to a static `core-model` enum — see R1).

**DMCA (AND-384):** `POST /ui/dmca` (per `dmca.ts`) with body:

```json
{
  "claimant_name": "…",
  "contact_email": "…",
  "infringing_url": "https://…",
  "original_work": "description …",
  "good_faith_ack": true
}
```

→ 201 `{ "id": "dmca_01HF…", "status": "submitted" }`.

**Privacy / data export (AND-385):**
- `GET /ui/privacy/account-deletion/export` → list of requests:
  ```json
  [{ "id": "exp_01HF…", "status": "pending|processing|ready|expired", "requested_at": "…", "expires_at": "…" }]
  ```
- `POST /ui/privacy/account-deletion/export` → creates a request, returns the new item.
- `GET /ui/privacy/account-deletion/export/download?id=exp_…` (the `+download` path) → a
  short-lived download URL/token for a `ready` request.

All mutating calls carry session cookies + `X-CSRF-Token`; a 401 triggers one
`POST /ui/session/refresh` then a single retry in `core-network`, transparent to these
ViewModels (they observe only the final `ApiResult`). POSTs are never auto-retried by the
backoff layer.

## 6. Data & State Management

State models are immutable data classes; intents are sealed interfaces (exhaustive `when`).

```kotlin
data class ReportUiState(
    val target: ReportTarget,
    val reasons: List<ReportReason> = emptyList(),
    val reason: ReportReason? = null,
    val detail: String = "",
    val alsoBlock: Boolean = false,
    val phase: GuardPhase<ReportDraft> = GuardPhase.Idle,
    val banner: UiText? = null,
)

data class DmcaUiState(
    val form: DmcaForm = DmcaForm(),
    val acknowledged: Boolean = false,
    val phase: GuardPhase<DmcaForm> = GuardPhase.Idle,
    val caseId: String? = null,
    val banner: UiText? = null,
) { val canSubmit: Boolean get() = form.isValid && acknowledged }

data class PrivacyExportUiState(
    val isLoading: Boolean = true,
    val isRefreshing: Boolean = false,
    val requests: List<ExportRequest> = emptyList(),
    val isStale: Boolean = false,
    val phase: GuardPhase<Unit> = GuardPhase.Idle,
    val banner: UiText? = null,
)
```

`ReportTarget`, `ReportReason`, `ReportDraft`, `DmcaForm`, `ExportRequest`, and `BlockAction`
are `core-model` types (DMCA/report/export DTOs are added by the respective feature tickets;
where they do not yet exist, minimal models are introduced here and back-filled). Derived
fields (`canSubmit`) are computed, not stored, so they cannot drift.

State is in-memory and survives configuration changes via `viewModelScope`. `SavedStateHandle`
persists only **non-PII navigation inputs** — the `ReportTarget` id/kind, the DMCA form's
**non-sensitive** scalar fields, and the in-progress free-text drafts — never server responses,
download URLs, or export contents. On process death, lists re-fetch rather than persist. No
Room writes are added here; any caching is the underlying repository's responsibility.

## 7. Error Handling & Resilience

All repository results are `ApiResult<T>` (`Success` / `Failure(ApiError(code, message))`).
The reducers map as follows:

- **Network / timeout** (`NetworkError.Timeout | NoConnection`): for the export **list GET**
  (idempotent), if data is already loaded → keep it, set `isStale = true`, show a dismissible
  banner; if first load → `isLoading = false` + empty/error view. Honors the ~20s timeout and
  bounded backoff applied by `core-network` for idempotent GETs only. For **submissions**
  (report/DMCA/export-create/block — all POST/DELETE), a timeout moves the guard to
  `Failed(timeoutMessage)`; the action is **not** auto-retried (avoids duplicate reports/DMCA).
  The user may explicitly re-confirm.
- **Validation (local):** missing reason (FR-5), missing acknowledgement (FR-2), invalid DMCA
  fields (FR-8), or download of a non-`READY` request (FR-12) are rejected before any network
  call, with a `banner`, leaving the guard in `Confirming`/`Idle` as appropriate.
- **Duplicate / benign conflicts:** `already_reported` (409) and re-blocking an already-blocked
  user are mapped to success (`onSuccess`), per FR-6/FR-7 and AND-382's idempotency rule.
- **Re-entrancy:** `confirm()` returns `null` while already `Submitting` (FR-4), so a
  double-tap cannot create two reports/filings; `submitJob` is cancelled-then-relaunched only
  on a fresh confirm. List `refresh()` cancels the prior load job.
- **FastAPI `detail` mapping:** delegated to `core-network`'s parser
  (`string | [{msg}] | {code,...}`) producing `ApiError(code, message)`; the ViewModel maps
  `message` into a `UiText` for the banner / `Failed` phase.
- **403 (permission):** surfaced as a non-fatal banner; the ViewModel assumes an authenticated
  session (auth gating is enforced server-side and by navigation guards).

## 8. Security & Privacy

These features are inherently privacy-sensitive. No new auth surface is introduced: all calls
rely on the cookie-based session, persistent cookie jar, and `X-CSRF-Token` echo handled in
`core-network`. The ViewModels never store credentials, tokens, or cookies.

- **PII handling:** report detail text, DMCA claimant name/email, infringing URLs, and export
  request contents are PII/sensitive. They must not be logged at INFO or above (see §10) and
  must not be persisted to disk by this layer. `SavedStateHandle` persists only non-sensitive
  scalar inputs and in-progress drafts the user is actively editing — **not** server responses
  and **not** export download URLs/tokens.
- **Download tokens:** export download URLs/tokens (FR-12) are short-lived, kept in transient
  state only, delivered to the UI via a one-shot effect channel, and never written to logs,
  `SavedStateHandle`, or any cache.
- **Irreversible-action guard as a safety control:** the guard is a security/safety control,
  not just UX — it is the enforced double-confirmation for destructive moderation/legal/
  data-deletion actions and the duplicate-submission guard. Its invariants (FR-1, FR-2, FR-4)
  are unit-tested as security-relevant behavior.
- **Least authority:** the also-block path issues a block only after an explicit report
  success and only when the user opted in; it never blocks silently.

## 9. Accessibility & i18n

As a state layer there is no direct UI, but every user-facing string is emitted as `UiText`
(string-resource reference resolved in Compose), never hard-coded English, so localization and
TalkBack-readable content are preserved by the host screens. Reason labels come from the
backend list where available (already localized server-side) and otherwise map to
`R.string.report_reason_*` resources. Confirmation copy for the guard's `Confirming` phase
(e.g. "This can't be undone") is supplied by the host screen from string resources; the
ViewModel only signals the phase. The acknowledgement requirement (FR-2) maps to a labelled,
focusable checkbox in the UI. No locale-specific date formatting occurs in the ViewModel —
`requested_at` / `expires_at` stay ISO-8601 in state for the Composable to format. RTL
readiness is unaffected (no directional logic here).

## 10. Telemetry & Logging

Use the project `Logger` (Timber-backed) and the injected `AnalyticsClient` interface.

- **DEBUG:** intent received (name only), guard phase transitions (phase name only), submit
  start/end with result kind (`success | duplicate | failed`). Never log report detail, DMCA
  fields, email addresses, target ids of reported users, or export contents/URLs.
- **WARN:** submission timeouts and 403/permission failures (with action kind only, no PII).
- **Analytics (counts only, no content):**
  `report_submitted { target_type, reason_key, also_block }`,
  `dmca_submitted { }`, `privacy_export_requested { }`,
  `privacy_export_downloaded { }`, `safety_action_cancelled { kind }`. `reason_key` is a
  bounded enum, not free text.

All telemetry is fire-and-forget, must never block state emission, and is asserted in unit
tests only via a fake recording call counts/keys (never content).

## 11. Testing Strategy

This is the heart of the ticket (acceptance: **Unit-tested**). Tests live under each module's
`src/test/java/com/testlogon/android/.../safety/` using JUnit4, Turbine for `StateFlow`, fakes
(`FakeReportRepository`, `FakeDmcaRepository`, `FakePrivacyExportRepository`,
`FakeBlockingRepository`), and `MainDispatcherRule` from `core-testing`. `runTest` +
`advanceUntilIdle()` drive virtual time; no real delays. Coverage target ≥ 90% lines on the
ViewModels and **100% on `IrreversibleActionGuard`**.

`IrreversibleActionGuardTest`:
- `request` moves `Idle → Confirming`; `confirm()` from `Idle` returns `null` (FR-1).
- `confirm()` requires acknowledgement when configured: returns `null` and stays `Confirming`
  without ack; succeeds after `setAcknowledged(true)` (FR-2).
- `cancel()` returns to `Idle` from `Confirming`; no-op elsewhere (FR-3).
- second `confirm()` while `Submitting` returns `null` — the duplicate-submission guard (FR-4).
- `onSuccess` / `onFailure` move to terminal phases; `reset()` returns to `Idle`.

`ReportViewModelTest`:
- submit without a reason emits a banner, no network call (FR-5).
- happy path: `Request → Confirm` → repository called once → `phase == Submitted` (FR-6).
- `alsoBlock = true` issues a block exactly once after report success; `false` issues none.
- `already_reported` (409) is mapped to `Submitted`, not `Failed` (FR-7).
- double `Confirm` results in exactly one `submit` call (re-entrancy, FR-4/§7).

`DmcaViewModelTest`:
- `canSubmit` is false until form valid **and** acknowledged (FR-8/FR-2).
- confirm without ack does not submit; with ack submits once and stores `caseId` (FR-9).

`PrivacyExportViewModelTest`:
- initial load populates `requests`; timeout on refresh keeps data + sets `isStale` (FR-10/11).
- request-new is guard+ack gated and adds the new request on success (FR-11).
- download of a non-`READY` request emits a banner, no effect; `READY` emits one
  `DownloadReady` effect (FR-12).

`BlockActionDelegateTest`: block/unblock delegate to the repository; re-block is benign.

Cross-cutting: assert **distinct emissions** (no two consecutive equal `UiState`) and
cancellation-safety (a second refresh cancels the first) per FR-13/FR-14.

## 12. Dependencies & Sequencing

- **Depends on AND-382 (Block / unblock):** provides `BlockingRepository`, `BlockApi`, and the
  `BlockRelationship`/`BlockedUser` models reused by `BlockActionDelegate`. The delegate is
  additive; AND-382's repository/models are not modified, only its interaction-state is
  relocated here.
- **Owns the state layer for AND-383 / AND-384 / AND-385:** the report/DMCA/privacy feature
  screens (and their Compose UI tests) consume these ViewModels. The report DTOs (AND-383,
  tied to AND-163), DMCA DTOs (AND-384), and privacy-export DTOs (AND-385) are the contract
  source; where a feature ticket has not yet introduced its DTOs/repository, this ticket adds
  the minimal repository interface + `core-model` types and back-fills them to the owning
  ticket (recorded as R1).
- **Reuses** `core-network` `ApiResult` + 401-refresh interceptor, `core-ui` `UiText`, and
  `core-testing` `MainDispatcherRule`/Turbine. The new shared guard is added to `core-ui`.
- **No Gradle / manifest changes** beyond adding the new ViewModels to the Hilt-generated
  factory (automatic via `@HiltViewModel`) and binding `BlockActionDelegate` /
  the repositories in their `core-data` Hilt modules.
- **Sequencing:** implement `IrreversibleActionGuard` + tests first (pure Kotlin, no deps),
  then `BlockActionDelegate` (needs AND-382), then the three ViewModels in any order.

## 13. Risks & Open Questions

- **R1 — DTO / repository ownership boundary:** AND-383/384/385 may not have landed their
  repositories/DTOs when this ticket starts. Mitigation: introduce minimal repository
  interfaces + `core-model` types here against `frontend/src/api/endpoints/*.ts` and
  `/openapi.json`, and back-fill to the owning tickets; keep the ViewModel↔repository seam
  stable so the feature tickets can swap implementations without ViewModel changes.
- **R2 — Report reason source:** `GET /ui/reports/reasons` is assumed; if the backend has no
  such endpoint, fall back to a static `ReportReason` enum in `core-model`. Verify against
  `/openapi.json`.
- **R3 — Exact paths:** block/report/DMCA/export paths must be confirmed against
  `/openapi.json` where the web client and OpenAPI disagree (per project convention). The
  privacy `+download` path shape (query param vs path segment) in particular needs confirming.
- **R4 — Acknowledgement scope:** product/legal must confirm which actions require the FR-2
  acknowledgement. Current default: DMCA and account-deletion export require it; report and
  block use plain confirmation. Adjust the guard's `requiresAcknowledgement` flag accordingly.
- **Open question:** should a successful report optionally suppress the reported content
  immediately in the blocker's session (as block does)? Defaulting to **no** unless also-block
  is checked; revisit with AND-383's screen owner.

## 14. Acceptance Criteria

AC-1. `IrreversibleActionGuard` + `GuardPhase` exist in `com.testlogon.android.core.ui.safety`
with 100% unit-test coverage and the FR-1/FR-2/FR-3/FR-4 invariants proven by tests.

AC-2. `ReportViewModel`, `DmcaViewModel`, `PrivacyExportViewModel`, and `BlockActionDelegate`
exist in their respective modules, each exposing a single `StateFlow<UiState>` and a single
`onIntent` (or delegate method) entry point; the UI cannot mutate state directly.

AC-3. Functional requirements FR-1 through FR-14 are implemented and observable via state.

AC-4. Every destructive/irreversible action (block, report, DMCA, export request) is gated by
the guard and cannot be submitted without traversing `Confirming → Submitting`; a double-tap
on confirm produces exactly one network submission — proven by a test for each ViewModel.

AC-5. Unit tests cover every scenario in §11, run on a `TestDispatcher` with no real delays,
and pass deterministically; line coverage ≥ 90% on the ViewModels, 100% on the guard.

AC-6. Submission timeouts move the guard to `Failed` and are **never** auto-retried; the
export list GET is the only retry-eligible call; `already_reported`/re-block are benign —
each proven by a test.

AC-7. No PII (report detail, DMCA fields, emails, export contents/download URLs) is logged at
INFO+ or persisted by this layer; `SavedStateHandle` holds only non-sensitive inputs —
verified by review against §8/§10.

## 15. Definition of Done

- Code merged to `android-port` following module layering (`feature-* → core-*` only); the
  guard lives in `core-ui`.
- All four state holders injected via Hilt (`@HiltViewModel` / `@Inject`) with an injected
  dispatcher; no hard-coded `Dispatchers.IO`.
- Unit test suites green in CI
  (`./gradlew :core-ui:testDebugUnitTest :feature-profile:testDebugUnitTest
  :feature-messages:testDebugUnitTest` plus the report/DMCA/privacy feature modules) with the
  coverage thresholds met; tests use Turbine + `MainDispatcherRule`.
- ktlint/detekt clean; no new lint baseline entries.
- All user-facing strings are `UiText`/string resources; no hard-coded copy in any ViewModel.
- AC-1 through AC-7 verified and signed off; the AND-382 block UI and the AND-383/384/385
  screens wire to these ViewModels without modification.
- Spec references to AND-382, AND-383, AND-384, AND-385, and AND-163 remain consistent with the
  backlog; any deviations (R1/R2/R3/R4 resolutions) recorded back into the depended-on tickets.
