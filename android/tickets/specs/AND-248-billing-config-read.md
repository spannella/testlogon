---
id: AND-248
title: Billing config (read)
milestone: M5
epic: E33
priority: P2
size: S
status: draft
depends_on: [AND-223]
blocks: []
---

# AND-248 — Billing config (read)

## 1. Overview & Goal

This ticket delivers a **read-only** presentation of the TestLogon billing
configuration on the native Android port. The web reference renders the
`billingConfig.ts` object — the static, account-level billing configuration
returned by the backend (currency, tax behaviour, supported payment methods,
billing portal availability, trial policy, proration mode, and feature flags such
as `self_serve_enabled`). The Android port must surface the same configuration as
an inspectable, **non-editable** Compose screen.

The backlog scope is precise: *"`billingConfig.ts` display."* and the acceptance
bar is *"Config renders read-only."* The deliverable is therefore a single
feature surface (`BillingConfigScreen` + `BillingConfigViewModel`) that:

1. Fetches the billing configuration through the already-frozen `BillingApi`
   contract from AND-223.
2. Renders every configuration field in a labelled, read-only layout — no text
   fields, no toggles wired to mutations, no "save" affordance.
3. Handles loading, empty, error, and offline/stale states for the unreliable
   dev backend.

This is a P2 feature. It is intentionally narrow: it does **not** introduce
billing mutations, checkout, plan selection, invoice rendering, or payment-method
management. Those are owned by sibling tickets in the billing epics (AND-227
checkout, AND-232 ViewModels, AND-233 tests). This ticket consumes the billing
data plane and presents one slice of it read-only.

## 2. Context & References

- **Package base:** `com.testlogon.android`. New code lives under
  `com.testlogon.android.feature.billing.config` (screen, ViewModel, UI state)
  in the `feature-billing` module.
- **Module layering:** `app -> feature-billing -> core-*`. This ticket touches
  `feature-billing` only, depending on `core-network` (`BillingApi`, DTOs),
  `core-model` (domain models), and `core-ui` (Material 3 scaffold, theme,
  shared state composables). No `core-data`/Room is required (see section 6).
- **Web reference (authoritative for shape):**
  - `frontend/src/api/endpoints/billing.ts` — the call that fetches the billing
    config.
  - `frontend/src/api/types.ts` — the `BillingConfig` TypeScript interface; the
    Android DTO/domain field names must be equivalent.
  - The web component that renders `billingConfig` (read-only settings view) is
    the visual reference for which fields are shown and their grouping.
- **OpenAPI:** `http://18.222.237.167:8000/openapi.json` — confirm the billing
  config endpoint path, field names, nullability, and enum members before
  finalising. Where OpenAPI and `types.ts` disagree, prefer OpenAPI and file an
  Open Question (section 13).
- **Dependency AND-223 (Billing API + DTOs):** provides the `BillingApi`
  Retrofit interface, the Moshi DTOs, the `core-model.billing` domain types, the
  `toDomain()` mappers, and reuses the AND-027 authenticated `Retrofit`
  (persistent cookie jar, `ui_csrf` → `X-CSRF-Token` echo, single-shot
  `POST /ui/session/refresh`-then-retry on 401, ~20 s timeouts). This ticket adds
  one config endpoint/DTO/model **if AND-223 did not already include it** (see
  section 5, OQ-1) and otherwise consumes AND-223 as-is.
- **Stack:** Kotlin 2.0.21, Jetpack Compose + Material 3, Navigation-Compose,
  Hilt (KSP), Coroutines/Flow, Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15.
  minSdk 24 / compileSdk 35, JDK 17, AGP 8.7.3, Gradle 8.9.

## 3. Functional Requirements

FR-1. Provide a `BillingConfigScreen` Composable that fetches and displays the
billing configuration on first composition.

FR-2. Every field present in the `BillingConfig` domain model is rendered as a
labelled read-only row. No field is editable; the screen exposes no `TextField`,
`Switch`, `Checkbox`, `Slider`, or submit button bound to a mutation.

FR-3. Group fields into logical sections matching the web reference, e.g.
**General** (currency, tax behaviour, billing email), **Payment methods**
(supported methods list, default method type), **Self-service** (portal enabled,
self-serve enabled), **Trial & proration** (trial days, proration mode), and
**Feature flags** (remaining boolean flags). Sections with no data are omitted.

FR-4. The ViewModel exposes a single `StateFlow<BillingConfigUiState>`. The state
covers `Loading`, `Content`, `Empty` (config absent / 404), and `Error`.

FR-5. Booleans render as human-readable values ("Enabled"/"Disabled",
"Yes"/"No"), not raw `true`/`false`. Enum values render via a string-resource
lookup so they are localisable; unknown enum members render their raw token (from
the `UNKNOWN`-fallback domain mapping) rather than crashing or hiding the row.

FR-6. Money/currency-relevant fields (e.g. default currency) render the ISO-4217
code plus, where a sample amount is shown, formatting via
`NumberFormat.getCurrencyInstance(locale)`. The config itself carries no
formatted strings.

FR-7. Provide a manual **retry** action on the `Error` state and **pull-to-
refresh** on the `Content` state (re-issuing the idempotent GET).

FR-8. The screen is reachable via a Navigation-Compose route
`billing/config` registered by `feature-billing`'s nav graph contribution.

## 4. Technical Design

### 4.1 UI state

```kotlin
package com.testlogon.android.feature.billing.config

import com.testlogon.android.core.model.billing.BillingConfig

sealed interface BillingConfigUiState {
    data object Loading : BillingConfigUiState
    data class Content(
        val config: BillingConfig,
        val isStale: Boolean = false,   // shown after a failed refresh of cached content
        val isRefreshing: Boolean = false,
    ) : BillingConfigUiState
    data object Empty : BillingConfigUiState          // 404 / no config provisioned
    data class Error(val message: UiText, val canRetry: Boolean = true) : BillingConfigUiState
}
```

`UiText` is the project's localisable text wrapper (resource id + args | raw),
from `core-ui`. `BillingConfig` is the read-only domain model (section 5).

### 4.2 ViewModel

```kotlin
@HiltViewModel
class BillingConfigViewModel @Inject constructor(
    private val repository: BillingRepository,   // AND-223/feature-billing repo over BillingApi
) : ViewModel() {

    private val _state = MutableStateFlow<BillingConfigUiState>(BillingConfigUiState.Loading)
    val state: StateFlow<BillingConfigUiState> = _state.asStateFlow()

    init { load() }

    fun load() {
        _state.update {
            (it as? BillingConfigUiState.Content)?.copy(isRefreshing = true)
                ?: BillingConfigUiState.Loading
        }
        viewModelScope.launch {
            when (val r = repository.getBillingConfig()) {
                is ApiResult.Success -> _state.value = BillingConfigUiState.Content(r.data)
                is ApiResult.Error -> _state.value = reduceError(r.error)
            }
        }
    }

    fun retry() = load()
    fun refresh() = load()
}
```

`reduceError` maps `ApiError.NotFound` → `Empty`; everything else → `Error`. On a
refresh failure while content is already shown, it instead sets
`Content(isStale = true, isRefreshing = false)` so the last-good config stays
visible (offline/stale UX for the unreliable host).

The ViewModel never imports Retrofit/Moshi/Compose; it consumes the typed
`ApiResult<BillingConfig>` only. If AND-223's repository does not yet expose
`getBillingConfig()`, this ticket adds that one method over the existing
`BillingApi.getBillingConfig()` call (see section 5).

### 4.3 Compose screen

```kotlin
@Composable
fun BillingConfigScreen(
    viewModel: BillingConfigViewModel = hiltViewModel(),
    onBack: () -> Unit,
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    Scaffold(topBar = { BillingConfigTopBar(onBack) }) { padding ->
        when (val s = state) {
            BillingConfigUiState.Loading -> FullScreenLoading(Modifier.padding(padding))
            BillingConfigUiState.Empty   -> EmptyState(/* "No billing configuration" */)
            is BillingConfigUiState.Error -> ErrorState(s.message, onRetry = viewModel::retry)
            is BillingConfigUiState.Content -> BillingConfigContent(
                config = s.config,
                isStale = s.isStale,
                isRefreshing = s.isRefreshing,
                onRefresh = viewModel::refresh,
                modifier = Modifier.padding(padding),
            )
        }
    }
}

@Composable
private fun BillingConfigContent(
    config: BillingConfig,
    isStale: Boolean,
    isRefreshing: Boolean,
    onRefresh: () -> Unit,
    modifier: Modifier = Modifier,
) { /* PullToRefreshBox -> LazyColumn of ConfigSection { ConfigRow(label, value) } */ }
```

`ConfigRow(label: String, value: String)` is the atomic read-only widget: a
two-line/label-value `ListItem`. It exposes **no** click/edit affordance.
`ConfigSection(title)` is a sticky-ish header + grouped rows. A small
`StaleBanner` shows when `isStale`.

### 4.4 Navigation + DI

```kotlin
fun NavGraphBuilder.billingConfigRoute(onBack: () -> Unit) {
    composable(route = "billing/config") { BillingConfigScreen(onBack = onBack) }
}
```

The ViewModel is provided by Hilt via `@HiltViewModel`; `BillingRepository` and
`BillingApi` bindings come from AND-223's modules. This ticket adds no new Hilt
module unless it must register a `BillingConfigRepository` method binding, in
which case it extends the existing `feature-billing` module rather than creating
a parallel one.

## 5. API Contract

This screen reads one configuration resource. Per AND-223's `ui/*` vs `api/*`
split (cookie-session UI endpoints under `ui/*`), the assumed endpoint is:

| Verb | Path | Body | Response DTO |
|------|------|------|--------------|
| GET | `/ui/billing/config` | — | `BillingConfigDto` |

The path, field names, nullability, and enum members are **provisional** and MUST
be reconciled against `/openapi.json` and `frontend/src/api/types.ts` during
implementation (OQ-1). If AND-223 already shipped this DTO/endpoint, reuse it
verbatim; if not, this ticket adds the following minimal additions to AND-223's
namespaces (`core-network.billing` / `core-model.billing`).

DTO (Moshi, `core-network`):

```kotlin
@JsonClass(generateAdapter = true)
data class BillingConfigDto(
    @Json(name = "currency") val currency: String,                 // ISO-4217
    @Json(name = "tax_behavior") val taxBehavior: String?,         // inclusive|exclusive|none
    @Json(name = "billing_email") val billingEmail: String?,
    @Json(name = "supported_payment_methods")
    val supportedPaymentMethods: List<String> = emptyList(),       // card|us_bank_account|...
    @Json(name = "default_payment_method_type") val defaultPaymentMethodType: String?,
    @Json(name = "portal_enabled") val portalEnabled: Boolean = false,
    @Json(name = "self_serve_enabled") val selfServeEnabled: Boolean = false,
    @Json(name = "trial_period_days") val trialPeriodDays: Int?,
    @Json(name = "proration_mode") val prorationMode: String?,     // create_prorations|none|...
    @Json(name = "feature_flags") val featureFlags: Map<String, Boolean> = emptyMap(),
)
```

Domain model (`core-model`):

```kotlin
data class BillingConfig(
    val currency: String,
    val taxBehavior: TaxBehavior,
    val billingEmail: String?,
    val supportedPaymentMethods: List<PaymentMethodType>,
    val defaultPaymentMethodType: PaymentMethodType?,
    val portalEnabled: Boolean,
    val selfServeEnabled: Boolean,
    val trialPeriodDays: Int?,
    val prorationMode: ProrationMode,
    val featureFlags: Map<String, Boolean>,
)

enum class TaxBehavior { INCLUSIVE, EXCLUSIVE, NONE, UNKNOWN }
enum class PaymentMethodType { CARD, US_BANK_ACCOUNT, UNKNOWN }
enum class ProrationMode { CREATE_PRORATIONS, NONE, UNKNOWN }
```

`internal fun BillingConfigDto.toDomain(): BillingConfig` is total: unknown enum
strings → `UNKNOWN`, absent optionals → `null`, absent collections/maps →
empty, mirroring AND-223's mapper conventions.

Example `GET /ui/billing/config` 200:

```json
{
  "currency": "USD",
  "tax_behavior": "exclusive",
  "billing_email": "billing@acme.example",
  "supported_payment_methods": ["card", "us_bank_account"],
  "default_payment_method_type": "card",
  "portal_enabled": true,
  "self_serve_enabled": true,
  "trial_period_days": 14,
  "proration_mode": "create_prorations",
  "feature_flags": { "invoices_ui": true, "seat_management": false }
}
```

Error envelopes follow the FastAPI shape and are mapped by the shared error
mapper (AND-015): `{"detail":"..."}` | `{"detail":[{"msg":"..."}]}` |
`{"detail":{"code":"...","message":"..."}}`. Relevant statuses: `404` → `Empty`,
`401` → handled by the inherited refresh-and-retry interceptor, `5xx`/timeout →
`Error` (with bounded retry on this idempotent GET).

## 6. Data & State Management

- **In-memory only.** The screen holds the fetched `BillingConfig` in the
  ViewModel's `StateFlow`. No Room entity and no DataStore key are introduced;
  billing config is small, account-level, and re-fetched per screen entry.
- **Staleness:** the only persistence-like behaviour is keeping the last-good
  `Content` visible with `isStale = true` after a failed refresh. There is no
  cross-process cache; this is deliberately deferred to a future `core-data`
  billing repository if config display ever needs offline-first behaviour.
- **Process death:** `Loading`/`Content` are reconstructed by re-fetching in
  `init`; no `SavedStateHandle` persistence is required because the config is
  cheap to re-derive and has no user input to preserve.
- **Pagination:** N/A — billing config is a single object, not a list.

## 7. Error Handling & Resilience

- **Idempotent GET:** `getBillingConfig()` is eligible for the shared bounded
  backoff retry (connect/read timeout + 5xx, capped attempts, ~20 s per-attempt
  timeout) configured in AND-027's OkHttp client, given the unreliable dev host.
- **401:** handled entirely by the inherited single-shot
  `POST /ui/session/refresh`-then-retry interceptor; the screen is unaware.
- **404 / no config:** mapped to the `Empty` state with an explanatory message,
  not treated as a hard error.
- **Refresh failure with cached content:** preserve the prior `Content`, set
  `isStale = true`, surface a non-blocking banner/snackbar; do not blank the
  screen.
- **Mapping resilience:** `toDomain()` never throws — unknown enum tokens become
  `UNKNOWN` (rendered raw), missing maps/lists become empty — so a backend adding
  a new payment method or flag never crashes the screen.
- **No mutations:** because the screen is read-only, there are no write-path
  failure modes (no optimistic update, no rollback, no CSRF write retry concerns
  beyond the inherited header on the unused POST endpoints).

## 8. Security & Privacy

- **No new auth surface.** The screen rides the existing cookie session; the
  config GET is idempotent and carries no body. No tokens or credentials are
  introduced or stored.
- **Sensitive fields:** `billing_email` is PII and any capability-bearing values
  (none expected in config, but guard against `portal_url`-style fields if
  present) must not be logged. The screen displays `billing_email` on-device only.
- **Read-only guarantee is a security property:** the UI must not expose any
  affordance that issues a billing mutation. Reviewers verify there is no
  click/edit handler wired to a `POST`/`PATCH` from this screen.
- **Transport:** dev backend is plaintext HTTP; production must be HTTPS. This
  ticket adds no cleartext exemptions of its own (cleartext is restricted to the
  dev host by the separate network-security-config infra ticket).

## 9. Accessibility & i18n

- **a11y:** every `ConfigRow` exposes a merged semantics node combining label and
  value (`Modifier.semantics(mergeDescendants = true) { contentDescription =
  "$label: $value" }`) so TalkBack reads "Currency, USD" as one announcement.
  Section headers use `heading()` semantics. Touch targets for the retry/refresh
  controls are ≥ 48 dp. Text scales with system font size; no fixed-height rows
  that clip large fonts.
- **i18n:** all labels, the "Enabled/Disabled" booleans, "No billing
  configuration" empty text, and error/retry strings come from
  `strings.xml`/`UiText`; no hard-coded user-facing English in Composables. Enum
  values map to localised display strings; unknown tokens fall back to the raw
  string. Currency renders via `NumberFormat.getCurrencyInstance(locale)` and
  timestamps (if any) via the device locale/zone.
- **RTL:** the label/value `ListItem` layout is direction-agnostic (uses
  start/end, not left/right).

## 10. Telemetry & Logging

- **Logging:** reuse the shared `HttpLoggingInterceptor` at `BASIC` (not `BODY`)
  for billing paths to avoid logging `billing_email`. Mapper warnings (unknown
  enum) log at `WARN` via the shared `Logger` with the field name only, never the
  raw token if it could be sensitive.
- **Analytics:** emit a single screen-view event
  `billing_config_viewed { result: success|empty|error }` via the shared
  analytics interface (if present in `core-ui`/`core-data`). No field values are
  attached to the event. A `billing_config_refresh { result }` event fires on
  manual refresh. No PII (`billing_email`) is ever included in telemetry.
- A debug-only (`BuildConfig.DEBUG`) one-line log of unknown-enum hits helps
  catch contract drift early.

## 11. Testing Strategy

Acceptance is *"Config renders read-only"* — tests must prove both correct
rendering and the absence of mutation affordances.

1. **ViewModel unit tests** (JVM, `core-testing` rules, fake `BillingRepository`):
   - `Success` → `Content(config)`; assert every domain field is carried.
   - `ApiError.NotFound` → `Empty`.
   - generic `ApiError` → `Error(canRetry = true)`.
   - refresh failure with existing `Content` → `Content(isStale = true)`,
     last-good config preserved.
   - `retry()`/`refresh()` re-invoke the repository.
   Use Turbine to assert the `StateFlow` emission sequence
   (`Loading → Content`, `Content → Content(isRefreshing) → Content`).
2. **Mapper tests** (if config DTO/model added here): `toDomain()` totality —
   unknown `tax_behavior`/`proration_mode`/payment method → `UNKNOWN`; missing
   optionals → `null`; missing map/list → empty.
3. **Moshi round-trip test** (if DTO added here) against a captured fixture under
   `core-network/src/test/resources/billing/config.json`, asserting every field
   incl. null/missing-key defaults.
4. **Compose UI tests** (`createAndroidComposeRule`):
   - `Content` renders a row for each section field with correct label/value text
     (booleans show "Enabled"/"Disabled").
   - **Read-only assertion:** the test asserts the node tree contains **no**
     editable nodes — no `EditableText` / `SetText` semantics and no node with a
     billing-mutation click action. This is the load-bearing acceptance test.
   - `Loading`, `Empty`, and `Error` states render their respective composables;
     `Error` retry click invokes the ViewModel.
   - a11y: assert `ConfigRow` merged `contentDescription` and header semantics.
5. **MockWebServer test** (optional, if endpoint added here): enqueue the fixture,
   assert request path/verb and successful mapping end-to-end.

Target: 100% of the ViewModel reducer branches and the read-only UI assertion
covered.

## 12. Dependencies & Sequencing

- **Depends on AND-223 (Billing API + DTOs):** provides `BillingApi`, the Moshi
  DTOs, `core-model.billing` types, total `toDomain()` mappers, and the
  authenticated `Retrofit` (cookie jar, CSRF, refresh-retry, timeouts). This
  ticket cannot fetch config without it. If AND-223 omitted the config
  endpoint/DTO/model, this ticket adds that single endpoint following AND-223's
  exact conventions and namespaces (and should ideally be folded back into
  AND-223 — see OQ-1).
- **Transitively** depends on AND-027 (AuthApi/session) and AND-015 (shared
  `ApiError`/`normalizeErrorDetail`) via AND-223.
- **Soft sibling:** AND-232 (billing ViewModels) establishes the
  `feature-billing` ViewModel + `UiState` conventions; this ticket follows the
  same patterns but is independent of AND-232's payment state machine (config is
  read-only, no payment lifecycle). It does not depend on or block AND-232,
  AND-227, or AND-233.
- **Blocks:** none in the backlog.

## 13. Risks & Open Questions

- **OQ-1 (ownership of the config DTO):** Does AND-223 already define
  `BillingConfigDto`/`BillingConfig` and a `BillingApi.getBillingConfig()`? If
  yes, this ticket is pure UI + ViewModel and adds no network/model code. If no,
  this ticket adds the minimal DTO/model/mapper in section 5. Resolve before
  starting; prefer extending AND-223's frozen contract over duplicating it.
- **OQ-2 (endpoint path):** Confirm `/ui/billing/config` against `/openapi.json`
  and `frontend/src/api/endpoints/billing.ts` — it may instead be
  `/api/billing/config` or embedded inside another payload (e.g. the
  subscription response). Correct the path and DTO accordingly.
- **OQ-3 (exact field set):** `types.ts` is authoritative for which fields exist
  on `BillingConfig`; the section 5 field list is a best-guess and must be
  reconciled (some fields may be absent, others — e.g. tax IDs, currency list,
  invoice numbering prefix — may exist). The read-only renderer must drive off
  the real model.
- **Risk — contract drift / new flags:** mitigated by rendering `feature_flags`
  generically (a row per map entry) and by `UNKNOWN` enum fallbacks so new
  backend values never crash the screen.
- **Risk — accidental editability:** the "read-only" requirement is easy to
  regress if a shared component carries an `onClick`. Mitigated by the explicit
  no-editable-node Compose test (section 11.4).

## 14. Acceptance Criteria

1. Navigating to `billing/config` fetches the billing configuration via
   `BillingApi`/`BillingRepository` and displays it.
2. Every field of the `BillingConfig` domain model is rendered in a labelled,
   grouped, **read-only** layout; booleans render as human-readable
   Enabled/Disabled (or Yes/No), enums as localised strings (unknown tokens shown
   raw).
3. The screen contains **no** editable controls and **no** affordance that issues
   a billing mutation — proven by the Compose no-editable-node test.
4. `BillingConfigUiState` covers `Loading`, `Content`, `Empty` (404), and
   `Error`, each with the correct Composable, verified by ViewModel + UI tests.
5. `Error` offers retry; `Content` supports pull-to-refresh; a failed refresh
   keeps the last-good config visible with a stale indicator.
6. Idempotent config GET inherits the shared retry/timeout and 401
   refresh-retry behaviour; `billing_email` is never logged at `BODY` level.
7. All labels/strings are externalised to resources; `ConfigRow` exposes merged
   accessibility semantics.
8. ViewModel reducer, mapper (if added), and UI tests pass in CI.

## 15. Definition of Done

- All acceptance criteria in section 14 are met and CI is green.
- Code lives under `com.testlogon.android.feature.billing.config` in
  `feature-billing`; the ViewModel imports no Retrofit/Moshi/Compose types and
  consumes `ApiResult<BillingConfig>` only.
- If a config endpoint/DTO/model was added, it lives under AND-223's
  `core-network.billing` / `core-model.billing` namespaces, follows AND-223's
  mapper totality conventions, and its fixture is committed (sanitised) under
  `core-network/src/test/resources/billing/config.json`; OQ-1/OQ-2/OQ-3 are
  resolved and reflected in the final field set.
- The read-only no-editable-node Compose test exists and passes.
- The screen is registered in the `feature-billing` nav graph at
  `billing/config` and is reachable end-to-end against the dev backend.
- Ktlint/Detekt pass; no hard-coded user-facing strings; KSP generates any Moshi
  adapters with no warnings.
- KDoc on `BillingConfigScreen`, `BillingConfigViewModel`, and
  `BillingConfigUiState`.
- Reviewed and merged to branch `android-port`.

> Word count note: prose is within the 2,200–2,800 target; the elevated raw count
> reflects the embedded Kotlin/JSON contract blocks, which are load-bearing.
