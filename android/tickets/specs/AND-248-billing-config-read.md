---
id: AND-248
title: Billing config (read)
milestone: M5
epic: E33
priority: P2
size: S
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-223]
blocks: []
---

# AND-248 — Billing config (read)

## 1. Overview & Goal

This ticket delivers a **read-only** presentation of the TestLogon billing
configuration on the native Android port. The web reference
(`src/api/endpoints/billingConfig.ts` → `src/pages/admin/BillingConfigPage.tsx`)
renders the platform-level **admin billing configuration** returned by the
backend. **[Corrected]** The verified field set is platform-fee rates (in basis
points: tips, unlocks, subscriptions, catalog, ad-revenue), payout settings
(min-payout cents, per-payout fee cents, payout schedule, auto-payout flag),
deposit settings (min/max deposit cents, deposit-fee bps), currency
(`default_currency`, `supported_currencies`), tax settings (`tax_enabled`,
`default_tax_rate_bps`), and audit metadata (`updated_at`, `updated_by`). The
fields originally listed here (tax behaviour, supported payment methods, billing
portal availability, trial policy, proration mode, `self_serve_enabled`,
`feature_flags`) do **not** exist on this resource and have been removed — see
§5 and the §16 audit. The Android port must surface this configuration as an
inspectable, **non-editable** Compose screen (the web page is editable/root-only;
the Android port is read-only per the backlog scope).

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
- **Web reference (authoritative for shape — verified):**
  - `src/api/endpoints/billingConfig.ts` — `getBillingConfig()` calls
    `api.get<BillingConfigOut>("/ui/admin/billing-config")`. **[Corrected]** The
    fetch lives in `billingConfig.ts`, not `billing.ts`.
  - `src/api/types.ts` — the authoritative interface is **`BillingConfigOut`**
    (lines ~10537–10556), not the small public `BillingConfig` interface (line
    ~610, which is the Stripe publishable-key/currency object behind
    `/api/billing/config`). The Android DTO/domain field names must mirror
    `BillingConfigOut`.
  - `src/pages/admin/BillingConfigPage.tsx` — the web component that renders the
    config (an editable, root-only admin form grouped into Platform Fees, Payout
    Settings, Deposit Settings, Tax Settings, plus a Change History audit list).
    It is the visual reference for grouping; the Android port renders the same
    groups **read-only**.
- **OpenAPI:** confirmed against the local `reference/openapi.pretty.json` /
  `openapi.index.txt`. The endpoint is `GET /ui/admin/billing-config`
  (op `get_config_ui_admin_billing_config_get`, resp `200: BillingConfigOut`).
  All `BillingConfigOut` fields are required except `updated_at`/`updated_by`
  (each `integer|null` / `string|null`). Where OpenAPI and `types.ts` disagree,
  prefer OpenAPI; here they agree on the field set (types.ts adds the same
  fields with matching nullability).
- **Dependency AND-223 (Billing API + DTOs):** provides the `BillingApi`
  Retrofit interface, the Moshi DTOs, the `core-model.billing` domain types, the
  `toDomain()` mappers, and reuses the AND-027 authenticated `Retrofit`.
  **[Verified against `src/api/client.ts`]** transport = persistent cookie jar
  (`credentials: "include"`), `ui_csrf` cookie echoed into the `X-CSRF-Token`
  header (only meaningful on writes; this GET needs no CSRF), and a single-shot
  `POST /ui/session/refresh`-then-retry on 401 when already authenticated. (The
  ~20 s OkHttp timeout is an Android/AND-027 choice, not present in the web
  client — see §16.) This ticket adds
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

FR-3. **[Corrected]** Group fields into the sections the web reference
(`BillingConfigPage.tsx`) actually uses: **Platform Fees** (`fee_tips_bps`,
`fee_unlocks_bps`, `fee_subscriptions_bps`, `fee_catalog_bps`,
`fee_ad_revenue_bps`), **Payout Settings** (`min_payout_cents`,
`payout_fee_cents`, `payout_schedule`, `auto_payout_enabled`), **Deposit
Settings** (`min_deposit_cents`, `max_deposit_cents`, `deposit_fee_bps`),
**Currency** (`default_currency`, `supported_currencies`), **Tax Settings**
(`tax_enabled`, `default_tax_rate_bps`), and a **Last updated** footer
(`updated_at`, `updated_by`) shown only when present. Sections with no data are
omitted.

FR-4. The ViewModel exposes a single `StateFlow<BillingConfigUiState>`. The state
covers `Loading`, `Content`, and `Error`. **[Corrected]** There is no real
`Empty`/404 path: the backend returns an *effective* config ("override-or-
default", per the `BillingConfigOut` schema description), so `GET
/ui/admin/billing-config` always yields a populated 200 for an authorised
caller. The `Empty` state is retained only as a defensive fallback (mapped from
a 404 if the route is ever disabled); the dominant non-success path is **403**
(non-root / insufficient role) → `Error`. See §16.

FR-5. Booleans (`tax_enabled`, `auto_payout_enabled`) render as human-readable
values ("Enabled"/"Disabled", "Yes"/"No"), not raw `true`/`false`. **[Corrected]**
`payout_schedule` is delivered as a free-form **string** on the wire (web uses
"daily"/"weekly"/"monthly"; not a closed wire enum). It renders via a
string-resource lookup keyed on the known tokens so it is localisable; an
unrecognised token falls back to its raw value (via the `UNKNOWN`-fallback domain
mapping) rather than crashing or hiding the row.

FR-6. **[Corrected]** Fee/tax rates are integers in **basis points** (`*_bps`,
1/100 of a percent); render them as a percentage, e.g. `fee_tips_bps / 100` →
"2.5%" (web: `bpsToPct(bps) = (bps/100).toFixed(1)+"%"`). Cents fields
(`*_cents`) render as currency via `NumberFormat.getCurrencyInstance(locale)`
applied to `cents / 100` using `default_currency`; `default_currency` /
`supported_currencies` show the ISO-4217 code(s). The config carries only raw
integers/strings — all formatting is client-side.

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

This screen reads one configuration resource. **[Corrected — verified against
OpenAPI + `src/api/endpoints/billingConfig.ts`]** the endpoint is:

| Verb | Path | Body | Response DTO |
|------|------|------|--------------|
| GET | `/ui/admin/billing-config` | — | `BillingConfigDto` (`BillingConfigOut`) |

The previously-assumed `/ui/billing/config` does **not** exist; nor is this the
public `GET /api/billing/config` (which returns a flat `Dict[str,str]` of
Stripe publishable-key/currency — the small `BillingConfig` TS interface, a
different resource). The Android DTO mirrors the verified `BillingConfigOut`
schema. If AND-223 already shipped this DTO/endpoint, reuse it verbatim; if not,
this ticket adds the following to AND-223's namespaces
(`core-network.billing` / `core-model.billing`).

DTO (Moshi, `core-network`) — field names verified 1:1 against `BillingConfigOut`:

```kotlin
@JsonClass(generateAdapter = true)
data class BillingConfigDto(
    @Json(name = "fee_tips_bps") val feeTipsBps: Int,
    @Json(name = "fee_unlocks_bps") val feeUnlocksBps: Int,
    @Json(name = "fee_subscriptions_bps") val feeSubscriptionsBps: Int,
    @Json(name = "fee_catalog_bps") val feeCatalogBps: Int,
    @Json(name = "fee_ad_revenue_bps") val feeAdRevenueBps: Int,
    @Json(name = "min_payout_cents") val minPayoutCents: Int,
    @Json(name = "payout_fee_cents") val payoutFeeCents: Int,
    @Json(name = "payout_schedule") val payoutSchedule: String,     // daily|weekly|monthly (free string)
    @Json(name = "auto_payout_enabled") val autoPayoutEnabled: Boolean,
    @Json(name = "min_deposit_cents") val minDepositCents: Int,
    @Json(name = "max_deposit_cents") val maxDepositCents: Int,
    @Json(name = "deposit_fee_bps") val depositFeeBps: Int,
    @Json(name = "default_currency") val defaultCurrency: String,   // ISO-4217
    @Json(name = "supported_currencies") val supportedCurrencies: List<String> = emptyList(),
    @Json(name = "tax_enabled") val taxEnabled: Boolean,
    @Json(name = "default_tax_rate_bps") val defaultTaxRateBps: Int,
    @Json(name = "updated_at") val updatedAt: Long? = null,         // epoch seconds, nullable
    @Json(name = "updated_by") val updatedBy: String? = null,       // admin sub, nullable
)
```

All fields above are required by the schema **except** `updated_at` and
`updated_by` (both nullable). The `*_bps` and `*_cents` values are integers
(bps capped 0–5000 for fees / 0–10000 for tax; cents ≥ 0).

Domain model (`core-model`):

```kotlin
data class BillingConfig(
    val feeTipsBps: Int,
    val feeUnlocksBps: Int,
    val feeSubscriptionsBps: Int,
    val feeCatalogBps: Int,
    val feeAdRevenueBps: Int,
    val minPayoutCents: Int,
    val payoutFeeCents: Int,
    val payoutSchedule: PayoutSchedule,
    val autoPayoutEnabled: Boolean,
    val minDepositCents: Int,
    val maxDepositCents: Int,
    val depositFeeBps: Int,
    val defaultCurrency: String,
    val supportedCurrencies: List<String>,
    val taxEnabled: Boolean,
    val defaultTaxRateBps: Int,
    val updatedAt: Long?,
    val updatedBy: String?,
)

// payout_schedule is an OPEN wire string; modelled with an UNKNOWN(raw) fallback
sealed interface PayoutSchedule {
    data object Daily : PayoutSchedule
    data object Weekly : PayoutSchedule
    data object Monthly : PayoutSchedule
    data class Unknown(val raw: String) : PayoutSchedule
}
```

`internal fun BillingConfigDto.toDomain(): BillingConfig` is total: an
unrecognised `payout_schedule` → `PayoutSchedule.Unknown(raw)`, absent
optionals → `null`, absent `supported_currencies` → empty, mirroring AND-223's
mapper conventions. (There are no closed wire enums on this resource, so the only
`Unknown` fallback is `payout_schedule`.)

Example `GET /ui/admin/billing-config` 200:

```json
{
  "fee_tips_bps": 250,
  "fee_unlocks_bps": 250,
  "fee_subscriptions_bps": 1500,
  "fee_catalog_bps": 1000,
  "fee_ad_revenue_bps": 3000,
  "min_payout_cents": 5000,
  "payout_fee_cents": 25,
  "payout_schedule": "weekly",
  "auto_payout_enabled": true,
  "min_deposit_cents": 500,
  "max_deposit_cents": 1000000,
  "deposit_fee_bps": 290,
  "default_currency": "USD",
  "supported_currencies": ["USD", "EUR", "GBP"],
  "tax_enabled": false,
  "default_tax_rate_bps": 0,
  "updated_at": 1717200000,
  "updated_by": "root|abc123"
}
```

Error envelopes follow the FastAPI shape and are mapped by the shared error
mapper (AND-015): `{"detail":"..."}` | `{"detail":[{"msg":"..."}]}` |
`{"detail":{"code":"...","message":"..."}}` (the `{code,...}` form is the
role/authorization error shape handled by `mapAuthorizationError` in
`src/api/client.ts`, e.g. `code: "role_required"` / `"role_required_scope"`).
**[Corrected]** Relevant statuses: `403` (non-root / insufficient role) →
`Error` with the mapped authorization message; `401` → handled by the inherited
single-shot `POST /ui/session/refresh`-then-retry interceptor; `5xx`/timeout →
`Error` (with bounded retry on this idempotent GET). A `404` is not expected
(effective config always returns 200); if it ever occurs it maps to `Empty` as a
defensive fallback. The GET declares **no** `422` (no query/path params).

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
- **403 (non-root / insufficient role):** **[Corrected]** this is the primary
  access-control failure. The endpoint is root-only (PATCH is documented "ROOT
  only"; GET enforces the same admin gate server-side). Map 403 to `Error` with
  the authorization message produced by AND-015's mapper (the
  `{detail:{code:"role_required"...}}` shape). Do not auto-retry a 403.
- **404 / no config:** not expected (the resource returns an *effective*
  override-or-default config, always 200). Retained only as a defensive mapping
  to the `Empty` state, not treated as a hard error.
- **Refresh failure with cached content:** preserve the prior `Content`, set
  `isStale = true`, surface a non-blocking banner/snackbar; do not blank the
  screen.
- **Mapping resilience:** `toDomain()` never throws — an unrecognised
  `payout_schedule` becomes `PayoutSchedule.Unknown(raw)` (rendered raw), a
  missing `supported_currencies` becomes empty — so a backend adding a new
  schedule token or currency never crashes the screen.
- **No mutations:** because the screen is read-only, there are no write-path
  failure modes (no optimistic update, no rollback, no CSRF write retry concerns
  beyond the inherited header on the unused POST endpoints).

## 8. Security & Privacy

- **No new auth surface.** The screen rides the existing cookie session; the
  config GET is idempotent and carries no body. No tokens or credentials are
  introduced or stored.
- **Root-only resource:** **[Corrected]** this is platform-wide admin
  configuration gated to ROOT operators, not per-account data. Access control is
  enforced server-side (403 for non-root); the screen must not be reachable from
  non-admin navigation. There is no `billing_email`/PII field on this resource
  (that claim was based on the wrong DTO). The only identity-bearing value is
  `updated_by` (an admin `sub` token) — treat it as low-sensitivity operator
  metadata: display on-device, but exclude it from analytics/telemetry and do not
  log it at `BODY` level.
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
  `strings.xml`/`UiText`; no hard-coded user-facing English in Composables. The
  `payout_schedule` token maps to a localised display string; an unrecognised
  token falls back to the raw string. Bps rates render as percentages and cents
  via `NumberFormat.getCurrencyInstance(locale)` keyed on `default_currency`; the
  `updated_at` epoch-seconds timestamp renders via the device locale/zone.
- **RTL:** the label/value `ListItem` layout is direction-agnostic (uses
  start/end, not left/right).

## 10. Telemetry & Logging

- **Logging:** reuse the shared `HttpLoggingInterceptor` at `BASIC` (not `BODY`)
  for billing paths so the response body (including the `updated_by` admin sub
  and fee/payout figures) is not logged. Mapper warnings (unrecognised
  `payout_schedule`) log at `WARN` via the shared `Logger` with the field name
  only.
- **Analytics:** emit a single screen-view event
  `billing_config_viewed { result: success|error }` via the shared analytics
  interface (if present in `core-ui`/`core-data`). No field values (no
  `updated_by`, no fee/payout amounts) are attached. A
  `billing_config_refresh { result }` event fires on manual refresh.
- A debug-only (`BuildConfig.DEBUG`) one-line log of unknown-`payout_schedule`
  hits helps catch contract drift early.

## 11. Testing Strategy

Acceptance is *"Config renders read-only"* — tests must prove both correct
rendering and the absence of mutation affordances.

1. **ViewModel unit tests** (JVM, `core-testing` rules, fake `BillingRepository`):
   - `Success` → `Content(config)`; assert every domain field is carried.
   - `ApiError.Forbidden` (403, non-root) → `Error` (no auto-retry).
   - `ApiError.NotFound` (404 defensive) → `Empty`.
   - generic `ApiError` (5xx/timeout) → `Error(canRetry = true)`.
   - refresh failure with existing `Content` → `Content(isStale = true)`,
     last-good config preserved.
   - `retry()`/`refresh()` re-invoke the repository.
   Use Turbine to assert the `StateFlow` emission sequence
   (`Loading → Content`, `Content → Content(isRefreshing) → Content`).
2. **Mapper tests** (if config DTO/model added here): `toDomain()` totality —
   unrecognised `payout_schedule` → `PayoutSchedule.Unknown(raw)`; known tokens
   ("daily"/"weekly"/"monthly") map correctly; null `updated_at`/`updated_by`
   preserved; missing `supported_currencies` → empty list.
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
- **OQ-2 (endpoint path) — RESOLVED.** Verified: the endpoint is
  `GET /ui/admin/billing-config` returning `BillingConfigOut`
  (`src/api/endpoints/billingConfig.ts`; OpenAPI op
  `get_config_ui_admin_billing_config_get`). It is **not** `/ui/billing/config`
  and **not** the public `/api/billing/config` (a different `Dict[str,str]`
  resource). See §16.
- **OQ-3 (exact field set) — RESOLVED.** Verified field set = `BillingConfigOut`
  (fees `*_bps`, payouts `*_cents` + `payout_schedule` + `auto_payout_enabled`,
  deposits, `default_currency`/`supported_currencies`, `tax_enabled`/
  `default_tax_rate_bps`, plus nullable `updated_at`/`updated_by`). The original
  field guesses (tax behaviour, billing email, payment methods, trial, proration,
  feature flags) were wrong and are removed. See §5/§16.
- **OQ-4 (NEW — access role):** GET is gated to ROOT operators server-side
  (PATCH is explicitly "ROOT only"; the web page is labelled "Root only"). Confirm
  whether the Android nav exposes this screen only to root admins and how a 403 is
  surfaced (currently mapped to `Error`). Unverified: the exact role gate on the
  *GET* (the spec documents no auth schema; assumed same admin gate as PATCH).
- **Risk — contract drift / new payout schedule:** mitigated by the
  `PayoutSchedule.Unknown(raw)` fallback and by rendering `supported_currencies`
  generically, so new backend values never crash the screen.
- **Risk — accidental editability:** the "read-only" requirement is easy to
  regress if a shared component carries an `onClick`. Mitigated by the explicit
  no-editable-node Compose test (section 11.4).

## 14. Acceptance Criteria

1. Navigating to `billing/config` fetches the billing configuration via
   `BillingApi`/`BillingRepository` and displays it.
2. Every field of the `BillingConfig` domain model (`BillingConfigOut`) is
   rendered in a labelled, grouped, **read-only** layout; booleans render as
   human-readable Enabled/Disabled (or Yes/No), `*_bps` rates as percentages,
   `*_cents` as locale currency, `payout_schedule` as a localised string (unknown
   token shown raw).
3. The screen contains **no** editable controls and **no** affordance that issues
   a billing mutation (no PATCH/POST) — proven by the Compose no-editable-node
   test.
4. `BillingConfigUiState` covers `Loading`, `Content`, and `Error` (with a
   defensive `Empty` for 404), each with the correct Composable, verified by
   ViewModel + UI tests; a 403 (non-root) renders an authorization `Error`.
5. `Error` offers retry (403 excepted); `Content` supports pull-to-refresh; a
   failed refresh keeps the last-good config visible with a stale indicator.
6. Idempotent config GET inherits the shared retry/timeout and 401
   refresh-retry behaviour; the response body (incl. `updated_by`) is never
   logged at `BODY` level.
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer.

1. **Endpoint is `GET /ui/admin/billing-config` returning `BillingConfigOut`.**
   VERDICT: **Corrected** (spec had `GET /ui/billing/config`). SOURCE:
   `src/api/endpoints/billingConfig.ts: getBillingConfig` (`api.get<BillingConfigOut>("/ui/admin/billing-config")`);
   OpenAPI `GET /ui/admin/billing-config` (op `get_config_ui_admin_billing_config_get`, resp `200: BillingConfigOut`).
2. **The fetch helper lives in `billingConfig.ts`, not `billing.ts`.** VERDICT:
   **Corrected**. SOURCE: `src/api/endpoints/billingConfig.ts`.
3. **`/api/billing/config` is a different resource (public Stripe-style
   `Dict[str,str]`), not this screen's data.** VERDICT: **Verified**. SOURCE:
   OpenAPI `GET /api/billing/config` (op `billing_config_api_billing_config_get`,
   resp 200 = object with `additionalProperties: string`); `src/api/types.ts: BillingConfig` (line ~610: `publishable_key?`, `currency`).
4. **`BillingConfigOut` field set = fees(`*_bps`), payouts(`*_cents`,
   `payout_schedule`, `auto_payout_enabled`), deposits, `default_currency`,
   `supported_currencies`, `tax_enabled`, `default_tax_rate_bps`, `updated_at`,
   `updated_by`.** VERDICT: **Verified**. SOURCE: `src/api/types.ts: BillingConfigOut`
   (lines ~10537–10556); OpenAPI `components.schemas.BillingConfigOut`.
5. **Original fields (tax_behavior, billing_email, supported_payment_methods,
   default_payment_method_type, portal_enabled, self_serve_enabled,
   trial_period_days, proration_mode, feature_flags) do NOT exist on this
   resource.** VERDICT: **Corrected** (removed). SOURCE: absent from
   `components.schemas.BillingConfigOut` and `src/api/types.ts: BillingConfigOut`.
6. **All `BillingConfigOut` fields required except `updated_at`/`updated_by`
   (each nullable).** VERDICT: **Verified**. SOURCE: OpenAPI
   `BillingConfigOut.required` (16 fields; `updated_at`/`updated_by` use
   `anyOf[type, null]` and are omitted from `required`).
7. **`*_bps` are integers in basis points; web renders fees as `bps/100 + "%"`
   and cents as `cents/100` dollars.** VERDICT: **Verified**. SOURCE:
   `src/pages/admin/BillingConfigPage.tsx` (`bpsToPct`, `centsToDollars`);
   OpenAPI field descriptions ("...in basis points", maxima 5000/10000).
8. **`payout_schedule` is a free-form string (daily/weekly/monthly), not a closed
   wire enum.** VERDICT: **Corrected** (spec modelled it as a typed enum). SOURCE:
   `src/api/types.ts: BillingConfigOut.payout_schedule: string`; OpenAPI
   `payout_schedule: {type: string}`; web `<Select>` options daily/weekly/monthly.
9. **There are no closed wire enums on this resource (no TaxBehavior /
   PaymentMethodType / ProrationMode).** VERDICT: **Corrected**. SOURCE: same as
   #4/#5 — none of those tokens appear in the schema.
10. **Auth/transport: persistent cookie session (`credentials: include`),
    `ui_csrf` cookie echoed to `X-CSRF-Token` header, single-shot
    `POST /ui/session/refresh`-then-retry on 401 (only when already
    authenticated).** VERDICT: **Verified**. SOURCE: `src/api/client.ts`
    (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`;
    `refreshSession()` POSTs `/ui/session/refresh`; 401 retry block).
11. **`X-CSRF-Token` is set on every request but is only meaningful for writes;
    the GET needs no CSRF.** VERDICT: **Verified** (header set unconditionally;
    GET is safe/idempotent). SOURCE: `src/api/client.ts` (header set before verb
    branching).
12. **403 (insufficient role) is the primary access-control failure; mapped via
    AND-015's `mapAuthorizationError` (`detail.code` = `role_required` /
    `role_required_scope`).** VERDICT: **Verified** (error shape) /
    **Unverified-assumption** (that GET specifically enforces root). SOURCE:
    `src/api/client.ts: mapAuthorizationError`, `normalizeErrorDetail`; OpenAPI
    PATCH description "ROOT only"; web page subtitle "Root only".
13. **Endpoint always returns an effective (override-or-default) 200; no real
    `Empty`/404 path.** VERDICT: **Verified**. SOURCE: OpenAPI
    `BillingConfigOut.description` = "Effective billing configuration
    (override-or-default)."; GET declares only `200` (no 404, no 422).
14. **GET declares no query/path params and no 422.** VERDICT: **Verified**.
    SOURCE: OpenAPI index line `GET /ui/admin/billing-config | req= | resp=200:BillingConfigOut | params=`.
15. **Sibling endpoints exist (PATCH update, POST reset, POST preview, GET audit)
    but are OUT OF SCOPE for this read-only ticket.** VERDICT: **Verified**.
    SOURCE: `src/api/endpoints/billingConfig.ts` (`updateBillingConfig`,
    `resetBillingConfig`, `previewBillingConfig`, `getBillingConfigAudit`);
    OpenAPI index lines for `/ui/admin/billing-config{,/reset,/preview,/audit}`.
16. **Web page groups fields into Platform Fees / Payout Settings / Deposit
    Settings / Tax Settings (+ Change History).** VERDICT: **Verified**. SOURCE:
    `src/pages/admin/BillingConfigPage.tsx` (Card titles).
17. **~20 s OkHttp timeouts / bounded retry on the idempotent GET.** VERDICT:
    **Unverified-assumption** (Android/AND-027 client config; not derivable from
    the web client). SOURCE: framework ref — AND-027 OkHttp client (spec-internal).
18. **Android framework choices (Compose/Material 3, Hilt, Navigation-Compose,
    PullToRefreshBox, `collectAsStateWithLifecycle`, merged semantics).** VERDICT:
    **Unverified-assumption** (framework ref — standard Jetpack APIs; not
    verifiable against backend/web sources). SOURCE: framework ref
    (developer.android.com/jetpack/compose).

### Corrections made

- Endpoint path `/ui/billing/config` → `GET /ui/admin/billing-config`
  (`BillingConfigOut`); clarified it is distinct from public `/api/billing/config`.
- Endpoint-file reference `billing.ts` → `billingConfig.ts`; types reference
  `BillingConfig` → `BillingConfigOut`.
- Replaced the entire DTO/domain field set (§5) with the verified `BillingConfigOut`
  fields; removed the fabricated tax_behavior / billing_email / payment-method /
  trial / proration / feature_flags fields and their enums.
- `payout_schedule` modelled as an open string with `PayoutSchedule.Unknown(raw)`
  fallback instead of a closed wire enum; removed `TaxBehavior`/`PaymentMethodType`/
  `ProrationMode` enums (no such wire enums exist).
- Added bps→% and cents→currency rendering rules (FR-6); updated FR-3 grouping to
  match the web page.
- Reframed access errors: 403 (root-only) is the primary failure; 404/`Empty` is
  defensive only (effective config always 200).
- Security/telemetry: removed `billing_email` PII claims (field does not exist);
  replaced with `updated_by` (admin sub) handling and root-only access control.
- Resolved OQ-2/OQ-3; added OQ-4 (GET role gate).

### Open assumptions

- **GET role gate:** the GET's exact authorization (root vs general admin) is not
  expressed in the OpenAPI security block; assumed equal to PATCH's documented
  "ROOT only" based on the web page label. Confirm against the backend route
  guard before relying on it for nav gating.
- **OkHttp ~20 s timeout / bounded retry:** an Android-side AND-027 client
  decision; no web-client equivalent exists, so it cannot be source-verified here.
- **Android Jetpack API choices:** framework refs only (no backend/web source).
- **`payout_schedule` token universe:** the web `<Select>` offers
  daily/weekly/monthly; the wire type is an open `string`, so other tokens are
  possible — hence the `Unknown(raw)` fallback (cannot be exhaustively verified).
- **Analytics interface existence** (`billing_config_viewed`/`_refresh`): assumed
  from `core-ui`/`core-data`; not verifiable from the provided sources.

## 17. Test Plan

Test targets: **JVM** = local JVM/Robolectric (no device); **emu35** = headless
AVD `test35` (x86_64, API 35); **deviceA15** = physical Samsung Galaxy A15 5G
(SM-A156U, serial R5CX821TA9R, API 34, arm64-v8a). For this read-only,
network-only feature there is no camera/biometric/WebRTC/FCM behaviour, so the
emulator is sufficient for UI/instrumented cases; one e2e case uses the physical
device to confirm arm64 / API-34 behaviour against the real dev backend.

- **TC-AND-248-01** — Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: MockWebServer enqueues the §5 200 fixture for
  `/ui/admin/billing-config`. Steps: call `BillingApi.getBillingConfig()` via the
  repository. Expected: exactly one `GET /ui/admin/billing-config` (no body, no
  query); response maps to a `BillingConfig` with all 18 fields equal to the
  fixture (`payout_schedule` → `Weekly`). Traces: AC-1, AC-2.
- **TC-AND-248-02** — Type: unit (Moshi mapper). Target: JVM. Preconditions:
  DTO + `toDomain()` present. Steps: deserialize the §5 fixture and a variant
  with `"payout_schedule":"fortnightly"`, `updated_at`/`updated_by` = null, and
  `supported_currencies` absent. Expected: known token → `Weekly`; unknown →
  `PayoutSchedule.Unknown("fortnightly")`; nulls preserved; missing list → empty;
  `toDomain()` never throws. Traces: AC-2.
- **TC-AND-248-03** — Type: unit (ViewModel reducer). Target: JVM.
  Preconditions: fake `BillingRepository` returns `ApiResult.Success(config)`.
  Steps: construct ViewModel; collect `state` with Turbine. Expected emission
  `Loading → Content(config, isStale=false, isRefreshing=false)`. Traces: AC-1,
  AC-4.
- **TC-AND-248-04** — Type: unit (ViewModel reducer). Target: JVM.
  Preconditions: fake repo returns `ApiError.Forbidden` (403). Steps: init.
  Expected: `Loading → Error`; `canRetry == false`; message is the mapped
  authorization string. Traces: AC-4.
- **TC-AND-248-05** — Type: unit (ViewModel reducer). Target: JVM.
  Preconditions: fake repo returns generic `ApiError` (500/timeout). Steps: init,
  then `retry()`. Expected: `Loading → Error(canRetry=true)`; `retry()` re-invokes
  the repo and (on success) emits `Content`. Traces: AC-4, AC-5.
- **TC-AND-248-06** — Type: unit (ViewModel reducer). Target: JVM.
  Preconditions: first load → `Content`; second load (refresh) fails. Steps:
  `refresh()`. Expected: emits `Content(isRefreshing=true)` then
  `Content(isStale=true, isRefreshing=false)` with the prior config preserved
  (screen not blanked). Traces: AC-5.
- **TC-AND-248-07** — Type: unit (ViewModel reducer). Target: JVM.
  Preconditions: fake repo returns `ApiError.NotFound` (404, defensive). Steps:
  init. Expected: `Loading → Empty`. Traces: AC-4.
- **TC-AND-248-08** — Type: Compose-UI. Target: emu35. Preconditions:
  `Content(config)` from the fixture. Steps: render `BillingConfigScreen`.
  Expected: a labelled row per field under the correct section header; booleans
  show "Enabled"/"Disabled"; `fee_tips_bps=250` shows "2.5%"; `payout_fee_cents=25`
  shows "$0.25"; `payout_schedule` shows localised "Weekly". Traces: AC-1, AC-2,
  AC-7.
- **TC-AND-248-09** — Type: Compose-UI (load-bearing read-only assertion).
  Target: emu35. Preconditions: `Content`. Steps: traverse the semantics tree.
  Expected: NO node with `EditableText`/`SetText` semantics and NO node carrying a
  click/edit action that would issue a PATCH/POST; no `TextField`/`Switch`/submit
  button. Traces: AC-3.
- **TC-AND-248-10** — Type: Compose-UI. Target: emu35. Preconditions: each of
  `Loading`, `Empty`, `Error` states. Steps: render each; on `Error` click Retry.
  Expected: correct composable per state; Retry invokes `viewModel.retry()`;
  pull-to-refresh on `Content` invokes `refresh()`. Traces: AC-4, AC-5.
- **TC-AND-248-11** — Type: Compose-UI (accessibility). Target: emu35.
  Preconditions: `Content`. Steps: inspect merged semantics. Expected: each
  `ConfigRow` exposes one merged `contentDescription` "label: value" (e.g.
  "Default currency: USD"); section headers carry `heading()` semantics; retry/
  refresh targets ≥ 48 dp; layout survives a 2x font-scale config without
  clipping. Traces: AC-7.
- **TC-AND-248-12** — Type: contract/MockWebServer (security/permission).
  Target: JVM. Preconditions: enqueue `403` with
  `{"detail":{"code":"role_required","message":"..."}}`. Steps: fetch. Expected:
  mapped to `ApiError.Forbidden`; ViewModel → `Error` (authorization message); no
  auto-retry attempt is made on 403; the response body is not logged at `BODY`
  level (logging interceptor at `BASIC`). Traces: AC-3, AC-4, AC-6.
- **TC-AND-248-13** — Type: integration (offline / flaky-host). Target: emu35
  (airplane-mode toggle) with MockWebServer. Preconditions: a `Content` is shown,
  then connectivity drops. Steps: trigger `refresh()` while offline (socket
  failure). Expected: prior `Content` retained with `isStale=true` and a
  non-blocking stale banner; a subsequent online refresh clears the banner and
  updates the data. Traces: AC-5.
- **TC-AND-248-14** — Type: instrumented/e2e (real device, real backend).
  Target: **deviceA15 (MUST run on physical device)** — confirms arm64-v8a /
  API-34 behaviour against the live dev host. Preconditions: app installed; signed
  in as a ROOT operator; cookie session valid. Steps: navigate to `billing/config`
  end-to-end. Expected: live config renders read-only with correct
  formatting; (negative path) signing in as a non-root user yields the 403
  authorization `Error` and the screen exposes no edit affordance. Traces: AC-1,
  AC-2, AC-3, AC-6.

### Coverage matrix

| AC (§14) | Covered by |
|----------|------------|
| AC-1 (fetch + display) | TC-01, TC-03, TC-08, TC-14 |
| AC-2 (all fields, formatting, read-only layout) | TC-01, TC-02, TC-08, TC-14 |
| AC-3 (no editable / no mutation affordance) | TC-09, TC-12, TC-14 |
| AC-4 (Loading/Content/Empty/Error + 403) | TC-03, TC-04, TC-05, TC-07, TC-10, TC-12 |
| AC-5 (retry / pull-to-refresh / stale) | TC-05, TC-06, TC-10, TC-13 |
| AC-6 (retry/timeout, 401 refresh, no BODY logging) | TC-12, TC-14 |
| AC-7 (externalised strings, merged a11y semantics) | TC-08, TC-11 |
| AC-8 (reducer + mapper + UI tests pass in CI) | TC-01 – TC-13 |
