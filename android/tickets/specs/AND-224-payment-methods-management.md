---
id: AND-224
title: Payment methods management
milestone: M5
epic: E31
priority: P0
size: M
status: draft
depends_on: [AND-223]
blocks: []
---

# AND-224 — Payment methods management

## 1. Overview & Goal

Deliver the user-facing Android feature for managing saved payment methods: list
all payment methods on the account, add a new method, remove an existing one, and
designate exactly one method as the default. This ticket owns the `feature-billing`
payment-methods screen, its `ViewModel`, UI state, and the repository/use-case glue
that drives the billing API. It does **not** own the network DTOs, Retrofit service,
or DTO→domain mapping — those are delivered by **AND-223 (Billing API + DTOs)**,
which this ticket consumes.

Goal (testable): a signed-in user can open the Payment Methods screen, see every
saved method rendered with its brand/last-four/expiry, add a method, remove a
method, and mark a method as default; each action persists to the backend and the
list reflects the new server state. Acceptance from backlog: "Methods render +
manage."

The feature must behave correctly against the unreliable plaintext dev backend
(`http://18.222.237.167:8000`): bounded retry on idempotent GET, ~20s timeouts,
explicit offline/stale presentation, optimistic-but-reconciled mutations, and a
single 401→`/ui/session/refresh`→retry path that lives in the shared OkHttp stack.

## 2. Context & References

- Repo `spannella/testlogon`, Android app in `android/`, branch `android-port`.
- Module: `feature-billing` (new code here) depending on `core-data`, `core-model`,
  `core-network`, `core-ui`, `core-testing`. Namespace base
  `com.testlogon.android` → feature package `com.testlogon.android.feature.billing`.
- **AND-223** provides `BillingApi` (Retrofit), the `core-network` billing DTOs, and
  the `BillingRepository` contract + DTO mapping. This ticket implements/extends the
  repository methods specific to payment methods and the entire presentation layer.
- Web reference: `frontend/src/api/endpoints/billing.ts` and shared types in
  `frontend/src/api/types.ts` define the canonical endpoint shapes and field names
  this port mirrors.
- Auth/session is cookie-based with `X-CSRF-Token` echo of the `ui_csrf` cookie and
  a single refresh-on-401 retry, all handled by the shared interceptor stack from
  the core-network milestone (AND-027 lineage via AND-223). No auth code is added
  here.
- OpenAPI source of truth: `GET /openapi.json` on the dev backend; field names in
  Section 5 must be reconciled against it during AND-223 integration.

## 3. Functional Requirements

FR-1 **List.** On screen entry the feature loads payment methods via
`GET /ui/billing/payment-methods` and renders each as a row: card brand icon,
masked number (`•••• 4242`), expiry (`MM/YY`), and a "Default" badge on the default
method. Methods are ordered default-first, then by `created_at` descending.

FR-2 **Empty state.** When the account has zero methods, show an empty state with
an explanatory line and a primary "Add payment method" action.

FR-3 **Add.** A primary "Add" action opens an add flow (bottom sheet or dedicated
route `billing/payment-methods/add`) collecting a payment token/handle. The client
submits `POST /ui/billing/payment-methods`. On success the new method appears in the
list. (Card data capture/PCI tokenization UI is the dev-backend's token-echo stub;
the screen submits the `payment_token` it is given — no raw PAN is stored or logged.)

FR-4 **Remove.** Each non-default row exposes a "Remove" affordance (overflow menu
or swipe) that prompts a confirmation dialog, then calls
`DELETE /ui/billing/payment-methods/{id}`. Removing the **default** method is only
permitted when it is the last method; otherwise the user must set another default
first (UI disables/explains).

FR-5 **Set default.** Each non-default row exposes "Set as default" which calls
`POST /ui/billing/payment-methods/{id}/default`. Exactly one method is default at
any time; the previous default loses its badge after server confirmation.

FR-6 **Refresh.** Pull-to-refresh re-fetches the list. Manual retry is available
from the error state.

FR-7 **Concurrency guard.** While a mutation (add/remove/set-default) is in flight,
the affected row shows an inline progress indicator and is non-interactive; the list
remains scrollable.

FR-8 **Stale/offline.** If the cached list is shown while the network is
unavailable or the fetch failed, a non-blocking "Showing saved data" banner is
displayed with a retry control.

## 4. Technical Design

Single-Activity, Navigation-Compose. New route registered by `feature-billing`:

```kotlin
const val PAYMENT_METHODS_ROUTE = "billing/payment-methods"

fun NavGraphBuilder.paymentMethodsScreen(
    onNavigateBack: () -> Unit,
)

fun NavController.navigateToPaymentMethods(navOptions: NavOptions? = null)
```

UI layer (Compose + Material 3):

```kotlin
@Composable
fun PaymentMethodsRoute(
    onNavigateBack: () -> Unit,
    viewModel: PaymentMethodsViewModel = hiltViewModel(),
)

@Composable
fun PaymentMethodsScreen(
    state: PaymentMethodsUiState,
    onAdd: (paymentToken: String, makeDefault: Boolean) -> Unit,
    onRemove: (methodId: String) -> Unit,
    onSetDefault: (methodId: String) -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onNavigateBack: () -> Unit,
)
```

ViewModel exposes `StateFlow<PaymentMethodsUiState>` and consumes a use-case-thin
repository:

```kotlin
@HiltViewModel
class PaymentMethodsViewModel @Inject constructor(
    private val repository: BillingRepository,   // from AND-223; payment-method ops added here
) : ViewModel() {
    val uiState: StateFlow<PaymentMethodsUiState>
    fun load()
    fun refresh()
    fun add(paymentToken: String, makeDefault: Boolean)
    fun remove(methodId: String)
    fun setDefault(methodId: String)
    fun consumeEvent()   // one-shot snackbar events
}
```

Repository surface owned/extended by this ticket (interface lives in `core-data`,
implementation in `core-data`; Retrofit `BillingApi` + DTO mapping land in AND-223):

```kotlin
interface BillingRepository {
    fun observePaymentMethods(): Flow<List<PaymentMethod>>          // Room-backed
    suspend fun refreshPaymentMethods(): ApiResult<Unit>
    suspend fun addPaymentMethod(token: String, makeDefault: Boolean): ApiResult<PaymentMethod>
    suspend fun removePaymentMethod(id: String): ApiResult<Unit>
    suspend fun setDefaultPaymentMethod(id: String): ApiResult<Unit>
}
```

Domain model (in `core-model`):

```kotlin
data class PaymentMethod(
    val id: String,
    val brand: CardBrand,        // VISA, MASTERCARD, AMEX, DISCOVER, UNKNOWN
    val last4: String,
    val expMonth: Int,
    val expYear: Int,
    val isDefault: Boolean,
    val createdAt: Instant,
)
```

Data flow is single-source-of-truth via Room: `observePaymentMethods()` emits from
the DAO; mutations call the API then update Room from the authoritative response
(or trigger a re-fetch when the mutation returns no body). The screen renders from
the Room flow so add/remove/set-default reconcile automatically. GET timeout/retry
and 401-refresh are handled by the shared OkHttp client; this ticket adds no
interceptors.

`ApiResult<T>` is the existing sealed type (`Success`, `Error(detail, code, http)`,
`NetworkError`, `Unauthorized`). FastAPI `detail` is parsed by the shared mapper
(string | `[{msg}]` | `{code,...}`).

## 5. API Contract

Endpoints (paths mirror `frontend/src/api/endpoints/billing.ts`; field names to be
locked against `/openapi.json` during AND-223). All carry session cookies and the
`X-CSRF-Token` header on mutations.

`GET /ui/billing/payment-methods` → 200:

```json
{
  "items": [
    {
      "id": "pm_01H...",
      "brand": "visa",
      "last4": "4242",
      "exp_month": 12,
      "exp_year": 2027,
      "is_default": true,
      "created_at": "2026-01-04T10:22:31Z"
    }
  ]
}
```

`POST /ui/billing/payment-methods` body:

```json
{ "payment_token": "tok_dev_echo_4242", "make_default": false }
```

→ 201 returns the created object (same shape as an `items[]` element).

`DELETE /ui/billing/payment-methods/{id}` → 204 No Content (empty body).

`POST /ui/billing/payment-methods/{id}/default` → 200 returning the updated method,
or 204 (in which case the client re-fetches the list).

Error envelope (FastAPI), e.g. 409 when removing a default while others exist:

```json
{ "detail": { "code": "default_method_required", "message": "Set another default first." } }
```

Validation errors arrive as `{"detail":[{"msg":"...","loc":[...]}]}`; 401 triggers
the shared refresh-and-retry-once path. Idempotent retry/backoff applies only to the
GET list call.

## 6. Data & State Management

Room (cache, `core-data`):

```kotlin
@Entity(tableName = "payment_method")
data class PaymentMethodEntity(
    @PrimaryKey val id: String,
    val brand: String,
    val last4: String,
    val expMonth: Int,
    val expYear: Int,
    val isDefault: Boolean,
    val createdAt: Long,        // epoch millis
    val updatedAtLocal: Long,   // for staleness banner
)

@Dao
interface PaymentMethodDao {
    @Query("SELECT * FROM payment_method ORDER BY isDefault DESC, createdAt DESC")
    fun observeAll(): Flow<List<PaymentMethodEntity>>
    @Upsert suspend fun upsertAll(items: List<PaymentMethodEntity>)
    @Query("DELETE FROM payment_method WHERE id = :id") suspend fun deleteById(id: String)
    @Query("DELETE FROM payment_method") suspend fun clear()
    @Transaction suspend fun replaceAll(items: List<PaymentMethodEntity>)
}
```

`refreshPaymentMethods()` performs `replaceAll` (clear+upsert in one transaction) so
removed-server-side methods disappear. `setDefault` writes the returned method and
clears the prior default flag locally only after server success. DataStore is not
used for this feature beyond the existing session prefs.

UI state:

```kotlin
data class PaymentMethodsUiState(
    val methods: List<PaymentMethodUi> = emptyList(),
    val isLoading: Boolean = false,      // first load / hard refresh
    val isRefreshing: Boolean = false,   // pull-to-refresh
    val rowInFlight: Set<String> = emptySet(),  // ids with active mutation
    val isStale: Boolean = false,        // cache shown, refresh failed
    val emptyState: Boolean = false,
    val errorMessage: String? = null,    // blocking error (empty + no cache)
    val event: PaymentMethodsEvent? = null,  // one-shot snackbar
)

data class PaymentMethodUi(
    val id: String, val brandLabel: String, val maskedNumber: String,
    val expiryLabel: String, val isDefault: Boolean, val canSetDefault: Boolean,
    val canRemove: Boolean,
)

sealed interface PaymentMethodsEvent {
    data class Added(val maskedNumber: String) : PaymentMethodsEvent
    data class Removed(val maskedNumber: String) : PaymentMethodsEvent
    data class DefaultSet(val maskedNumber: String) : PaymentMethodsEvent
    data class Failure(val message: String) : PaymentMethodsEvent
}
```

The ViewModel combines the Room `Flow` with a transient operation state to compute
`uiState`. `rowInFlight` drives per-row spinners and disables that row only.

## 7. Error Handling & Resilience

- **GET list:** ~20s OkHttp timeout; bounded backoff retry (max 2 retries,
  jittered) since GET is idempotent — handled by shared client. On final failure
  with a non-empty cache → `isStale = true` + banner; with empty cache →
  `errorMessage` blocking state + Retry.
- **Mutations (add/remove/set-default):** NOT retried automatically (non-idempotent
  POST/DELETE). On failure, the row exits `rowInFlight`, no local DB change is
  committed, and a `Failure` snackbar surfaces the mapped `detail` message.
- **401:** shared interceptor calls `POST /ui/session/refresh` once and retries;
  if refresh fails the result is `Unauthorized` → emit event and let app-level
  session handling route to re-auth.
- **409 `default_method_required`:** surfaced as an explanatory message; the remove
  affordance for the default method is pre-disabled when other methods exist
  (`canRemove = false`).
- **Network unavailable:** `NetworkError` maps to the stale banner if cache exists,
  else the blocking error state.
- All transitions are idempotent on repeated taps because in-flight rows are locked.

## 8. Security & Privacy

- No raw PAN, CVV, or full card number is ever held, persisted, or logged. The
  client handles only the server-issued `payment_token` (opaque) and the masked
  `last4`. Room stores `last4` only.
- All mutating calls send `X-CSRF-Token` (echo of `ui_csrf` cookie) via the shared
  stack; session rides the persistent cookie jar. No tokens are placed in URLs.
- Logging: payment tokens and any request body for `POST payment-methods` are
  redacted by the OkHttp logging redactor; only method `id` and `last4` may appear
  in debug logs. Telemetry events carry `id`/`brand`/`last4` only.
- Dev backend is plaintext HTTP (cleartext permitted for the dev host only via the
  existing network-security-config); this is acknowledged dev-only risk and not a
  production posture. No card data crosses the wire from this client regardless.

## 9. Accessibility & i18n

- All interactive elements have `contentDescription`/`semantics`: brand icons
  ("Visa card ending 4242"), "Set as default", "Remove", and the default badge.
- Minimum 48dp touch targets; overflow menu items reachable by TalkBack; swipe-to-
  remove has an equivalent menu action (no swipe-only affordances).
- Confirmation dialog focus order: title → body → cancel → confirm; destructive
  confirm labeled clearly ("Remove card ending 4242").
- All strings in `feature-billing/src/main/res/values/strings.xml`; no hardcoded
  text. Brand labels, masked-number format (`•••• %s`), and expiry (`MM/YY`) are
  locale-aware via `stringResource`. Dynamic type and dark theme via Material 3
  tokens; `last4` masking uses non-LTR-breaking formatting.

## 10. Telemetry & Logging

Analytics via the existing `core-ui`/analytics facade (no new SDK). Events:

- `billing_pm_list_viewed` { count, has_default }
- `billing_pm_add_succeeded` / `billing_pm_add_failed` { brand, error_code? }
- `billing_pm_removed` / `billing_pm_remove_failed` { error_code? }
- `billing_pm_default_set` / `billing_pm_default_failed` { error_code? }
- `billing_pm_stale_shown` { reason }

Structured debug logs at the repository boundary: operation name, method `id`,
HTTP status, latency ms — never token or PAN. Error logs include the mapped
`detail.code`.

## 11. Testing Strategy

Unit (`core-testing`, JUnit + Turbine + MockWebServer/fake repo):
- ViewModel: list load success → `methods` populated, `emptyState=false`.
- Empty response → `emptyState=true`.
- Add success emits `Added` event and DB upsert observed via flow.
- Remove default while others exist → `canRemove=false`, action blocked.
- Set-default success clears prior default flag in derived state.
- Mutation failure → row leaves `rowInFlight`, `Failure` event, no DB change.
- GET failure with cache → `isStale=true`; without cache → `errorMessage` set.
- 401 path surfaces `Unauthorized` (refresh handled by interceptor, asserted via
  MockWebServer queued 401→200).

Repository: DTO→entity→domain round-trip (against AND-223 mappers); `replaceAll`
removes server-deleted methods; 204 delete updates DB.

UI/Compose (`createComposeRule`): rows render brand/last4/expiry/badge; empty
state shows Add; confirmation dialog gates remove; per-row spinner during
in-flight; pull-to-refresh triggers `onRefresh`. Semantics assertions for
TalkBack labels.

Coverage target: ViewModel + repository payment-method paths ≥ 85% line.

## 12. Dependencies & Sequencing

- **Depends on AND-223** (Billing API + DTOs): provides `BillingApi`, billing DTOs,
  DTO↔domain mappers, and the `BillingRepository` contract this ticket extends. The
  payment-method endpoints and JSON shapes in Section 5 must be the ones validated
  in AND-223 against `/openapi.json`.
- Transitively relies on the core-network session/CSRF/refresh stack (AND-027
  lineage) and `core-ui` theming/components.
- Blocks: none currently in backlog. Any "billing overview"/subscription screen that
  embeds a payment-method summary should reuse `PaymentMethodUi` and the repository
  flow from this ticket.
- Sequencing: implementable immediately after AND-223 merges; UI can be developed in
  parallel against a fake `BillingRepository` from `core-testing`.

## 13. Risks & Open Questions

- **Endpoint/field drift:** exact paths and field names (`items` vs bare array,
  `payment_token` naming, default-set verb) are assumed from the web client and must
  be confirmed against `/openapi.json` in AND-223; mismatches are mapper-only fixes.
- **Default-removal semantics:** assumed server rejects removing the default when
  others exist (409). If the backend instead auto-promotes another method, FR-4 and
  `canRemove` logic relax — confirm behavior.
- **Tokenization:** dev backend uses an echo/stub token; production card capture
  (PCI SDK / hosted fields) is out of scope and will be a separate ticket. The add
  flow is built to accept an opaque token to avoid rework.
- **Dev host flakiness:** plaintext + unreliable; stale/offline UX mitigates but
  set-default/remove failures may leave perceived inconsistency until refresh —
  reconciliation via re-fetch covers this.
- Open: should "make default" be offered inline during Add (checkbox) only, or also
  auto-default when it is the first method? Current design auto-defaults the first
  method server-side; UI reflects whatever the response says.

## 14. Acceptance Criteria

AC-1 Opening Payment Methods renders every saved method with brand, masked number,
expiry, and a single default badge; ordered default-first.

AC-2 Zero methods shows the empty state with a working "Add payment method" action.

AC-3 Adding a method (submitting a payment token) results in the method appearing in
the list, sourced from the server response; an "Added" confirmation is shown.

AC-4 Removing a non-default method (after confirmation) removes it from the list and
the local cache; the default method cannot be removed while others exist.

AC-5 "Set as default" moves the default badge to the chosen method and clears it
from the previous default after server confirmation; exactly one default always.

AC-6 Each in-flight mutation locks only its row with a spinner; the list stays
usable; repeated taps cause no duplicate calls.

AC-7 With a populated cache and a failed/absent network, the list still renders with
a "Showing saved data" banner and a working Retry; with no cache, a blocking error
state with Retry is shown.

AC-8 No PAN/CVV/full card number is logged or stored; mutations send
`X-CSRF-Token`; a 401 is transparently recovered once via session refresh.

AC-9 Unit + Compose tests in Section 11 pass in CI.

## 15. Definition of Done

- `feature-billing` payment-methods route, screen, ViewModel, UI state, and
  repository payment-method operations implemented per Sections 4–6, consuming
  AND-223's `BillingApi`/DTOs/mappers.
- All FR-1…FR-8 and AC-1…AC-9 satisfied and demonstrated against the dev backend.
- Strings externalized; TalkBack labels and 48dp targets verified; dark/dynamic
  theme correct.
- Telemetry events from Section 10 emitted; logging redaction verified (no token/PAN).
- Tests from Section 11 added and green in CI; coverage ≥ 85% on the new ViewModel
  and repository paths.
- `./gradlew :feature-billing:lint :feature-billing:test` clean; ktlint/detekt pass.
- Code reviewed and merged to `android-port`; no new interceptors or auth code added
  (shared stack reused).
