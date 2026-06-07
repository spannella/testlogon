---
id: AND-224
title: Payment methods management
milestone: M5
epic: E31
priority: P0
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-223]
blocks: []
---

# AND-224 — Payment methods management

## 1. Overview & Goal

Deliver the user-facing Android feature for managing saved payment methods: list
all payment methods on the account, add a new method, remove an existing one, and
designate exactly one method as the default. (Correction: the dev backend's add-card
endpoint `POST /ui/billing/payment-methods/card` accepts raw card fields — `card_number`,
`exp_month`, `exp_year`, `cvc`, optional `cardholder_name` — per `AddCardReq`; it is NOT
an opaque-token submission. The web reference notes that production would replace this with
Stripe Elements. See §5/§8 and §16 for the security implications of this correction.) This ticket owns the `feature-billing`
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
- Auth/session (verified against `src/api/client.ts`): the web client sends THREE
  credentials, all handled by the shared interceptor stack from the core-network
  milestone (AND-027 lineage via AND-223), so no auth code is added here:
  (1) `Authorization: Bearer <accessToken>` from the auth store — the spec previously
  omitted this; (2) `X-CSRF-Token` set to the `ui_csrf` cookie value on EVERY request
  when the cookie is present (not only mutations); (3) the persistent cookie jar
  (`credentials: "include"`). Note the backend OpenAPI declares request params
  `user_sub`, `X-SESSION-ID`, and `X-IMPERSONATION-TOKEN` on these operations (an
  impersonation header is added only when impersonating); the Bearer/CSRF/cookie trio
  is what the live web client actually transmits. A single refresh-on-401 retry via
  `POST /ui/session/refresh` is confirmed.
- OpenAPI source of truth: `GET /openapi.json` on the dev backend; field names in
  Section 5 must be reconciled against it during AND-223 integration.

## 3. Functional Requirements

FR-1 **List.** On screen entry the feature loads payment methods via
`GET /ui/billing/payment-methods` and renders each as a row: card brand icon,
masked number (`•••• 4242`), expiry (`MM/YY`), and a "Default" badge on the default
method. Methods are ordered default-first, then by ascending `priority` (the
`PaymentMethod` DTO exposes a `priority: number` field; there is **no `created_at`
field** — the prior spec's `created_at` ordering was a corrected error, see §16).

FR-2 **Empty state.** When the account has zero methods, show an empty state with
an explanatory line and a primary "Add payment method" action.

FR-3 **Add.** A primary "Add" action opens an add flow (bottom sheet or dedicated
route `billing/payment-methods/add`). Against the dev backend the client submits
`POST /ui/billing/payment-methods/card` (corrected path — there is no bare
`POST /ui/billing/payment-methods`) with an `AddCardReq` body: `card_number`,
`exp_month`, `exp_year`, `cvc`, optional `cardholder_name`. The response is
`{ payment_method_id, brand?, last4?, label? }` (not the full method object), so the
client re-fetches the list (FR-6) to render the new row. On success the new method
appears in the list. NOTE: this dev endpoint takes raw card fields; the web reference
states production would use Stripe Elements for PCI-compliant collection. There is no
`make_default` flag on this endpoint (corrected — see §16); to make a newly added card
default, call FR-5 afterward. The Android port MAY instead target the
`POST /ui/billing/payment-methods/ccbill-token` (`SavePaymentTokenIn`) tokenized path
on the `/api` surface to avoid raw-PAN handling, but that is an unverified design choice
for the `/ui` surface — see §16 Open assumptions.

FR-4 **Remove.** Each row exposes a "Remove" affordance (overflow menu or swipe) that
prompts a confirmation dialog, then calls
`DELETE /ui/billing/payment-methods/{payment_method_id}`, which returns `OkResp`
(`{ "ok": true }`) with HTTP **200** (corrected — not 204 No Content). After success
the client re-fetches the list. **Correction:** the web reference (`PaymentMethods.tsx`)
shows the Remove (trash) control on EVERY row, including the default, and has no
client-side block on removing the default and no `default_method_required` handling.
The prior spec's rule "default cannot be removed while others exist (UI
disables/explains) → 409 `default_method_required`" is **not supported by any
authoritative source** and is downgraded to an unverified assumption (see §16). Default
implementation SHOULD mirror the web client: allow remove on all rows and surface
whatever error the server returns. If a future backend confirmation establishes a 409
guard, re-introduce `canRemove=false` for the default.

FR-5 **Set default.** Each non-default row exposes "Set as default" which calls
`POST /ui/billing/payment-methods/default` with a `SetDefaultReq` body
`{ "payment_method_id": "<id>" }` (corrected — the id is in the JSON body, NOT a
path segment `/{id}/default`). The response is `OkResp` (`{ "ok": true }`), so the
client re-fetches the list. Exactly one method is default at any time; the previous
default loses its badge after the re-fetch reflects server state.

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

Note on the `add(...)`/`onAdd(...)` signatures below: they take card fields, not a
single opaque token. The `AddCardReq` body is `card_number`, `exp_month`, `exp_year`,
`cvc`, optional `cardholder_name`. The `makeDefault` parameter is a CLIENT convenience
only — the add endpoint has no `make_default` flag, so when `makeDefault==true` the
ViewModel sequences add → `setDefault(newId)` after the list re-fetch returns the new
`payment_method_id`. (Signatures are shown with the original token-style parameter for
continuity; implementers MUST use the card-field shape from §5.)

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
    val id: String,              // maps DTO field `payment_method_id` (NOT `id`)
    val methodType: String,      // DTO `method_type`, e.g. "card", "us_bank_account"
    val brand: CardBrand,        // VISA, MASTERCARD, AMEX, DISCOVER, UNKNOWN; DTO `brand` is OPTIONAL
    val last4: String?,          // DTO `last4` is OPTIONAL (nullable)
    val expMonth: Int?,          // DTO `exp_month` OPTIONAL (bank accounts have none)
    val expYear: Int?,           // DTO `exp_year` OPTIONAL
    val label: String?,          // DTO `label` OPTIONAL
    val priority: Int,           // DTO `priority` — drives ordering (no created_at exists)
    val provider: String?,       // DTO `provider` OPTIONAL
    val isDefault: Boolean,
)
```

Corrections vs. the prior model: the DTO id field is `payment_method_id` (not `id`);
there is **no `created_at`** field (removed); `brand`/`last4`/`exp_month`/`exp_year`/
`label` are all OPTIONAL in `types.ts: PaymentMethod`; and `method_type`, `priority`,
`provider` exist and matter (bank-account methods carry no card brand/expiry). See §16.

Data flow is single-source-of-truth via Room: `observePaymentMethods()` emits from
the DAO; mutations call the API then trigger a list re-fetch to update Room from the
authoritative GET response. (Corrected reconciliation model: set-default and remove
return only `OkResp` `{ok:true}` at HTTP 200, and add returns a partial
`{payment_method_id, brand?, last4?, label?}` — none return a full method object, so
every mutation reconciles by re-fetching `GET /ui/billing/payment-methods` rather than
upserting the response, exactly as the web client does via
`queryClient.invalidateQueries`.) The screen renders from
the Room flow so add/remove/set-default reconcile automatically. GET timeout/retry
and 401-refresh are handled by the shared OkHttp client; this ticket adds no
interceptors.

`ApiResult<T>` is the existing sealed type (`Success`, `Error(detail, code, http)`,
`NetworkError`, `Unauthorized`). FastAPI `detail` is parsed by the shared mapper
(string | `[{msg}]` | `{code,...}`).

## 5. API Contract

Endpoints VERIFIED against `reference/src/api/endpoints/billing.ts`, the DTOs in
`reference/src/api/types.ts`, and `reference/openapi.index.txt` / `openapi.pretty.json`.
Transport: `Authorization: Bearer`, `X-CSRF-Token` (`ui_csrf` cookie value, sent on
all requests when present), and the cookie jar (`credentials:"include"`) — see §2.

`GET /ui/billing/payment-methods` → 200. **Corrected:** the body is a BARE JSON ARRAY
of `PaymentMethod` (`api.get<PaymentMethod[]>(...)`), NOT a `{ "items": [...] }`
envelope. Each element:

```json
[
  {
    "payment_method_id": "pm_01H...",
    "method_type": "card",
    "label": "Personal Visa",
    "brand": "visa",
    "last4": "4242",
    "exp_month": 12,
    "exp_year": 2027,
    "priority": 0,
    "provider": "stripe",
    "provider_method_id": "pm_stripe_...",
    "is_default": true
  }
]
```

Required fields per `types.ts: PaymentMethod`: `payment_method_id`, `method_type`,
`priority`, `is_default`. Optional/nullable: `label`, `brand`, `last4`, `exp_month`,
`exp_year`, `provider`, `provider_method_id`. (There is no `created_at`.) The OpenAPI
list operation declares no response schema component, so `types.ts` is the canonical
shape.

`POST /ui/billing/payment-methods/card` (**corrected path**; req schema `AddCardReq`)
body:

```json
{ "card_number": "4242424242424242", "exp_month": 12, "exp_year": 2027, "cvc": "123", "cardholder_name": "Jane Doe" }
```

→ 200 returns a partial object `{ "payment_method_id": "...", "brand": "visa", "last4": "4242", "label": "..." }`
(`brand`/`last4`/`label` optional). Required by `AddCardReq`: `card_number`,
`exp_month` (1–12), `exp_year` (2000–2100), `cvc`; `cardholder_name` optional. There is
**no `make_default`** field. Client re-fetches the list after success.

`DELETE /ui/billing/payment-methods/{payment_method_id}` → **200** returning `OkResp`
`{ "ok": true }` (**corrected** — not 204; `api.del<OkResp>(...)`). Client re-fetches.

`POST /ui/billing/payment-methods/default` (**corrected** — id in body, not path) with
`SetDefaultReq` body `{ "payment_method_id": "<id>" }` → 200 `OkResp` `{ "ok": true }`.
Client re-fetches. (Related real endpoints not used by this ticket:
`POST /ui/billing/payment-methods/priority` (`SetPriorityReq`),
`POST /ui/billing/payment-methods/{payment_method_id}/set-default-and-retry`.)

Error envelope (FastAPI): backend errors surface as `{"detail": <string | object | array>}`.
The shared mapper handles all three forms (`src/api/client.ts: normalizeErrorDetail`):
a plain string; a validation array `{"detail":[{"msg":"...","loc":[...]}]}` (the 422
shape these ops declare); or an authorization object `{"detail":{"code":"role_required_scope","required_scope":"..."}}`.
**Note:** the previously cited 409 `{"detail":{"code":"default_method_required",...}}`
envelope does NOT appear in any source and is removed as a fabricated example (see §16).
All listed ops declare `422 HTTPValidationError`. 401 triggers the shared
refresh-and-retry-once path (`POST /ui/session/refresh`, verified). Idempotent
retry/backoff applies only to the GET list call.

## 6. Data & State Management

Room (cache, `core-data`):

```kotlin
@Entity(tableName = "payment_method")
data class PaymentMethodEntity(
    @PrimaryKey val id: String, // DTO payment_method_id
    val methodType: String,     // DTO method_type
    val brand: String?,         // nullable (corrected — optional in DTO)
    val last4: String?,         // nullable
    val expMonth: Int?,         // nullable
    val expYear: Int?,          // nullable
    val label: String?,         // nullable
    val priority: Int,          // DTO priority — ordering key (replaces createdAt)
    val provider: String?,      // nullable
    val isDefault: Boolean,
    val updatedAtLocal: Long,   // for staleness banner
)

@Dao
interface PaymentMethodDao {
    // Corrected ordering: no created_at exists; order default-first then by priority asc.
    @Query("SELECT * FROM payment_method ORDER BY isDefault DESC, priority ASC")
    fun observeAll(): Flow<List<PaymentMethodEntity>>
    @Upsert suspend fun upsertAll(items: List<PaymentMethodEntity>)
    @Query("DELETE FROM payment_method WHERE id = :id") suspend fun deleteById(id: String)
    @Query("DELETE FROM payment_method") suspend fun clear()
    @Transaction suspend fun replaceAll(items: List<PaymentMethodEntity>)
}
```

`refreshPaymentMethods()` performs `replaceAll` (clear+upsert in one transaction) so
removed-server-side methods disappear. **Corrected:** `setDefault`, `add`, and `remove`
do NOT return a full method object (they return `OkResp`/partial), so each mutation
reconciles by calling `refreshPaymentMethods()` on success rather than upserting a
response object. DataStore is not used for this feature beyond the existing session
prefs.

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
    val expiryLabel: String?, // null for bank accounts / missing exp (corrected: optional)
    val isDefault: Boolean, val canSetDefault: Boolean,
    val canRemove: Boolean,   // = true for ALL rows by default; see FR-4 correction (§16)
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
- **Default removal:** **Corrected** — no `default_method_required` 409 exists in any
  source and the web client does not pre-disable removing the default. Therefore remove
  is offered on all rows (`canRemove = true`) and any server-side rejection is mapped
  generically from `detail` and shown as a `Failure` snackbar. (If a backend 409 guard
  is later confirmed, surface its `detail.code` message and reinstate `canRemove=false`
  for the default — tracked as an open assumption in §16.)
- **Network unavailable:** `NetworkError` maps to the stale banner if cache exists,
  else the blocking error state.
- All transitions are idempotent on repeated taps because in-flight rows are locked.

## 8. Security & Privacy

- **Correction (raw card data):** the dev `POST /ui/billing/payment-methods/card`
  endpoint accepts raw `card_number`, `cvc`, expiry, and `cardholder_name` in the
  request body (`AddCardReq`). So the prior claim that the client "handles only an
  opaque `payment_token`" is false for this endpoint. Consequences and MUST controls:
  raw PAN/CVC are held ONLY transiently in the add form's in-memory ViewModel state,
  are NEVER persisted to Room/DataStore, NEVER logged, and the `AddCardReq` request
  body MUST be fully redacted by the OkHttp logging redactor. Room persists only
  `last4` (and brand/label/type/priority) — never the full PAN or CVC. Production will
  replace raw collection with a PCI-compliant SDK (Stripe Elements per the web
  reference); see §13.
- All requests send `X-CSRF-Token` (the `ui_csrf` cookie value) AND `Authorization:
  Bearer <accessToken>` via the shared stack; session also rides the persistent cookie
  jar. No tokens or ids are placed in URLs (the id is in the body for set-default; the
  delete id is a path segment but is a non-secret opaque method id).
- Logging: the `AddCardReq` body and any `cvc`/`card_number` are redacted by the OkHttp
  logging redactor; only method `id`, `last4`, and `brand` may appear in debug logs.
  Telemetry events carry `id`/`brand`/`last4` only.
- Dev backend is plaintext HTTP (cleartext permitted for the dev host only via the
  existing network-security-config); this is acknowledged dev-only risk and not a
  production posture. **Correction:** because the dev add-card endpoint takes raw card
  fields, raw PAN/CVC DO cross the wire over plaintext HTTP to the dev host — this is an
  explicit, dev-only acceptance and a hard reason production must use a PCI SDK over TLS.

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
- **Default-removal semantics:** RESOLVED toward "no client guard" — the web reference
  (`PaymentMethods.tsx`) allows removing any row including the default and has no 409
  `default_method_required` handling; no such code exists in OpenAPI or the frontend.
  FR-4/`canRemove` were corrected accordingly. Open: the server's actual response when
  the last/default method is removed is still unconfirmed against a live backend.
- **Tokenization:** **Corrected** — the dev `.../card` endpoint takes raw card fields
  (`AddCardReq`), not a stub token; the web reference collects raw PAN/CVC and notes
  production would use Stripe Elements. Production PCI capture (PCI SDK / hosted fields)
  is out of scope and a separate ticket. To minimize rework the add layer SHOULD isolate
  the card-collection step behind an interface so a tokenizing implementation can be
  swapped in without touching the repository/ViewModel.
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

AC-3 Adding a method (submitting card fields per `AddCardReq` to
`POST /ui/billing/payment-methods/card`) results in the method appearing in the list
after the post-add re-fetch; an "Added" confirmation is shown.

AC-4 Removing a method (after confirmation) removes it from the list and the local
cache after the post-mutation re-fetch. (Corrected: remove is available on all rows
including the default, matching the web reference; there is no client-side
default-removal block — see §16. Any server-side rejection is shown as a failure
snackbar.)

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

## 16. Citations & Assumption Audit

Each key technical claim with VERDICT and an exact SOURCE pointer. Sources:
`idx` = `reference/openapi.index.txt`; `oas` = `reference/openapi.pretty.json`
(`components.schemas.<Name>`); frontend paths are under `reference/src/`.

1. List endpoint is `GET /ui/billing/payment-methods`. VERIFIED. Source:
   `src/api/endpoints/billing.ts: getPaymentMethods`; idx `GET /ui/billing/payment-methods`.
2. List response is a BARE ARRAY `PaymentMethod[]`, not `{ "items": [...] }`.
   CORRECTED (spec said `{items:[]}`). Source: `src/api/endpoints/billing.ts:
   getPaymentMethods` (`api.get<PaymentMethod[]>`); the page reads
   `Array.isArray(methodsQuery.data)` in `src/pages/billing/PaymentMethods.tsx`.
3. `PaymentMethod` DTO id field is `payment_method_id` (not `id`). CORRECTED. Source:
   `src/api/types.ts: PaymentMethod`.
4. `PaymentMethod` has `method_type`, `priority`, `provider`, `provider_method_id`,
   optional `label`/`brand`/`last4`/`exp_month`/`exp_year`, and `is_default`; there is
   NO `created_at`. CORRECTED (spec listed `created_at`, treated brand/last4/exp as
   required). Source: `src/api/types.ts: PaymentMethod`. No `PaymentMethod` component
   exists in OpenAPI (grep of `oas` returns none), so `types.ts` is canonical.
5. Ordering uses `priority` (default-first then priority asc), not `created_at`.
   CORRECTED. Source: `src/api/types.ts: PaymentMethod.priority`; `created_at` absent.
6. Add endpoint is `POST /ui/billing/payment-methods/card` with `AddCardReq`
   (`card_number`, `exp_month` 1–12, `exp_year` 2000–2100, `cvc`, optional
   `cardholder_name`) — NOT `POST /ui/billing/payment-methods` with an opaque
   `payment_token`/`make_default`. CORRECTED. Source: `src/api/endpoints/billing.ts:
   addCard`; idx `POST /ui/billing/payment-methods/card | req=AddCardReq`; oas
   `components.schemas.AddCardReq`.
7. Add response is partial `{ payment_method_id, brand?, last4?, label? }` at HTTP 200,
   not 201 returning the full object. CORRECTED. Source: `src/api/endpoints/billing.ts:
   addCard` return type.
8. There is no `make_default` field on add; "make default on add" is a client-side
   add-then-setDefault sequence. CORRECTED. Source: `AddCardReq` (oas) has only the
   five card fields.
9. Set-default endpoint is `POST /ui/billing/payment-methods/default` with body
   `SetDefaultReq { payment_method_id }`, NOT `POST .../{id}/default`. CORRECTED.
   Source: `src/api/endpoints/billing.ts: setDefault`; idx
   `POST /ui/billing/payment-methods/default | req=SetDefaultReq`; oas
   `components.schemas.SetDefaultReq`.
10. Set-default returns `OkResp { ok }` (200), client re-fetches; it does not return the
    updated method. CORRECTED. Source: `src/api/endpoints/billing.ts: setDefault`
    (`api.post<OkResp>`); oas `components.schemas.OkResp`.
11. Remove endpoint is `DELETE /ui/billing/payment-methods/{payment_method_id}`
    returning `OkResp` at HTTP 200, NOT 204 No Content. CORRECTED. Source:
    `src/api/endpoints/billing.ts: removePaymentMethod` (`api.del<OkResp>`); idx
    `DELETE /ui/billing/payment-methods/{payment_method_id} | resp=200:`.
12. Mutations reconcile by re-fetching the list (not by upserting the mutation
    response). VERIFIED/CORRECTED. Source: `src/pages/billing/PaymentMethods.tsx`
    (`queryClient.invalidateQueries({ queryKey:["billing","payment-methods"] })` in
    add/default/remove `onSuccess`).
13. Default-removal: web client shows Remove on EVERY row including the default and has
    no `default_method_required` 409 handling. CORRECTED (spec asserted a 409 guard +
    `canRemove=false`). Source: `src/pages/billing/PaymentMethods.tsx` (Trash2 button
    rendered for all methods; `removeMutation`); grep for `default_method_required`
    across `reference/` returns nothing.
14. Auth transport: `Authorization: Bearer <accessToken>` + `X-CSRF-Token` (= `ui_csrf`
    cookie, on every request when present) + cookie jar (`credentials:"include"`).
    CORRECTED (spec omitted the Bearer token and implied CSRF only on mutations).
    Source: `src/api/client.ts` (lines setting `Authorization`, `X-CSRF-Token`,
    `credentials:"include"`).
15. 401 → single `POST /ui/session/refresh` then retry once. VERIFIED. Source:
    `src/api/client.ts: refreshSession` + the 401 retry block; idx
    `POST /ui/session/refresh | resp=200:`.
16. Network error surfaces as a transport error (`ApiError(0,...)`) → maps to
    `NetworkError`/stale-banner. VERIFIED. Source: `src/api/client.ts` catch block.
17. Error `detail` may be string | `[{msg,loc}]` (422) | object `{code,...}`; shared
    mapper handles all three. VERIFIED. Source: `src/api/client.ts:
    normalizeErrorDetail` / `mapAuthorizationError`; all PM ops declare
    `422 HTTPValidationError` (idx).
18. The 409 example `{"detail":{"code":"default_method_required",...}}` does NOT exist.
    CORRECTED/REMOVED as fabricated. Source: absence in `oas` and `reference/src/`.
19. Dev backend add-card transmits raw PAN/CVC over plaintext HTTP. VERIFIED (security
    implication). Source: `AddCardReq` fields (oas) + dev host `http://...:8000` (spec
    §1) + web note "production would use Stripe Elements"
    (`src/pages/billing/PaymentMethods.tsx`).
20. Framework choices: single-Activity Navigation-Compose, Hilt `hiltViewModel()`,
    `StateFlow` UI state, Room single-source-of-truth, Compose Material 3,
    pull-to-refresh, Turbine/MockWebServer/`createComposeRule` tests. UNVERIFIED-
    ASSUMPTION at the source level (no Android code in the reference repo); these are
    standard Android Jetpack patterns. framework ref:
    https://developer.android.com/jetpack/compose ,
    https://developer.android.com/develop/ui/compose/testing ,
    https://developer.android.com/training/data-storage/room ,
    https://developer.android.com/topic/libraries/architecture/viewmodel .

### Corrections made

- §1/§3/§5/§8/§13: Add is `POST .../card` with raw `AddCardReq` card fields (not a bare
  `POST .../payment-methods` opaque-token submit); response is partial at 200; no
  `make_default`.
- §3/§5: Set-default is `POST .../default` with `{payment_method_id}` in the body (not a
  `/{id}/default` path); returns `OkResp`.
- §5/§6: Delete returns `OkResp` at 200 (not 204).
- §5: List response is a bare array (not `{items:[]}`).
- §4/§5/§6: DTO/domain/entity corrected — `payment_method_id`, added
  `method_type`/`priority`/`provider`/`label`, made brand/last4/exp nullable, removed
  `created_at`; ordering now `isDefault DESC, priority ASC`.
- §4/§5/§6: Mutations reconcile via list re-fetch (none return a full method object).
- §3/§4/§7/§13/§14(AC-4): Removed the default-removal 409 guard / `canRemove=false` rule
  and the fabricated `default_method_required` code; remove allowed on all rows.
- §2/§8: Auth corrected to Bearer + CSRF(all requests) + cookie jar.
- §8: Security corrected — raw PAN/CVC are handled and cross the wire to the dev host;
  added explicit redaction/no-persistence MUST controls.

### Open assumptions

- Server behavior when the last/default method is removed (success vs. 4xx, auto-promote
  vs. reject) is UNVERIFIED — no live backend in the reference set and no schema/code
  describing it. Client mirrors the web (allow + show any error).
- Whether the `/ui` surface accepts a tokenized add (e.g. a `ccbill-token` analogue) is
  UNVERIFIED for `/ui`; only `/api/billing/payment-methods/ccbill-token`
  (`SavePaymentTokenIn`) exists in idx. Treated as a possible future swap behind the
  card-collection interface.
- All Android framework/library/test-tool choices (§20 above) are UNVERIFIED against any
  reference source because the reference app is web-only; cited to Android docs instead.
- The exact GET-retry counts/timeouts (~20s, max 2 jittered retries) come from the spec
  and the core-network milestone, not from the reference client; UNVERIFIED here.
- 422 validation `loc`/`msg` wording for card fields is the generic FastAPI shape; exact
  messages are backend-defined and UNVERIFIED.

## 17. Test Plan

Test targets: JVM = local JVM/Robolectric unit; MWS = JVM contract tests with
MockWebServer; emu = headless emulator AVD `test35` (x86_64, API 35); dev = Samsung
Galaxy A15 5G physical device (SM-A156U, serial R5CX821TA9R, API 34, arm64-v8a). No case
here needs camera/biometrics/FCM/WebRTC/Telecom, so the physical device is required only
for the real-network/cleartext and ABI/API-skew checks (TC-13, TC-14); all UI suites run
on the emulator in CI.

TC-AND-224-01 — List happy path renders rows
- Type: contract/MockWebServer (MWS). Target: MWS + JVM.
- Preconditions: MockWebServer enqueues 200 with a bare JSON array of two
  `PaymentMethod` objects (one `is_default:true`, `priority:0`; one `priority:1`).
- Steps: Call `refreshPaymentMethods()`; collect `observePaymentMethods()` / `uiState`.
- Expected: Two `PaymentMethodUi` rows; default-first ordering (default then priority
  asc); brand/last4/expiry mapped; single default badge; `emptyState=false`. Request
  path is exactly `GET /ui/billing/payment-methods`.
- Traces: AC-1.

TC-AND-224-02 — Empty list shows empty state
- Type: unit (JVM). Target: JVM + fake repo / MWS `[]`.
- Preconditions: List endpoint returns `[]`.
- Steps: Load screen state.
- Expected: `emptyState=true`, `methods` empty, primary "Add payment method" action
  present and enabled.
- Traces: AC-2.

TC-AND-224-03 — Add card success (correct request + reconcile)
- Type: contract/MockWebServer (MWS). Target: MWS + JVM.
- Preconditions: First enqueue 200 partial `{payment_method_id, brand, last4}` for the
  add; second enqueue the GET list (now including the new method).
- Steps: Call `add(card fields, makeDefault=false)`.
- Expected: Exactly one `POST /ui/billing/payment-methods/card` whose JSON body is an
  `AddCardReq` (`card_number`, `exp_month`, `exp_year`, `cvc`, `cardholder_name`) and
  contains NO `payment_token`/`make_default`; followed by a GET re-fetch; new row
  appears; `Added` event emitted. Body carries `X-CSRF-Token` and `Authorization` headers.
- Traces: AC-3, AC-8.

TC-AND-224-04 — Add with makeDefault sequences add → setDefault
- Type: contract/MockWebServer (MWS). Target: MWS + JVM.
- Preconditions: Enqueue add 200; GET list; set-default 200 `OkResp`; GET list with new
  default.
- Steps: Call `add(card fields, makeDefault=true)`.
- Expected: After add+refetch, a `POST /ui/billing/payment-methods/default` with body
  `{payment_method_id:<newId>}` is sent, then a final re-fetch; the new method is
  default. No `make_default` was ever sent on the add.
- Traces: AC-3, AC-5.

TC-AND-224-05 — Set default uses body id and reconciles
- Type: contract/MockWebServer (MWS). Target: MWS + JVM.
- Preconditions: Two methods cached (A default, B not); enqueue set-default 200
  `{"ok":true}`; enqueue GET list with B now default.
- Steps: `setDefault(B.id)`.
- Expected: Request is `POST /ui/billing/payment-methods/default` with body
  `{"payment_method_id":"B"}` (id NOT in the path); on success a re-fetch runs; badge
  moves to B; exactly one default; `DefaultSet` event.
- Traces: AC-5.

TC-AND-224-06 — Remove returns OkResp@200 and reconciles
- Type: contract/MockWebServer (MWS). Target: MWS + JVM.
- Preconditions: Method M cached; enqueue `DELETE` → 200 `{"ok":true}`; enqueue GET list
  without M.
- Steps: Confirm and `remove(M.id)`.
- Expected: `DELETE /ui/billing/payment-methods/M` is sent; client treats 200 `OkResp`
  as success (NOT expecting 204); re-fetch removes M from cache/list; `Removed` event.
- Traces: AC-4.

TC-AND-224-07 — Default row is removable (no client guard)
- Type: Compose-UI (emu). Target: emu (AVD test35).
- Preconditions: Two methods, one default, rendered.
- Steps: Inspect the default row; tap its Remove affordance; confirm.
- Expected: Remove control is present and enabled on the default row (`canRemove=true`);
  confirmation dialog appears; on confirm the DELETE is issued. No "set another default
  first" block. (Mirrors web reference.)
- Traces: AC-4.

TC-AND-224-08 — Validation/error response (422) maps to Failure
- Type: contract/MockWebServer (MWS). Target: MWS + JVM.
- Preconditions: Enqueue add → 422
  `{"detail":[{"msg":"value is not a valid integer","loc":["body","exp_month"]}]}`.
- Steps: `add(card fields...)`.
- Expected: No DB change; row leaves `rowInFlight`; `Failure` event whose message is the
  joined `msg` from the array (per shared mapper); no automatic retry of the POST.
- Traces: AC-6, AC-9.

TC-AND-224-09 — GET failure with cache → stale banner; without cache → blocking error
- Type: unit + contract (JVM/MWS). Target: JVM + MWS.
- Preconditions (A): Non-empty cache present; GET fails (e.g. 500 after retries).
  Preconditions (B): Empty cache; GET fails.
- Steps: `refresh()` in each scenario.
- Expected (A): `isStale=true`, list still rendered, retry control works (a queued
  subsequent 200 clears the banner). (B): `errorMessage` blocking state with Retry.
- Traces: AC-7.

TC-AND-224-10 — Offline/network-error path
- Type: contract/MockWebServer (MWS). Target: MWS + JVM (emu optional).
- Preconditions: Simulate transport failure (MockWebServer `SocketPolicy`
  DISCONNECT_AT_START) with a populated cache.
- Steps: `refresh()`.
- Expected: Maps to `NetworkError` → `isStale=true` + "Showing saved data" banner +
  working Retry; with empty cache, blocking error state.
- Traces: AC-7.

TC-AND-224-11 — 401 transparent refresh-and-retry-once
- Type: contract/MockWebServer (MWS). Target: MWS + JVM.
- Preconditions: Enqueue GET → 401; then `POST /ui/session/refresh` → 200; then GET
  retry → 200 array.
- Steps: `refresh()`.
- Expected: Exactly one refresh call, original GET retried once, list loads; no
  `Unauthorized` surfaced. If the refresh returns non-200, result is `Unauthorized` and
  the app-level handler is invoked.
- Traces: AC-8.

TC-AND-224-12 — Per-row in-flight lock prevents duplicate calls
- Type: Compose-UI (emu). Target: emu.
- Preconditions: Two methods; set-default response delayed.
- Steps: Tap "Set as default" on row B repeatedly while in flight; scroll the list.
- Expected: Row B shows a spinner and is non-interactive; only ONE
  `POST .../default` is issued; the rest of the list stays scrollable/interactive.
- Traces: AC-6.

TC-AND-224-13 — Security: no PAN/CVC stored or logged; headers present (PHYSICAL DEVICE)
- Type: instrumented/e2e (dev). Target: PHYSICAL DEVICE (real cleartext HTTP to dev
  host; MUST run on device to exercise the real OkHttp stack + network-security-config
  cleartext allowance, not the emulator's loopback).
- Preconditions: Debug build pointing at `http://18.222.237.167:8000`; logcat captured;
  Room inspected after an add.
- Steps: Add a card via the form; remove a method; capture logcat + Room dump.
- Expected: No `card_number`/`cvc` appears in logcat (AddCardReq body redacted); Room
  `payment_method` rows contain only `last4` (+ brand/label/type/priority), never full
  PAN/CVC; outbound add/set-default/delete carry `X-CSRF-Token` and `Authorization`
  headers.
- Traces: AC-8.

TC-AND-224-14 — ABI / API-skew smoke (PHYSICAL DEVICE vs emulator)
- Type: instrumented/e2e (dev + emu). Target: run on BOTH PHYSICAL DEVICE (arm64-v8a,
  API 34) and emu (x86_64, API 35) — MUST include the physical device to catch
  arm64-vs-x86 / API-34-vs-35 differences in Room/Compose/serialization.
- Preconditions: Same debug build installed on both targets.
- Steps: Run the list→add→set-default→remove flow end to end on each target.
- Expected: Identical behavior and rendering on both; no ABI/API-specific crashes or
  serialization diffs.
- Traces: AC-1, AC-3, AC-4, AC-5.

TC-AND-224-15 — Accessibility (TalkBack semantics + touch targets)
- Type: Compose-UI / accessibility (emu). Target: emu.
- Preconditions: Two methods rendered (one card, one bank account with null
  brand/expiry).
- Steps: Assert semantics for brand icon ("Visa card ending 4242"), "Set as default",
  "Remove", and the default badge; verify the confirmation dialog focus order
  title→body→cancel→confirm; verify swipe-to-remove has an equivalent menu action;
  verify ≥48dp targets; verify a null-brand/expiry bank row renders without crashing and
  has a sensible label.
- Traces: AC-1, AC-4, AC-9.

### Coverage matrix

- AC-1 (render, default-first ordering): TC-01, TC-14, TC-15
- AC-2 (empty state + Add action): TC-02
- AC-3 (add → appears, confirmation): TC-03, TC-04, TC-14
- AC-4 (remove from list/cache; default removable, no guard): TC-06, TC-07, TC-14, TC-15
- AC-5 (set default, single default): TC-04, TC-05, TC-14
- AC-6 (per-row lock, no duplicate calls): TC-08, TC-12
- AC-7 (stale banner / blocking error + Retry): TC-09, TC-10
- AC-8 (no PAN/CVV stored/logged; CSRF; 401 recovery): TC-03, TC-11, TC-13
- AC-9 (unit + Compose tests pass in CI): TC-08, TC-15 (and the suite TC-01…TC-15)
