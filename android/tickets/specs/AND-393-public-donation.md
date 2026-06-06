---
id: AND-393
title: Public donation
milestone: M8
epic: E51
priority: P2
size: L
status: draft
depends_on: [AND-031]
blocks: []
---

# AND-393 — Public donation

## 1. Overview & Goal

Implement the public, unauthenticated-capable donation flow reachable at the
`/donate/:fundraiserId` route. A user — logged in or anonymous — can open a
fundraiser, enter an amount and donor details, submit a donation, and reach a
confirmation/receipt screen. The defining constraint of this ticket is that the
flow MUST work without a valid `ui` session cookie: it cannot require
`GET /ui/me` to succeed, cannot hard-gate behind login, and must degrade
gracefully when the persistent cookie jar is empty.

The goal is a self-contained `feature-donation` module exposing a single deep
linkable destination, a `DonationViewModel` that drives the screen through a
`StateFlow<DonationUiState>`, and a thin network layer that talks to the public
fundraiser/donation endpoints. "Done" for the acceptance bullet means an
end-to-end test proves a donation completes (load fundraiser → enter amount →
submit → confirmation) against the dev backend contract, with no authenticated
session present.

Out of scope: real payment-processor (Stripe/Apple/Google Pay) integration,
recurring donations, refunds, fundraiser creation/editing, and the
authenticated "my donations" history list. Those are owned by separate M8
tickets; this ticket covers the public single-shot donation path and its test.

## 2. Context & References

- Web reference: `frontend/src/api/endpoints/donations.ts` and
  `frontend/src/api/endpoints/fundraisers.ts`, with shared shapes in
  `frontend/src/api/types.ts`. The web route is `/donate/:fundraiserId`; mirror
  its field names and validation.
- Backend: FastAPI + DynamoDB, OpenAPI at
  `http://18.222.237.167:8000/openapi.json`. Donation/fundraiser endpoints under
  `/public/...` are designed to be callable anonymously. Confirm exact paths and
  request bodies against the live OpenAPI spec during implementation; the shapes
  in §5 are the contract this spec targets and any drift is an open question
  (§13) to reconcile, not to silently diverge from.
- `AND-031` (LoginViewModel) is the upstream dependency: it establishes the
  `StateFlow<UiState>` + submit-handler + `ApiResult<T>` ViewModel pattern and
  the FastAPI `detail` error mapping this ticket reuses. This ticket does NOT
  depend on a live session from AND-031 — only on its patterns and the shared
  `core-network` plumbing (cookie jar, CSRF interceptor, `ApiResult`).
- Project stack: Kotlin 2.0.21, Compose + Material 3, single-Activity
  Navigation-Compose, Hilt (KSP), Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15,
  DataStore for prefs, Coil for the fundraiser hero image. Namespace base
  `com.testlogon.android`. Module layering `app -> feature-* -> core-*`.

## 3. Functional Requirements

FR-1 — Deep link & navigation. The route `donate/{fundraiserId}` is registered
in the single NavHost. It is reachable from in-app navigation and from an
external deep link (`https://testlogon.com/donate/{fundraiserId}` and the app
scheme). `fundraiserId` is a required non-empty path argument (`NavType.StringType`).

FR-2 — Anonymous capability. The screen loads and submits with no session.
A logged-in user's identity (name/email) MAY pre-fill donor fields but is never
required. No path in this flow calls `GET /ui/me` as a precondition.

FR-3 — Fundraiser load. On entry the screen fetches the fundraiser summary
(title, description, goal amount, raised amount, currency, optional hero image,
`acceptsDonations` flag) and renders title, a progress indicator
(raised/goal), and the hero image via Coil.

FR-4 — Amount entry. The user enters a donation amount in the fundraiser's
currency. Preset chips (e.g., 10 / 25 / 50 / 100) plus a free-form field.
Amount is validated: numeric, > minimum (default 1 major unit), <= a sane max
(default 1,000,000 minor units), parsed to integer minor units before submit.

FR-5 — Donor details. Fields: donor name (optional), email (required for a
public/anonymous donation so a receipt can be sent; validated as email),
optional public display name, optional comment/message, and an "anonymous"
toggle that hides the donor name on the public wall.

FR-6 — Submit. A submit button is enabled only when the form is valid and not
already submitting. Submitting posts to the donation endpoint and transitions
to a terminal confirmation state showing a receipt id and the amount.

FR-7 — Loading/disabled states. Initial load shows a skeleton; the submit
button shows a spinner and is disabled while in flight (mirrors AND-031's
loading/disabled handling). Inputs are disabled during submission.

FR-8 — Closed fundraiser. If `acceptsDonations == false` or the fundraiser is
not found (404), render a non-actionable terminal state explaining the
fundraiser is unavailable; the form is not shown.

FR-9 — Stale/offline. On load failure the screen shows an error state with a
Retry action. If a cached fundraiser exists it MAY be shown with a "stale"
banner (cache owned by core-data; optional for this ticket, see §6).

## 4. Technical Design

New Gradle module `feature-donation`
(`com.testlogon.android.feature.donation`), depending on `core-network`,
`core-model`, `core-ui`, `core-data`, and `core-testing` (test scope).

Navigation entry:

```kotlin
object DonationRoute {
    const val ARG_FUNDRAISER_ID = "fundraiserId"
    const val PATTERN = "donate/{fundraiserId}"
    fun build(fundraiserId: String) = "donate/$fundraiserId"
}

fun NavGraphBuilder.donationScreen(onClose: () -> Unit) {
    composable(
        route = DonationRoute.PATTERN,
        arguments = listOf(navArgument(DonationRoute.ARG_FUNDRAISER_ID) {
            type = NavType.StringType
        }),
        deepLinks = listOf(
            navDeepLink { uriPattern = "https://testlogon.com/donate/{fundraiserId}" },
            navDeepLink { uriPattern = "testlogon://donate/{fundraiserId}" },
        ),
    ) { DonationScreen(onClose = onClose) }
}
```

ViewModel (Hilt, `SavedStateHandle` carries `fundraiserId`):

```kotlin
@HiltViewModel
class DonationViewModel @Inject constructor(
    private val repository: DonationRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val fundraiserId: String =
        checkNotNull(savedStateHandle[DonationRoute.ARG_FUNDRAISER_ID])

    private val _uiState = MutableStateFlow(DonationUiState(fundraiserId = fundraiserId))
    val uiState: StateFlow<DonationUiState> = _uiState.asStateFlow()

    init { loadFundraiser() }

    fun loadFundraiser()                      // GET, retry-on-Retry
    fun onAmountChanged(raw: String)
    fun onPresetSelected(minorUnits: Long)
    fun onEmailChanged(value: String)
    fun onNameChanged(value: String)
    fun onCommentChanged(value: String)
    fun onAnonymousToggled(value: Boolean)
    fun submit()                              // POST, idempotency key
    fun consumeError()                        // clears transient error
}
```

Repository abstracts the network call and result mapping:

```kotlin
interface DonationRepository {
    suspend fun getFundraiser(id: String): ApiResult<Fundraiser>
    suspend fun donate(
        fundraiserId: String,
        request: DonationRequest,
        idempotencyKey: String,
    ): ApiResult<DonationReceipt>
}
```

The Compose layer is a stateless `DonationScreen(onClose)` that collects
`uiState` with `collectAsStateWithLifecycle()` and renders sub-composables:
`FundraiserHeader`, `AmountSection`, `DonorDetailsSection`,
`SubmitBar`, and terminal `ConfirmationContent` / `UnavailableContent` /
`ErrorContent`. No business logic lives in composables.

Idempotency: `submit()` generates a `UUID` idempotency key once per
form-fill (stored in `SavedStateHandle` so it survives recomposition/rotation)
and sends it as a header so a retried POST cannot double-charge.

## 5. API Contract

All calls go through the shared `core-network` Retrofit/OkHttp client (20s
timeouts, persistent cookie jar, `X-CSRF-Token` echoed from the `ui_csrf`
cookie when present). These endpoints are public; absence of the session cookie
must not block them. The CSRF header is sent when the cookie exists and omitted
when it does not (anonymous case) — verify the backend accepts anonymous POSTs
without CSRF against OpenAPI (§13).

Retrofit service:

```kotlin
interface DonationApi {
    @GET("public/fundraisers/{id}")
    suspend fun getFundraiser(@Path("id") id: String): Response<FundraiserDto>

    @POST("public/fundraisers/{id}/donations")
    suspend fun donate(
        @Path("id") id: String,
        @Header("Idempotency-Key") idempotencyKey: String,
        @Body body: DonationRequestDto,
    ): Response<DonationReceiptDto>
}
```

`GET /public/fundraisers/{id}` → 200:

```json
{
  "id": "fr_123",
  "title": "Help Build the Library",
  "description": "Short blurb...",
  "currency": "USD",
  "goal_minor_units": 500000,
  "raised_minor_units": 132500,
  "accepts_donations": true,
  "hero_image_url": "https://.../hero.jpg"
}
```

`POST /public/fundraisers/{id}/donations` request:

```json
{
  "amount_minor_units": 2500,
  "currency": "USD",
  "donor_email": "spannella@gmail.com",
  "donor_name": "Sean P.",
  "display_anonymous": false,
  "message": "Good luck!"
}
```

201 response:

```json
{
  "donation_id": "don_789",
  "fundraiser_id": "fr_123",
  "amount_minor_units": 2500,
  "currency": "USD",
  "status": "completed",
  "receipt_url": "https://.../receipt/don_789"
}
```

Errors follow FastAPI `detail` (string | `[{msg}]` | `{code,...}`), mapped by
the shared `ApiResult` error mapper: 404 → fundraiser-unavailable terminal
state; 409 (closed/duplicate) → friendly message; 422 → field validation
mapped back to the offending input; 5xx/timeout → retryable error.

## 6. Data & State Management

`DonationUiState` is a single immutable data class exposed as `StateFlow`:

```kotlin
data class DonationUiState(
    val fundraiserId: String,
    val phase: Phase = Phase.LoadingFundraiser,
    val fundraiser: Fundraiser? = null,
    val amountInput: String = "",
    val amountMinorUnits: Long? = null,
    val donorEmail: String = "",
    val donorName: String = "",
    val message: String = "",
    val anonymous: Boolean = false,
    val fieldErrors: Map<DonationField, String> = emptyMap(),
    val isSubmitting: Boolean = false,
    val transientError: String? = null,
    val receipt: DonationReceipt? = null,
) {
    val isFormValid: Boolean get() =
        amountMinorUnits != null && fieldErrors.isEmpty() &&
        donorEmail.isNotBlank()
    val canSubmit: Boolean get() = isFormValid && !isSubmitting &&
        phase == Phase.Form
}

enum class Phase { LoadingFundraiser, Form, Unavailable, Submitting, Confirmed, LoadError }
enum class DonationField { Amount, Email, Name }
```

Domain models (`Fundraiser`, `DonationRequest`, `DonationReceipt`) live in
`core-model`; DTO↔domain mappers live in `feature-donation` data layer. Money is
always carried as integer minor units; formatting to display strings uses the
fundraiser currency via `java.text.NumberFormat`.

Persistence: form input survives configuration changes through
`SavedStateHandle` (amount, email, name, message, anonymous, idempotency key).
Fundraiser caching in Room (`core-data`) is OPTIONAL for this ticket; if the
cache table from M8 fundraiser tickets is available it is read on load to back
the stale state (FR-9), otherwise load is network-only. No PII is written to
DataStore.

## 7. Error Handling & Resilience

- Load (`GET`) is idempotent: bounded backoff retry (per project policy, e.g. 2
  retries, jittered ~0.5s/1s) on timeout/5xx; Retry button re-invokes
  `loadFundraiser()`. Timeout budget 20s per the unreliable dev host.
- Submit (`POST`) is NOT auto-retried. The `Idempotency-Key` makes a
  user-initiated retry safe; on transient failure the UI surfaces
  `transientError` with a manual "Try again" that reuses the same key.
- 401 on a public endpoint: the shared client's single
  `POST /ui/session/refresh`-then-retry interceptor applies; if still 401 the
  anonymous request proceeds without session (it must not be treated as a hard
  auth wall for these public paths).
- 404 → `Phase.Unavailable`. 409 closed → `Phase.Unavailable` with the
  closed copy. 422 → populate `fieldErrors` from the `detail` array's `loc`/`msg`.
- All branches map through `ApiResult<T>`; no raw exceptions reach Compose.

## 8. Security & Privacy

- Donor email/name are PII: held only in memory + `SavedStateHandle`, never
  logged at any level, never persisted to DataStore/Room. Redact email in any
  telemetry (§10).
- Dev backend is plaintext HTTP (`18.222.237.167:8000`); cleartext is allowed
  only for that host via the existing `network_security_config.xml`. Production
  host is HTTPS-only.
- CSRF: when a `ui_csrf` cookie exists it is echoed as `X-CSRF-Token`
  automatically; anonymous donations carry no session and rely on backend's
  public-endpoint policy. Do not fabricate a CSRF token client-side.
- No payment card data passes through this screen in this ticket (no PCI
  surface); real payment capture is a downstream ticket.
- Idempotency-Key is a random UUID, not derived from PII.

## 9. Accessibility & i18n

- All strings in `feature-donation`'s `strings.xml`; no hardcoded literals.
  Plurals for "X donors". Currency/amount formatted via locale-aware
  `NumberFormat` using the fundraiser currency code.
- Every interactive element has a `contentDescription` / semantics: preset
  chips announce their value, the amount field announces its currency, the
  submit button announces busy state via `Modifier.semantics { stateDescription }`.
- Progress bar exposes `progressBarRangeInfo`. Min touch target 48dp. Color is
  never the sole carrier of validation state — error text accompanies field
  outlines. Supports dynamic font scaling and dark theme via Material 3.

## 10. Telemetry & Logging

- Events via the shared analytics interface (no PII): `donation_screen_view`
  `{fundraiser_id}`, `donation_amount_selected` `{minor_units, preset:bool}`,
  `donation_submit_attempt` `{fundraiser_id, amount_minor_units}`,
  `donation_submit_success` `{fundraiser_id, donation_id}`,
  `donation_submit_failure` `{fundraiser_id, error_code}`.
- Email/name/message are NEVER included in events. If logged for debugging,
  email is redacted to `***@domain`.
- Network logging uses the shared OkHttp logging interceptor at BODY level in
  debug builds only, with the donor-PII fields redacted by a header/field
  scrubber; NONE in release.

## 11. Testing Strategy

The acceptance bullet ("Donation completes (test)") is satisfied by:

- ViewModel unit tests (JUnit + Turbine + coroutine test, `core-testing`
  fakes): initial load success → `Phase.Form`; amount validation
  (empty/zero/non-numeric/over-max → `fieldErrors`); email validation; `canSubmit`
  gating; submit success → `Phase.Confirmed` with receipt; submit failure →
  `transientError`, `isSubmitting=false`; 404 load → `Phase.Unavailable`; 422
  submit → field errors mapped; anonymous path runs with an empty cookie jar.
- Repository tests with MockWebServer: assert request path, body shape,
  `Idempotency-Key` header present and stable across retry, `detail` error
  mapping for 404/409/422/500, and that a submit succeeds with NO session
  cookie set (the core anonymous-capability assertion).
- Compose UI test (`createAndroidComposeRule`): enter amount + email, tap
  submit, assert confirmation receipt is displayed; disabled-submit-while-invalid;
  spinner shown during submission; unavailable state for closed fundraiser.
- The end-to-end "donation completes" test runs the full screen against a
  MockWebServer scripted to the §5 contract, asserting the terminal
  `Phase.Confirmed` and a visible receipt id.

## 12. Dependencies & Sequencing

- Depends on AND-031 for the `StateFlow<UiState>` + submit-handler +
  `ApiResult` patterns and the `core-network` cookie jar / CSRF / refresh
  interceptor. AND-031 must be merged first.
- Consumes `core-network` (client, `ApiResult`, error mapper), `core-model`
  (domain types), `core-ui` (theme, common components, skeletons), `core-data`
  (optional fundraiser cache), `core-testing` (fakes, MockWebServer harness).
- Coordinate with the M8 fundraiser-detail ticket(s) on the shared `Fundraiser`
  model and any Room cache table so the model is defined once in `core-model`.
- Blocks: none recorded. The single NavHost owner must wire
  `donationScreen(...)` and the deep-link intent filters in the app manifest.

## 13. Risks & Open Questions

- OQ-1: Exact public endpoint paths and field names — `/public/fundraisers/{id}`
  vs another prefix — must be confirmed against `/openapi.json`; §5 is the
  working contract.
- OQ-2: Does the backend require any CSRF/token for anonymous POST donations, or
  a bot-protection token (captcha/turnstile)? If yes, scope may grow.
- OQ-3: Is `donor_email` truly required for anonymous donations, or optional?
  Affects FR-5/validation.
- OQ-4: Server-side support for `Idempotency-Key`. If unsupported, document the
  double-submit window and rely on UI disabling only.
- Risk: payment processing is explicitly out of scope; if the backend expects a
  payment token in the donation body, this ticket cannot "complete" a real
  donation and must be re-scoped — the test uses the mock contract.
- Risk: unreliable dev host may make the live E2E flaky; primary tests use
  MockWebServer to keep the acceptance test deterministic.

## 14. Acceptance Criteria

- AC-1: Route `donate/{fundraiserId}` is registered with deep links and opens
  the donation screen from a cold deep-link launch.
- AC-2: The full flow (load fundraiser → enter amount + email → submit →
  confirmation with receipt id) completes successfully with NO authenticated
  session present (empty cookie jar). [primary backlog acceptance]
- AC-3: Submit is disabled until the form is valid and while a submission is in
  flight; a spinner is shown during submission.
- AC-4: Invalid amount/email produce inline field errors and block submit.
- AC-5: A 404/closed fundraiser renders the unavailable terminal state with no
  form; a load failure renders an error state with a working Retry.
- AC-6: A retried submit reuses the same `Idempotency-Key`.
- AC-7: No donor PII appears in logs or telemetry events.
- AC-8: ViewModel, repository (MockWebServer), and Compose UI tests described in
  §11 exist and pass, including the anonymous-capability assertion.

## 15. Definition of Done

- `feature-donation` module created under `com.testlogon.android.feature.donation`
  with route, ViewModel, repository, DTO/mappers, and Compose UI as specified.
- All §14 acceptance criteria met; §11 test suite green in CI.
- Endpoint paths/shapes reconciled with `/openapi.json` (or §13 open questions
  resolved and the spec/code updated to match).
- Strings externalized; a11y semantics verified; dark theme + font scaling OK.
- No PII in logs/telemetry; cleartext limited to the dev host; release builds
  use NONE network logging.
- NavHost owner has wired `donationScreen(...)` and manifest deep-link filters.
- Code reviewed and merged to `android-port`; ktlint/detekt clean; no new
  lint regressions.
