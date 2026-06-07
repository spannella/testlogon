---
id: AND-393
title: Public donation
milestone: M8
epic: E51
priority: P2
size: L
status: reviewed
reviewed_on: 2026-06-06
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
  `http://18.222.237.167:8000/openapi.json`. The public fundraiser/donation
  endpoints live under `/public/fundraisers/...` and are designed to be callable
  anonymously (no `user_sub`/`X-SESSION-ID` params on these routes). [VERIFIED
  against OpenAPI: `GET /public/fundraisers/{fundraiser_id}`,
  `POST /public/fundraisers/{fundraiser_id}/donate`, and
  `GET /public/fundraisers/{fundraiser_id}/donations/{donation_id}/receipt`.]
  The corrected shapes in §5 are now reconciled with OpenAPI components
  (`GroupPublicFundraiserOut`, `GroupDonateIn`, `GroupDonationOut`,
  `GroupDonationReceiptOut`); see §16 for the per-claim audit.
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
(`group_name`, `title`, `description`, `currency`, `goal_cents`, `raised_cents`,
`donation_count`, optional `cover_image_url`, `status`, optional `ends_at`) and
renders title/group, a progress indicator (raised/goal), and the cover image via
Coil. [CORRECTED: the public schema `GroupPublicFundraiserOut` has no
`hero_image_url` or `acceptsDonations` boolean — the image field is
`cover_image_url` and open/closed is derived from `status`. See §16.]

FR-4 — Amount entry. The user enters a donation amount in the fundraiser's
currency (default `usd`). Preset chips (the web client uses 500 / 1000 / 2500 /
5000 cents, i.e. $5 / $10 / $25 / $50) plus a free-form field. Amount is
validated: numeric, >= minimum 100 cents ($1.00), <= maximum 10,000,000 cents
($100,000), parsed to integer cents (`amount_cents`) before submit. [CORRECTED:
the backend field is `amount_cents` with `minimum: 100`, `maximum: 10000000` per
`GroupDonateIn`; the spec's previous "minor units / 1,000,000 max" bounds were
wrong. See §16.]

FR-5 — Donor details. Fields per `GroupDonateIn`: donor name (OPTIONAL,
`donor_name`, max 100 chars) and email (OPTIONAL, `donor_email`, max 254 chars;
validated as email when non-blank). [CORRECTED: `donor_email` is NOT required by
the backend nor by the web client — both `donor_name` and `donor_email` are
optional. There is NO `display_anonymous`/anonymous toggle, NO public display
name, and NO `message`/comment field in `GroupDonateIn`; those were invented by
the prior draft. See §16/OQ-3. This ticket SHOULD drop the anonymous toggle and
message field, or treat them as client-only UI with no backend persistence.]

FR-6 — Submit. A submit button is enabled only when the form is valid and not
already submitting. Submitting posts to the donation endpoint and transitions
to a terminal confirmation state showing a receipt id and the amount.

FR-7 — Loading/disabled states. Initial load shows a skeleton; the submit
button shows a spinner and is disabled while in flight (mirrors AND-031's
loading/disabled handling). Inputs are disabled during submission.

FR-8 — Closed fundraiser. If `status != "active"` (i.e. `paused`, `completed`,
or `cancelled`) or the fundraiser is not found, render a non-actionable terminal
state explaining the fundraiser is unavailable; the form is not shown.
[CORRECTED: open/closed is derived from the `status` enum, not an
`acceptsDonations` boolean — the web client gates on `fundraiser.status !==
"active"`. The public GET documents only 200/422 (no explicit 404 schema); a
missing fundraiser surfaces as an absent/empty body which the web treats as "not
found". See §16/OQ-1.]

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

Retrofit service [CORRECTED throughout — the donate path was `/donations`,
should be `/donate`; field names and DTO shapes were wrong; the receipt is a
SEPARATE endpoint the prior draft omitted]:

```kotlin
interface DonationApi {
    // GET /public/fundraisers/{fundraiser_id} -> GroupPublicFundraiserOut
    @GET("public/fundraisers/{fundraiserId}")
    suspend fun getFundraiser(
        @Path("fundraiserId") fundraiserId: String,
    ): Response<PublicFundraiserDto>

    // POST /public/fundraisers/{fundraiser_id}/donate -> GroupDonationOut (201)
    @POST("public/fundraisers/{fundraiserId}/donate")
    suspend fun donate(
        @Path("fundraiserId") fundraiserId: String,
        @Body body: DonateRequestDto,
    ): Response<DonationDto>

    // GET /public/fundraisers/{fundraiser_id}/donations/{donation_id}/receipt
    //   -> GroupDonationReceiptOut (200)
    @GET("public/fundraisers/{fundraiserId}/donations/{donationId}/receipt")
    suspend fun getReceipt(
        @Path("fundraiserId") fundraiserId: String,
        @Path("donationId") donationId: String,
    ): Response<DonationReceiptDto>
}
```

> NOTE on `Idempotency-Key`: neither `GroupDonateIn` nor the donate route
> declares any idempotency header/param, and the web client does NOT send one.
> Treat server idempotency as UNVERIFIED/unsupported (§16, OQ-4). The header MAY
> still be sent defensively (servers ignore unknown headers) but MUST NOT be
> relied on for double-submit safety; rely on UI disabling. Do not assert its
> presence as a backend contract.

`GET /public/fundraisers/{fundraiserId}` → 200 `GroupPublicFundraiserOut`:

```json
{
  "fundraiser_id": "fr_123",
  "group_id": "grp_1",
  "group_name": "Westside Library Friends",
  "title": "Help Build the Library",
  "description": "Short blurb...",
  "currency": "usd",
  "goal_cents": 500000,
  "raised_cents": 132500,
  "donation_count": 42,
  "status": "active",
  "cover_image_url": "https://.../cover.jpg",
  "ends_at": 1735689600
}
```

(Required fields: `fundraiser_id`, `group_id`, `group_name`, `title`, `status`.
`currency` defaults to `"usd"`; `goal_cents` and `ends_at` are nullable;
`raised_cents`/`donation_count` default to 0; `cover_image_url` is nullable.)

`POST /public/fundraisers/{fundraiserId}/donate` request body `GroupDonateIn`:

```json
{
  "amount_cents": 2500,
  "donor_email": "spannella@gmail.com",
  "donor_name": "Sean P."
}
```

(`amount_cents` is the only REQUIRED field, integer, `minimum: 100`,
`maximum: 10000000`. `donor_email` ≤254 chars and `donor_name` ≤100 chars are
both nullable/optional. No `currency`, `display_anonymous`, or `message`
fields exist on this schema.)

201 response `GroupDonationOut`:

```json
{
  "donation_id": "don_789",
  "amount_cents": 2500,
  "status": "pending",
  "created_at": 1717804800,
  "donor_name": "Sean P.",
  "is_external": true,
  "checkout_url": null
}
```

(Required: `donation_id`, `amount_cents`, `status`, `created_at`. `status` enum:
`pending | completed | failed | refunded`. `is_external` defaults true;
`checkout_url` is nullable — if a non-null `checkout_url` is returned, payment is
NOT yet complete and the donation may need an external checkout step, which is
out of scope here, see §13/Risks. The response carries NO `fundraiser_id`,
`currency`, or `receipt_url`.)

Receipt is fetched in a SECOND call after the donation, mirroring the web
client: `GET /public/fundraisers/{id}/donations/{donation_id}/receipt` → 200
`GroupDonationReceiptOut`:

```json
{
  "donation_id": "don_789",
  "amount_cents": 2500,
  "currency": "usd",
  "donor_name": "Sean P.",
  "group_name": "Westside Library Friends",
  "fundraiser_title": "Help Build the Library",
  "created_at": 1717804800,
  "status": "completed"
}
```

(Required: `donation_id`, `amount_cents`, `group_name`, `fundraiser_title`,
`created_at`, `status`. The web client tolerates a not-yet-ready receipt: if the
receipt GET fails it falls back to a minimal confirmation built from the donation
response — this ticket SHOULD replicate that soft-fallback so `Phase.Confirmed`
is reachable even when the receipt endpoint 404s/errors transiently.)

Errors: each of these routes documents 200/201 plus `422 HTTPValidationError`
(FastAPI). `HTTPValidationError.detail` is an array of
`{loc:[...], msg, type}`. There is NO documented 404/409 response schema on the
public donate/get routes, so a missing/closed fundraiser is inferred from the
GET result (`status != "active"` or absent body), not from a 404 body. Mapped by
the shared `ApiResult` error mapper: missing fundraiser → unavailable terminal
state; 422 → field validation mapped back to the offending input via
`detail[].loc`; 5xx/timeout → retryable error. [CORRECTED: the prior draft's
"404 → unavailable / 409 closed/duplicate" contract is not backed by the
OpenAPI spec for these routes; only 422 is declared. Treat 404/409 handling as a
defensive client behavior, not a documented backend contract — see §16/OQ-1.]

## 6. Data & State Management

`DonationUiState` is a single immutable data class exposed as `StateFlow`:

```kotlin
data class DonationUiState(
    val fundraiserId: String,
    val phase: Phase = Phase.LoadingFundraiser,
    val fundraiser: Fundraiser? = null,
    val amountInput: String = "",
    val amountCents: Long? = null,          // [CORRECTED: backend field is amount_cents]
    val donorEmail: String = "",
    val donorName: String = "",
    // NOTE: `message`/`anonymous` have NO backend field (see §5/§16); keep them
    // only if product wants client-only UI, otherwise drop them.
    val fieldErrors: Map<DonationField, String> = emptyMap(),
    val isSubmitting: Boolean = false,
    val transientError: String? = null,
    val receipt: DonationReceipt? = null,
) {
    // [CORRECTED: donor_email is OPTIONAL per GroupDonateIn — do NOT gate
    // submit on a non-blank email. Validity requires a valid amount and no
    // field errors; email, when provided, must be a valid address.]
    val isFormValid: Boolean get() =
        amountCents != null && fieldErrors.isEmpty()
    val canSubmit: Boolean get() = isFormValid && !isSubmitting &&
        phase == Phase.Form
}

enum class Phase { LoadingFundraiser, Form, Unavailable, Submitting, Confirmed, LoadError }
enum class DonationField { Amount, Email, Name }
```

Domain models (`Fundraiser`, `DonationRequest`, `DonationReceipt`) live in
`core-model`; DTO↔domain mappers live in `feature-donation` data layer. Money is
always carried as integer cents (the backend's `*_cents` fields, currency
default `usd`); formatting to display strings uses the fundraiser currency via
`java.text.NumberFormat`.

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
- Submit (`POST`) is NOT auto-retried. On transient failure the UI surfaces
  `transientError` with a manual "Try again". [CORRECTED: there is no backend
  `Idempotency-Key` contract (see §5/§16) — a user-initiated retry is NOT
  guaranteed safe server-side. Mitigate double-submit primarily via UI disabling;
  any client idempotency header is best-effort only.]
- 401 on a public endpoint: per the web client (`src/api/client.ts`), the
  refresh-then-retry path runs ONLY when the caller was already authenticated; an
  UNauthenticated 401 propagates directly to the caller (no refresh attempt).
  For the anonymous donation path the request therefore proceeds/fails without a
  refresh loop and must never be treated as a hard auth wall. [CORRECTED: the
  prior "single refresh-then-retry interceptor applies, then proceeds without
  session" was inaccurate for the anonymous case — refresh is skipped entirely
  when unauthenticated. Note: the Android `core-network` interceptor from
  AND-031 should mirror this guard; verify against that module (unverified here,
  §16).]
- Missing/closed fundraiser → `Phase.Unavailable` (derived from GET result:
  absent body or `status != "active"`). 422 → populate `fieldErrors` from the
  `detail` array's `loc`/`msg`. [CORRECTED: the public donate/get routes declare
  only 200/201 + 422 in OpenAPI; 404/409 bodies are not part of the documented
  contract, so unavailability is inferred from the GET, not a 404/409 response.]
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
  `donation_submit_attempt` `{fundraiser_id, amount_cents}`,
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

- OQ-1: [RESOLVED in this review against OpenAPI] Public paths are
  `GET /public/fundraisers/{fundraiser_id}`,
  `POST /public/fundraisers/{fundraiser_id}/donate`, and
  `GET /public/fundraisers/{fundraiser_id}/donations/{donation_id}/receipt`.
  Field names corrected in §5 (`amount_cents`, `*_cents`, `cover_image_url`,
  `status`). Remaining sub-question: behavior for a non-existent fundraiser is
  undocumented (only 422 declared) — handle defensively.
- OQ-2: Does the backend require any CSRF/token for anonymous POST donations, or
  a bot-protection token (captcha/turnstile)? If yes, scope may grow.
- OQ-3: [RESOLVED] `donor_email` is OPTIONAL per `GroupDonateIn` (nullable, max
  254) and the web client sends it as optional. FR-5/validation updated: do not
  require email; validate format only when provided. (Product may still choose to
  request an email for receipt delivery, but it must not block submit.)
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
- AC-2: The full flow (load fundraiser → enter amount [email optional] → submit
  donation → fetch receipt → confirmation with receipt/donation id) completes
  successfully with NO authenticated session present (empty cookie jar). The
  confirmation MUST still be reachable when the receipt GET errors transiently,
  via the soft-fallback in §5. [primary backlog acceptance]
- AC-3: Submit is disabled until the form is valid (valid amount; email valid IF
  provided) and while a submission is in flight; a spinner is shown during
  submission.
- AC-4: An invalid amount (non-numeric, < $1.00 / 100 cents, or > 10,000,000
  cents) blocks submit with an inline error; a malformed email, when entered,
  blocks submit with an inline error. A blank email does NOT block submit.
- AC-5: A 404/closed fundraiser renders the unavailable terminal state with no
  form; a load failure renders an error state with a working Retry.
- AC-6: Double-submit is prevented: the submit control is disabled while a
  submission is in flight, and a user-initiated retry after failure reuses the
  same client idempotency key IF one is sent. [NOTE: server idempotency is
  unverified/unsupported (§5/§16); the binding guarantee here is UI disabling,
  not a backend dedupe contract.]
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer.

1. Fundraiser GET path is `GET /public/fundraisers/{fundraiser_id}`.
   VERDICT: Verified. SOURCE: OpenAPI `GET /public/fundraisers/{fundraiser_id}`
   (op `public_fundraiser_...`, resp `200:GroupPublicFundraiserOut`);
   frontend `src/api/endpoints/groups.ts: getPublicFundraiser`.
2. Donation POST path is `POST /public/fundraisers/{fundraiser_id}/donate`
   (NOT `/donations`). VERDICT: Corrected. SOURCE: OpenAPI
   `POST /public/fundraisers/{fundraiser_id}/donate`
   (op `public_donate_...`, req `GroupDonateIn`, resp `201:GroupDonationOut`);
   frontend `src/api/endpoints/groups.ts: submitDonation`.
3. The receipt is a SEPARATE second call,
   `GET /public/fundraisers/{fundraiser_id}/donations/{donation_id}/receipt`
   → `GroupDonationReceiptOut` — the prior draft folded a `receipt_url` into the
   donation response, which does not exist. VERDICT: Corrected. SOURCE: OpenAPI
   `GET /public/fundraisers/{fundraiser_id}/donations/{donation_id}/receipt`
   (resp `200:GroupDonationReceiptOut`); frontend
   `src/api/endpoints/groups.ts: getDonationReceipt` and
   `src/pages/groups/PublicDonationPage.tsx` (handleDonate → getDonationReceipt
   with soft-fallback).
4. Donation amount field is `amount_cents` (integer, min 100, max 10000000), not
   `amount_minor_units` and there is no separate `currency` in the request.
   VERDICT: Corrected. SOURCE: OpenAPI `components.schemas.GroupDonateIn`
   (`amount_cents` minimum 100 / maximum 10000000, required); frontend
   `src/api/endpoints/groups.ts: submitDonation` body type `{ amount_cents }`.
5. `donor_email` and `donor_name` are OPTIONAL (nullable; ≤254 / ≤100 chars);
   email is NOT required for an anonymous donation. VERDICT: Corrected. SOURCE:
   OpenAPI `GroupDonateIn` (`required: [amount_cents]`; donor_* in `anyOf` with
   null); frontend `PublicDonationPage.tsx` (`donor_email: donorEmail ||
   undefined`, submit disabled only on amount) and `src/api/types.ts` submit
   signature `donor_name?`, `donor_email?`.
6. `GroupDonateIn` has NO `display_anonymous`, `message`/comment, or public
   display-name field. VERDICT: Corrected (prior draft invented them). SOURCE:
   OpenAPI `components.schemas.GroupDonateIn` (only `amount_cents`,
   `donor_email`, `donor_name`).
7. Fundraiser image field is `cover_image_url` (nullable), not `hero_image_url`.
   VERDICT: Corrected. SOURCE: OpenAPI `GroupPublicFundraiserOut.cover_image_url`.
8. Open/closed is derived from `status` (enum incl. `active`), not an
   `accepts_donations` boolean. VERDICT: Corrected. SOURCE: OpenAPI
   `GroupPublicFundraiserOut.status` (required); frontend
   `PublicDonationPage.tsx` gate `fundraiser.status !== "active"`.
9. Money/goal fields on the fundraiser are `goal_cents` (nullable) and
   `raised_cents` (default 0), plus `donation_count`, `group_name`, `currency`
   (default `usd`). VERDICT: Corrected (prior `goal_minor_units` /
   `raised_minor_units`). SOURCE: OpenAPI `GroupPublicFundraiserOut`; frontend
   `src/api/types.ts: GroupPublicFundraiser`/`GroupFundraiser` and
   `PublicDonationPage.tsx` (uses `goal_cents`, `raised_cents`, `donation_count`,
   `group_name`).
10. Donation 201 response (`GroupDonationOut`) carries `donation_id`,
    `amount_cents`, `status` (`pending|completed|failed|refunded`), `created_at`,
    `donor_name?`, `is_external`, `checkout_url?` — and does NOT include
    `fundraiser_id`, `currency`, or `receipt_url`. VERDICT: Corrected. SOURCE:
    OpenAPI `components.schemas.GroupDonationOut`; frontend
    `src/api/types.ts: GroupDonation`.
11. Receipt response (`GroupDonationReceiptOut`) fields: `donation_id`,
    `amount_cents`, `currency` (default `usd`), `donor_name?`, `group_name`,
    `fundraiser_title`, `created_at`, `status`. VERDICT: Verified. SOURCE:
    OpenAPI `components.schemas.GroupDonationReceiptOut`; frontend
    `src/api/types.ts: GroupDonationReceipt`.
12. CSRF transport: the web client echoes the `ui_csrf` cookie as the
    `X-CSRF-Token` header when that cookie is present, and sends cookies via
    `credentials: include`. VERDICT: Verified. SOURCE: `src/api/client.ts`
    (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`;
    `credentials: "include"`).
13. 401 handling: refresh-then-retry runs only if the caller was already
    authenticated; an unauthenticated 401 propagates directly (no refresh).
    VERDICT: Corrected (prior draft implied refresh always applies on public
    paths). SOURCE: `src/api/client.ts` (`if (!useAuthStore.getState()
    .isAuthenticated) throw ApiError(401, ...)` before the refresh branch).
14. These public routes accept anonymous calls (no `user_sub`/`X-SESSION-ID`
    params). VERDICT: Verified. SOURCE: OpenAPI index entries for the three
    `/public/fundraisers/...` routes have `params=` limited to path ids (contrast
    the `/ui/groups/fundraising/...` routes which list `user_sub,X-SESSION-ID`).
15. Documented error responses on the public donate/get routes are only
    `422:HTTPValidationError` (plus 200/201). There is no documented 404/409
    body. VERDICT: Corrected (prior draft asserted 404→unavailable /
    409→closed-or-duplicate as a contract). SOURCE: OpenAPI index resp columns
    for the three routes (`resp=...;422:HTTPValidationError`);
    `components.schemas.HTTPValidationError` (detail: array of
    `{loc, msg, type}`).
16. Compose/Hilt/Navigation-Compose/Coil/Retrofit/Moshi stack and
    `NavType.StringType` deep-link wiring. VERDICT: Verified (framework ref).
    SOURCE: framework ref https://developer.android.com/jetpack/compose/navigation
    (deep links, typed nav args) and
    https://developer.android.com/training/data-storage/room (optional cache).

### Corrections made

- Donate endpoint path `/donations` → `/donate` (§2, §5).
- Request schema rewritten to `GroupDonateIn`: `amount_cents` (min 100 / max
  10000000) + optional `donor_email`/`donor_name`; removed invented `currency`,
  `display_anonymous`, `message`, display-name (§3 FR-4/FR-5, §5, §6).
- Email changed from required → optional in validation and `isFormValid` gate
  (§3 FR-5, §6, §14 AC-3/AC-4, OQ-3).
- Fundraiser response remapped to `GroupPublicFundraiserOut`: `*_cents`,
  `cover_image_url`, `group_name`, `donation_count`, `status` enum; removed
  `goal_minor_units`/`raised_minor_units`/`accepts_donations`/`hero_image_url`
  (§3 FR-3/FR-8, §5, §6).
- Added the separate receipt endpoint + soft-fallback confirmation pattern
  (§5, §14 AC-2).
- Donation 201 response remapped to `GroupDonationOut`; removed
  `fundraiser_id`/`currency`/`receipt_url`; documented `checkout_url`/`status`
  semantics (§5).
- 404/409 "contract" reframed as defensive client inference (only 422 is
  documented) (§5, §7, OQ-1).
- 401 refresh behavior corrected to match the web client's authenticated-only
  refresh guard (§7).
- `Idempotency-Key` downgraded from a backend contract to best-effort, with UI
  disabling as the binding double-submit guard (§5, §7, §14 AC-6, OQ-4).
- Telemetry `amount_minor_units` → `amount_cents` (§10).
- Frontmatter `status: reviewed`, added `reviewed_on: 2026-06-06`.

### Open assumptions

- OA-1 (OQ-2): Whether anonymous POST `/donate` requires CSRF or a bot-protection
  token is UNVERIFIED — the OpenAPI spec does not encode CSRF/captcha
  requirements and the web client only attaches `X-CSRF-Token` when a `ui_csrf`
  cookie already exists (never for a truly anonymous caller). Must be confirmed
  against the live dev host.
- OA-2 (OQ-4): Server-side idempotency for repeated donates is UNVERIFIED —
  neither the route nor `GroupDonateIn` declares an idempotency header/field.
- OA-3: Behavior for a non-existent `fundraiser_id` is UNVERIFIED — only 422 is
  documented; the web client treats an absent body as "not found". Confirm
  whether the backend returns 404, empty 200, or 422.
- OA-4: `checkout_url` semantics on `GroupDonationOut` — when non-null it implies
  an external payment step that is OUT OF SCOPE here. The dev contract used for
  the acceptance test assumes a null `checkout_url` and a terminal donation
  status; if the real backend always returns a `checkout_url`, the "donation
  completes" acceptance must be re-scoped (see §13 Risk).
- OA-5: AND-031's Android `core-network` interceptor (cookie jar, CSRF, 401
  refresh guard) is assumed to mirror the web client; the Android module was not
  inspected in this review (only the web reference). Verify on integration.

## 17. Test Plan

Test targets: JVM = JVM unit/Robolectric (local, no device); EMU = headless
emulator AVD `test35` (x86_64, API 35); DEVICE = physical Samsung Galaxy A15 5G
(SM-A156U, API 34, arm64-v8a). Cases note when a target is mandatory.

- TC-AND-393-01 — Happy path: full anonymous donation completes.
  Type: integration (Compose-UI + MockWebServer). Target: EMU (CI). 
  Preconditions: MockWebServer scripted to §5 contract; cookie jar EMPTY (no
  `ui`/`ui_csrf` cookies). Steps: launch `donate/fr_123`; wait for
  `GroupPublicFundraiserOut` (status `active`) to render; enter amount `25.00`;
  leave email blank; tap Donate; server returns `201 GroupDonationOut`; client
  then GETs the receipt → `200 GroupDonationReceiptOut`. Expected: `Phase.Confirmed`
  with the donation/receipt id and `$25.00` shown; the POST body was
  `{"amount_cents":2500}` (no currency/message/anonymous keys); NO `X-CSRF-Token`
  header sent (empty jar). Traces: AC-2.

- TC-AND-393-02 — Receipt soft-fallback: donation succeeds, receipt GET fails.
  Type: integration (Compose-UI + MockWebServer). Target: EMU. Preconditions:
  POST `/donate` → 201; receipt GET → 404/500. Steps: complete a donation as in
  TC-01; receipt call errors. Expected: client still reaches `Phase.Confirmed`
  using a minimal confirmation built from the `GroupDonationOut` (donation id,
  amount, status); no crash; no auto-retry storm on the receipt. Traces: AC-2.

- TC-AND-393-03 — Anonymous-capability contract assertion.
  Type: contract/MockWebServer (repository). Target: JVM. Preconditions: empty
  OkHttp cookie jar; no auth token. Steps: call `donate(...)`; capture the
  recorded request. Expected: request reaches `POST
  /public/fundraisers/fr_123/donate`, succeeds with 201, and carries NO
  `Authorization`, NO `X-SESSION-ID`, NO `X-CSRF-Token`; `GET /ui/me` is never
  called during the flow. Traces: AC-2, AC-7.

- TC-AND-393-04 — Endpoint/shape contract (path, method, body, DTO mapping).
  Type: contract/MockWebServer (repository). Target: JVM. Preconditions: canned
  §5 JSON. Steps: call `getFundraiser` then `donate`; assert recorded paths,
  methods, and that DTOs map to domain (`goal_cents`/`raised_cents`/`status`/
  `cover_image_url`/`group_name`; donation `status` enum). Expected: GET path
  `public/fundraisers/{id}`, POST path `public/fundraisers/{id}/donate`; body key
  is `amount_cents`; response fields parse without unknown-key failures.
  Traces: AC-2.

- TC-AND-393-05 — Amount validation.
  Type: unit (ViewModel + Turbine). Target: JVM. Preconditions: loaded
  `Phase.Form`. Steps: feed amounts `""`, `abc`, `0`, `0.50` (50¢ < min 100),
  `100000.00`+ (> 10,000,000¢), and a valid `25.00`. Expected: invalid inputs set
  `fieldErrors[Amount]` and keep `canSubmit=false`; valid input clears the error,
  sets `amountCents=2500`, `canSubmit=true`. Traces: AC-3, AC-4.

- TC-AND-393-06 — Email is optional; format validated only when present.
  Type: unit (ViewModel + Turbine). Target: JVM. Preconditions: valid amount
  entered. Steps: (a) leave email blank → submit allowed; (b) enter
  `not-an-email` → `fieldErrors[Email]`, submit blocked; (c) enter
  `spannella@gmail.com` → error cleared, submit allowed. Expected: blank email
  never blocks; malformed email blocks; valid email passes. Traces: AC-3, AC-4.

- TC-AND-393-07 — Submit gating + in-flight spinner/disabled inputs.
  Type: Compose-UI. Target: EMU. Preconditions: valid form. Steps: observe submit
  disabled while invalid; make valid; tap submit; while POST is in flight assert
  spinner shown, submit + inputs disabled; on success transitions to confirmation.
  Expected: matches FR-6/FR-7; `canSubmit` false during `isSubmitting`.
  Traces: AC-3.

- TC-AND-393-08 — Closed fundraiser → Unavailable, no form.
  Type: Compose-UI + MockWebServer. Target: EMU. Preconditions: GET returns
  `GroupPublicFundraiserOut` with `status:"paused"` (and a second variant
  `cancelled`). Steps: open screen. Expected: `Phase.Unavailable` terminal copy;
  amount/donor fields and Donate button NOT shown. Traces: AC-5.

- TC-AND-393-09 — Missing fundraiser + load error with Retry.
  Type: integration (Compose-UI + MockWebServer). Target: EMU. Preconditions:
  GET first returns an error/absent body (e.g. 500, then a network drop), then a
  valid 200 on retry. Steps: open screen → error state; tap Retry → loads
  successfully. Expected: error state shows a working Retry that re-invokes
  `loadFundraiser()`; a not-found result yields `Phase.Unavailable`. Traces: AC-5.

- TC-AND-393-10 — 422 validation mapping from FastAPI `detail`.
  Type: contract/MockWebServer (repository + ViewModel). Target: JVM.
  Preconditions: POST `/donate` returns `422 HTTPValidationError` with
  `detail:[{"loc":["body","amount_cents"],"msg":"...","type":"..."}]`. Steps:
  submit. Expected: `detail[].loc` last segment maps to `fieldErrors[Amount]`;
  `isSubmitting=false`; no raw exception reaches Compose. Traces: AC-4.

- TC-AND-393-11 — Transient submit failure → manual retry (no double-charge).
  Type: contract/MockWebServer (repository + ViewModel). Target: JVM.
  Preconditions: POST `/donate` returns 500 once, then 201. Steps: submit (fails →
  `transientError`, `isSubmitting=false`, NOT auto-retried); user taps Try again →
  201. Expected: exactly one POST per user action (no auto-retry); if a client
  idempotency key is sent it is identical across the two attempts; success →
  `Phase.Confirmed`. Traces: AC-6.

- TC-AND-393-12 — Flaky/offline dev host on load.
  Type: integration (Compose-UI + MockWebServer with throttling/SocketPolicy).
  Target: EMU. Preconditions: GET delayed past timeout / connection reset, then
  a good response. Steps: open screen under the flaky condition; tap Retry.
  Expected: bounded backoff for the GET per §7; 20s timeout budget respected; no
  hang; Retry recovers; submit POST is never auto-retried. Traces: AC-5.

- TC-AND-393-13 — No PII in logs/telemetry.
  Type: unit (telemetry/log scrubber). Target: JVM. Preconditions: capture
  emitted analytics events + debug log lines during a donation with
  `donor_email`/`donor_name` set. Steps: run submit success and failure.
  Expected: events contain only `fundraiser_id`/`amount_cents`/`donation_id`/
  `error_code`; no email/name/message; any logged email is redacted to
  `***@domain`. Traces: AC-7.

- TC-AND-393-14 — Cold deep-link launch into the donation screen.
  Type: instrumented/e2e. Target: DEVICE (mandatory — real cold-start intent
  routing and manifest deep-link filters on API 34/arm64 differ from the
  emulator; validates the actual install on the physical device). Steps: with the
  app not running, `adb -s R5CX821TA9R shell am start -a android.intent.action.VIEW
  -d "https://testlogon.com/donate/fr_123"` (and the `testlogon://donate/fr_123`
  scheme). Expected: app cold-starts directly on the donation screen for `fr_123`;
  `fundraiserId` arg parsed; flow then completes against the dev/mock backend.
  Traces: AC-1, AC-2.

- TC-AND-393-15 — Accessibility checks on the form.
  Type: Compose-UI (a11y). Target: EMU (functional semantics) + DEVICE (real
  TalkBack pass recommended). Steps: assert semantics: preset chips announce
  their value; amount field announces currency; submit button announces busy
  `stateDescription`; progress bar exposes `progressBarRangeInfo`; touch targets
  ≥48dp; error text accompanies field outlines (color not sole carrier); verify at
  largest font scale and in dark theme. Expected: all semantics present; layout
  intact at max font scale. Traces: AC-3, AC-4 (and §9).

### Coverage matrix

- AC-1 (route + deep link): TC-14.
- AC-2 (full anonymous flow → confirmation): TC-01, TC-02, TC-03, TC-04, TC-14.
- AC-3 (submit gating + spinner): TC-05, TC-06, TC-07, TC-15.
- AC-4 (amount/email inline errors block submit): TC-05, TC-06, TC-10, TC-15.
- AC-5 (closed/unavailable + load error Retry): TC-08, TC-09, TC-12.
- AC-6 (retried submit / no double-charge): TC-11 (and idempotency note in TC-01).
- AC-7 (no PII in logs/telemetry): TC-13 (and anonymous-headers check in TC-03).
- AC-8 (VM + repository/MockWebServer + Compose tests incl. anonymous): satisfied
  collectively by TC-01..TC-13, TC-15 (unit: TC-05/06/13; repo/MockWebServer:
  TC-03/04/10/11; Compose: TC-01/02/07/08/09/12/15).
