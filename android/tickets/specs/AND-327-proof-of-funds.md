---
id: AND-327
title: Proof of funds
milestone: M7
epic: E42
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-321]
blocks: []
---

# AND-327 — Proof of funds

## 1. Overview & Goal

This ticket delivers in-app **proof-of-funds (PoF) document submission** for the
TestLogon native Android client. A signed-in user who is required to evidence the
source of their funds — typically as part of advancing a KYC tier or satisfying a
compliance case (E42) — must be able to (a) see what proof-of-funds evidence is
required, (b) provide one or more supporting documents (bank statement, payslip,
deposit confirmation, etc.) by capturing or picking files, (c) optionally annotate
the submission with the declared source and amount, and (d) submit the
`kycProofOfFunds` record to the backend and observe its review status.

The functional bar from the backlog is exact and narrow: **`kycProofOfFunds`
document submission; proof submits + status.** This spec therefore scopes a single
PoF feature surface inside `feature-kyc`: a requirements/summary screen, a small
submission form, the wiring that uploads each supporting document, the
`kycProofOfFunds` registration call, and the status display that reflects the
backend review state (pending / approved / rejected / more-info).

This ticket does **not** re-specify document capture, the camera surface, image
compression, or the generic presign→PUT→confirm uploader — all of that is owned by
**AND-321 (Document capture + upload)** and is consumed here verbatim. It also does
not own the KYC transport DTOs (AND-319) nor tier/status requirements display
(AND-320); it consumes those types and patterns.

Success definition: a user who needs to prove source of funds can attach the
required supporting document(s) via the AND-321 capture/upload pipeline, submit a
`kycProofOfFunds` record with the declared source and amount, and then see an
accurate, refreshable submission status — with full test coverage of the
submit-then-status path.

## 2. Context & References

- Repo `spannella/testlogon`; Android app in `android/` (monorepo subfolder);
  branch `android-port`.
- Namespace / applicationId base: `com.testlogon.android` (used everywhere a
  package appears).
- Feature module: **`feature-kyc`** (`com.testlogon.android.feature.kyc`). PoF
  code lives under `feature-kyc/prooffunds/` (screens, ViewModel) with repository
  surface added to `core-data` (`com.testlogon.android.core.data.kyc`).
- Stack: Kotlin 2.0.21, Jetpack Compose + Material 3, single-Activity
  Navigation-Compose, Hilt (KSP), Coroutines/Flow, Retrofit 2.11 / OkHttp 4.12 /
  Moshi 1.15, Room 2.6 (cache), DataStore (prefs), Coil, Paging 3. minSdk 24,
  compileSdk/targetSdk 35, JDK 17, AGP 8.7.3, Gradle 8.9.
- Backend: FastAPI + DynamoDB; dev host `http://18.222.237.167:8000` (plaintext,
  unreliable — design for ~20 s timeouts, bounded backoff for idempotent GETs only,
  offline/stale UI). OpenAPI at `/openapi.json`; KYC endpoints under `/v1/kyc/*`.
- Web reference: `frontend/src/api/endpoints/kyc.ts` (look for the
  `proofOfFunds` / `proof_of_funds` calls) and shared types in
  `frontend/src/api/types.ts` — mirror snake_case wire keys; do not invent
  camelCase.
- **Dependency ticket — AND-321 (Document capture + upload):** provides the camera
  capture surface, `CaptureImageProcessor`, the navigation-result contract that
  returns confirmed `attachmentId`s, and the AND-129 `AttachmentUploader`
  (presign→PUT→confirm, progress/cancel/retry). PoF reuses this end to end to turn
  a captured/picked file into a confirmed `attachmentId`; this ticket only adds the
  PoF metadata form, the `kycProofOfFunds` registration call, and status display.
- **Consumed (not redefined):** AND-319 (`KycApi` + KYC DTOs, error enums,
  `@AppMoshiAdapter` hook), AND-320 (tier/status requirements UX patterns).
- Cross-cutting infra consumed: persistent cookie jar (AND-011), CSRF interceptor
  (AND-012), 401-refresh authenticator (AND-013), error/`detail` mapping (AND-015),
  retry-backoff for idempotent GETs (AND-016), connectivity probe (AND-017),
  `ApiResult<T>` (AND-018), Material 3 theme (AND-019), input composables
  (AND-020), state composables loading/empty/error/offline (AND-021), telemetry
  facade (AND-052), MockWebServer harness (AND-046).

## 3. Functional Requirements

FR-1 **Entry & requirement summary.** On entering the PoF flow the user sees a
summary screen. [CORRECTED] There is **no** single requirement/summary endpoint
that returns "the current submission + accepted document types + required
metadata"; that shape was invented. The real surface is: `GET
/ui/kyc/proof-of-funds/summary` (aggregate counts — `count`, `verified_count`,
`active_risk_contribution`, `verified_amount_cents`, `verified_categories`,
`user_sub`) and `GET /ui/kyc/proof-of-funds/submissions` (the user's list of
submissions). [CORRECTED] The accepted **source categories** are **not**
server-driven; the web reference hardcodes them as a client constant
(`bank_statement, pay_stub, sale_of_asset, investment, business_income,
inheritance, gift, savings`). If prior submissions exist, the latest submission's
status is shown (Section FR-7); the flow always also allows a new submission
(the model is a list, not a single record — see FR-8).

FR-2 **Declared source & amount.** The submission form collects: a **source
category** selection. [CORRECTED] The wire field is `source_category` (not
`source`), and the canonical client-side set is `bank_statement | pay_stub |
sale_of_asset | investment | business_income | inheritance | gift | savings`
(from the web reference's `SOURCE_CATEGORIES` constant) — there is no `salary`
and no `other` category, and no server-supplied enum. [CORRECTED] There is no
dedicated `source_description`; the free-text field is `note` (always optional —
not conditionally required). The form also collects a **declared amount**
(decimal) and **currency** (ISO-4217 string). All POST fields
(`source_category`, `declared_amount_cents`, `currency`, `document_s3_key`,
`note`) are **optional/nullable** in the backend schema; the client may impose
its own stricter requirements (Section 7). Inputs reuse AND-020 core input
composables and are validated client side before submit (Section 7).

FR-3 **Supporting document.** [CORRECTED] The backend accepts a **single**
`document_s3_key` string per submission, and it is **optional** — not an ordered
array of `attachments`/`attachmentId`s, and not server-required. The Android
design still uses the AND-321 capture/upload flow to produce the S3 key: the user
captures or picks a document, AND-321's presign→PUT→confirm pipeline yields the
confirmed object's **S3 key**, and that single key is sent as `document_s3_key`.
(The web reference simply takes a manually typed "Document key" string, confirming
it is a single optional S3 key.) The PoF screen shows the chosen document with a
label, thumbnail (Coil), and a remove/replace action. [UNVERIFIED-ASSUMPTION]
The client SHOULD require at least one document before submit as a product/UX
choice; the **server does not enforce a minimum** and there is no `min_documents`
field. If multiple documents must be supported, that is an additional Android-side
decision not reflected in the single-key wire contract.

FR-4 **Submit.** When the client-side requirements are met, **Submit** is enabled.
[CORRECTED] Submit calls `POST /ui/kyc/proof-of-funds/submissions` (not
`POST /v1/kyc/proof-of-funds`) with `source_category`, `declared_amount_cents`,
`currency`, the single `document_s3_key`, and `note`. The call is non-idempotent
and excluded from the AND-016 GET retry policy.

FR-5 **Submission feedback.** [CORRECTED] On `200` (not `201` — the OpenAPI
declares the success response as `200`), the screen transitions to the status view
showing the returned submission (`submission_id` + `status`). On validation failure
(`422`), field-level errors are mapped from the FastAPI `detail` list and rendered
inline. (`422` is the only error response the OpenAPI declares for these PoF
operations besides auth/network failures handled cross-cuttingly.)

FR-6 **Status display & refresh.** [CORRECTED] The status view renders the current
status as one of the server's actual values: `pending`, `verified`, `rejected`,
`needs_more_info`, `expired` (from the web reference's `REVIEW_STATUSES`) — **not**
`pending_review`/`approved`/`more_info_required`, and `expired` must be handled.
For `rejected` / `needs_more_info` the backend `reviewer_note` (field name is
`reviewer_note`, not `review_note`) is shown and a **Resubmit / Provide more**
affordance opens a new submission (pre-filled where possible). The view supports
pull-to-refresh re-reading `GET /ui/kyc/proof-of-funds/submissions` (and/or
`GET /ui/kyc/proof-of-funds/submissions/{submission_id}`).

FR-7 **Idempotent read on return.** Re-entering the flow always reads the latest
submission list first (cache-then-network, Section 6) so status is current after
backend review without requiring re-submission.

FR-8 **Multiple submissions allowed.** [CORRECTED] The backend model is a **list**
of submissions per user (`GET .../submissions` returns `{submissions: [...]}`, and
`summary` exposes a `count`); the web reference always permits creating a new
submission regardless of existing statuses. There is **no** server `409`
"already submitted" guard and no single-active-submission constraint. The original
"no duplicate submit / form locked while pending or approved" rule is therefore an
**Android-only UX policy**, not a backend contract: the client MAY discourage
duplicate submits while one is `pending`, but must not assume the server rejects
them. Resubmission after `rejected`/`needs_more_info` is simply another POST.

## 4. Technical Design

Single-Activity Navigation-Compose. New routes registered in `feature-kyc`:

```
kyc/proof-of-funds            -> ProofOfFundsScreen (summary + status host)
kyc/proof-of-funds/submit     -> ProofOfFundsFormScreen
```

The PoF capture/file-pick is **not** a new route here; it deep-links into the
AND-321 capture route (`kyc/capture/{templateId}` with a `proof_of_funds`
template id) and consumes its result. [CORRECTED] The result PoF needs is the
single uploaded object's **S3 key** (`document_s3_key`), not an ordered list of
`attachmentId`s — adapt the navigation-result contract accordingly (or map a
returned attachment to its S3 key).

ViewModel exposes `StateFlow<UiState>` per layering rules:

```kotlin
@HiltViewModel
class ProofOfFundsViewModel @Inject constructor(
    private val repository: ProofOfFundsRepository,   // added here, types from AND-319
    private val connectivity: ConnectivityObserver,   // AND-017
    savedState: SavedStateHandle,
) : ViewModel() {
    val uiState: StateFlow<ProofOfFundsUiState>
    fun load(forceRefresh: Boolean = false)
    fun onSourceChanged(source: PoFSource)
    fun onSourceDescriptionChanged(text: String)
    fun onAmountChanged(raw: String)
    fun onCurrencyChanged(code: String)
    fun onAttachmentAdded(attachmentId: String, label: String)
    fun onAttachmentRemoved(attachmentId: String)
    fun submit()
    fun onResubmit()
    fun retry()
}

sealed interface ProofOfFundsUiState {
    data object Loading : ProofOfFundsUiState
    data class Status(                                  // existing submission
        val submission: ProofOfFunds,
        val canResubmit: Boolean,
        val refreshing: Boolean = false,
    ) : ProofOfFundsUiState
    data class Form(                                    // new / resubmission
        val requirement: PoFRequirement,
        val source: PoFSource? = null,
        val sourceDescription: String = "",
        val amountRaw: String = "",
        val currency: String,
        val attachments: List<PoFAttachment> = emptyList(),
        val fieldErrors: Map<String, String> = emptyMap(),
        val submitting: Boolean = false,
        val submitEnabled: Boolean = false,
    ) : ProofOfFundsUiState
    data class Error(val error: UiError, val retryable: Boolean) : ProofOfFundsUiState
    data object Offline : ProofOfFundsUiState
}

data class PoFAttachment(val attachmentId: String, val label: String)
// [CORRECTED] Real source categories come from the web reference's
// SOURCE_CATEGORIES constant; the wire field is `source_category`. There is NO
// `salary` and NO `other`. Keep an UNKNOWN fallback for forward-compat, but do
// not invent an `other`/free-text-required category.
enum class PoFSource(val token: String) {
    BANK_STATEMENT("bank_statement"), PAY_STUB("pay_stub"),
    SALE_OF_ASSET("sale_of_asset"), INVESTMENT("investment"),
    BUSINESS_INCOME("business_income"), INHERITANCE("inheritance"),
    GIFT("gift"), SAVINGS("savings"), UNKNOWN("unknown");
    companion object { fun fromToken(t: String) = entries.firstOrNull { it.token == t } ?: UNKNOWN }
}
```
[CORRECTED] Note: `document_s3_key` is a **single** optional string, so `Form`
should hold at most one selected document (or treat the attachment list as a
1-element convenience). The single key is what is sent on the wire.

Domain models (`core-model`, mapped from AND-319-style DTOs by the repository):

```kotlin
// [CORRECTED] Real server status values: pending, verified, rejected,
// needs_more_info, expired (web REVIEW_STATUSES). NOT pending_review/approved/
// more_info_required. EXPIRED must be modeled.
enum class PoFStatus { PENDING, VERIFIED, REJECTED, NEEDS_MORE_INFO, EXPIRED, UNKNOWN }

// [CORRECTED] Field names match the real ProofOfFundsSubmission DTO:
// submission_id, source_category, declared_amount_cents, currency,
// document_s3_key, note, status, score, risk_contribution, created_at,
// updated_at, reviewer_sub, reviewer_note, reviewed_at. Timestamps are EPOCH
// numbers (Long), not ISO-8601 strings. Document is a single key, not a list.
data class ProofOfFunds(
    val submissionId: String,           // wire: submission_id
    val status: PoFStatus,
    val source: PoFSource?,             // wire: source_category (nullable)
    val declaredAmountCents: Long?,     // wire: declared_amount_cents (nullable)
    val currency: String?,
    val documentS3Key: String?,         // wire: document_s3_key (single, nullable)
    val note: String? = null,
    val score: Double = 0.0,
    val riskContribution: Double = 0.0,
    val reviewerNote: String? = null,   // wire: reviewer_note (NOT review_note)
    val createdAt: Long,                // wire: created_at (epoch seconds)
    val updatedAt: Long,                // wire: updated_at (epoch)
    val reviewedAt: Long? = null,       // wire: reviewed_at (epoch, nullable)
)

// [CORRECTED] There is no server "requirement" object. The summary endpoint
// returns aggregate counts, not accepted sources / min documents / formats.
data class PoFSummary(
    val count: Int,
    val verifiedCount: Int,             // wire: verified_count
    val activeRiskContribution: Double, // wire: active_risk_contribution
    val verifiedAmountCents: Long,      // wire: verified_amount_cents
    val verifiedCategories: List<String>, // wire: verified_categories
)
// Accepted source categories and the default currency are client-side constants
// (see PoFSource above); the web reference defaults currency to "USD".
```

Repository surface (added here; DTOs and `KycApi` extension from AND-319):

```kotlin
interface ProofOfFundsRepository {
    /** Cache-then-network read of the PoF summary + submissions list. */
    fun observe(): Flow<ApiResult<ProofOfFundsState>>
    suspend fun refresh(): ApiResult<ProofOfFundsState>
    suspend fun submit(req: SubmitProofOfFunds): ApiResult<ProofOfFunds>
}

// [CORRECTED] State is the summary + the list of submissions (multiple allowed),
// not requirement + single submission.
data class ProofOfFundsState(
    val summary: PoFSummary?,           // aggregate counts (may be absent)
    val submissions: List<ProofOfFunds>, // empty when nothing submitted yet
)

// [CORRECTED] Submit body mirrors CreateProofOfFundsSubmissionIn exactly:
// source_category, declared_amount_cents, currency, document_s3_key (single),
// note. All optional/nullable on the wire.
data class SubmitProofOfFunds(
    val sourceCategory: PoFSource?,     // wire: source_category
    val declaredAmountCents: Long?,     // wire: declared_amount_cents (>=0)
    val currency: String?,              // wire: currency (default "USD")
    val documentS3Key: String?,         // wire: document_s3_key (single key)
    val note: String?,                  // wire: note
)
```

Amount handling: the form captures a decimal string. [CORRECTED] The wire field is
`declared_amount_cents` and the web reference converts with a flat
`Math.round(parseFloat(amount) * 100)` — i.e. **always cents (×100), regardless of
currency**. Do **not** use `Currency.getInstance(code).defaultFractionDigits`
(that would send the wrong magnitude for zero-decimal currencies like JPY, which
the backend still expects in cents). Reject malformed/negative input client side;
the schema constrains `declared_amount_cents` to `>= 0`.

The document is a **single** `document_s3_key`. The capture/upload runs inside the
AND-321 flow; PoF stores the returned S3 key (one value) in `SavedStateHandle` so
it survives process death before submit.

## 5. API Contract

[CORRECTED] This ticket adds PoF operations on the **`/ui/kyc/proof-of-funds/*`**
surface (tag `kyc-proof-of-funds`), declared as methods on `KycApi` / a thin
`ProofOfFundsApi`, DTOs in `core-model`, owned by AND-319's serialization
conventions. Upload mechanics (presign→PUT→confirm) are AND-321 / AND-129 and are
not redefined here. The end-user-relevant operations are: `GET .../summary`,
`GET .../submissions`, `GET .../submissions/{submission_id}`, and `POST
.../submissions`. (`review/by-status/{status}` and `review/{id}/adjudicate` are
**reviewer/admin** operations and are **out of scope** for this end-user ticket.)

**GET `/ui/kyc/proof-of-funds/submissions`** — the user's submissions list
(idempotent; eligible for AND-016 backoff). Verified: `src/api/endpoints/
kycProofOfFunds.ts: listMine`.

```
Response 200:
{
  "submissions": [
    {
      "user_sub": "usr_...",
      "submission_id": "pof_a1b2",
      "source_category": "bank_statement",
      "declared_amount_cents": 250000,
      "currency": "USD",
      "document_s3_key": "kyc/pof/usr_.../doc1.pdf",
      "note": null,
      "status": "needs_more_info",
      "score": 0.42,
      "risk_contribution": 0.1,
      "created_at": 1748768400,
      "updated_at": 1748941200,
      "reviewer_sub": "rev_...",
      "reviewer_note": "Statement is older than 90 days; please upload a recent one.",
      "reviewed_at": 1748941200
    }
  ]
}
```
The array is empty when nothing has been submitted (NOT a `null` submission —
[CORRECTED]). `GET .../summary` returns `{count, verified_count,
active_risk_contribution, verified_amount_cents, verified_categories, user_sub}`.
`GET .../submissions/{submission_id}` returns a single `ProofOfFundsSubmission`.
`401` → AND-013 refresh-then-retry once (web does `POST /ui/session/refresh` then
one retry — verified `src/api/client.ts`).

**POST `/ui/kyc/proof-of-funds/submissions`** — submit / resubmit (non-idempotent;
**not** retried by AND-016). [CORRECTED] Success status is **`200`**, not `201`.

```
Headers: X-CSRF-Token: <ui_csrf cookie value>   (cookie-based session, AND-012)
Content-Type: application/json
Request (CreateProofOfFundsSubmissionIn — all fields optional/nullable):
{
  "source_category": "bank_statement",
  "declared_amount_cents": 250000,           // integer >= 0, cents (×100)
  "currency": "USD",
  "document_s3_key": "kyc/pof/usr_.../doc1.pdf",  // single S3 key (optional)
  "note": null
}
Response 200: a ProofOfFundsSubmission (same shape as the list items above), e.g.
{
  "user_sub": "usr_...",
  "submission_id": "pof_a1b2",
  "source_category": "bank_statement",
  "declared_amount_cents": 250000,
  "currency": "USD",
  "document_s3_key": "kyc/pof/usr_.../doc1.pdf",
  "note": null,
  "status": "pending",
  "score": 0.0,
  "risk_contribution": 0.0,
  "created_at": 1749124800,
  "updated_at": 1749124800,
  "reviewer_sub": null,
  "reviewer_note": null,
  "reviewed_at": null
}
```
[CORRECTED] Note the OpenAPI declares the `200` body schema as `{}` (untyped);
the web client types it as `ProofOfFundsSubmission`, which this spec adopts.
The POST also accepts optional `user_sub` query param + `X-SESSION-ID` /
`X-IMPERSONATION-TOKEN` headers (web/impersonation concerns; the mobile client
relies on its session cookie and does not set these).

Error envelope: FastAPI `detail` union (`string | [{msg,type,loc}] | {code,...}`)
mapped by AND-015 (web `normalizeErrorDetail` confirms this union — also maps
`detail.code` authorization objects). `422` validation maps `detail[].loc` to the
corresponding form field (e.g. `loc: ["body","declared_amount_cents"]` → amount
field error). [CORRECTED] `422` is the **only** documented error besides
auth/network; there is **no** `409` "already submitted" response (multiple
submissions are allowed — see FR-8), so do not special-case `409`. DTOs
(`PoFSummaryDto`, `PoFSubmissionDto`, `PoFSubmissionListResp`, `SubmitPoFReq`)
follow AND-319 conventions:
`@JsonClass(generateAdapter = true)`, snake_case `@Json(name=…)`, enum tokens via
a `PoFStatus`/`PoFSource` Moshi adapter with `UNKNOWN`/`OTHER` fallback registered
on the shared `Moshi` via `@AppMoshiAdapter`.

## 6. Data & State Management

- **Transient form state** lives in `ProofOfFundsViewModel` (`StateFlow`) plus
  `SavedStateHandle` for: selected `source_category`, note, amount string,
  currency, and the single confirmed `document_s3_key` ([CORRECTED] one key, not a
  list of `attachmentId`s — to survive process death before submit). No image
  bytes are held — only the key.
- **Read caching (SWR):** `ProofOfFundsState` (summary + submissions list) is
  cached in Room via the AND-116 cache-repository pattern. [CORRECTED] Because the
  backend allows **multiple** submissions, use a `kyc_pof_submissions` table keyed
  by `submission_id` (plus a small summary row), not a single-row table, with a
  short TTL (e.g. 5 min) and stale-allowed reads. `observe()` emits
  cached-then-network; `refresh()` forces a network read. This satisfies the
  offline/stale baseline (status visible offline, marked stale).
- **No DataStore keys** are added. Currency default comes from the requirement, not
  a persisted pref.
- **Mappers:** DTO→domain mapping (`PoFSubmissionDto.toDomain()`,
  `PoFSummaryDto.toDomain()`) lives in `core-data`. [CORRECTED] Timestamps are
  **epoch numbers** on the wire (`created_at`/`updated_at`/`reviewed_at`), kept as
  `Long` at the DTO layer and formatted for display in the ViewModel — they are
  not ISO-8601 strings.
- **The single `document_s3_key`** is the cross-flow state shared with AND-321; it
  is passed back via the Navigation-Compose `savedStateHandle` result pattern on
  returning from the capture route.
- **Cache invalidation:** a successful `submit()` inserts the returned submission
  into the Room submissions table immediately (optimistic-after-confirm), so the
  status view is correct without an extra round trip.

## 7. Error Handling & Resilience

- **Client validation (pre-submit):** [CORRECTED] All POST fields are
  optional/nullable server-side, so validation is an Android-only UX policy. There
  is **no `other` category** and **no conditionally-required `source_description`**
  — the free-text field is `note` and is always optional. Recommended client
  rules: a `source_category` is selected; the declared amount, if entered, parses
  to a non-negative integer number of **cents** (×100, currency-independent);
  currency is a valid ISO-4217 string (default `USD`); and (UX choice) at least
  one `document_s3_key` is present. Failures populate `Form.fieldErrors` and
  disable Submit; no network call is made.
- **`422` server validation:** mapped via AND-015 from `detail[].loc` to field
  errors (e.g. `["body","declared_amount_cents"]`); non-field `detail` strings
  surface as a form-level banner. This is the only documented PoF error code.
- **[CORRECTED] No `409` handling:** the backend does not return `409` for PoF and
  allows multiple submissions (FR-8); do not implement an "already submitted"
  branch. If a generic non-2xx other than `401`/`422` ever occurs, fall through to
  the standard AND-015 error banner.
- **Submit timeout / transport failure:** `POST /ui/kyc/proof-of-funds/submissions`
  is non-idempotent → **not** auto-retried (per AND-016 policy). On
  `SocketTimeoutException`/`IOException` (~20 s OkHttp timeout) show a retry-able
  error; the user re-taps Submit. The confirmed `document_s3_key` remains in state
  so resubmission does **not** re-upload the document.
- **`401`:** handled transparently by the AND-013 authenticator (one refresh +
  retry); a second `401` routes to an auth-expired state (AND-025).
- **Offline:** the AND-017 connectivity probe gates Submit (disabled offline with
  an offline banner from AND-021). The status read still renders cached data marked
  stale; a reconnect re-reads via `refresh()`.
- **Read failures:** `GET` failures fall back to cached `ProofOfFundsState` if
  present (stale badge); if no cache, render the AND-021 error state with retry.
- **Attachment flow failures** (capture/upload) are owned and surfaced by AND-321;
  PoF simply does not receive an `attachmentId` and the document is not added.

## 8. Security & Privacy

- Proof-of-funds documents and the declared source/amount are sensitive financial
  PII. **No document bytes ever pass through this ticket** — only confirmed
  `attachmentId`s; capture/storage hygiene (internal-cache-only, delete-after-
  confirm, no `MediaStore`) is enforced by AND-321.
- **Request bodies must not be logged.** [CORRECTED] The
  `/ui/kyc/proof-of-funds/submissions` POST path is added to the AND-009 redacting
  `HttpLoggingInterceptor` redaction list (declared here as a constraint for
  AND-009). `SubmitPoFReq.toString()` masks amount and note:
  `"SubmitPoFReq(source=$sourceCategory, amount=***, currency=$currency, note=***, doc=$documentS3Key)"`.
- Session is cookie-based; the CSRF token rides as `X-CSRF-Token` from the
  `ui_csrf` cookie (AND-012) — **verified** against `src/api/client.ts`.
  [VERIFY/NOTE] The web client additionally sends `Authorization: Bearer
  <accessToken>` on every request alongside the session cookie; whether the Android
  client uses bearer tokens or pure cookie auth is owned by AND-011/AND-013. This
  spec assumes cookie-based auth and declares no manual `Cookie`/`Authorization`
  headers, but the bearer-token detail should be reconciled with AND-013.
- On `dev` these calls ride plaintext HTTP — a known dev-only risk permitted by the
  scoped cleartext config (AND-006); only synthetic data is exercised against the
  dev host. `staging`/`prod` are HTTPS-only.
- Telemetry (Section 10) records metadata only — never the amount value, source
  description text, document content, or signed attachment URLs.
- Recommend `FLAG_SECURE` on the PoF form/status surfaces (financial PII visible
  on-screen); flagged as an open question pending product decision (Section 13).

## 9. Accessibility & i18n

- All static UI strings live in `strings.xml` (no hardcoded copy in composables);
  server-supplied strings (`reviewer_note`, status labels) are
  passed through. Source enum tokens map to localized labels in
  `strings.xml` (`pof_source_salary`, etc.).
- Form fields have associated labels and error text exposed via Compose semantics
  (`error` semantics on invalid fields); the amount field uses a numeric/decimal
  keyboard and announces currency.
- Status changes (e.g. submit success, refresh result) are announced via a
  `liveRegion`; the status chip has a `contentDescription` conveying the textual
  status, not color alone.
- All interactive controls (Submit, Add document, Remove, Resubmit, refresh) have
  `contentDescription`s and ≥48 dp touch targets; operable under TalkBack.
- Respects dynamic font scaling, dark theme, and RTL readiness via the Material 3
  theme (AND-019); no fixed-width text containers that clip translations.

## 10. Telemetry & Logging

Use the redacted telemetry facade (AND-052 pattern). Events (metadata only):

- `pof_viewed` { has_submission, status }
- `pof_form_opened` { resubmission }
- `pof_document_added` { document_count }
- `pof_document_removed` { document_count }
- `pof_submit_attempted` { source, document_count, currency }
- `pof_submit_succeeded` { pof_id, status }
- `pof_submit_failed` { error_code }
- `pof_status_refreshed` { status }

No amount values, description text, document bytes, signed URLs, or raw response
bodies are logged. Failures log the mapped `ApiError.code` only. HTTP logging is
inherited from the AND-009 redacting interceptor (debug builds), with the PoF POST
body redacted (Section 8).

## 11. Testing Strategy

Acceptance: **proof submits + status** — proven end to end with MockWebServer +
Compose, on the headless emulator (AND-051) and JVM (AND-050).

**Unit (JVM, core-testing + MockWebServer):** [CORRECTED throughout for real
paths/fields/statuses]
- `ProofOfFundsViewModel` state machine: load with an existing `needs_more_info`
  submission → `Status(canResubmit=true)`; `onResubmit` → `Form` pre-filled;
  add document + fill metadata → `submitEnabled=true`; `submit()` success →
  `Status(pending)`. Assert `StateFlow` transitions.
- Validation: missing `source_category` / non-positive amount / no
  `document_s3_key` each set `fieldErrors` and keep `submitEnabled=false`; no
  network call. (No `other`-without-description case — that field does not exist.)
- Amount conversion: decimal string → `declared_amount_cents` via flat ×100
  (USD `2.50` → `250`; and JPY `250` → `25000` — always cents, currency-independent,
  matching the web reference); malformed/negative rejected.
- Resubmit-without-reupload: after a submit timeout, the confirmed
  `document_s3_key` remains in state and a second `submit()` sends the same key
  (no upload invoked).
- `ProofOfFundsRepository`: `GET /ui/kyc/proof-of-funds/submissions` and
  `POST /ui/kyc/proof-of-funds/submissions` request/response shapes — POST body
  contains `source_category`, `declared_amount_cents`, `currency`,
  `document_s3_key`, `note`; **200** maps to `ProofOfFunds`; empty
  `submissions: []` maps to `ProofOfFundsState(submissions=emptyList())`;
  `422`/`401` mapped via AND-015. SWR cache: cached-then-network emission and
  write-through on submit.
- DTO round-trip: `PoFSubmissionListResp`/`SubmitPoFReq` (de)serialize snake_case
  keys and lowercase category/status tokens; unknown status → `UNKNOWN`; committed
  fixtures under `core-model/src/test/resources/kyc/pof_*.json`.
- Redaction: `SubmitPoFReq.toString()` does not contain the amount or the note.

**Instrumented / Compose UI tests:** [CORRECTED for real statuses/fields]
- Status view renders each status (`pending` / `verified` / `rejected` /
  `needs_more_info` / `expired`) with the correct label and `reviewer_note` where
  present; resubmit affordance only for `rejected` / `needs_more_info`.
- Form: filling required fields and adding a (fake) document key enables Submit;
  tapping Submit issues the POST to MockWebServer and the UI reaches the status
  view. The document is simulated by injecting a `document_s3_key` via the
  navigation-result seam (no real camera).
- Offline state disables Submit and shows the offline banner; cached status still
  renders with a stale badge.
- `422` from the POST renders the mapped field error inline.

**Definition of "tested submit + status":** an instrumented test that fills the
PoF form, simulates a `document_s3_key`, asserts the
`POST /ui/kyc/proof-of-funds/submissions` request body (`source_category`,
`declared_amount_cents`, `currency`, `document_s3_key`, `note`) hits MockWebServer,
and the UI transitions to a `pending` status view (HTTP **200**); plus a test that
a subsequent `GET .../submissions` reflecting `verified` updates the status on
refresh.

## 12. Dependencies & Sequencing

- **Hard dep (must merge first):**
  - **AND-321 (Document capture + upload)** — provides the capture/file-pick flow,
    the AND-129 `AttachmentUploader`, and the navigation-result contract that yields
    confirmed `attachmentId`s. PoF cannot attach documents without it.
- **Transitively relied on:** AND-319 (`KycApi` + KYC DTO/adapter conventions and
  `@AppMoshiAdapter` hook), AND-320 (tier/requirements UX patterns), AND-116 (SWR
  cache pattern), AND-011/AND-012/AND-013 (cookie/CSRF/refresh), AND-015 (error
  mapping), AND-016 (GET backoff), AND-017 (connectivity), AND-018 (`ApiResult`),
  AND-019 (theme), AND-020 (inputs), AND-021 (state composables), AND-046
  (MockWebServer harness), AND-052 (telemetry).
- **New library:** none. PoF adds source files to `feature-kyc` and `core-data`,
  plus PoF DTOs/methods following AND-319 conventions.
- **Blocks:** none listed in the backlog. Downstream KYC tier-advancement /
  compliance-case screens (E42) may surface the PoF entry point but are not gated by
  a declared id here.
- **Sequencing within ticket:** (1) PoF DTOs + Moshi enum adapter + `KycApi`
  PoF methods, (2) `ProofOfFundsRepository` + mappers + Room cache row, (3)
  `ProofOfFundsViewModel` state machine + amount conversion, (4) Compose status +
  form screens wired to the AND-321 capture result, (5) tests.

## 13. Risks & Open Questions

- **R-1 Endpoint shape. [RESOLVED — corrected.]** The real paths are
  `/ui/kyc/proof-of-funds/{summary,submissions,submissions/{id}}` and the field
  names are `source_category`, `declared_amount_cents`, `document_s3_key`, `note`
  (not `/v1/...`, `declared_amount_minor`, `source`, `attachments`). Verified
  against `openapi.index.txt`, `CreateProofOfFundsSubmissionIn`, and
  `src/api/endpoints/kycProofOfFunds.ts`.
- **R-2 Amount representation. [RESOLVED — corrected.]** Backend uses integer
  `declared_amount_cents` (`>= 0`); the web reference always multiplies by 100
  regardless of currency. Use flat ×100, not currency fraction digits.
- **R-3 Source enum set. [RESOLVED — corrected.]** Canonical categories are
  client-side constants: `bank_statement, pay_stub, sale_of_asset, investment,
  business_income, inheritance, gift, savings`. No `salary`/`other`. Keep an
  `UNKNOWN` fallback for forward-compat.
- **R-4 Resubmission semantics. [RESOLVED — corrected.]** Resubmit is just another
  `POST .../submissions`; there is no distinct resubmit endpoint and no `case_id`.
  Reviewer-side adjudication lives at `review/{id}/adjudicate` (out of scope).
- **R-5 Single vs. multiple submissions. [RESOLVED — corrected.]** Multiple
  submissions per user ARE allowed (`submissions` is a list; `summary.count`).
  There is no `409` guard. The status surface is a list of submissions.
- **R-6 `FLAG_SECURE`.** Financial PII on-screen suggests screenshot blocking on
  the PoF surfaces; not specified — needs product decision. Open.
- **R-7 PII redaction gap.** If AND-009's redaction list lacks
  `/ui/kyc/proof-of-funds/submissions`, the POST body could leak to logcat in debug. Mitigation:
  add the path to AND-009's redaction set; assert via `toString()` redaction test.

## 14. Acceptance Criteria

AC-1 A signed-in user with a proof-of-funds requirement can open the PoF flow and
see either the submission form (no prior submission) or the current submission
status. (Backlog: "`kycProofOfFunds` document submission.")

AC-2 [CORRECTED] The user can select a `source_category` (from the canonical
client set), optional `note`, declared amount, and currency, and attach a
supporting document via the AND-321 capture/upload flow, receiving a confirmed
single `document_s3_key`.

AC-3 [CORRECTED] With the client-required metadata and a document present, Submit
issues `POST /ui/kyc/proof-of-funds/submissions` with the correct
`source_category`, `declared_amount_cents`, `currency`, `document_s3_key`, and
`note`; on `200` the UI shows the returned submission in a status view. (Backlog:
"proof submits.")

AC-4 [CORRECTED] The status view accurately renders `pending`, `verified`,
`rejected`, `needs_more_info`, and `expired`, shows `reviewer_note` for
`rejected`/`needs_more_info`, supports refresh, and offers resubmission only for
`rejected` / `needs_more_info`. (Backlog: "+ status.")

AC-5 [CORRECTED] Client validation, `422` (field errors), timeout, offline, and
`401` each produce a non-crashing, retry-able/appropriate state; a resubmit after
a submit failure does **not** re-upload the already-confirmed document. (No `409`
"already submitted" case — multiple submissions are allowed.)

AC-6 [CORRECTED] No document bytes, amount values, note text, or signed/S3 URLs
appear in logs or telemetry; the `/ui/kyc/proof-of-funds/submissions` POST body is
redacted.

AC-7 [CORRECTED] An automated test (MockWebServer + Compose, headless emulator)
fills the form, simulates a `document_s3_key`, asserts the submit request shape,
and asserts the UI reaches a `pending` status view (HTTP 200), plus a refresh
reflecting `verified`. (Backlog: "tested submit + status.")

## 15. Definition of Done

- All Acceptance Criteria (Section 14) met and demonstrated.
- PoF flow implemented in `feature-kyc` (`com.testlogon.android.feature.kyc`):
  `ProofOfFundsViewModel`, `ProofOfFundsScreen`, `ProofOfFundsFormScreen`, the
  routes in Section 4, and the navigation-result wiring into the AND-321 capture
  flow; `ProofOfFundsRepository` + mappers + Room cache row in `core-data`.
- PoF DTOs/`KycApi` methods + the `PoFStatus`/`PoFSource` Moshi adapter follow
  AND-319 conventions (snake_case, `@JsonClass`, `@AppMoshiAdapter` registration);
  no new networking client/Retrofit/Moshi instance.
- No new third-party library; capture/upload reused from AND-321/AND-129 with no
  duplication.
- Unit tests (ViewModel state machine, amount conversion, repository
  request/response + SWR cache, DTO round-trip, redaction) and instrumented
  Compose/UI tests pass locally and in CI (AND-050 / AND-051); committed fixtures
  under `core-model/src/test/resources/kyc/`.
- Lint, ktlint/detekt (AND-005) clean; no new warnings.
- No financial PII (amount, description, document bytes) or signed URLs in
  logs/telemetry; `/ui/kyc/proof-of-funds/submissions` POST body added to AND-009 redaction list.
- Open questions in Section 13 resolved against `/openapi.json` /
  `frontend/src/api/endpoints/kyc.ts` / product, or tracked as follow-ups.
- Code reviewed and merged to `android-port`.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer.

1. **PoF endpoints live under `/ui/kyc/proof-of-funds/*`** (not `/v1/kyc/proof-of-funds`).
   VERDICT: Corrected. SOURCE: `openapi.index.txt` lines 1558-1561 — `GET
   /ui/kyc/proof-of-funds/submissions`, `POST /ui/kyc/proof-of-funds/submissions`,
   `GET /ui/kyc/proof-of-funds/submissions/{submission_id}`, `GET
   /ui/kyc/proof-of-funds/summary`; and `src/api/endpoints/kycProofOfFunds.ts`.
2. **POST request body = `CreateProofOfFundsSubmissionIn`** with fields
   `source_category`, `declared_amount_cents`, `currency`, `document_s3_key`,
   `note` — all optional/nullable, `declared_amount_cents >= 0`. VERDICT: Corrected
   (spec had `source`, `source_description`, `declared_amount_minor`, `attachments[]`).
   SOURCE: `components.schemas.CreateProofOfFundsSubmissionIn` (openapi.pretty.json
   L23178-23239); `src/api/endpoints/kycProofOfFunds.ts: createSubmission`.
3. **Document is a single `document_s3_key` string, optional** — not an ordered
   array of confirmed `attachmentId`s, and no server minimum. VERDICT: Corrected.
   SOURCE: `CreateProofOfFundsSubmissionIn.document_s3_key`;
   `src/pages/kyc/KycProofOfFunds.tsx` ("Document key (optional)" single field).
4. **Submission response = `ProofOfFundsSubmission`** with `submission_id`,
   `source_category`, `declared_amount_cents`, `currency`, `document_s3_key`,
   `note`, `status`, `score`, `risk_contribution`, `created_at`, `updated_at`,
   `reviewer_sub`, `reviewer_note`, `reviewed_at`, `user_sub`. VERDICT: Corrected
   (spec had `id`, `review_note`, `attachments[]`, ISO `submitted_at`).
   SOURCE: `src/api/endpoints/kycProofOfFunds.ts: ProofOfFundsSubmission`.
5. **Timestamps are epoch numbers** (`created_at`/`updated_at`/`reviewed_at`:
   `number`), not ISO-8601 strings. VERDICT: Corrected. SOURCE:
   `src/api/endpoints/kycProofOfFunds.ts: ProofOfFundsSubmission` (typed `number`).
6. **Review note field is `reviewer_note`**, not `review_note`. VERDICT: Corrected.
   SOURCE: `src/api/endpoints/kycProofOfFunds.ts: ProofOfFundsSubmission.reviewer_note`.
7. **Status values: `pending`, `verified`, `rejected`, `needs_more_info`,
   `expired`** — not `pending_review`/`approved`/`more_info_required`. VERDICT:
   Corrected. SOURCE: `src/pages/kyc/KycProofOfFunds.tsx: REVIEW_STATUSES` and
   `statusClass()`.
8. **Source categories: `bank_statement, pay_stub, sale_of_asset, investment,
   business_income, inheritance, gift, savings`** (client-side constant), no
   `salary`/`other`, not server-supplied. VERDICT: Corrected. SOURCE:
   `src/pages/kyc/KycProofOfFunds.tsx: SOURCE_CATEGORIES`.
9. **Amount is `declared_amount_cents`, computed as `round(amount * 100)`
   regardless of currency** (flat cents, not currency fraction-digits). VERDICT:
   Corrected. SOURCE: `src/pages/kyc/KycProofOfFunds.tsx: submit()` (`Math.round(parseFloat * 100)`).
10. **POST success status is `200`, not `201`.** VERDICT: Corrected. SOURCE:
    `openapi.pretty.json` create_submission responses (L23540-23548: only `200`/`422`).
11. **`422` is the only documented error (besides auth/network); no `409`.**
    VERDICT: Corrected (spec invented `409 already-submitted`). SOURCE:
    create_submission `responses` (only `200`,`422`); no `409` in schema.
12. **Multiple submissions per user are allowed** (list + `summary.count`); no
    single-active-submission constraint. VERDICT: Corrected. SOURCE: `GET
    .../submissions` returns `{submissions: [...]}` (`ProofOfFundsSubmissionList`);
    `ProofOfFundsSummary.count`; web "My submissions" list renders all.
13. **No server "requirement" object** (accepted_sources/min_documents/
    default_currency/accepted_formats). VERDICT: Corrected — replaced with the real
    `GET .../summary` (`count`, `verified_count`, `active_risk_contribution`,
    `verified_amount_cents`, `verified_categories`, `user_sub`). SOURCE:
    `src/api/endpoints/kycProofOfFunds.ts: ProofOfFundsSummary`.
14. **CSRF: `X-CSRF-Token` header sourced from the `ui_csrf` cookie.** VERDICT:
    Verified. SOURCE: `src/api/client.ts` (`getCookie("ui_csrf")` →
    `headers.set("X-CSRF-Token", csrf)`).
15. **401 handling: one refresh then one retry.** VERDICT: Verified (refresh path
    is `POST /ui/session/refresh`). SOURCE: `src/api/client.ts` (`refreshSession`,
    single-flight `refreshPromise`, single retry).
16. **Web client also sends `Authorization: Bearer <accessToken>`** alongside the
    cookie. VERDICT: Verified (noted as a discrepancy with the spec's "no
    Authorization header" claim; Android auth strategy owned by AND-011/013).
    SOURCE: `src/api/client.ts` (`headers.set("Authorization", \`Bearer ${accessToken}\`)`).
17. **FastAPI `detail` error union (`string | [{msg,loc,type}] | {code,...}`)**
    mapped by AND-015. VERDICT: Verified. SOURCE: `src/api/client.ts:
    normalizeErrorDetail` / `mapAuthorizationError`; `HTTPValidationError` schema.
18. **Network/offline error path** (fetch throws → friendly error). VERDICT:
    Verified analogue for the offline-banner design. SOURCE: `src/api/client.ts`
    catch block ("Network error — check your connection").
19. **Reviewer/adjudication endpoints (`review/by-status/{status}`,
    `review/{id}/adjudicate`) are admin-only and out of scope.** VERDICT: Verified.
    SOURCE: `openapi.index.txt` L1556-1557; `src/api/endpoints/kycProofOfFunds.ts:
    listByStatus/adjudicate` (used in web "Reviewer queue").
20. **Stack/framework choices** (Compose, Navigation-Compose savedStateHandle
    result, Room SWR, Moshi adapters, Hilt). VERDICT: Unverified-assumption
    (Android-side architecture; not derivable from backend/web sources). Framework
    refs: Navigation result —
    https://developer.android.com/guide/navigation/use-graph/programmatic#returning_a_result ;
    Compose accessibility/semantics —
    https://developer.android.com/jetpack/compose/accessibility .

### Corrections made
- Paths `/v1/kyc/proof-of-funds` → `/ui/kyc/proof-of-funds/{summary,submissions,
  submissions/{id}}` throughout (FR-1/3/4/5/6, §4, §5, §7, §8, §11, §13, §14, §15).
- Request fields: `source`→`source_category`; removed `source_description`
  (free-text is `note`, always optional); `declared_amount_minor`→
  `declared_amount_cents`; `attachments[]`→ single `document_s3_key`.
- Response fields: `id`→`submission_id`; `review_note`→`reviewer_note`; ISO-8601
  `submitted_at`/`reviewed_at` strings → epoch-number `created_at`/`updated_at`/
  `reviewed_at`; added `score`/`risk_contribution`/`user_sub`.
- Status enum: `pending_review/approved/more_info_required` → `pending/verified/
  rejected/needs_more_info/expired` (added `expired`).
- Source categories corrected to the real 8-value set; removed `salary`/`other`.
- Amount conversion: currency-fraction-digits → flat ×100 cents.
- Success status `201` → `200`.
- Removed `409`/"no duplicate submit"/single-active-submission model; documented
  that multiple submissions are allowed and there is no requirement endpoint.
- Removed the server-driven `min_documents`/`PoFRequirement`; replaced with the
  real `PoFSummary` and client-side category/currency constants.
- Domain models, repository surface, ViewModel enums, Room schema, telemetry, and
  test assertions updated to match the above.

### Open assumptions
- **A-1 (status surface as a list).** The exact UX for multiple submissions
  (latest-only vs. full history) is an Android product choice; the backend supports
  a list but does not prescribe presentation. Unverifiable from sources.
- **A-2 (client-required document & category).** The server makes every POST field
  optional; requiring a document and a `source_category` before submit is an
  Android-only UX policy. Cannot be confirmed from the contract.
- **A-3 (AND-321 returns an S3 key).** This spec assumes AND-321's
  presign→PUT→confirm pipeline can yield the object's `document_s3_key`. AND-321's
  result contract is described as returning `attachmentId`s; the mapping
  attachmentId→S3 key must be confirmed with AND-321/AND-129. Not in these sources.
- **A-4 (auth model).** Whether Android uses pure cookie auth or also a bearer
  token (as the web client does) is owned by AND-011/AND-013; assumed cookie-based
  here. Unverifiable from PoF sources alone.
- **A-5 (`expired` transitions / resubmission eligibility).** Whether `expired`
  should offer resubmission like `rejected`/`needs_more_info` is a product
  decision; assumed yes. Not specified in sources.
- **A-6 (`FLAG_SECURE`).** Screenshot blocking on PoF surfaces — product decision
  (Section 13 R-6). Unverifiable.

## 17. Test Plan

Test IDs `TC-AND-327-NN`. Acceptance-criteria links are to Section 14 (AC-1..AC-7).
"Physical device" = Samsung Galaxy A15 5G (SM-A156U, serial R5CX821TA9R, Android 14
/ API 34, arm64-v8a). "Emulator" = AVD `test35` (API 35, x86_64). JVM = local
Robolectric/unit.

**TC-AND-327-01 — Happy-path submit then status (e2e)**
- Type: instrumented/e2e (Compose + MockWebServer).
- Target: Emulator `test35` (camera mocked via nav-result seam; no real hardware).
- Preconditions: signed-in session; MockWebServer scripted: `GET .../submissions`
  → `{submissions:[]}`, `POST .../submissions` → `200` submission `status:"pending"`.
- Steps: open PoF flow; select `source_category=bank_statement`; enter amount
  `2500.00`; inject a `document_s3_key` via the AND-321 nav-result seam; add note;
  tap Submit.
- Expected: a single `POST /ui/kyc/proof-of-funds/submissions` with body
  `{source_category:"bank_statement", declared_amount_cents:250000, currency:"USD",
  document_s3_key:<key>, note:<text>}`; UI transitions to a status view showing
  `pending`. No `201` expected — `200` is success.
- Traces: AC-1, AC-3, AC-7.

**TC-AND-327-02 — Refresh reflects reviewer decision `verified` (integration)**
- Type: integration (MockWebServer + repository/ViewModel).
- Target: JVM.
- Preconditions: cached submission `pending`; MockWebServer next `GET
  .../submissions` returns the same `submission_id` with `status:"verified"`.
- Steps: trigger pull-to-refresh / `refresh()`.
- Expected: status view updates to `verified`; resubmit affordance hidden; Room row
  updated.
- Traces: AC-4, AC-7.

**TC-AND-327-03 — All status renderings incl. `expired` (Compose-UI)**
- Type: Compose-UI.
- Target: Emulator `test35`.
- Preconditions: seeded submissions for each of `pending`, `verified`, `rejected`,
  `needs_more_info`, `expired`; `reviewer_note` present on `rejected`/`needs_more_info`.
- Steps: render the status view for each status.
- Expected: correct localized label for each (incl. `expired`); `reviewer_note`
  shown only for `rejected`/`needs_more_info`; resubmit affordance only for
  `rejected`/`needs_more_info` (and `expired` per A-5, if adopted); status chip
  exposes a textual `contentDescription` (not color-only).
- Traces: AC-4, plus accessibility (Section 9).

**TC-AND-327-04 — Client validation blocks submit (unit)**
- Type: unit (ViewModel state machine).
- Target: JVM.
- Preconditions: empty form.
- Steps: (a) no `source_category`; (b) negative/malformed amount; (c) no
  `document_s3_key` (per client UX policy A-2).
- Expected: each sets `fieldErrors`, keeps `submitEnabled=false`, and makes **no**
  network call. No `other`-without-description case (field does not exist).
- Traces: AC-5.

**TC-AND-327-05 — Amount → cents conversion (unit)**
- Type: unit.
- Target: JVM.
- Preconditions: none.
- Steps: convert `"2.50"`/USD, `"250"`/JPY, `"0"`, `"-1"`, `"abc"`.
- Expected: USD `2.50`→`250`; JPY `250`→`25000` (flat ×100, currency-independent);
  `0`→`0`; negative and malformed rejected (no submit). Asserts the ×100 rule, not
  `defaultFractionDigits`.
- Traces: AC-3, AC-5.

**TC-AND-327-06 — `422` field-error mapping (contract/MockWebServer)**
- Type: contract/MockWebServer.
- Target: JVM.
- Preconditions: `POST .../submissions` → `422` with
  `detail:[{loc:["body","declared_amount_cents"],msg:"...",type:"..."}]`.
- Steps: submit a filled form.
- Expected: AND-015 maps `loc`→amount field error rendered inline; non-field
  `detail` strings surface as a form banner; no crash; form remains editable.
- Traces: AC-5.

**TC-AND-327-07 — Submit timeout does not re-upload document (unit/contract)**
- Type: unit + contract (MockWebServer with delayed/closed socket).
- Target: JVM.
- Preconditions: confirmed `document_s3_key` in state; `POST` times out (~20 s).
- Steps: tap Submit (fails); tap Submit again (now `200`).
- Expected: POST is **not** auto-retried by AND-016; retryable error shown; the
  second submit sends the **same** `document_s3_key` with **no** AND-321 upload
  invoked.
- Traces: AC-5.

**TC-AND-327-08 — Offline gating + stale cache (Compose-UI)**
- Type: Compose-UI / instrumented.
- Target: Physical device (real connectivity toggle: airplane mode exercises the
  AND-017 probe more faithfully than the emulator). MUST run on the physical device
  for the real network-loss transition; emulator acceptable as a smoke check.
- Preconditions: a cached submission present; device goes offline.
- Steps: open PoF flow offline; observe banner and cached content; attempt Submit;
  reconnect and refresh.
- Expected: offline banner (AND-021); Submit disabled; cached status renders with a
  stale badge; on reconnect `refresh()` re-reads `GET .../submissions`.
- Traces: AC-5.

**TC-AND-327-09 — `401` refresh-then-retry, then auth-expired (contract)**
- Type: contract/MockWebServer.
- Target: JVM.
- Preconditions: first `GET .../submissions` → `401`; refresh succeeds; retry →
  `200`. Second scenario: refresh path also `401`.
- Steps: load the flow under each scenario.
- Expected: scenario 1 — one transparent refresh + retry yields data (AND-013);
  scenario 2 — routes to auth-expired (AND-025); no crash.
- Traces: AC-5.

**TC-AND-327-10 — DTO round-trip + unknown-token fallback (unit)**
- Type: unit (Moshi).
- Target: JVM.
- Preconditions: fixtures `core-model/src/test/resources/kyc/pof_*.json`.
- Steps: (de)serialize `ProofOfFundsSubmission`, `ProofOfFundsSubmissionList`,
  `CreateProofOfFundsSubmissionIn`; include an unknown `status` and unknown
  `source_category`.
- Expected: snake_case keys map exactly; epoch `Long` timestamps preserved; unknown
  `status`→`UNKNOWN`, unknown `source_category`→`UNKNOWN`; nullable fields tolerate
  `null`. No `id`/`review_note`/`attachments` keys are emitted.
- Traces: AC-3, AC-4.

**TC-AND-327-11 — CSRF header + body redaction (unit/contract + security)**
- Type: contract/MockWebServer + unit.
- Target: JVM.
- Preconditions: `ui_csrf` cookie set in the cookie jar (AND-011).
- Steps: perform a POST; capture the recorded request; also call
  `SubmitPoFReq.toString()`.
- Expected: request carries `X-CSRF-Token: <ui_csrf>` and `Content-Type:
  application/json`; the POST path is on AND-009's redaction list so the body is not
  logged; `toString()` masks amount and note (`amount=***`, `note=***`).
- Traces: AC-6 (security), AC-3.

**TC-AND-327-12 — No PII in telemetry/logs (unit)**
- Type: unit (telemetry facade spy).
- Target: JVM.
- Preconditions: telemetry facade captured.
- Steps: run viewed/form-opened/document-added/submit-attempted/submit-succeeded/
  submit-failed events.
- Expected: events carry metadata only (`status`, `document_count`, `source`
  category token, `currency`, `error_code`); **no** amount value, note text, S3
  key, or signed URL. Failure logs only the mapped `ApiError.code`.
- Traces: AC-6.

**TC-AND-327-13 — Real document capture → S3 key → submit (instrumented/e2e)**
- Type: instrumented/e2e (real camera + AND-321 upload pipeline).
- Target: Physical device (MUST — exercises the device camera and the real
  presign→PUT→confirm path; verifies the attachment→`document_s3_key` mapping, A-3).
- Preconditions: signed-in; dev host reachable; camera permission grantable.
- Steps: open PoF; launch capture; grant camera permission; capture a document;
  confirm upload; verify a `document_s3_key` is returned and submit succeeds.
- Expected: AND-321 returns a usable S3 key; `POST .../submissions` sends it;
  UI reaches `pending`. Validates the cross-flow contract on real hardware.
- Traces: AC-2, AC-3.

**TC-AND-327-14 — Accessibility sweep (instrumented/manual)**
- Type: Compose-UI + manual (TalkBack).
- Target: Physical device (real TalkBack) for the manual pass; emulator for the
  automated semantics assertions.
- Preconditions: form and status screens.
- Steps: enable TalkBack; traverse Submit / Add document / Remove / Resubmit /
  refresh; trigger a submit-success announcement; inspect amount field keyboard.
- Expected: all controls have `contentDescription`s and ≥48 dp targets; invalid
  fields expose `error` semantics; status change announced via `liveRegion`; amount
  field uses a decimal keyboard; dynamic font scaling/dark/RTL do not clip.
- Traces: AC-4, Section 9 (accessibility).

### Coverage matrix

| AC (Section 14) | Covered by |
| --- | --- |
| AC-1 (open flow; form or status) | TC-01 |
| AC-2 (declare metadata + attach document via AND-321) | TC-13 |
| AC-3 (Submit POST shape; 200 → status view) | TC-01, TC-05, TC-10, TC-11, TC-13 |
| AC-4 (status rendering incl. refresh & resubmit gating) | TC-02, TC-03, TC-10, TC-14 |
| AC-5 (validation/422/timeout/offline/401; no re-upload) | TC-04, TC-05, TC-06, TC-07, TC-08, TC-09 |
| AC-6 (no PII in logs/telemetry; body redacted) | TC-11, TC-12 |
| AC-7 (automated submit→pending + refresh→verified) | TC-01, TC-02 |
