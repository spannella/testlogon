package com.testlogon.android.core.model.kyc

/**
 * AND-327 - transport DTOs for the KYC proof-of-funds surface (`ui/kyc/proof-of-funds`):
 *   summary, submissions list, single submission, and submit.
 *
 * RECONCILIATION NOTE (identical to AND-319's Kyc.kt / AND-321 .. AND-326): core-model has NO Moshi
 * dependency and NO Moshi codegen, so these DTOs carry NO annotations. The production Moshi
 * (core-network NetworkModule.provideMoshi) decodes them via the reflective KotlinJsonAdapterFactory,
 * which maps Kotlin property names to JSON keys VERBATIM. Every property below is therefore named
 * EXACTLY as the snake_case wire key (submission_id, source_category, declared_amount_cents,
 * document_s3_key, risk_contribution, reviewer_sub, reviewer_note, reviewed_at, created_at, ...).
 * Zero annotations, zero new dependencies. Required wire fields (submission_id, status) have NO default
 * so the reflective adapter throws JsonDataException when absent; optional wire fields are nullable (or
 * empty-collection) with a default. Extra/unknown wire fields are tolerated leniently.
 *
 * Wire contract (verified; cookie + CSRF + Bearer attached globally):
 *   GET  ui/kyc/proof-of-funds/summary                       -> ProofOfFundsSummaryDto
 *   GET  ui/kyc/proof-of-funds/submissions                   -> { submissions: [ProofOfFundsSubmissionOutDto] }
 *   GET  ui/kyc/proof-of-funds/submissions/{submission_id}   -> ProofOfFundsSubmissionOutDto
 *   POST ui/kyc/proof-of-funds/submissions  body ProofOfFundsSubmitRequestDto (all optional) -> 200 ProofOfFundsSubmissionOutDto
 *
 * created_at / updated_at / reviewed_at are epoch-Long timestamps (NOT Instant/ISO) so JVM unit tests
 * need no java.time; the feature mapper converts created_at to Instant. status / source_category are
 * plain Strings on the wire (the typed enums + UNKNOWN fallback live in the feature domain mapper).
 * reviewer_note is the wire key (NOT review_note).
 */

/**
 * GET ui/kyc/proof-of-funds/summary. Only [count] + [verified_count] are required; everything else is
 * modelled leniently (nullable, default) so a sparse summary decodes.
 */
data class ProofOfFundsSummaryDto(
    val count: Int = 0,
    val verified_count: Int = 0,
    val active_risk_contribution: Double? = null,
    val verified_amount_cents: Long? = null,
    val verified_categories: List<String>? = null,
    val user_sub: String? = null,
)

/** GET ui/kyc/proof-of-funds/submissions envelope (absent key -> empty list). */
data class ProofOfFundsSubmissionListDto(
    val submissions: List<ProofOfFundsSubmissionOutDto> = emptyList(),
)

/**
 * A single proof-of-funds submission as returned by the backend. Required wire fields (submission_id,
 * status, created_at) have NO default; everything else is optional. Timestamps are epoch Longs.
 */
data class ProofOfFundsSubmissionOutDto(
    val submission_id: String,
    val status: String,
    val created_at: Long,
    val source_category: String? = null,
    val declared_amount_cents: Long? = null,
    val currency: String? = null,
    val document_s3_key: String? = null,
    val note: String? = null,
    val score: Double? = null,
    val risk_contribution: Double? = null,
    val reviewer_sub: String? = null,
    val reviewer_note: String? = null,
    val reviewed_at: Long? = null,
    val updated_at: Long? = null,
)

/**
 * Body for POST ui/kyc/proof-of-funds/submissions. EVERY field is optional on the wire; nulls are omitted
 * by Moshi. [document_s3_key] is the SINGLE optional S3 key returned by the presign->PUT document upload.
 */
data class ProofOfFundsSubmitRequestDto(
    val source_category: String? = null,
    val declared_amount_cents: Long? = null,
    val currency: String? = null,
    val document_s3_key: String? = null,
    val note: String? = null,
)
