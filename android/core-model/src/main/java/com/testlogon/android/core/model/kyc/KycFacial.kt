package com.testlogon.android.core.model.kyc

/**
 * AND-323 - transport DTOs for the KYC facial-comparison flow (selfie vs. ID, compared SERVER-SIDE).
 *
 * RECONCILIATION NOTE (identical to AND-319's Kyc.kt / AND-321 / AND-322): core-model has NO Moshi
 * dependency and NO Moshi codegen, so these DTOs carry NO annotations. The production Moshi
 * (core-network NetworkModule.provideMoshi) decodes them via the reflective KotlinJsonAdapterFactory,
 * which maps Kotlin property names to JSON keys VERBATIM. Every property below is therefore named
 * EXACTLY as the snake_case wire key (comparison_id, confidence_score, anti_spoof, total_checks,
 * passed_checks, attempt_number, max_attempts, remaining_attempts, created_at). Zero annotations,
 * zero new dependencies. Required wire fields have NO default so the reflective adapter throws
 * JsonDataException when absent; optional wire fields are nullable with a default.
 *
 * Wire contract (verified):
 *   POST v1/kyc/cases/{case_id}/compare-face   (EMPTY body)
 *     response 200 FaceComparisonResultOut { comparison_id, confidence_score(0..100),
 *              result("pass"|"review"|"fail"), anti_spoof{ passed, checks[], total_checks,
 *              passed_checks }, attempt_number, max_attempts, remaining_attempts,
 *              created_at(epoch seconds), admin_override? }
 *   GET  v1/kyc/cases/{case_id}/face-comparisons
 *     response 200 FaceComparisonListOut { comparisons[] }  (modelled leniently, see below)
 *
 * The selfie image itself is uploaded via the presign (v1/fs/presign-upload) -> bare PUT pipeline and
 * attached via AND-319's KycApi.attachFile (file_type "selfie"); this file covers ONLY the compare +
 * history control-plane responses.
 */

/** One anti-spoof sub-check. [detail] is an optional human-facing note. */
data class AntiSpoofCheckDto(
    val check: String,
    val passed: Boolean,
    val detail: String? = null,
)

/** Aggregate anti-spoof (liveness) verdict for a comparison. */
data class AntiSpoofResultDto(
    val passed: Boolean,
    val checks: List<AntiSpoofCheckDto> = emptyList(),
    val total_checks: Int,
    val passed_checks: Int,
)

/**
 * 200 response for one face comparison. [result] is a free-form token mapped leniently to the domain
 * FaceResult enum (unknown -> UNKNOWN). [admin_override] is a loosely-typed map (heterogeneous wire
 * values) carrying @JvmSuppressWildcards for Moshi reflection; it is null when no admin acted.
 * [created_at] is epoch SECONDS (a Long, NOT ISO) so JVM unit tests need no java.time.
 */
data class FaceComparisonResultDto(
    val comparison_id: String,
    val confidence_score: Int,
    val result: String,
    val anti_spoof: AntiSpoofResultDto,
    val attempt_number: Int,
    val max_attempts: Int,
    val remaining_attempts: Int,
    val created_at: Long,
    val admin_override: Map<String, @JvmSuppressWildcards Any?>? = null,
)

/**
 * History envelope for GET face-comparisons. The wire wrapper is modelled leniently: [comparisons]
 * defaults to empty so a body using a different/absent key decodes without throwing rather than
 * failing the whole history load.
 */
data class FaceComparisonListDto(
    val comparisons: List<FaceComparisonResultDto> = emptyList(),
)
