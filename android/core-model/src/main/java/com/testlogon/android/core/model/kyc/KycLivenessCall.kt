package com.testlogon.android.core.model.kyc

/**
 * AND-324 - transport DTOs for the `ui/kyc/liveness-call` scheduled video-verification endpoint.
 *
 * RECONCILIATION NOTE (identical to AND-319's Kyc.kt / AND-321 / AND-322 / AND-323): core-model has NO
 * Moshi dependency and NO Moshi codegen, so these DTOs carry NO annotations. The production Moshi
 * (core-network NetworkModule.provideMoshi) decodes them via the reflective KotlinJsonAdapterFactory,
 * which maps Kotlin property names to JSON keys VERBATIM. Every property below is therefore named
 * EXACTLY as the snake_case wire key (case_id, scheduled_at, duration_minutes, join_url, verifier_sub,
 * created_at, updated_at, ...). Zero annotations, zero new dependencies. Required wire fields have NO
 * default so the reflective adapter throws JsonDataException when absent; optional wire fields are
 * nullable with a default. Extra/unknown wire fields are tolerated leniently.
 *
 * FEATURE NATURE: this is a FULLY REAL REST scheduling feature, NOT in-app WebRTC. The user books a
 * scheduled video-verification appointment against a KYC case; a human verifier conducts it later; the
 * actual video is reached via the opaque [KycLivenessCallOutDto.join_url] opened EXTERNALLY (an
 * ACTION_VIEW intent). There is NO WebRTC / ML / camera / vendor SDK and NO flagged seam.
 *
 * Wire contract (verified, base ui/kyc/liveness-call; cookie + CSRF + Bearer attached globally):
 *   POST ui/kyc/liveness-call  request KycLivenessCallScheduleRequestDto -> 201 KycLivenessCallOutDto
 *   GET  ui/kyc/liveness-call  -> KycLivenessCallListDto { calls[] }
 *   GET  ui/kyc/liveness-call/{callId} -> KycLivenessCallOutDto
 *   GET  ui/kyc/liveness-call/case/{caseId} -> KycLivenessCallCaseStatusEnvelopeDto { verification_call? }
 *   POST ui/kyc/liveness-call/{callId}/cancel  (no body) -> KycLivenessCallOutDto (status cancelled)
 *
 * scheduled_at / created_at / updated_at are epoch-SECOND Longs (NOT Instant/ISO) so JVM unit tests need
 * no java.time; the feature mapper converts scheduled_at to Instant. status / result are plain Strings on
 * the wire (the typed enums + UNKNOWN fallback live in the feature domain mapper).
 */

/** Body for POST ui/kyc/liveness-call. Schedules ONE video-verification appointment for a KYC case. */
data class KycLivenessCallScheduleRequestDto(
    val case_id: String,
    val scheduled_at: Long,
    val duration_minutes: Int,
    val note: String? = null,
    val verifier_sub: String? = null,
)

/** A scheduled liveness (video-verification) call as returned by the backend. */
data class KycLivenessCallOutDto(
    val call_id: String,
    val case_id: String,
    val status: String,
    val scheduled_at: Long,
    val duration_minutes: Int,
    val join_url: String? = null,
    val result: String? = null,
    val created_at: Long? = null,
    val updated_at: Long? = null,
    val note: String? = null,
    val verifier_sub: String? = null,
)

/** GET ui/kyc/liveness-call envelope: the user's scheduled calls (absent key -> empty list). */
data class KycLivenessCallListDto(
    val calls: List<KycLivenessCallOutDto> = emptyList(),
)

/**
 * A lighter status shape returned inside the case-owner view. Modelled leniently: every field is
 * nullable with a default so a sparse / differently-keyed body decodes without throwing.
 */
data class KycLivenessCallStatusOutDto(
    val status: String? = null,
    val result: String? = null,
    val scheduled_at: Long? = null,
    val join_url: String? = null,
)

/** GET ui/kyc/liveness-call/case/{caseId} envelope: the owner-view status, which may be null. */
data class KycLivenessCallCaseStatusEnvelopeDto(
    val verification_call: KycLivenessCallStatusOutDto? = null,
)
