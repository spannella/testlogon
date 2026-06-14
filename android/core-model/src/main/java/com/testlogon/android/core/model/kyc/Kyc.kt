package com.testlogon.android.core.model.kyc

/**
 * AND-319 - KYC domain enums + transport DTOs for the `v1/kyc` endpoint surface.
 *
 * RECONCILIATION NOTE: core-model has NO Moshi dependency and NO KSP/Moshi-codegen plugin (its
 * build.gradle.kts only applies android.library + kotlin.android). It therefore CANNOT carry
 * `@JsonClass(generateAdapter = true)` or `@Json(name = ...)` annotations (those types live in the
 * moshi artifact, which core-model does not depend on, and adding it is forbidden by this ticket).
 *
 * The production Moshi (core-network NetworkModule.provideMoshi) decodes these via the reflective
 * KotlinJsonAdapterFactory, which maps Kotlin property names to JSON keys verbatim. So every DTO
 * property below is named EXACTLY as the snake_case wire key (e.g. `kyc_case_id`, `created_at`),
 * giving correct mapping with zero annotations and zero new dependencies. The two enum tokens are
 * mapped by KycCaseStatusAdapter / KycFileTypeAdapter in core-network.
 *
 * Timestamps are epoch-SECOND Longs (NOT Instant/ISO) so JVM unit tests need no java.time.
 * Optional fields are nullable with null defaults; required fields (created_at / updated_at /
 * version on KycCaseOut) have NO default so the reflective adapter throws JsonDataException when
 * they are absent. Enums fall back to UNKNOWN and never throw.
 */

/** Lifecycle status of a KYC case (wire token <-> enum via KycCaseStatusAdapter). */
enum class KycCaseStatus(val token: String) {
    DRAFT("draft"),
    SUBMITTED("submitted"),
    UNDER_REVIEW("under_review"),
    NEEDS_MORE_INFO("needs_more_info"),
    APPROVED("approved"),
    REJECTED("rejected"),
    EXPIRED("expired"),
    UNKNOWN("unknown"),
    ;

    companion object {
        /** Lenient: an unrecognized token maps to [UNKNOWN] rather than throwing. */
        fun fromToken(t: String?): KycCaseStatus = entries.firstOrNull { it.token == t } ?: UNKNOWN
    }
}

/** Type of an uploaded KYC document (wire token <-> enum via KycFileTypeAdapter). */
enum class KycFileType(val token: String) {
    ID_FRONT("id_front"),
    ID_BACK("id_back"),
    SELFIE("selfie"),
    PROOF_OF_ADDRESS("proof_of_address"),
    UNKNOWN("unknown"),
    ;

    companion object {
        /** Lenient: an unrecognized token maps to [UNKNOWN] rather than throwing. */
        fun fromToken(t: String?): KycFileType = entries.firstOrNull { it.token == t } ?: UNKNOWN
    }
}

// ---- Nested refs (all optional) ----

/** Reference to the questionnaire intake artifacts attached to a case. */
data class KycCaseQuestionnaireRef(
    val questionnaire_id: String? = null,
    val version_id: String? = null,
    val response_session_id: String? = null,
    val response_pdf_ref: String? = null,
)

/** Reference to the e-signature packet attached to a case. */
data class KycCaseSignatureRef(
    val packet_id: String? = null,
    val status: String? = null,
    val final_pdf_ref: String? = null,
    val legal_notice_version: String? = null,
    val legal_notice_accepted: Boolean? = null,
)

/** Reference to the admin review/decision attached to a case. */
data class KycCaseReviewRef(
    val ticket_id: String? = null,
    val assigned_admin_sub: String? = null,
    val decision: String? = null,
    val decided_at: Long? = null,
    val reason_codes: List<String> = emptyList(),
)

/** A single uploaded file entry on a case. */
data class KycCaseFile(
    val type: String? = null,
    val path: String? = null,
    val uploaded_at: Long? = null,
    val size: Long? = null,
    val verification_state: String? = null,
)

// ---- Case + envelopes ----

/**
 * A KYC case as returned by the backend.
 *
 * `created_at`, `updated_at` and `version` are REQUIRED (no default) so a body missing any of them
 * fails fast with a JsonDataException at decode time. `submission` / `verification_call` are loosely
 * typed maps; the production Moshi resolves Map<String, Any?> via its built-in support (the same
 * mechanism the test harness uses to decode request bodies), so they are kept faithfully typed
 * rather than collapsed. `@JvmSuppressWildcards` keeps the reflective adapter from generating a
 * wildcard-typed value adapter it cannot resolve.
 */
data class KycCaseOut(
    val contract_version: String = "2026-03-kyc-v1",
    val kyc_case_id: String,
    val user_sub: String,
    val status: KycCaseStatus,
    val intake_profile: String? = null,
    val questionnaire: KycCaseQuestionnaireRef? = null,
    val files: List<KycCaseFile> = emptyList(),
    val signature: KycCaseSignatureRef? = null,
    val submission: Map<String, @JvmSuppressWildcards Any?> = emptyMap(),
    val review: KycCaseReviewRef? = null,
    val verification_call: Map<String, @JvmSuppressWildcards Any?>? = null,
    val created_at: Long,
    val updated_at: Long,
    val version: Int,
    val missing_requirements: List<String> = emptyList(),
)

/** Single-case envelope: `{ "case": {...} }`. */
data class KycCaseEnvelope(
    val case: KycCaseOut,
)

/** Case-list envelope: `{ "items": [...], "next_cursor": ... }`. */
data class KycCaseListEnvelope(
    val items: List<KycCaseOut> = emptyList(),
    val next_cursor: String? = null,
)

// ---- Readiness ----

/** Submission-readiness evaluation for a case. */
data class KycReadinessResult(
    val contract_version: String = "2026-03-kyc-v1",
    val kyc_case_id: String,
    val status: KycCaseStatus,
    val ready_to_submit: Boolean,
    val missing_requirements: List<String> = emptyList(),
    val missing_hints: List<String> = emptyList(),
    val checks: Map<String, @JvmSuppressWildcards Boolean> = emptyMap(),
    val requirements: List<Map<String, @JvmSuppressWildcards Any?>> = emptyList(),
)

/** Readiness envelope: `{ "readiness": {...} }`. */
data class KycReadinessEnvelope(
    val readiness: KycReadinessResult,
)

// ---- Estimated wait ----

/** Estimated review wait time for the queue. */
data class KycEstimatedWaitResult(
    val contract_version: String = "2026-03-kyc-v1",
    val estimated_hours: Double,
    val queue_position: Int? = null,
    val message: String,
)

/** Estimated-wait envelope: `{ "estimated_wait": {...} }`. */
data class KycEstimatedWaitEnvelope(
    val estimated_wait: KycEstimatedWaitResult,
)

// ---- Request DTOs ----

/** Body for creating a new draft case. */
data class KycCaseCreateRequest(
    val intake_profile: String? = null,
)

/** Body for patching a draft case (optimistic concurrency via expected_version). */
data class KycCaseDraftPatchRequest(
    val expected_version: Int,
    val intake_profile: String? = null,
)

/** Body for attaching a file to a case. */
data class KycFileAttachmentRequest(
    val expected_version: Int,
    val path: String,
    val file_type: KycFileType,
)

/** Body for submitting a case for review. */
data class KycSubmitCaseRequest(
    val expected_version: Int,
)
