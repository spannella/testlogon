package com.testlogon.android.core.model.kyc

/**
 * AND-326 - transport DTOs for the two KYC residency / address-verification surfaces:
 *   1. proof-of-residency DOCUMENT upload + status  (`ui/kyc/residency`)
 *   2. structured ADDRESS verification, case-scoped (`v1/kyc/address-verification`)
 *
 * RECONCILIATION NOTE (identical to AND-319's Kyc.kt / AND-321 / AND-322 / AND-323 / AND-324 / AND-325):
 * core-model has NO Moshi dependency and NO Moshi codegen, so these DTOs carry NO annotations. The
 * production Moshi (core-network NetworkModule.provideMoshi) decodes them via the reflective
 * KotlinJsonAdapterFactory, which maps Kotlin property names to JSON keys VERBATIM. Every property below is
 * therefore named EXACTLY as the snake_case wire key (document_id, document_type, file_name, content_b64,
 * recency_valid, recency_days, extracted_address, line_1, postal_code, confidence_score,
 * standardized_address, ...). Zero annotations, zero new dependencies. Required wire fields have NO default
 * so the reflective adapter throws JsonDataException when absent; optional wire fields are nullable (or
 * empty-collection) with a default. Extra/unknown wire fields are tolerated leniently.
 *
 * Wire contract (verified; cookie + CSRF + Bearer attached globally):
 *   GET  ui/kyc/residency                       -> KycResidencyListResponseDto { documents[] }
 *   POST ui/kyc/residency                       body KycResidencyUploadRequestDto -> 201 KycResidencyDocumentOutDto
 *   POST ui/kyc/residency/{document_id}/extract (no body) -> 200 KycResidencyDocumentOutDto
 *   POST v1/kyc/address-verification/cases/{case_id}/verify  body AddressInputDto -> 200 AddressVerificationOutDto
 *   GET  v1/kyc/address-verification/cases/{case_id}         -> AddressVerificationOutDto
 *   POST v1/kyc/address-verification/validate-postal-code    body {postal_code, country} -> PostalCodeValidationDto
 *
 * created_at / updated_at are epoch-SECOND Longs (NOT Instant/ISO) so JVM unit tests need no java.time; the
 * feature mapper converts them to Instant. document_type / status / verification status + decision are plain
 * Strings on the wire (the typed enums + UNKNOWN fallback live in the feature domain mapper).
 */

// ---- RESIDENCY DOCUMENT (ui/kyc/residency) ----

/** GET ui/kyc/residency envelope: the uploaded residency documents (absent key -> empty list). */
data class KycResidencyListResponseDto(
    val documents: List<KycResidencyDocumentOutDto> = emptyList(),
)

/**
 * A single proof-of-residency document as returned by the backend. Required wire fields (document_id,
 * document_type, file_name, status, recency_valid, recency_days, created_at, updated_at) have NO default;
 * everything else is optional. `extracted_address` / `address_match` / `review_decision` are loosely-typed
 * (the production Moshi resolves Map and Any? via its built-in support; `@JvmSuppressWildcards` keeps the
 * reflective adapter from generating a wildcard-typed value adapter it cannot resolve).
 */
data class KycResidencyDocumentOutDto(
    val document_id: String,
    val document_type: String,
    val file_name: String,
    val status: String,
    val recency_valid: Boolean,
    val recency_days: Int,
    val created_at: Long,
    val updated_at: Long,
    val case_id: String? = null,
    val user_sub: String? = null,
    val issuing_entity: String? = null,
    val document_date: String? = null,
    val provider: String? = null,
    val document_url: String? = null,
    val extraction_id: String? = null,
    val extracted_address: Map<String, String>? = null,
    val address_match: Map<String, @JvmSuppressWildcards Any?>? = null,
    val review_decision: String? = null,
    val review_note: String? = null,
)

/** Body for POST ui/kyc/residency. The proof image/PDF is inline base64 (NO_WRAP) in [content_b64]. */
data class KycResidencyUploadRequestDto(
    val document_type: String,
    val issuing_entity: String,
    val document_date: String,
    val file_name: String,
    val content_b64: String,
    val case_id: String? = null,
)

// ---- ADDRESS VERIFICATION (v1/kyc/address-verification) ----

/** Body for POST v1/kyc/address-verification/cases/{case_id}/verify. Structured postal address. */
data class AddressInputDto(
    val line_1: String,
    val city: String,
    val state: String,
    val postal_code: String,
    val country: String,
    val line_2: String? = null,
)

/**
 * Response of the verify POST + the status GET. `discrepancies` entries are loosely-typed maps (field-name
 * + detail); the feature mapper flattens them to the discrepant field names. `standardized_address` is the
 * normalized address echoed by the verifier when available.
 */
data class AddressVerificationOutDto(
    val status: String,
    val decision: String,
    val discrepancies: List<Map<String, @JvmSuppressWildcards Any?>> = emptyList(),
    val confidence_score: Int? = null,
    val standardized_address: Map<String, String>? = null,
)

/**
 * Response of POST v1/kyc/address-verification/validate-postal-code. Only [valid] is required; the verifier
 * may echo extra lenient fields (region, normalized form) which are ignored by the reflective adapter.
 */
data class PostalCodeValidationDto(
    val valid: Boolean,
    val country: String? = null,
    val normalized: String? = null,
)

/** Body for POST v1/kyc/address-verification/validate-postal-code. */
data class PostalCodeValidationRequestDto(
    val postal_code: String,
    val country: String,
)
