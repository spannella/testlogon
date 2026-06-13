package com.testlogon.android.core.model.kyc

/**
 * AND-321 - transport DTOs for the `ui/kyc/documents` identity-document upload endpoint.
 *
 * RECONCILIATION NOTE (same as AND-319's Kyc.kt): core-model has NO Moshi dependency and NO Moshi
 * codegen, so these DTOs carry NO annotations. The production Moshi (core-network
 * NetworkModule.provideMoshi) decodes them via the reflective KotlinJsonAdapterFactory, which maps
 * Kotlin property names to JSON keys VERBATIM. Every property below is therefore named EXACTLY as the
 * snake_case wire key (document_type, file_name, content_b64, document_id, image_url, ...). Zero
 * annotations, zero new dependencies.
 *
 * Wire contract:
 *   POST ui/kyc/documents  (note the /ui/ prefix, NOT /v1/)
 *   request  KycDocumentUploadRequestDto { document_type, file_name, content_b64, case_id? }
 *   response 201 KycDocumentOutDto { document_id (NOT id), document_type, file_name, status,
 *            image_url?, extracted_fields, case_id?, user_sub?, created_at, updated_at }
 *
 * created_at / updated_at are epoch-SECOND Longs (NOT Instant/ISO) so JVM unit tests need no
 * java.time; the feature mapper converts them to Instant. created_at / updated_at have NO default so
 * the reflective adapter throws JsonDataException when absent. document_type/status are plain Strings
 * on the wire (the typed enum + UNKNOWN fallback lives in the feature domain mapper).
 */

/** Body for POST ui/kyc/documents. ONE call per image (a front+back ID is two calls). */
data class KycDocumentUploadRequestDto(
    val document_type: String,
    val file_name: String,
    val content_b64: String,
    val case_id: String? = null,
)

/** A single uploaded KYC document as returned by the backend (201). */
data class KycDocumentOutDto(
    val document_id: String,
    val document_type: String,
    val file_name: String,
    val status: String,
    val image_url: String? = null,
    val extracted_fields: Map<String, @JvmSuppressWildcards Any?> = emptyMap(),
    val case_id: String? = null,
    val user_sub: String? = null,
    val created_at: Long,
    val updated_at: Long,
)
