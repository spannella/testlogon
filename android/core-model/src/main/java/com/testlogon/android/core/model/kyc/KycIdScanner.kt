package com.testlogon.android.core.model.kyc

/**
 * AND-322 - transport DTOs for the `ui/kyc/id-scanner` guided government-ID capture+scan flow.
 *
 * RECONCILIATION NOTE (same as AND-319's Kyc.kt + AND-321's KycDocuments.kt): core-model has NO Moshi
 * dependency and NO Moshi codegen, so these DTOs carry NO annotations. The production Moshi (core-network
 * NetworkModule.provideMoshi) decodes them via the reflective KotlinJsonAdapterFactory, which maps Kotlin
 * property names to JSON keys VERBATIM. Every property below is therefore named EXACTLY as the snake_case
 * wire key (document_type, sides_required, has_mrz, mrz_valid, file_type, ...). Zero annotations, zero new
 * dependencies. Required wire fields have NO default so the reflective adapter throws JsonDataException when
 * absent; optional wire fields are nullable with a default.
 *
 * Wire contract (verified):
 *   POST ui/kyc/id-scanner/cases/{case_id}/validate-document
 *     request  KycIdScannerValidateRequestDto { document_type }
 *     response 200 KycIdScannerValidationOutDto { document_type, sides_required, sides_present, has_mrz,
 *              mrz_format?, all_sides_present }
 *   POST ui/kyc/id-scanner/cases/{case_id}/scan-document
 *     request  KycIdScannerScanRequestDto { document_type, file_type, mrz_lines?, image_ref? }
 *     response 201 KycIdScannerScanOutDto { scan_id, case_id, document_type, file_type, status, mrz_valid,
 *              extraction, expiry_check, cross_reference?, review_decision?, review_note?, image_url? }
 *
 * The base64 image upload itself reuses AND-321's `ui/kyc/documents` endpoint (KycDocumentsApi /
 * KycDocumentUploadRequestDto); this file covers ONLY the validate + per-side scan control-plane calls.
 */

/** Body for POST ui/kyc/id-scanner/cases/{case_id}/validate-document. */
data class KycIdScannerValidateRequestDto(
    val document_type: String,
)

/** 200 response describing which sides are required/present and the MRZ expectation for a document type. */
data class KycIdScannerValidationOutDto(
    val document_type: String,
    val sides_required: List<String>,
    val sides_present: List<String>,
    val has_mrz: Boolean,
    val mrz_format: String? = null,
    val all_sides_present: Boolean,
)

/**
 * Body for POST ui/kyc/id-scanner/cases/{case_id}/scan-document. [file_type] defaults to the front side;
 * [mrz_lines] (the FLAGGED on-device MRZ OCR output) and [image_ref] (the document_id from the AND-321
 * upload) are optional on the wire.
 */
data class KycIdScannerScanRequestDto(
    val document_type: String,
    val file_type: String = "id_front",
    val mrz_lines: List<String>? = null,
    val image_ref: String? = null,
)

/**
 * 201 response for a per-side scan. Required: scan_id, case_id, document_type, file_type, status, mrz_valid,
 * extraction, expiry_check. cross_reference / review_decision / review_note / image_url are optional.
 */
data class KycIdScannerScanOutDto(
    val scan_id: String,
    val case_id: String,
    val document_type: String,
    val file_type: String,
    val status: String,
    val mrz_valid: Boolean,
    val extraction: KycIdScannerExtractionDto,
    val expiry_check: KycExpiryCheckDto,
    val cross_reference: KycCrossReferenceDto? = null,
    val review_decision: String? = null,
    val review_note: String? = null,
    val image_url: String? = null,
)

/** Extracted MRZ / document fields. All fields optional except the per-field [checksums] map. */
data class KycIdScannerExtractionDto(
    val document_number: String? = null,
    val expiry_date: String? = null,
    val given_names: String? = null,
    val surname: String? = null,
    val nationality: String? = null,
    val date_of_birth: String? = null,
    val sex: String? = null,
    val issuing_state: String? = null,
    val checksums: Map<String, Boolean> = emptyMap(),
)

/** Document-expiry verdict. [status] is a free-form token; [message] is the human-facing summary. */
data class KycExpiryCheckDto(
    val status: String,
    val message: String,
    val expiry_date: String? = null,
    val days_until_expiry: Int? = null,
)

/**
 * Cross-reference of the extraction against the case's known data. [matches] / [mismatches] are loosely
 * typed maps (the values are heterogeneous on the wire) carrying @JvmSuppressWildcards for Moshi reflection.
 */
data class KycCrossReferenceDto(
    val match_score: Double? = null,
    val total_fields_checked: Int? = null,
    val fields_matched: Int? = null,
    val matches: Map<String, @JvmSuppressWildcards Any?> = emptyMap(),
    val mismatches: Map<String, @JvmSuppressWildcards Any?> = emptyMap(),
)
