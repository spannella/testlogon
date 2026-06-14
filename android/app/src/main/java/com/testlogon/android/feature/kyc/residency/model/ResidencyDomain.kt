package com.testlogon.android.feature.kyc.residency.model

import com.testlogon.android.core.model.kyc.AddressVerificationOutDto
import com.testlogon.android.core.model.kyc.KycResidencyDocumentOutDto
import java.time.Instant

/**
 * AND-326 - feature domain model + DTO mappers for KYC residency / address verification.
 *
 * The wire `document_type` / `status` / verification `status` + `decision` tokens are mapped to lenient
 * enums here (unknown token -> UNKNOWN, never throws). The epoch-second wire `created_at` becomes a
 * [java.time.Instant]. Discrepancy maps are flattened to the discrepant field names. All DTO -> domain
 * mapping happens BEFORE the typed ApiResult in the repository (mirrors AND-320 / AND-321 / AND-325).
 *
 * BOTH surfaces are REAL REST: the residency document is uploaded as inline base64 (REUSING AND-321's
 * CaptureImageProcessor for the proof bytes); the address is verified server-side. NO vendor / ML / CameraX
 * SDK, NO flagged seam.
 */

/** Lenient proof-of-residency document type (unknown token -> [UNKNOWN]). [wire] is the upload token. */
enum class ResidencyDocType(val wire: String) {
    UTILITY_BILL("utility_bill"),
    BANK_STATEMENT("bank_statement"),
    GOVERNMENT_LETTER("government_letter"),
    TAX_DOCUMENT("tax_document"),
    LEASE_AGREEMENT("lease_agreement"),
    UNKNOWN("unknown"),
    ;

    companion object {
        /** The five user-selectable proof types (excludes [UNKNOWN], which is a decode-only fallback). */
        val selectable: List<ResidencyDocType> =
            listOf(UTILITY_BILL, BANK_STATEMENT, GOVERNMENT_LETTER, TAX_DOCUMENT, LEASE_AGREEMENT)

        fun fromToken(token: String?): ResidencyDocType =
            entries.firstOrNull { it.wire == token?.lowercase() } ?: UNKNOWN
    }
}

/** Lenient residency document review status (unknown token -> [UNKNOWN]). */
enum class ResidencyStatus {
    PENDING,
    VERIFIED,
    REJECTED,
    EXPIRED,
    UNKNOWN,
    ;

    companion object {
        fun fromToken(token: String?): ResidencyStatus = when (token?.lowercase()) {
            "pending" -> PENDING
            "verified" -> VERIFIED
            "rejected" -> REJECTED
            "expired" -> EXPIRED
            else -> UNKNOWN
        }
    }
}

/** Lenient address-verification overall status (unknown token -> [UNKNOWN]). */
enum class AddrStatus {
    PENDING,
    PARTIAL_MATCH,
    UNVERIFIABLE,
    VERIFIED,
    ERROR,
    UNKNOWN,
    ;

    companion object {
        fun fromToken(token: String?): AddrStatus = when (token?.lowercase()) {
            "pending" -> PENDING
            "partial_match" -> PARTIAL_MATCH
            "unverifiable" -> UNVERIFIABLE
            "verified" -> VERIFIED
            "error" -> ERROR
            else -> UNKNOWN
        }
    }
}

/** Lenient address-verification decision (unknown token -> [UNKNOWN]). */
enum class AddrDecision {
    VERIFIED,
    NEEDS_REVIEW,
    FAILED,
    UNKNOWN,
    ;

    companion object {
        fun fromToken(token: String?): AddrDecision = when (token?.lowercase()) {
            "verified" -> VERIFIED
            "needs_review" -> NEEDS_REVIEW
            "failed" -> FAILED
            else -> UNKNOWN
        }
    }
}

/** Domain model of one uploaded proof-of-residency document. */
data class ResidencyDocument(
    val documentId: String,
    val docType: ResidencyDocType,
    val status: ResidencyStatus,
    val fileName: String,
    val issuingEntity: String?,
    val documentDate: String?,
    val reviewNote: String?,
    val createdAt: Instant,
)

/** A structured postal address the user enters for verification. */
data class AddressForm(
    val line1: String = "",
    val line2: String = "",
    val city: String = "",
    val state: String = "",
    val postalCode: String = "",
    val country: String = "",
)

/**
 * Domain model of an address-verification outcome. [discrepancies] is the flattened list of discrepant
 * field names (extracted from the loosely-typed wire discrepancy maps).
 */
data class AddressVerification(
    val status: AddrStatus,
    val decision: AddrDecision,
    val discrepancies: List<String>,
    val confidenceScore: Int?,
    val standardizedAddress: Map<String, String>?,
)

// ---- DTO -> domain mappers (never throw; unknown tokens -> UNKNOWN; epoch -> Instant) ----

fun KycResidencyDocumentOutDto.toDomain(): ResidencyDocument = ResidencyDocument(
    documentId = document_id,
    docType = ResidencyDocType.fromToken(document_type),
    status = ResidencyStatus.fromToken(status),
    fileName = file_name,
    issuingEntity = issuing_entity,
    documentDate = document_date,
    reviewNote = review_note,
    createdAt = Instant.ofEpochSecond(created_at),
)

fun AddressVerificationOutDto.toDomain(): AddressVerification = AddressVerification(
    status = AddrStatus.fromToken(status),
    decision = AddrDecision.fromToken(decision),
    discrepancies = discrepancies.flattenFieldNames(),
    confidenceScore = confidence_score,
    standardizedAddress = standardized_address,
)

/**
 * Flattens the loosely-typed wire discrepancy maps to their field names. Each entry is expected to carry a
 * "field" key; falls back to the first string value, then to a stringified entry so nothing is lost.
 */
private fun List<Map<String, Any?>>.flattenFieldNames(): List<String> = mapNotNull { entry ->
    (entry["field"] as? String)
        ?: entry.values.firstOrNull { it is String } as? String
        ?: entry.keys.firstOrNull()
}
