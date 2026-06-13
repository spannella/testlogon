package com.testlogon.android.feature.kyc.idscanner.model

import androidx.annotation.StringRes
import com.testlogon.android.R
import com.testlogon.android.core.model.kyc.KycIdScannerScanOutDto
import com.testlogon.android.core.model.kyc.KycIdScannerValidationOutDto

/**
 * AND-322 - feature domain model + DTO mappers for the KYC ID-scanner flow.
 *
 * The document types are a FIXED client enum (there is NO template-list endpoint per the contract). The wire
 * status string is mapped to a lenient [ScanStatus] enum here (unknown token -> [ScanStatus.UNKNOWN], never
 * throws). All DTO -> domain mapping happens BEFORE the typed ApiResult in the repository (mirrors AND-320 /
 * AND-321).
 */

/** The four government-ID document types the client supports. [wireType] is the fixed server enum id. */
enum class IdDocumentType(val wireType: String, @StringRes val label: Int) {
    PASSPORT("passport", R.string.idscan_type_passport),
    NATIONAL_ID_CARD("national_id_card", R.string.idscan_type_national_id_card),
    DRIVING_LICENSE("driving_license", R.string.idscan_type_driving_license),
    RESIDENCE_PERMIT("residence_permit", R.string.idscan_type_residence_permit),
}

/**
 * Which physical side of a document is being captured. [fileType] is the wire `file_type` value used by both
 * the AND-321 upload (document_type) and the scan call (file_type).
 */
enum class IdSide(val fileType: String, @StringRes val label: Int) {
    FRONT("id_front", R.string.idscan_side_front),
    BACK("id_back", R.string.idscan_side_back),
}

/** Lenient scan verdict (unknown token -> [UNKNOWN]). */
enum class ScanStatus {
    MATCHED,
    FLAGGED,
    REJECTED,
    APPROVED,
    DECLINED,
    UNKNOWN,
    ;

    companion object {
        fun fromToken(token: String?): ScanStatus = when (token?.lowercase()) {
            "matched" -> MATCHED
            "flagged" -> FLAGGED
            "rejected" -> REJECTED
            "approved" -> APPROVED
            "declined" -> DECLINED
            else -> UNKNOWN
        }
    }
}

/**
 * Server guidance for a document type: which sides to capture, whether an MRZ is expected, and its format.
 * Mapped from [KycIdScannerValidationOutDto].
 */
data class ValidationInfo(
    val documentType: String,
    val sidesRequired: List<String>,
    val sidesPresent: List<String>,
    val hasMrz: Boolean,
    val mrzFormat: String?,
    val allSidesPresent: Boolean,
)

/** A concise summary of the extracted document fields for the result panel. */
data class ExtractionSummary(
    val documentNumber: String?,
    val surname: String?,
    val givenNames: String?,
    val nationality: String?,
    val expiryDate: String?,
)

/**
 * Domain result of ONE per-side scan. [reason] is derived (best-effort) from the expiry-check message, the
 * review note, or the cross-reference mismatch keys, so the UI can show a single human-facing explanation.
 */
data class ScanResult(
    val scanId: String,
    val side: IdSide,
    val status: ScanStatus,
    val mrzValid: Boolean,
    val reason: String?,
    val extraction: ExtractionSummary,
    val imageUrl: String?,
)

/** Maps the validation DTO to the domain [ValidationInfo]. */
fun KycIdScannerValidationOutDto.toDomain(): ValidationInfo = ValidationInfo(
    documentType = document_type,
    sidesRequired = sides_required,
    sidesPresent = sides_present,
    hasMrz = has_mrz,
    mrzFormat = mrz_format,
    allSidesPresent = all_sides_present,
)

/**
 * Maps the scan DTO to the domain [ScanResult]. [side] is the side the caller scanned (the wire echoes a
 * file_type, but the caller is the source of truth for which slot this result belongs to). Never throws; an
 * unrecognized status token becomes [ScanStatus.UNKNOWN].
 */
fun KycIdScannerScanOutDto.toDomain(side: IdSide): ScanResult = ScanResult(
    scanId = scan_id,
    side = side,
    status = ScanStatus.fromToken(status),
    mrzValid = mrz_valid,
    reason = deriveReason(),
    extraction = ExtractionSummary(
        documentNumber = extraction.document_number,
        surname = extraction.surname,
        givenNames = extraction.given_names,
        nationality = extraction.nationality,
        expiryDate = extraction.expiry_date,
    ),
    imageUrl = image_url,
)

/**
 * Best-effort human-facing reason: prefer an explicit review note, then a problematic expiry-check message,
 * then the set of mismatched cross-reference field keys. Returns null when there is nothing to surface.
 */
private fun KycIdScannerScanOutDto.deriveReason(): String? {
    review_note?.takeIf { it.isNotBlank() }?.let { return it }
    val expiryMessage = expiry_check.message.takeIf { it.isNotBlank() }
    val mismatchKeys = cross_reference?.mismatches?.keys.orEmpty()
    return when {
        mismatchKeys.isNotEmpty() -> {
            val joined = mismatchKeys.joinToString(", ")
            if (expiryMessage != null) "$expiryMessage ($joined)" else "Mismatched fields: $joined"
        }
        expiryMessage != null -> expiryMessage
        else -> null
    }
}
