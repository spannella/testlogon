package com.testlogon.android.feature.kyc.capture.model

import com.testlogon.android.core.model.kyc.KycDocumentOutDto
import java.time.Instant

/**
 * AND-321 - domain model for an uploaded KYC identity document.
 *
 * Mapped from [KycDocumentOutDto] BEFORE the typed ApiResult (mirrors AND-320's repo idiom). The wire's
 * epoch-second Longs become [Instant]s here; the wire's free-form status string becomes the lenient
 * [KycDocumentStatus] enum (unrecognized tokens fall back to [KycDocumentStatus.UNKNOWN], never throws).
 */
data class KycDocument(
    val documentId: String,
    val documentType: String,
    val fileName: String,
    val status: KycDocumentStatus,
    val imageUrl: String? = null,
    val caseId: String? = null,
    val createdAt: Instant,
    val updatedAt: Instant,
)

/** Lifecycle status of an uploaded document (lenient: unknown token -> [UNKNOWN]). */
enum class KycDocumentStatus(val token: String) {
    PENDING("pending"),
    EXTRACTED("extracted"),
    FAILED("failed"),
    APPROVED("approved"),
    REJECTED("rejected"),
    UNKNOWN("unknown"),
    ;

    companion object {
        fun fromToken(t: String?): KycDocumentStatus = entries.firstOrNull { it.token == t } ?: UNKNOWN
    }
}

/** Maps the transport DTO to the domain model (epoch seconds -> Instant; status token -> enum). */
fun KycDocumentOutDto.toDomain(): KycDocument = KycDocument(
    documentId = document_id,
    documentType = document_type,
    fileName = file_name,
    status = KycDocumentStatus.fromToken(status),
    imageUrl = image_url,
    caseId = case_id,
    createdAt = Instant.ofEpochSecond(created_at),
    updatedAt = Instant.ofEpochSecond(updated_at),
)
