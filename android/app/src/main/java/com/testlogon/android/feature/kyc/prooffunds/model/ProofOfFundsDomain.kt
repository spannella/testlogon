package com.testlogon.android.feature.kyc.prooffunds.model

import com.testlogon.android.core.model.kyc.ProofOfFundsSubmissionOutDto
import com.testlogon.android.core.model.kyc.ProofOfFundsSummaryDto
import java.time.Instant

/**
 * AND-327 - feature domain model + DTO mappers for the KYC proof-of-funds surface.
 *
 * The wire `source_category` / `status` tokens are mapped to lenient enums here (unknown token ->
 * [PoFSource.UNKNOWN] / [PoFStatus.UNKNOWN], never throws). The epoch-Long wire `created_at` becomes a
 * [java.time.Instant]. All DTO -> domain mapping happens BEFORE the typed ApiResult in the repository
 * (mirrors AND-320 .. AND-326).
 *
 * REAL REST: the optional supporting document is uploaded via the AND-129 presign->PUT pipeline (REUSED by
 * the repository) and only the returned S3 key rides the submission as [ProofOfFunds.documentS3Key]. NO
 * vendor / ML / CameraX SDK, NO flagged seam.
 */

/**
 * Lenient proof-of-funds source category (unknown token -> [UNKNOWN]). [token] is the wire value. This is a
 * CLIENT constant set (the backend enforces NO server enum); there is deliberately no "salary" / "other".
 */
enum class PoFSource(val token: String) {
    BANK_STATEMENT("bank_statement"),
    PAY_STUB("pay_stub"),
    SALE_OF_ASSET("sale_of_asset"),
    INVESTMENT("investment"),
    BUSINESS_INCOME("business_income"),
    INHERITANCE("inheritance"),
    GIFT("gift"),
    SAVINGS("savings"),
    UNKNOWN("unknown"),
    ;

    companion object {
        /** The eight user-selectable source categories (excludes [UNKNOWN], a decode-only fallback). */
        val selectable: List<PoFSource> = listOf(
            BANK_STATEMENT,
            PAY_STUB,
            SALE_OF_ASSET,
            INVESTMENT,
            BUSINESS_INCOME,
            INHERITANCE,
            GIFT,
            SAVINGS,
        )

        fun fromToken(token: String?): PoFSource =
            entries.firstOrNull { it.token == token?.lowercase() } ?: UNKNOWN
    }
}

/** Lenient proof-of-funds submission status (unknown token -> [UNKNOWN]). */
enum class PoFStatus {
    PENDING,
    VERIFIED,
    REJECTED,
    NEEDS_MORE_INFO,
    EXPIRED,
    UNKNOWN,
    ;

    /** True when the status invites the user to (re)submit additional evidence. */
    val invitesResubmit: Boolean
        get() = this == REJECTED || this == NEEDS_MORE_INFO || this == EXPIRED

    companion object {
        fun fromToken(token: String?): PoFStatus = when (token?.lowercase()) {
            "pending" -> PENDING
            "verified" -> VERIFIED
            "rejected" -> REJECTED
            "needs_more_info" -> NEEDS_MORE_INFO
            "expired" -> EXPIRED
            else -> UNKNOWN
        }
    }
}

/** Domain model of one proof-of-funds submission. */
data class ProofOfFunds(
    val submissionId: String,
    val status: PoFStatus,
    val source: PoFSource?,
    val declaredAmountCents: Long?,
    val currency: String?,
    val documentS3Key: String?,
    val note: String?,
    val reviewerNote: String?,
    val createdAt: Instant,
)

/** Domain model of the proof-of-funds summary. */
data class PoFSummary(
    val count: Int,
    val verifiedCount: Int,
    val activeRiskContribution: Double?,
    val verifiedAmountCents: Long?,
    val verifiedCategories: List<String>,
    val userSub: String?,
)

// ---- DTO -> domain mappers (never throw; unknown tokens -> UNKNOWN; epoch -> Instant) ----

fun ProofOfFundsSubmissionOutDto.toDomain(): ProofOfFunds = ProofOfFunds(
    submissionId = submission_id,
    status = PoFStatus.fromToken(status),
    // A null/absent source_category maps to null (not UNKNOWN) so the form starts unselected; an
    // unrecognized non-null token maps to UNKNOWN.
    source = source_category?.let { PoFSource.fromToken(it) },
    declaredAmountCents = declared_amount_cents,
    currency = currency,
    documentS3Key = document_s3_key,
    note = note,
    reviewerNote = reviewer_note,
    createdAt = Instant.ofEpochSecond(created_at),
)

fun ProofOfFundsSummaryDto.toDomain(): PoFSummary = PoFSummary(
    count = count,
    verifiedCount = verified_count,
    activeRiskContribution = active_risk_contribution,
    verifiedAmountCents = verified_amount_cents,
    verifiedCategories = verified_categories ?: emptyList(),
    userSub = user_sub,
)
