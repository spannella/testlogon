package com.testlogon.android.data.referrals

/**
 * AND-264 — framework-free referral domain models + total DTO -> domain mappers.
 *
 * Money is integer cents (the backend's `*_cents`). The shareable link is derived client-side from a
 * code (NOT read from the wire). Link building uses java.net.URI / plain String only (no android.net.Uri)
 * so this stays JVM-unit-testable. Mapping is TOTAL: absent optionals default per the schema.
 */

/** Aggregate of the referral dashboard: stats + the user's codes. */
data class ReferralDashboard(
    val stats: ReferralStats,
    val codes: List<ReferralCode>,
) {
    /** FR-6: "no program / nothing to share" is represented by an empty referral_codes[]. */
    val isIneligible: Boolean get() = codes.isEmpty()
}

data class ReferralStats(
    val totalReferrals: Int,
    val confirmedReferrals: Int,
    val pendingReferrals: Int,
    val totalEarnedCents: Long,
    val pendingCommissionCents: Long,
    val paidCommissionCents: Long,
    val availableForWithdrawalCents: Long,
)

data class ReferralCode(
    val code: String,
    val active: Boolean,
    val commissionTier: String,
    val referralCount: Int,
    val createdAt: String,
) {
    /**
     * Client-constructed share link: <webOrigin>/?ref=<code> (FR-2). Mirrors the web's
     * `${window.location.origin}/?ref=${code}`. Pure String build (no android.net.Uri) so it is
     * JVM-testable; [webOrigin] must be the PUBLIC web origin, not the dev API host.
     */
    fun shareLink(webOrigin: String): String = "${webOrigin.trimEnd('/')}/?ref=$code"
}

// ---- Mappers (DTO -> domain) ----

internal fun ReferralDashboardDto.toDomain(): ReferralDashboard = ReferralDashboard(
    stats = ReferralStats(
        totalReferrals = totalReferrals,
        confirmedReferrals = confirmedReferrals,
        pendingReferrals = pendingReferrals,
        totalEarnedCents = totalEarnedCents,
        pendingCommissionCents = pendingCommissionCents,
        paidCommissionCents = paidCommissionCents,
        availableForWithdrawalCents = availableForWithdrawalCents,
    ),
    codes = referralCodes.map { it.toDomain() },
)

internal fun ReferralCodeDto.toDomain(): ReferralCode = ReferralCode(
    code = code,
    active = active,
    commissionTier = commissionTier,
    referralCount = referralCount,
    createdAt = createdAt,
)

internal fun ReferralCodeCreateRespDto.toDomain(): ReferralCode = ReferralCode(
    code = code,
    active = true,
    commissionTier = commissionTier,
    referralCount = 0,
    createdAt = createdAt,
)
