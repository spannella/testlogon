package com.testlogon.android.data.referrals

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.GET
import retrofit2.http.POST

/**
 * AND-264 — Retrofit interface + Moshi DTOs for the real referral surface.
 *
 * Verified against reference/openapi.index.txt (lines 1783..1789) and
 * reference/src/api/endpoints/referrals.ts + src/api/types.ts (the OpenAPI 200 bodies are untyped
 * `schema: {}`, so the frontend TypeScript types are the authoritative shape). The screen's hard
 * acceptance ("referral link + stats render") is satisfied by getDashboard() alone; create-code is
 * included for the empty-state CTA (web parity). Money is uniformly integer cents.
 *
 * Endpoint citations (reference/openapi.index.txt):
 *  - GET  ui/referrals/dashboard  L1788 (stats + referral_codes[]) — primary screen call
 *  - POST ui/referrals/code       L1784 (201 -> {code, link, commission_tier, created_at})
 *
 * Session cookies, Authorization Bearer and X-CSRF-Token are attached by core-network interceptors;
 * the operator-only user_sub / X-SESSION-ID / X-IMPERSONATION-TOKEN params are deliberately NOT sent.
 * The shareable link is CLIENT-constructed as <webOrigin>/?ref=<code>; the dashboard has no top-level
 * `link` (verified ReferralDashboard.tsx copyLink()).
 */
interface ReferralsApi {

    /** Referral dashboard: stats + the user's referral_codes[]. */
    @GET("ui/referrals/dashboard")
    suspend fun getDashboard(): ReferralDashboardDto

    /** Creates a new referral code (201). The only payload carrying a server-side `link`. */
    @POST("ui/referrals/code")
    suspend fun createCode(): ReferralCodeCreateRespDto
}

// ---- DTOs (AND-264) ----

@JsonClass(generateAdapter = true)
data class ReferralDashboardDto(
    @Json(name = "total_referrals") val totalReferrals: Int = 0,
    @Json(name = "confirmed_referrals") val confirmedReferrals: Int = 0,
    @Json(name = "pending_referrals") val pendingReferrals: Int = 0,
    @Json(name = "total_earned_cents") val totalEarnedCents: Long = 0,
    @Json(name = "pending_commission_cents") val pendingCommissionCents: Long = 0,
    @Json(name = "paid_commission_cents") val paidCommissionCents: Long = 0,
    @Json(name = "available_for_withdrawal_cents") val availableForWithdrawalCents: Long = 0,
    @Json(name = "referral_codes") val referralCodes: List<ReferralCodeDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class ReferralCodeDto(
    val code: String,
    val active: Boolean = true,
    @Json(name = "commission_tier") val commissionTier: String = "",
    // optional in the web type; null/absent -> 0
    @Json(name = "referral_count") val referralCount: Int = 0,
    @Json(name = "created_at") val createdAt: String = "",
)

@JsonClass(generateAdapter = true)
data class ReferralCodeCreateRespDto(
    val code: String,
    val link: String = "",
    @Json(name = "commission_tier") val commissionTier: String = "",
    @Json(name = "created_at") val createdAt: String = "",
)
