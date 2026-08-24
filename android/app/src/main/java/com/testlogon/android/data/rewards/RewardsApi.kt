package com.testlogon.android.data.rewards

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import com.testlogon.android.core.network.json.LenientInt
import com.testlogon.android.core.network.json.LenientLong
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.POST
import retrofit2.http.Query

/**
 * Retrofit interface + Moshi DTOs for the REFERRALS + REWARDS surface, mirroring the web contract
 * EXACTLY (integer cents / integer points throughout). Paths are relative (no leading slash) so they
 * resolve against the shared authenticated Retrofit base URL; the session cookie + CSRF header are
 * attached by the core-network interceptor chain. All methods are suspend and return a typed DTO.
 *
 * READS ([referral], [referralList], [rewards], [rewardsHistory], [rewardsCatalog]) degrade on 404 in
 * the repository to an honest empty/unavailable state. The MUTATION ([redeem]) surfaces a rejection /
 * undeployed-404 as a clear error, never a silent success. Crediting is server-side; the client only
 * owns the surfaces + share + redeem.
 *
 * Every DTO is codegen-only Moshi with numerics made lenient ([LenientLong]/[LenientInt]) and every
 * field defaulted, so a partial or string-encoded-numeric shape still parses (see LenientNumberAdapters).
 */
interface RewardsApi {

    /** GET me/referral -> referral code/link + counts + reward totals. Read degrades on 404. */
    @GET("me/referral")
    suspend fun referral(): ReferralSummaryDto

    /** GET me/referral/list -> {referrals:[...]}. Read degrades on 404. */
    @GET("me/referral/list")
    suspend fun referralList(): ReferralListDto

    /** GET me/rewards -> points + cash balance + ways to earn. Read degrades on 404. */
    @GET("me/rewards")
    suspend fun rewards(): RewardsSummaryDto

    /** GET me/rewards/history -> {entries:[...]}. Read degrades on 404. */
    @GET("me/rewards/history")
    suspend fun rewardsHistory(): RewardsHistoryDto

    /** GET me/rewards/catalog -> {rewards:[...]}. Read degrades on 404. */
    @GET("me/rewards/catalog")
    suspend fun rewardsCatalog(): RewardsCatalogDto

    /** POST me/rewards/redeem {reward_id} -> {ok, points_remaining}. Mutation: errors surface. */
    @Headers("Content-Type: application/json")
    @POST("me/rewards/redeem")
    suspend fun redeem(@Body body: RedeemRequestDto): RedeemResultDto

    /**
     * GET me/referral/leaderboard?period=all|month -> top referrers + (optionally) the caller's own
     * out-of-slice rank. Read degrades on 404 to an honest coming-soon state.
     */
    @GET("me/referral/leaderboard")
    suspend fun referralLeaderboard(@Query("period") period: String): ReferralLeaderboardDto

    /**
     * OPTIONAL authoritative TRADING-REWARDS read: points accrued from executed trading volume. Points
     * accrue server-side; the client shows the earn rate + an estimate from the caller's own 30-day
     * volume and swaps to these numbers when the endpoint ships. Read degrades on 404 -> client estimate.
     */
    @GET("me/rewards/trading")
    suspend fun tradingRewards(): TradingRewardsDto
}

// ---- GET me/referral ----

@JsonClass(generateAdapter = true)
data class ReferralSummaryDto(
    @Json(name = "code") val code: String? = null,
    @Json(name = "link") val link: String? = null,
    @LenientInt @Json(name = "referred_count") val referredCount: Int? = null,
    @LenientInt @Json(name = "qualified_count") val qualifiedCount: Int? = null,
    @LenientLong @Json(name = "pending_reward_cents") val pendingRewardCents: Long? = null,
    @LenientLong @Json(name = "earned_reward_cents") val earnedRewardCents: Long? = null,
    @LenientLong @Json(name = "reward_per_referral_cents") val rewardPerReferralCents: Long? = null,
)

// ---- GET me/referral/list ----

@JsonClass(generateAdapter = true)
data class ReferralListDto(
    @Json(name = "referrals") val referrals: List<ReferralEntryDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class ReferralEntryDto(
    @Json(name = "id") val id: String? = null,
    @Json(name = "masked_name") val maskedName: String? = null,
    @LenientLong @Json(name = "joined_ts") val joinedTs: Long? = null,
    @Json(name = "status") val status: String? = null,
    @LenientLong @Json(name = "reward_cents") val rewardCents: Long? = null,
)

// ---- GET me/rewards ----

@JsonClass(generateAdapter = true)
data class RewardsSummaryDto(
    @LenientLong @Json(name = "points") val points: Long? = null,
    @LenientLong @Json(name = "cash_cents") val cashCents: Long? = null,
    @LenientLong @Json(name = "lifetime_points") val lifetimePoints: Long? = null,
    @Json(name = "ways_to_earn") val waysToEarn: List<WayToEarnDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class WayToEarnDto(
    @Json(name = "id") val id: String? = null,
    @Json(name = "title") val title: String? = null,
    @LenientLong @Json(name = "points") val points: Long? = null,
    @Json(name = "detail") val detail: String? = null,
)

// ---- GET me/rewards/trading (optional authoritative) ----

@JsonClass(generateAdapter = true)
data class TradingRewardsDto(
    @LenientLong @Json(name = "points_per_dollar") val pointsPerDollar: Long? = null,
    @LenientLong @Json(name = "volume_30d_cents") val volume30dCents: Long? = null,
    @LenientLong @Json(name = "points_earned_30d") val pointsEarned30d: Long? = null,
    @LenientLong @Json(name = "lifetime_trading_points") val lifetimeTradingPoints: Long? = null,
)

// ---- GET me/rewards/history ----

@JsonClass(generateAdapter = true)
data class RewardsHistoryDto(
    @Json(name = "entries") val entries: List<RewardsHistoryEntryDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class RewardsHistoryEntryDto(
    @LenientLong @Json(name = "ts") val ts: Long? = null,
    @Json(name = "type") val type: String? = null,
    @Json(name = "description") val description: String? = null,
    @LenientLong @Json(name = "points") val points: Long? = null,
    @LenientLong @Json(name = "cash_cents") val cashCents: Long? = null,
    @Json(name = "status") val status: String? = null,
)

// ---- GET me/rewards/catalog ----

@JsonClass(generateAdapter = true)
data class RewardsCatalogDto(
    @Json(name = "rewards") val rewards: List<CatalogRewardDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class CatalogRewardDto(
    @Json(name = "id") val id: String? = null,
    @Json(name = "name") val name: String? = null,
    @Json(name = "description") val description: String? = null,
    @LenientLong @Json(name = "cost_points") val costPoints: Long? = null,
    @LenientLong @Json(name = "value_cents") val valueCents: Long? = null,
    @Json(name = "kind") val kind: String? = null,
)

// ---- POST me/rewards/redeem ----

@JsonClass(generateAdapter = true)
data class RedeemRequestDto(
    @Json(name = "reward_id") val rewardId: String,
)

@JsonClass(generateAdapter = true)
data class RedeemResultDto(
    @Json(name = "ok") val ok: Boolean? = null,
    @LenientLong @Json(name = "points_remaining") val pointsRemaining: Long? = null,
    @Json(name = "detail") val detail: String? = null,
    @Json(name = "error") val error: String? = null,
)

// ---- GET me/referral/leaderboard ----

@JsonClass(generateAdapter = true)
data class ReferralLeaderboardDto(
    @Json(name = "period") val period: String? = null,
    @LenientLong @Json(name = "updated_ts") val updatedTs: Long? = null,
    @Json(name = "entries") val entries: List<ReferralLeaderboardEntryDto> = emptyList(),
    @Json(name = "you") val you: ReferralLeaderboardYouDto? = null,
)

@JsonClass(generateAdapter = true)
data class ReferralLeaderboardEntryDto(
    @LenientInt @Json(name = "rank") val rank: Int? = null,
    @Json(name = "id") val id: String? = null,
    @Json(name = "masked_name") val maskedName: String? = null,
    @Json(name = "is_you") val isYou: Boolean? = null,
    @LenientInt @Json(name = "referred_count") val referredCount: Int? = null,
    @LenientInt @Json(name = "qualified_count") val qualifiedCount: Int? = null,
    @LenientLong @Json(name = "reward_cents") val rewardCents: Long? = null,
)

@JsonClass(generateAdapter = true)
data class ReferralLeaderboardYouDto(
    @LenientInt @Json(name = "rank") val rank: Int? = null,
    @LenientInt @Json(name = "referred_count") val referredCount: Int? = null,
    @LenientInt @Json(name = "qualified_count") val qualifiedCount: Int? = null,
    @LenientLong @Json(name = "reward_cents") val rewardCents: Long? = null,
)
