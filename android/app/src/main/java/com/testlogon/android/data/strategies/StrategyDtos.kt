package com.testlogon.android.data.strategies

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import com.testlogon.android.core.network.json.LenientInt
import com.testlogon.android.core.network.json.LenientLong

/**
 * Wire DTOs for the USER-CREATED STRATEGIES / BASKETS (investable funds) surface (`me/strategies/(all)`).
 *
 * NONE of these endpoints exist on the backend yet — the repository degrades every GET to an
 * empty-but-honest state on 404/absence and surfaces a clear error on every failed mutation. All
 * numeric fields are lenient (the edge may stringify ids / cents / bps) and every field is defaulted
 * so a partial / drifted payload still parses. Amounts are integer CENTS; `Bps` are basis points.
 *
 * The model (mirrored EXACTLY from the web contract): a creator defines a STRATEGY = a basket of legs
 * (target weights in bps summing to 10000) following a simple rebalance rule, with a dual fee
 * (management fee on AUM + performance fee on profit above a high-water mark), a min investment, a
 * max AUM (capacity) and a redemption policy. It is a POOLED fund with NAV units: investors
 * subscribe/redeem at NAV and own units.
 */
@JsonClass(generateAdapter = true)
data class StrategyLegDto(
    @LenientInt @Json(name = "symbol_id") val symbolId: Int? = null,
    @LenientInt @Json(name = "weight_bps") val weightBps: Int? = null,
)

@JsonClass(generateAdapter = true)
data class RedemptionDto(
    @Json(name = "type") val type: String? = null,
    @LenientInt @Json(name = "notice_days") val noticeDays: Int? = null,
    @LenientInt @Json(name = "lockup_days") val lockupDays: Int? = null,
)

@JsonClass(generateAdapter = true)
data class StrategyDto(
    @Json(name = "strategy_id") val strategyId: String? = null,
    @Json(name = "creator_sub") val creatorSub: String? = null,
    @Json(name = "name") val name: String? = null,
    @Json(name = "description") val description: String? = null,
    @Json(name = "kind") val kind: String? = null,
    @Json(name = "status") val status: String? = null,
    @Json(name = "legs") val legs: List<StrategyLegDto>? = null,
    @Json(name = "rebalance") val rebalance: String? = null,
    @LenientInt @Json(name = "threshold_bps") val thresholdBps: Int? = null,
    @LenientLong @Json(name = "min_investment_cents") val minInvestmentCents: Long? = null,
    @LenientLong @Json(name = "max_aum_cents") val maxAumCents: Long? = null,
    @LenientInt @Json(name = "mgmt_fee_bps") val mgmtFeeBps: Int? = null,
    @LenientInt @Json(name = "perf_fee_bps") val perfFeeBps: Int? = null,
    @Json(name = "high_water_mark") val highWaterMark: Boolean? = null,
    @Json(name = "redemption") val redemption: RedemptionDto? = null,
    @LenientLong @Json(name = "created_ts") val createdTs: Long? = null,
    @LenientLong @Json(name = "nav_per_unit") val navPerUnit: Long? = null,
    @LenientLong @Json(name = "aum_cents") val aumCents: Long? = null,
    @LenientInt @Json(name = "investor_count") val investorCount: Int? = null,
    @LenientInt @Json(name = "inception_return_bps") val inceptionReturnBps: Int? = null,
)

/** `GET me/strategies` (mine) / `GET me/strategies/market` (browse published) -> {strategies:[Strategy]}. */
@JsonClass(generateAdapter = true)
data class StrategyListDto(
    @Json(name = "strategies") val strategies: List<StrategyDto>? = null,
)

/** `POST me/strategies` / `PUT me/strategies/{id}` body. */
@JsonClass(generateAdapter = true)
data class UpsertStrategyRequestDto(
    @Json(name = "name") val name: String,
    @Json(name = "description") val description: String,
    @Json(name = "kind") val kind: String,
    @Json(name = "legs") val legs: List<StrategyLegDto>,
    @Json(name = "rebalance") val rebalance: String,
    @Json(name = "threshold_bps") val thresholdBps: Int?,
    @Json(name = "min_investment_cents") val minInvestmentCents: Long,
    @Json(name = "max_aum_cents") val maxAumCents: Long,
    @Json(name = "mgmt_fee_bps") val mgmtFeeBps: Int,
    @Json(name = "perf_fee_bps") val perfFeeBps: Int,
    @Json(name = "high_water_mark") val highWaterMark: Boolean,
    @Json(name = "redemption") val redemption: RedemptionDto,
)

/** `GET me/strategies/{id}/nav` -> current NAV/unit + AUM + units outstanding. */
@JsonClass(generateAdapter = true)
data class StrategyNavDto(
    @Json(name = "strategy_id") val strategyId: String? = null,
    @LenientLong @Json(name = "nav_per_unit") val navPerUnit: Long? = null,
    @LenientLong @Json(name = "aum_cents") val aumCents: Long? = null,
    @LenientLong @Json(name = "units_outstanding") val unitsOutstanding: Long? = null,
    @LenientInt @Json(name = "inception_return_bps") val inceptionReturnBps: Int? = null,
)

/** One holding row on `GET me/strategies/{id}/holdings`. */
@JsonClass(generateAdapter = true)
data class StrategyHoldingDto(
    @LenientInt @Json(name = "symbol_id") val symbolId: Int? = null,
    @LenientInt @Json(name = "target_weight_bps") val targetWeightBps: Int? = null,
    @LenientInt @Json(name = "actual_weight_bps") val actualWeightBps: Int? = null,
    @LenientLong @Json(name = "value_cents") val valueCents: Long? = null,
)

@JsonClass(generateAdapter = true)
data class StrategyHoldingsDto(
    @Json(name = "strategy_id") val strategyId: String? = null,
    @Json(name = "holdings") val holdings: List<StrategyHoldingDto>? = null,
)

/** `POST me/strategies/{id}/invest` body — amount in integer cents. */
@JsonClass(generateAdapter = true)
data class InvestRequestDto(
    @Json(name = "amount_cents") val amountCents: Long,
)

/** `POST me/strategies/{id}/redeem` body — units to redeem. */
@JsonClass(generateAdapter = true)
data class RedeemRequestDto(
    @Json(name = "units") val units: Long,
)

/** `GET me/strategies/{id}/position` -> the caller's investor position (defaults zeroed). */
@JsonClass(generateAdapter = true)
data class InvestorPositionDto(
    @Json(name = "strategy_id") val strategyId: String? = null,
    @LenientLong @Json(name = "units") val units: Long? = null,
    @LenientLong @Json(name = "nav_per_unit") val navPerUnit: Long? = null,
    @LenientLong @Json(name = "invested_cents") val investedCents: Long? = null,
    @LenientLong @Json(name = "current_value_cents") val currentValueCents: Long? = null,
    @LenientLong @Json(name = "unrealized_pnl_cents") val unrealizedPnlCents: Long? = null,
    @LenientLong @Json(name = "fees_paid_cents") val feesPaidCents: Long? = null,
    @LenientLong @Json(name = "high_water_mark") val highWaterMark: Long? = null,
)

/** One fee accrual row on `GET me/strategies/{id}/fees`. */
@JsonClass(generateAdapter = true)
data class FeeAccrualDto(
    @LenientLong @Json(name = "ts") val ts: Long? = null,
    @Json(name = "type") val type: String? = null,
    @LenientLong @Json(name = "amount_cents") val amountCents: Long? = null,
)

@JsonClass(generateAdapter = true)
data class StrategyFeesDto(
    @Json(name = "strategy_id") val strategyId: String? = null,
    @LenientLong @Json(name = "mgmt_fees_accrued_cents") val mgmtFeesAccruedCents: Long? = null,
    @LenientLong @Json(name = "perf_fees_accrued_cents") val perfFeesAccruedCents: Long? = null,
    @LenientLong @Json(name = "high_water_mark") val highWaterMark: Long? = null,
    @Json(name = "accruals") val accruals: List<FeeAccrualDto>? = null,
)

/** Generic mutation ack ({status:"ok"|"ack", ...}); parsed defensively. */
@JsonClass(generateAdapter = true)
data class StrategyAckDto(
    @Json(name = "status") val status: String? = null,
    @Json(name = "message") val message: String? = null,
)
