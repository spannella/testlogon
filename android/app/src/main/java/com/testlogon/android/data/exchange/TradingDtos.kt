package com.testlogon.android.data.exchange

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/** Order-entry request. Raw integer [price]/[qty]; [clordid] must be unique and <= 20 chars. */
@JsonClass(generateAdapter = true)
data class PlaceOrderDto(
    @Json(name = "symbolid") val symbolId: Int,
    val side: String,
    val price: Long,
    val qty: Long,
    val clordid: String,
    val market: Boolean? = null,
    val tif: String? = null,
    @Json(name = "post_only") val postOnly: Boolean? = null,
    val hidden: Boolean? = null,
    val aon: Boolean? = null,
    @Json(name = "display_qty") val displayQty: Long? = null,
    @Json(name = "min_qty") val minQty: Long? = null,
    @Json(name = "expiry_ns") val expiryNs: Long? = null,
)

/** Amend request. The engine requires `new_qty`; `new_price` is optional. */
@JsonClass(generateAdapter = true)
data class AmendOrderDto(
    @Json(name = "new_qty") val newQty: Long,
    @Json(name = "new_price") val newPrice: Long? = null,
)

/**
 * Unified order/cancel ack. `status` = "ack" | "nak"; `type` = new_order_ack | cancel_ack | ...
 * On nak the engine sends `detail`/`error`. `fills` carries any immediate fills on placement.
 */
@JsonClass(generateAdapter = true)
data class OrderAckDto(
    val status: String? = null,
    val type: String? = null,
    val clordid: String? = null,
    val orderid: Long? = null,
    val symbolid: Int? = null,
    val mpid: String? = null,
    @Json(name = "cancelled_qty") val cancelledQty: Long? = null,
    val fills: List<FillDto>? = null,
    val detail: String? = null,
    val error: String? = null,
    val note: String? = null,
    val reason: String? = null,
)

@JsonClass(generateAdapter = true)
data class FillDto(
    val price: Long? = null,
    val qty: Long? = null,
    @Json(name = "ts_ns") val tsNs: Long? = null,
    val side: String? = null,
    val aggressor: String? = null,
)

/** Margin account snapshot: cash wallet + reserved margin + single net position + liq state. */
@JsonClass(generateAdapter = true)
data class MarginAccountDto(
    @Json(name = "available_balance") val availableBalance: Long? = null,
    val balance: Long? = null,
    @Json(name = "reserved_margin") val reservedMargin: Long? = null,
    @Json(name = "num_positions") val numPositions: Int? = null,
    @Json(name = "pos_symbol_idx") val posSymbolIdx: Int? = null,
    @Json(name = "pos_qty") val posQty: Long? = null,
    @Json(name = "pos_entry_price") val posEntryPrice: Long? = null,
    @Json(name = "pos_liquidation_price") val posLiquidationPrice: Long? = null,
    @Json(name = "pos_unrealized_pnl") val posUnrealizedPnl: Long? = null,
    @Json(name = "distress_level") val distressLevel: Int? = null,
    @Json(name = "is_liquidating") val isLiquidating: Int? = null,
    @Json(name = "margin_mode") val marginMode: Int? = null,
    val mpid: String? = null,
    val status: String? = null,
    val type: String? = null,
)

/**
 * ADMIN margin-config request (POST /me/margin_config). All bps params + max position qty are int64.
 * initial/maintenance margin are the per-symbol collateral requirement in basis points; fees are the
 * per-fill maker/taker charge in bps; hourly_borrow_rate is the funding accrual; max_position_qty caps
 * the net position.
 */
@JsonClass(generateAdapter = true)
data class MarginConfigDto(
    @Json(name = "symbolid") val symbolId: Int,
    @Json(name = "initial_margin_bps") val initialMarginBps: Long,
    @Json(name = "maintenance_margin_bps") val maintenanceMarginBps: Long,
    @Json(name = "liquidation_fee_bps") val liquidationFeeBps: Long,
    @Json(name = "hourly_borrow_rate_bps") val hourlyBorrowRateBps: Long,
    @Json(name = "maker_fee_bps") val makerFeeBps: Long,
    @Json(name = "taker_fee_bps") val takerFeeBps: Long,
    @Json(name = "max_position_qty") val maxPositionQty: Long,
)

/** Margin-config ack. status = "ack" | "rejected"; result == 0 means applied. */
@JsonClass(generateAdapter = true)
data class MarginConfigAckDto(
    val status: String? = null,
    val type: String? = null,
    @Json(name = "symbolid") val symbolId: Int? = null,
    val result: Int? = null,
    val detail: String? = null,
    val error: String? = null,
    val note: String? = null,
)

/** Deposit request: raw integer [amount] of collateral to credit. */
@JsonClass(generateAdapter = true)
data class MarginDepositDto(val amount: Long)

/** Deposit ack: the resulting balances. */
@JsonClass(generateAdapter = true)
data class MarginDepositAckDto(
    val status: String? = null,
    val type: String? = null,
    @Json(name = "new_balance") val newBalance: Long? = null,
    @Json(name = "available_balance") val availableBalance: Long? = null,
    val result: Int? = null,
    val detail: String? = null,
    val error: String? = null,
)

/** Cancel-all ack. */
@JsonClass(generateAdapter = true)
data class BulkCancelAckDto(
    val status: String? = null,
    val type: String? = null,
    @Json(name = "cancelled_count") val cancelledCount: Int? = null,
)

/** Two-sided quote request (fields verified live: bid_price/ask_price/bid_qty/ask_qty). */
@JsonClass(generateAdapter = true)
data class QuoteDto(
    @Json(name = "symbolid") val symbolId: Int,
    @Json(name = "bid_price") val bidPrice: Long,
    @Json(name = "ask_price") val askPrice: Long,
    @Json(name = "bid_qty") val bidQty: Long,
    @Json(name = "ask_qty") val askQty: Long,
)

@JsonClass(generateAdapter = true)
data class QuoteAckDto(
    val status: String? = null,
    val type: String? = null,
    @Json(name = "quote_id") val quoteId: String? = null,
    @Json(name = "bid_orderid") val bidOrderId: Long? = null,
    @Json(name = "ask_orderid") val askOrderId: Long? = null,
    val fills: List<FillDto>? = null,
    @Json(name = "reasoncode") val reasonCode: Int? = null,
    val detail: String? = null,
    val error: String? = null,
    val note: String? = null,
)

/** Algo order. [algoType] = stop | stop_limit | stop_market | take_profit. */
@JsonClass(generateAdapter = true)
data class AlgoOrderDto(
    @Json(name = "algo_type") val algoType: String,
    @Json(name = "symbolid") val symbolId: Int,
    val side: String,
    val qty: Long,
    @Json(name = "stop_price") val stopPrice: Long? = null,
    @Json(name = "limit_price") val limitPrice: Long? = null,
)

@JsonClass(generateAdapter = true)
data class AlgoAckDto(
    val status: String? = null,
    val type: String? = null,
    @Json(name = "algo_id") val algoId: Long? = null,
    val clordid: String? = null,
    @Json(name = "reasoncode") val reasonCode: Int? = null,
    val detail: String? = null,
    val error: String? = null,
    val note: String? = null,
)

/** One-triggers-other (fields verified live: parent and child legs). */
@JsonClass(generateAdapter = true)
data class OtoOrderDto(
    @Json(name = "symbolid") val symbolId: Int,
    @Json(name = "parent_side") val parentSide: String,
    @Json(name = "parent_price") val parentPrice: Long,
    @Json(name = "parent_qty") val parentQty: Long,
    @Json(name = "child_side") val childSide: String,
    @Json(name = "child_price") val childPrice: Long,
    @Json(name = "child_qty") val childQty: Long,
)

@JsonClass(generateAdapter = true)
data class OtoAckDto(
    val status: String? = null,
    val type: String? = null,
    @Json(name = "oto_id") val otoId: Long? = null,
    @Json(name = "parent_orderid") val parentOrderId: Long? = null,
    @Json(name = "parent_clordid") val parentClordid: String? = null,
    @Json(name = "child_clordid") val childClordid: String? = null,
    val fills: List<FillDto>? = null,
    @Json(name = "reasoncode") val reasonCode: Int? = null,
    val detail: String? = null,
    val error: String? = null,
    val note: String? = null,
)

/** A triggered algo/OTO event (fields captured loosely; unknown keys ignored by Moshi). */
@JsonClass(generateAdapter = true)
data class TriggerDto(
    @Json(name = "algo_id") val algoId: Long? = null,
    @Json(name = "oto_id") val otoId: Long? = null,
    val clordid: String? = null,
    val orderid: Long? = null,
    val symbolid: Int? = null,
)

/** GET /me/algo/events drain: async fills + algo/oto triggers since the last drain. */
@JsonClass(generateAdapter = true)
data class ExecEventsDto(
    val fills: List<FillDto>? = null,
    val triggered: List<TriggerDto>? = null,
    @Json(name = "oto_triggered") val otoTriggered: List<TriggerDto>? = null,
)

// ==== Pre-staged advanced surfaces (behind TradingFeatures flags) ====
// The contracts below reflect what was observed live; align exact field names with the backend port.

/** One OCO leg. */
@JsonClass(generateAdapter = true)
data class OcoLegDto(val side: String, val price: Long, val qty: Long)

/** OCO request: two opposite-side legs (engine rejects same-side). */
@JsonClass(generateAdapter = true)
data class OcoOrderDto(
    @Json(name = "symbolid") val symbolId: Int,
    val legs: List<OcoLegDto>,
)

@JsonClass(generateAdapter = true)
data class OcoAckDto(
    val status: String? = null,
    val type: String? = null,
    @Json(name = "oco_id") val ocoId: Long? = null,
    @Json(name = "orderids") val orderIds: List<Long>? = null,
    val fills: List<FillDto>? = null,
    @Json(name = "reasoncode") val reasonCode: Int? = null,
    val note: String? = null,
    val detail: String? = null,
    val error: String? = null,
)

/** Funding (borrow/lend) request. Contract verified from the handler: rate_bps/qty/is_borrow/duration. */
@JsonClass(generateAdapter = true)
data class FundingOrderDto(
    @Json(name = "rate_bps") val rateBps: Long,
    val qty: Long,
    @Json(name = "is_borrow") val isBorrow: Boolean,
    @Json(name = "duration_seconds") val durationSeconds: Long? = null,
    @Json(name = "symbolid") val symbolId: Int? = null,
    val clordid: String? = null,
)

@JsonClass(generateAdapter = true)
data class FundingAckDto(
    val status: String? = null,
    val type: String? = null,
    val clordid: String? = null,
    @Json(name = "funding_id") val fundingId: Long? = null,
    val reason: Int? = null,
    @Json(name = "reasoncode") val reasonCode: Int? = null,
    val detail: String? = null,
    val error: String? = null,
    val note: String? = null,
)

/** One spot asset balance (shape captured loosely; unknown keys ignored). */
@JsonClass(generateAdapter = true)
data class SpotAssetDto(
    val asset: Int? = null,
    val symbol: String? = null,
    val balance: Long? = null,
    val available: Long? = null,
)

@JsonClass(generateAdapter = true)
data class SpotBalanceDto(
    val balances: List<SpotAssetDto>? = null,
    val mpid: String? = null,
)

/** Spot deposit request (asset is a numeric asset id per the handler). */
@JsonClass(generateAdapter = true)
data class SpotDepositDto(val asset: Int, val amount: Long)

@JsonClass(generateAdapter = true)
data class SpotDepositAckDto(
    val status: String? = null,
    val type: String? = null,
    val asset: Int? = null,
    @Json(name = "new_balance") val newBalance: Long? = null,
    @Json(name = "available_balance") val availableBalance: Long? = null,
    val detail: String? = null,
    val error: String? = null,
)

/** Binary prediction-market state (`GET /me/pm_state`). state = "trading" | "resolved". */
@JsonClass(generateAdapter = true)
data class PmStateDto(
    val symbolid: Int? = null,
    @Json(name = "is_binary") val isBinary: Boolean? = null,
    val state: String? = null,
    val outcome: Int? = null,
    @Json(name = "face_value") val faceValue: Long? = null,
    @Json(name = "resolve_ts") val resolveTs: Long? = null,
    @Json(name = "resolver_id") val resolverId: String? = null,
    val status: String? = null,
    val error: String? = null,
    val detail: String? = null,
)

// ==== Fees (custody-exchange-gaps) ====

/**
 * GET me/fees/schedule?symbolid=<n> (REAL). {status, type, symbolid, maker_fee_bps, taker_fee_bps,
 * liquidation_fee_bps, source, configured}. source is "engine" (a configured rate) or "venue_default";
 * configured tells whether this symbol has an explicit override. bps fields may be stringified by the
 * edge, so all use @LenientInt.
 */
@JsonClass(generateAdapter = true)
data class FeeScheduleDto(
    @Json(name = "status") val status: String? = null,
    @Json(name = "type") val type: String? = null,
    @com.testlogon.android.core.network.json.LenientInt @Json(name = "symbolid") val symbolId: Int? = null,
    @com.testlogon.android.core.network.json.LenientInt @Json(name = "maker_fee_bps") val makerFeeBps: Int? = null,
    @com.testlogon.android.core.network.json.LenientInt @Json(name = "taker_fee_bps") val takerFeeBps: Int? = null,
    @com.testlogon.android.core.network.json.LenientInt @Json(name = "liquidation_fee_bps") val liquidationFeeBps: Int? = null,
    @Json(name = "source") val source: String? = null,
    @Json(name = "configured") val configured: Boolean? = null,
)

/**
 * One enriched fill from GET me/fills/fees (REAL contract). [fee] is the engine-charged fee (not a
 * client estimate); [liquidity] is "maker"|"taker"; [ts] is a nanosecond timestamp. bps/int64 fields
 * may be stringified by the edge -> lenient.
 */
@JsonClass(generateAdapter = true)
data class FillFeeDto(
    @com.testlogon.android.core.network.json.LenientInt @Json(name = "symbolid") val symbolId: Int? = null,
    @com.testlogon.android.core.network.json.LenientLong @Json(name = "price") val price: Long? = null,
    @com.testlogon.android.core.network.json.LenientLong @Json(name = "qty") val qty: Long? = null,
    @Json(name = "side") val side: String? = null,
    @Json(name = "liquidity") val liquidity: String? = null,
    @com.testlogon.android.core.network.json.LenientLong @Json(name = "fee") val fee: Long? = null,
    @com.testlogon.android.core.network.json.LenientInt @Json(name = "fee_asset") val feeAsset: Int? = null,
    @com.testlogon.android.core.network.json.LenientLong @Json(name = "ts") val ts: Long? = null,
)

/**
 * GET me/fills/fees (REAL): {status, type:"fills", count, fills:[...]}. The [fills] carry the engine's
 * real per-fill [FillFeeDto.fee] + maker/taker liquidity -> the client no longer estimates the fee.
 */
@JsonClass(generateAdapter = true)
data class FillsFeesDto(
    @Json(name = "status") val status: String? = null,
    @Json(name = "type") val type: String? = null,
    @com.testlogon.android.core.network.json.LenientInt @Json(name = "count") val count: Int? = null,
    @Json(name = "fills") val fills: List<FillFeeDto>? = null,
)

// ==== Liquidations (me/liquidations) — REAL ====

/** One forced-liquidation event: symbol, qty closed, mark price, realized PnL (signed), fee, ts(ns). */
@JsonClass(generateAdapter = true)
data class LiquidationDto(
    @com.testlogon.android.core.network.json.LenientInt @Json(name = "symbolid") val symbolId: Int? = null,
    @com.testlogon.android.core.network.json.LenientLong @Json(name = "qty") val qty: Long? = null,
    @com.testlogon.android.core.network.json.LenientLong @Json(name = "mark_price") val markPrice: Long? = null,
    @com.testlogon.android.core.network.json.LenientLong @Json(name = "realized_pnl") val realizedPnl: Long? = null,
    @com.testlogon.android.core.network.json.LenientLong @Json(name = "fee") val fee: Long? = null,
    @com.testlogon.android.core.network.json.LenientLong @Json(name = "ts") val ts: Long? = null,
)

/** GET me/liquidations: {status, type:"liquidations", count, liquidations:[...]}. */
@JsonClass(generateAdapter = true)
data class LiquidationsDto(
    @Json(name = "status") val status: String? = null,
    @Json(name = "type") val type: String? = null,
    @com.testlogon.android.core.network.json.LenientInt @Json(name = "count") val count: Int? = null,
    @Json(name = "liquidations") val liquidations: List<LiquidationDto>? = null,
)

// ==== Funding payments (me/funding/payments) — REAL ====

/**
 * One perpetual funding payment. [payment] is SIGNED (negative = paid out, positive = received);
 * [received] mirrors the sign. [fundingRateBps] is the applied rate; [positionQty] the position charged.
 */
@JsonClass(generateAdapter = true)
data class FundingPaymentDto(
    @com.testlogon.android.core.network.json.LenientInt @Json(name = "symbolid") val symbolId: Int? = null,
    @com.testlogon.android.core.network.json.LenientInt @Json(name = "funding_rate_bps") val fundingRateBps: Int? = null,
    @com.testlogon.android.core.network.json.LenientLong @Json(name = "mark_price") val markPrice: Long? = null,
    @com.testlogon.android.core.network.json.LenientLong @Json(name = "position_qty") val positionQty: Long? = null,
    @com.testlogon.android.core.network.json.LenientLong @Json(name = "payment") val payment: Long? = null,
    @Json(name = "received") val received: Boolean? = null,
    @com.testlogon.android.core.network.json.LenientLong @Json(name = "ts") val ts: Long? = null,
)

/** GET me/funding/payments: {status, type:"funding", count, funding:[...]}. */
@JsonClass(generateAdapter = true)
data class FundingPaymentsDto(
    @Json(name = "status") val status: String? = null,
    @Json(name = "type") val type: String? = null,
    @com.testlogon.android.core.network.json.LenientInt @Json(name = "count") val count: Int? = null,
    @Json(name = "funding") val funding: List<FundingPaymentDto>? = null,
)

// ==== Admin engine-config (exchange-admin-config) — POST me/{matching_algo,spread_config,...} ====
// All six are admin-only and return the shared engine ack [EngineConfigAckDto] ({status, ...}).
// Not deployed to prod yet -> the repository degrades on 404 (see marginConfig-style handling).

/** POST me/matching_algo: set the per-symbol matching algorithm (0 = price-time; 1+ = pro-rata/specialist). */
@JsonClass(generateAdapter = true)
data class MatchingAlgoDto(
    @Json(name = "symbolid") val symbolId: Int,
    @Json(name = "algo") val algo: Int,
    @Json(name = "specialist_mpid") val specialistMpid: String? = null,
    @Json(name = "specialist_pct") val specialistPct: Int? = null,
)

/** POST me/spread_config: define a two-leg spread instrument (leg1/leg2 symbol ids + signed ratios). */
@JsonClass(generateAdapter = true)
data class SpreadConfigDto(
    @Json(name = "spread_symbolid") val spreadSymbolId: Int,
    @Json(name = "leg1") val leg1: Int,
    @Json(name = "leg2") val leg2: Int,
    @Json(name = "leg1_ratio") val leg1Ratio: Int? = null,
    @Json(name = "leg2_ratio") val leg2Ratio: Int? = null,
)

/** POST me/trading_params: per-symbol risk-limit / trading-parameter overrides (all optional but symbolid). */
@JsonClass(generateAdapter = true)
data class TradingParamsDto(
    @Json(name = "symbolid") val symbolId: Int,
    @Json(name = "max_qty") val maxQty: Int? = null,
    @Json(name = "max_notional") val maxNotional: Long? = null,
    @Json(name = "price_band_pct") val priceBandPct: Long? = null,
    @Json(name = "circuit_breaker_pct") val circuitBreakerPct: Long? = null,
    @Json(name = "min_block_size") val minBlockSize: Int? = null,
)

/** POST me/risk_config: an aggregate notional cap over a rolling window (optionally scoped to an mpid). */
@JsonClass(generateAdapter = true)
data class RiskConfigDto(
    @Json(name = "max_notional") val maxNotional: Long,
    @Json(name = "window_seconds") val windowSeconds: Int,
    @Json(name = "mpid") val mpid: String? = null,
)

/** POST me/spot_index: publish a spot index (mark) price for a symbol. */
@JsonClass(generateAdapter = true)
data class SpotIndexDto(
    @Json(name = "symbolid") val symbolId: Int,
    @Json(name = "spot_index_price") val spotIndexPrice: Long,
)

/** POST me/spot_config: bind a symbol to its base/quote asset ids (defines a spot pair). */
@JsonClass(generateAdapter = true)
data class SpotConfigDto(
    @Json(name = "symbolid") val symbolId: Int,
    @Json(name = "base_asset") val baseAsset: Int,
    @Json(name = "quote_asset") val quoteAsset: Int,
)

/**
 * Shared engine-config ack for the six admin routes. status = "ack" | "rejected"; result == 0 (when
 * present) means applied. detail/error/note carry any engine message. Tolerant: all fields optional.
 */
@JsonClass(generateAdapter = true)
data class EngineConfigAckDto(
    val status: String? = null,
    val type: String? = null,
    @Json(name = "symbolid") val symbolId: Int? = null,
    val result: Int? = null,
    val detail: String? = null,
    val error: String? = null,
    val note: String? = null,
)
