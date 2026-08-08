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
