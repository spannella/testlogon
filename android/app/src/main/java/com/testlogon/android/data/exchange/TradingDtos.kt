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
