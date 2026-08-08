package com.testlogon.android.data.exchange

/** Order side for trader-submitted orders. */
enum class OrderSide(val wire: String) {
    BUY("buy"),
    SELL("sell"),
}

/** An immediate fill on an order. */
data class Fill(
    val price: Long,
    val qty: Long,
    val tsNs: Long,
    val side: OrderSide?,
)

/** Result of a place/amend order. [accepted] reflects status == "ack". */
data class OrderAck(
    val accepted: Boolean,
    val clordid: String,
    val orderId: Long?,
    val symbolId: Int?,
    val fills: List<Fill>,
    val message: String?,
)

/** Result of a cancel. */
data class CancelAck(
    val accepted: Boolean,
    val clordid: String,
    val cancelledQty: Long,
    val message: String?,
)

/** A net position within the margin account (single position per account today). */
data class PositionSnapshot(
    val symbolId: Int,
    val qty: Long,
    val entryPrice: Long,
    val liquidationPrice: Long,
    val unrealizedPnl: Long,
) {
    val side: OrderSide? get() = when {
        qty > 0 -> OrderSide.BUY
        qty < 0 -> OrderSide.SELL
        else -> null
    }
}

/** Margin account snapshot: cash wallet, reserved margin, position, and risk/liq state. */
data class MarginAccount(
    val balance: Long,
    val availableBalance: Long,
    val reservedMargin: Long,
    val numPositions: Int,
    val position: PositionSnapshot?,
    val distressLevel: Int,
    val isLiquidating: Boolean,
    val mpid: String,
) {
    /** Fraction of balance currently locked as margin (0..1), or 0 when there's no balance. */
    val marginUsedFraction: Float
        get() = if (balance > 0) (reservedMargin.toFloat() / balance.toFloat()).coerceIn(0f, 1f) else 0f
}

// ---- mappers ----

private fun sideOf(s: String?): OrderSide? = when (s?.lowercase()) {
    "buy" -> OrderSide.BUY
    "sell" -> OrderSide.SELL
    else -> null
}

fun FillDto.toDomain(): Fill = Fill(
    price = price ?: 0L,
    qty = qty ?: 0L,
    tsNs = tsNs ?: 0L,
    side = sideOf(side ?: aggressor),
)

fun OrderAckDto.toOrderAck(fallbackClordid: String): OrderAck = OrderAck(
    accepted = status == "ack",
    clordid = clordid ?: fallbackClordid,
    orderId = orderid,
    symbolId = symbolid,
    fills = fills.orEmpty().map { it.toDomain() },
    message = detail ?: error ?: note ?: reason,
)

fun OrderAckDto.toCancelAck(fallbackClordid: String): CancelAck = CancelAck(
    accepted = status == "ack",
    clordid = clordid ?: fallbackClordid,
    cancelledQty = cancelledQty ?: 0L,
    message = detail ?: error,
)

fun MarginAccountDto.toDomain(): MarginAccount {
    val posQtyVal = posQty ?: 0L
    val position = if ((numPositions ?: 0) > 0 || posQtyVal != 0L) {
        PositionSnapshot(
            symbolId = posSymbolIdx ?: 0,
            qty = posQtyVal,
            entryPrice = posEntryPrice ?: 0L,
            liquidationPrice = posLiquidationPrice ?: 0L,
            unrealizedPnl = posUnrealizedPnl ?: 0L,
        )
    } else {
        null
    }
    return MarginAccount(
        balance = balance ?: 0L,
        availableBalance = availableBalance ?: 0L,
        reservedMargin = reservedMargin ?: 0L,
        numPositions = numPositions ?: 0,
        position = position,
        distressLevel = distressLevel ?: 0,
        isLiquidating = (isLiquidating ?: 0) != 0,
        mpid = mpid.orEmpty(),
    )
}

/** Result of a collateral deposit. */
data class DepositAck(
    val accepted: Boolean,
    val newBalance: Long,
    val availableBalance: Long,
    val message: String?,
)

fun MarginDepositAckDto.toDomain(): DepositAck = DepositAck(
    accepted = status == "ack",
    newBalance = newBalance ?: 0L,
    availableBalance = availableBalance ?: 0L,
    message = detail ?: error,
)
