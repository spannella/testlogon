package com.testlogon.android.data.bailout

/**
 * DTO -> domain mappers for the MARGIN DISTRESS / PRE-EMPTIVE BAILOUT AUCTION surface. Every field is
 * defensively defaulted (the endpoints don't exist yet + the edge may drift), so a partial payload maps
 * to a sane, honest domain object rather than throwing. NOTHING here fabricates distress: absent
 * flags map to false, absent numbers to zero.
 */

private fun String?.toPositionSide(): PositionSide = when (this?.trim()?.lowercase()) {
    "long", "buy", "b" -> PositionSide.LONG
    "short", "sell", "s" -> PositionSide.SHORT
    else -> PositionSide.UNKNOWN
}

private fun String?.toBailoutStatus(): BailoutStatus = when (this?.trim()?.lowercase()) {
    "open" -> BailoutStatus.OPEN
    "cleared" -> BailoutStatus.CLEARED
    "cancelled", "canceled" -> BailoutStatus.CANCELLED
    "liquidated" -> BailoutStatus.LIQUIDATED
    else -> BailoutStatus.UNKNOWN
}

fun DistressPositionDto.toDomain(): DistressPosition = DistressPosition(
    symbolId = symbolId ?: 0,
    symbol = symbol.orEmpty(),
    side = side.toPositionSide(),
    qty = qty ?: 0L,
    entryPrice = entryPrice ?: 0L,
    markPrice = markPrice ?: 0L,
    liqPrice = liqPrice ?: 0L,
    equityCents = equityCents ?: 0L,
    maintenanceCents = maintenanceCents ?: 0L,
    bufferBps = bufferBps ?: 0,
    volatilityBps = volatilityBps ?: 0,
    dangerBps = dangerBps ?: 0,
    inBand = inBand ?: false,
    eligible = eligible ?: false,
    auctionId = auctionId?.takeIf { it.isNotBlank() },
)

fun DistressResponseDto.toDomain(): List<DistressPosition> =
    positions.orEmpty().map { it.toDomain() }.filter { it.symbolId != 0 || it.symbol.isNotBlank() }

fun BailoutRescuerDto.toDomain(): BailoutRescuer = BailoutRescuer(
    sub = sub.orEmpty(),
    capitalCents = capitalCents ?: 0L,
    shareBps = shareBps ?: 0,
)

fun BailoutAuctionDto.toDomain(fallbackId: String = ""): BailoutAuction = BailoutAuction(
    auctionId = auctionId?.takeIf { it.isNotBlank() } ?: fallbackId,
    symbolId = symbolId ?: 0,
    ownerSub = ownerSub.orEmpty(),
    side = side.toPositionSide(),
    qty = qty ?: 0L,
    capitalNeededCents = capitalNeededCents ?: 0L,
    maxShareBps = maxShareBps ?: 0,
    status = status.toBailoutStatus(),
    clearingShareBps = clearingShareBps,
    raisedCents = raisedCents,
    rescuers = rescuers.orEmpty().map { it.toDomain() },
    liqPrice = liqPrice ?: 0L,
    markPrice = markPrice ?: 0L,
    closeTs = closeTs ?: 0L,
)

fun BailoutListDto.toDomain(): List<BailoutAuction> =
    auctions.orEmpty().map { it.toDomain() }.filter { it.auctionId.isNotBlank() }

fun BailoutPrefsDto.toDomain(): BailoutPrefs = BailoutPrefs(
    autoEnabled = autoEnabled ?: false,
    defaultMaxShareBps = defaultMaxShareBps ?: 0,
)

/** An ack is accepted when the server returns a positive status token. */
fun BailoutAckDto.toDomain(): BailoutAck {
    val accepted = when (status?.trim()?.lowercase()) {
        "ok", "ack", "accepted", "queued", "success", "opened" -> true
        else -> false
    }
    return BailoutAck(accepted = accepted, message = message)
}
