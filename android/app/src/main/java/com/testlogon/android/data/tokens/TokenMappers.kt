package com.testlogon.android.data.tokens

/**
 * DTO -> domain mappers for the CREATOR REVENUE-SHARE TOKEN surface. Every field is defensively
 * defaulted (the endpoints don't exist yet + the edge may drift), so a partial payload maps to a
 * sane, honest domain object rather than throwing.
 */

private fun String?.toTokenStatus(): TokenStatus = when (this?.trim()?.lowercase()) {
    "draft" -> TokenStatus.DRAFT
    "minted" -> TokenStatus.MINTED
    "listed" -> TokenStatus.LISTED
    "frozen" -> TokenStatus.FROZEN
    "delisted" -> TokenStatus.DELISTED
    else -> TokenStatus.UNKNOWN
}

private fun String?.toAuctionStatus(): AuctionStatus = when (this?.trim()?.lowercase()) {
    "open" -> AuctionStatus.OPEN
    "cleared" -> AuctionStatus.CLEARED
    "cancelled", "canceled" -> AuctionStatus.CANCELLED
    else -> AuctionStatus.UNKNOWN
}

private fun String?.toUpkeepStatus(): UpkeepStatus = when (this?.trim()?.lowercase()) {
    "covered" -> UpkeepStatus.COVERED
    "due" -> UpkeepStatus.DUE
    "paid" -> UpkeepStatus.PAID
    "delinquent" -> UpkeepStatus.DELINQUENT
    "frozen" -> UpkeepStatus.FROZEN
    else -> UpkeepStatus.UNKNOWN
}

fun TokenDto.toDomain(): Token = Token(
    tokenId = tokenId.orEmpty(),
    symbolId = symbolId,
    creatorSub = creatorSub,
    name = name.orEmpty(),
    ticker = ticker.orEmpty(),
    totalSupply = totalSupply ?: 0L,
    revenueShareBps = revenueShareBps ?: 0,
    status = status.toTokenStatus(),
    createdTs = createdTs ?: 0L,
    offeredPctBps = offeredPctBps,
    clearingPrice = clearingPrice,
)

fun TokenListDto.toDomain(): List<Token> =
    tokens.orEmpty().map { it.toDomain() }.filter { it.tokenId.isNotBlank() }

fun TokenHolderDto.toDomain(): TokenHolder = TokenHolder(
    sub = sub.orEmpty(),
    qty = qty ?: 0L,
    pctBps = pctBps ?: 0,
)

fun TokenCapTableDto.toDomain(fallbackId: String): TokenCapTable = TokenCapTable(
    tokenId = tokenId ?: fallbackId,
    creatorPctBps = creatorPctBps ?: 0,
    holders = holders.orEmpty().map { it.toDomain() },
)

fun TokenBidDto.toDomain(): TokenBid = TokenBid(
    sub = sub.orEmpty(),
    qty = qty ?: 0L,
    limitPrice = limitPrice ?: 0L,
)

fun TokenAuctionDto.toDomain(fallbackId: String): TokenAuction = TokenAuction(
    auctionId = auctionId.orEmpty(),
    tokenId = tokenId ?: fallbackId,
    offeredPctBps = offeredPctBps ?: 0,
    reservePrice = reservePrice ?: 0L,
    status = status.toAuctionStatus(),
    clearingPrice = clearingPrice,
    filledQty = filledQty,
    closeTs = closeTs ?: 0L,
    bids = bids.orEmpty().map { it.toDomain() },
)

/** Map the open-auctions feed; each row falls back to its own token_id when present, else blank. */
fun TokenAuctionListDto.toDomain(): List<TokenAuction> =
    auctions.orEmpty().map { it.toDomain(it.tokenId.orEmpty()) }

fun TokenDistributionDto.toDomain(): TokenDistribution = TokenDistribution(
    ts = ts ?: 0L,
    totalAmount = totalAmount ?: 0L,
    perTokenAmount = perTokenAmount ?: 0L,
    source = source.orEmpty(),
)

fun TokenRevenueDto.toDomain(fallbackId: String): TokenRevenue = TokenRevenue(
    tokenId = tokenId ?: fallbackId,
    myQty = myQty ?: 0L,
    myPctBps = myPctBps ?: 0,
    myClaimable = myClaimable ?: 0L,
    distributions = distributions.orEmpty().map { it.toDomain() },
)

fun TokenUpkeepDto.toDomain(fallbackId: String): TokenUpkeep = TokenUpkeep(
    tokenId = tokenId ?: fallbackId,
    month = month.orEmpty(),
    feesGenerated = feesGenerated ?: 0L,
    threshold = threshold ?: 0L,
    amountDue = amountDue ?: 0L,
    myShare = myShare ?: 0L,
    status = status.toUpkeepStatus(),
)

/** An ack is accepted when the server returns a positive status token (ok/ack/accepted/paid/queued). */
fun TokenAckDto.toDomain(): TokenAck {
    val accepted = when (status?.trim()?.lowercase()) {
        "ok", "ack", "accepted", "paid", "queued", "success" -> true
        else -> false
    }
    return TokenAck(accepted = accepted, message = message)
}
