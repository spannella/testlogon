package com.testlogon.android.data.tokens

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import com.testlogon.android.core.network.json.LenientInt
import com.testlogon.android.core.network.json.LenientLong

/**
 * Wire DTOs for the CREATOR REVENUE-SHARE TOKEN surface (`me/tokens/(all)`).
 *
 * NONE of these endpoints exist on the backend yet — the repository degrades every GET to an
 * empty-but-honest state on 404/absence and surfaces a clear error on every failed mutation. All
 * numeric fields are lenient (the edge may stringify ids / cents / bps) and every field is defaulted
 * so a partial / drifted payload still parses. Amounts are integer CENTS; `Bps` are basis points.
 */
@JsonClass(generateAdapter = true)
data class TokenDto(
    @Json(name = "token_id") val tokenId: String? = null,
    @Json(name = "symbol_id") val symbolId: String? = null,
    @Json(name = "creator_sub") val creatorSub: String? = null,
    @Json(name = "name") val name: String? = null,
    @Json(name = "ticker") val ticker: String? = null,
    @LenientLong @Json(name = "total_supply") val totalSupply: Long? = null,
    @LenientInt @Json(name = "revenue_share_bps") val revenueShareBps: Int? = null,
    @Json(name = "status") val status: String? = null,
    @LenientLong @Json(name = "created_ts") val createdTs: Long? = null,
    @LenientInt @Json(name = "offered_pct_bps") val offeredPctBps: Int? = null,
    @LenientLong @Json(name = "clearing_price") val clearingPrice: Long? = null,
)

/** `GET me/tokens` (issued) / `GET me/tokens/market` (browse listed) -> {tokens:[Token]}. */
@JsonClass(generateAdapter = true)
data class TokenListDto(
    @Json(name = "tokens") val tokens: List<TokenDto>? = null,
)

/** `POST me/tokens` body — server charges the $100 creation fee. */
@JsonClass(generateAdapter = true)
data class MintTokenRequestDto(
    @Json(name = "name") val name: String,
    @Json(name = "ticker") val ticker: String,
    @Json(name = "total_supply") val totalSupply: Long,
    @Json(name = "revenue_share_bps") val revenueShareBps: Int,
)

/** One cap-table holder row. */
@JsonClass(generateAdapter = true)
data class TokenHolderDto(
    @Json(name = "sub") val sub: String? = null,
    @LenientLong @Json(name = "qty") val qty: Long? = null,
    @LenientInt @Json(name = "pct_bps") val pctBps: Int? = null,
)

/** `GET me/tokens/{id}/captable` -> {token_id, creator_pct_bps, holders:[...]}. */
@JsonClass(generateAdapter = true)
data class TokenCapTableDto(
    @Json(name = "token_id") val tokenId: String? = null,
    @LenientInt @Json(name = "creator_pct_bps") val creatorPctBps: Int? = null,
    @Json(name = "holders") val holders: List<TokenHolderDto>? = null,
)

/** `POST me/tokens/{id}/list` body — list N% via a single-clearing-price IPO auction. */
@JsonClass(generateAdapter = true)
data class ListTokenRequestDto(
    @Json(name = "offered_pct_bps") val offeredPctBps: Int,
    @Json(name = "reserve_price") val reservePrice: Long,
    @Json(name = "close_ts") val closeTs: Long,
)

/** One sealed IPO bid. */
@JsonClass(generateAdapter = true)
data class TokenBidDto(
    @Json(name = "sub") val sub: String? = null,
    @LenientLong @Json(name = "qty") val qty: Long? = null,
    @LenientLong @Json(name = "limit_price") val limitPrice: Long? = null,
)

/** `GET me/tokens/{id}/auction` -> the IPO auction state (open|cleared|cancelled). */
@JsonClass(generateAdapter = true)
data class TokenAuctionDto(
    @Json(name = "auction_id") val auctionId: String? = null,
    @Json(name = "token_id") val tokenId: String? = null,
    @LenientInt @Json(name = "offered_pct_bps") val offeredPctBps: Int? = null,
    @LenientLong @Json(name = "reserve_price") val reservePrice: Long? = null,
    @Json(name = "status") val status: String? = null,
    @LenientLong @Json(name = "clearing_price") val clearingPrice: Long? = null,
    @LenientLong @Json(name = "filled_qty") val filledQty: Long? = null,
    @LenientLong @Json(name = "close_ts") val closeTs: Long? = null,
    @Json(name = "bids") val bids: List<TokenBidDto>? = null,
)

/** `GET me/tokens/auctions` -> the open IPO auctions feed. Optional endpoint (degrade-on-404). */
@JsonClass(generateAdapter = true)
data class TokenAuctionListDto(
    @Json(name = "auctions") val auctions: List<TokenAuctionDto>? = null,
)

/** `POST me/tokens/{id}/auction/bid` body. */
@JsonClass(generateAdapter = true)
data class PlaceBidRequestDto(
    @Json(name = "qty") val qty: Long,
    @Json(name = "limit_price") val limitPrice: Long,
)

/** One revenue distribution row. */
@JsonClass(generateAdapter = true)
data class TokenDistributionDto(
    @LenientLong @Json(name = "ts") val ts: Long? = null,
    @LenientLong @Json(name = "total_amount") val totalAmount: Long? = null,
    @LenientLong @Json(name = "per_token_amount") val perTokenAmount: Long? = null,
    @Json(name = "source") val source: String? = null,
)

/** `GET me/tokens/{id}/revenue` -> my pro-rata claim + the distribution history. */
@JsonClass(generateAdapter = true)
data class TokenRevenueDto(
    @Json(name = "token_id") val tokenId: String? = null,
    @LenientLong @Json(name = "my_qty") val myQty: Long? = null,
    @LenientInt @Json(name = "my_pct_bps") val myPctBps: Int? = null,
    @LenientLong @Json(name = "my_claimable") val myClaimable: Long? = null,
    @Json(name = "distributions") val distributions: List<TokenDistributionDto>? = null,
)

/** `GET me/tokens/{id}/upkeep` -> the $100/month book-upkeep shortfall state. */
@JsonClass(generateAdapter = true)
data class TokenUpkeepDto(
    @Json(name = "token_id") val tokenId: String? = null,
    @Json(name = "month") val month: String? = null,
    @LenientLong @Json(name = "fees_generated") val feesGenerated: Long? = null,
    @LenientLong @Json(name = "threshold") val threshold: Long? = null,
    @LenientLong @Json(name = "amount_due") val amountDue: Long? = null,
    @LenientLong @Json(name = "my_share") val myShare: Long? = null,
    @Json(name = "status") val status: String? = null,
)

/** Generic mutation ack ({status:"ok"|"ack", ...}); parsed defensively. */
@JsonClass(generateAdapter = true)
data class TokenAckDto(
    @Json(name = "status") val status: String? = null,
    @Json(name = "message") val message: String? = null,
)
