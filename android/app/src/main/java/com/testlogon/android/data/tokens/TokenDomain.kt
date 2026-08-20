package com.testlogon.android.data.tokens

/**
 * CREATOR REVENUE-SHARE TOKEN domain models — render-ready shapes the feature layer consumes.
 *
 * A content-selling creator tokenizes their revenue share into a tradeable coin: minting holds 100%
 * of supply, sets a revenue-share % (`revenueShareBps`), and pays a $100 creation fee. Holders receive
 * pro-rata distributions of that % of the creator's ongoing content revenue. Amounts are integer CENTS.
 */
enum class TokenStatus { DRAFT, MINTED, LISTED, FROZEN, DELISTED, UNKNOWN }

data class Token(
    val tokenId: String,
    val symbolId: String? = null,
    val creatorSub: String? = null,
    val name: String,
    val ticker: String,
    val totalSupply: Long,
    val revenueShareBps: Int,
    val status: TokenStatus,
    val createdTs: Long = 0,
    val offeredPctBps: Int? = null,
    /** Cleared IPO price in cents-per-token, when the token has listed. */
    val clearingPrice: Long? = null,
)

/** One cap-table holder: a [sub], their [qty], and their ownership [pctBps]. */
data class TokenHolder(
    val sub: String,
    val qty: Long,
    val pctBps: Int,
)

data class TokenCapTable(
    val tokenId: String,
    val creatorPctBps: Int,
    val holders: List<TokenHolder>,
)

enum class AuctionStatus { OPEN, CLEARED, CANCELLED, UNKNOWN }

/** One sealed IPO bid. */
data class TokenBid(
    val sub: String,
    val qty: Long,
    val limitPrice: Long,
)

/**
 * The single-clearing-price IPO auction: sealed bids clear at ONE price, all fills at that price.
 * [clearingPrice]/[filledQty] are set once [status] is CLEARED.
 */
data class TokenAuction(
    val auctionId: String,
    val tokenId: String,
    val offeredPctBps: Int,
    val reservePrice: Long,
    val status: AuctionStatus,
    val clearingPrice: Long? = null,
    val filledQty: Long? = null,
    val closeTs: Long = 0,
    val bids: List<TokenBid> = emptyList(),
)

/** One pro-rata revenue distribution to holders. */
data class TokenDistribution(
    val ts: Long,
    val totalAmount: Long,
    val perTokenAmount: Long,
    val source: String,
)

data class TokenRevenue(
    val tokenId: String,
    val myQty: Long,
    val myPctBps: Int,
    val myClaimable: Long,
    val distributions: List<TokenDistribution>,
)

enum class UpkeepStatus { COVERED, DUE, PAID, DELINQUENT, FROZEN, UNKNOWN }

/**
 * Book-upkeep for the month: $100 kept the book tradeable, charged to holders PRO-RATA by holding as a
 * SHORTFALL top-up — `amountDue = max(0, $100 - feesGenerated)`; $0 when monthly fees >= $100.
 * Non-payment freezes the book (reversible on payment).
 */
data class TokenUpkeep(
    val tokenId: String,
    val month: String,
    val feesGenerated: Long,
    val threshold: Long,
    val amountDue: Long,
    val myShare: Long,
    val status: UpkeepStatus,
)

/** A simple mutation acknowledgement — [accepted] is false when the server didn't confirm. */
data class TokenAck(
    val accepted: Boolean,
    val message: String? = null,
)
