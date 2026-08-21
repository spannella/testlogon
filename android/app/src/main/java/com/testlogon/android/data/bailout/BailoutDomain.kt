package com.testlogon.android.data.bailout

/**
 * MARGIN DISTRESS / PRE-EMPTIVE BAILOUT AUCTION domain models — render-ready shapes the feature layer
 * consumes.
 *
 * A leveraged margin position approaching a margin call can open a PRE-EMPTIVE bailout auction to raise
 * rescue capital and avoid forced liquidation. The auction exists ONLY while the position is in a
 * volatility-scaled DISTRESS band but STILL SOLVENT (`equity > maintenance`); once equity <= maintenance
 * a bailout is impossible (that is liquidation). Rescuers inject capital for a POSITION-SHARE (they
 * co-own a slice of the position + its uPnL). The auction clears at a SINGLE clearing share (the least
 * total position-share the owner must give up to raise the capital needed). All amounts are integer
 * CENTS; `Bps` are basis points (10_000 bps == 100%). Server-authoritative — the client renders the
 * read and never fabricates distress.
 */

/** Which side the underlying margin position is. */
enum class PositionSide { LONG, SHORT, UNKNOWN }

/** The three health zones derived from the buffer vs the volatility-scaled danger line + solvency. */
enum class HealthZone { HEALTHY, DISTRESS, LIQUIDATION }

/**
 * One margin position projected with its distress read. [inBand] is the server's authoritative
 * "in the distress band AND solvent" flag; [eligible] is whether a pre-emptive bailout can be opened
 * right now. [auctionId] is set when an auction already exists for this position.
 */
data class DistressPosition(
    val symbolId: Int,
    val symbol: String,
    val side: PositionSide,
    val qty: Long,
    val entryPrice: Long,
    val markPrice: Long,
    val liqPrice: Long,
    val equityCents: Long,
    val maintenanceCents: Long,
    val bufferBps: Int,
    val volatilityBps: Int,
    val dangerBps: Int,
    val inBand: Boolean,
    val eligible: Boolean,
    val auctionId: String? = null,
)

enum class BailoutStatus { OPEN, CLEARED, CANCELLED, LIQUIDATED, UNKNOWN }

/** One rescuer's injected capital and the position-share they receive for it. */
data class BailoutRescuer(
    val sub: String,
    val capitalCents: Long,
    val shareBps: Int,
)

/**
 * A pre-emptive bailout auction over a distressed-but-solvent margin position. Rescuers bid capital for
 * a position-share; the auction clears at a SINGLE clearing share ([clearingShareBps]) — the least
 * total share given up to raise [capitalNeededCents]. If the mark hits [liqPrice] mid-auction the
 * position breaches maintenance, the auction auto-cancels ([BailoutStatus.LIQUIDATED]) and normal
 * liquidation proceeds.
 */
data class BailoutAuction(
    val auctionId: String,
    val symbolId: Int,
    val ownerSub: String,
    val side: PositionSide,
    val qty: Long,
    val capitalNeededCents: Long,
    val maxShareBps: Int,
    val status: BailoutStatus,
    val clearingShareBps: Int? = null,
    val raisedCents: Long? = null,
    val rescuers: List<BailoutRescuer> = emptyList(),
    val liqPrice: Long,
    val markPrice: Long,
    val closeTs: Long = 0,
)

/**
 * The account-level auto-bailout preference: when [autoEnabled] a bailout auction auto-opens on
 * band-entry (else the trader must open it manually), offering up to [defaultMaxShareBps] of the
 * position-share.
 */
data class BailoutPrefs(
    val autoEnabled: Boolean,
    val defaultMaxShareBps: Int,
)

/** A simple mutation acknowledgement — [accepted] is false when the server didn't confirm. */
data class BailoutAck(
    val accepted: Boolean,
    val message: String? = null,
)
