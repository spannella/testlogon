package com.testlogon.android.data.bailout

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import com.testlogon.android.core.network.json.LenientInt
import com.testlogon.android.core.network.json.LenientLong

/**
 * Wire DTOs for the MARGIN DISTRESS / PRE-EMPTIVE BAILOUT AUCTION surface (`me/margin/distress`,
 * `me/bailouts`, `me/positions/{id}/bailout`, `me/prefs/bailout`).
 *
 * NONE of these endpoints exist on the backend yet — every READ degrades to an empty-but-honest state
 * on 404/absence (the UI shows an honest "pending backend" state and NEVER fabricates distress), and
 * every failed MUTATION surfaces a clear error (never a silent success). All numeric fields are lenient
 * (the edge may stringify ids / cents / bps) and every field is defaulted so a partial / drifted
 * payload still parses. Amounts are integer CENTS; `Bps` are basis points.
 */
@JsonClass(generateAdapter = true)
data class DistressPositionDto(
    @LenientInt @Json(name = "symbol_id") val symbolId: Int? = null,
    @Json(name = "symbol") val symbol: String? = null,
    @Json(name = "side") val side: String? = null,
    @LenientLong @Json(name = "qty") val qty: Long? = null,
    @LenientLong @Json(name = "entry_price") val entryPrice: Long? = null,
    @LenientLong @Json(name = "mark_price") val markPrice: Long? = null,
    @LenientLong @Json(name = "liq_price") val liqPrice: Long? = null,
    @LenientLong @Json(name = "equity_cents") val equityCents: Long? = null,
    @LenientLong @Json(name = "maintenance_cents") val maintenanceCents: Long? = null,
    @LenientInt @Json(name = "buffer_bps") val bufferBps: Int? = null,
    @LenientInt @Json(name = "volatility_bps") val volatilityBps: Int? = null,
    @LenientInt @Json(name = "danger_bps") val dangerBps: Int? = null,
    @Json(name = "in_band") val inBand: Boolean? = null,
    @Json(name = "eligible") val eligible: Boolean? = null,
    @Json(name = "auction_id") val auctionId: String? = null,
)

/** `GET me/margin/distress` -> {positions:[DistressPosition]}. */
@JsonClass(generateAdapter = true)
data class DistressResponseDto(
    @Json(name = "positions") val positions: List<DistressPositionDto>? = null,
)

/** One rescuer row on an auction. */
@JsonClass(generateAdapter = true)
data class BailoutRescuerDto(
    @Json(name = "sub") val sub: String? = null,
    @LenientLong @Json(name = "capital_cents") val capitalCents: Long? = null,
    @LenientInt @Json(name = "share_bps") val shareBps: Int? = null,
)

/** `GET me/bailouts/{id}` / `GET me/positions/{id}/bailout` -> the bailout auction state. */
@JsonClass(generateAdapter = true)
data class BailoutAuctionDto(
    @Json(name = "auction_id") val auctionId: String? = null,
    @LenientInt @Json(name = "symbol_id") val symbolId: Int? = null,
    @Json(name = "owner_sub") val ownerSub: String? = null,
    @Json(name = "side") val side: String? = null,
    @LenientLong @Json(name = "qty") val qty: Long? = null,
    @LenientLong @Json(name = "capital_needed_cents") val capitalNeededCents: Long? = null,
    @LenientInt @Json(name = "max_share_bps") val maxShareBps: Int? = null,
    @Json(name = "status") val status: String? = null,
    @LenientInt @Json(name = "clearing_share_bps") val clearingShareBps: Int? = null,
    @LenientLong @Json(name = "raised_cents") val raisedCents: Long? = null,
    @Json(name = "rescuers") val rescuers: List<BailoutRescuerDto>? = null,
    @LenientLong @Json(name = "liq_price") val liqPrice: Long? = null,
    @LenientLong @Json(name = "mark_price") val markPrice: Long? = null,
    @LenientLong @Json(name = "close_ts") val closeTs: Long? = null,
)

/** `GET me/bailouts` -> {auctions:[BailoutAuction]} (the rescuer opportunity board). */
@JsonClass(generateAdapter = true)
data class BailoutListDto(
    @Json(name = "auctions") val auctions: List<BailoutAuctionDto>? = null,
)

/** `POST me/positions/{id}/bailout` body — open a pre-emptive bailout auction. */
@JsonClass(generateAdapter = true)
data class OpenBailoutRequestDto(
    @Json(name = "max_share_bps") val maxShareBps: Int,
    @Json(name = "close_ts") val closeTs: Long? = null,
)

/** `POST me/bailouts/{id}/bid` body — inject capital for a position-share. */
@JsonClass(generateAdapter = true)
data class BailoutBidRequestDto(
    @Json(name = "capital_cents") val capitalCents: Long,
    @Json(name = "share_bps") val shareBps: Int,
)

/** Generic mutation ack ({status:"ok"|"ack", ...}); parsed defensively. */
@JsonClass(generateAdapter = true)
data class BailoutAckDto(
    @Json(name = "status") val status: String? = null,
    @Json(name = "message") val message: String? = null,
)

/** `GET me/prefs/bailout` / `PUT me/prefs/bailout` -> the auto-bailout preference. */
@JsonClass(generateAdapter = true)
data class BailoutPrefsDto(
    @Json(name = "auto_enabled") val autoEnabled: Boolean? = null,
    @LenientInt @Json(name = "default_max_share_bps") val defaultMaxShareBps: Int? = null,
)
