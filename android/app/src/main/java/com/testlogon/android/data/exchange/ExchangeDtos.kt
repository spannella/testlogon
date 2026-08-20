package com.testlogon.android.data.exchange

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/**
 * Markets (exchange market-data, VIEW-ONLY) transport DTOs for the `md/ (market-data)` endpoints.
 *
 * Prices/quantities are integers on the wire; divide by [SymbolDto.priceScaler] for display (all
 * scalers are 1 today). Every field has a default so a partial/new-endpoint payload never fails to
 * decode. Symbols are addressed by the numeric [SymbolDto.symbolId] (1=BTCUSDC, 2=ETHUSDC, 3=SOLUSDC).
 */
@JsonClass(generateAdapter = true)
data class SymbolsResponseDto(
    val symbols: List<SymbolDto> = emptyList(),
    val count: Int = 0,
)

@JsonClass(generateAdapter = true)
data class SymbolDto(
    val symbol: String = "",
    @Json(name = "symbol_id") val symbolId: Int = 0,
    @Json(name = "instrument_id") val instrumentId: Long = 0,
    @Json(name = "price_scaler") val priceScaler: Long = 1,
    @Json(name = "lot_size") val lotSize: Long = 1,
    @Json(name = "reference_price") val referencePrice: Long = 0,
    @Json(name = "matching_algo") val matchingAlgo: String = "",
    @Json(name = "is_perpetual") val isPerpetual: Boolean = false,
    @Json(name = "funding_interval_s") val fundingIntervalS: Long = 0,
)

@JsonClass(generateAdapter = true)
data class OrderBookDto(
    val symbol: Int = 0,
    val depth: Int = 0,
    @Json(name = "bid_levels") val bidLevels: Int = 0,
    @Json(name = "ask_levels") val askLevels: Int = 0,
    @Json(name = "bid_px") val bidPx: Long? = null,
    @Json(name = "ask_px") val askPx: Long? = null,
    val bids: List<List<Long>> = emptyList(),
    val asks: List<List<Long>> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class CandlesResponseDto(
    val symbol: Int = 0,
    @Json(name = "interval_sec") val intervalSec: Int = 0,
    val durable: Boolean = false,
    val from: Long = 0,
    val to: Long = 0,
    val count: Int = 0,
    val bars: List<BarDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class BarDto(
    val open: Long = 0,
    val high: Long = 0,
    val low: Long = 0,
    val close: Long = 0,
    val volume: Long = 0,
    val trades: Long = 0,
    @Json(name = "ts_start_ns") val tsStartNs: Long = 0,
)

@JsonClass(generateAdapter = true)
data class TradesResponseDto(
    val symbol: Int = 0,
    val count: Int = 0,
    val trades: List<TradeDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class TradeDto(
    val aggressor: String = "",
    val price: Long = 0,
    val qty: Long = 0,
    @Json(name = "ts_ns") val tsNs: Long = 0,
)

/**
 * Transport for the NEW long-range history endpoint (`GET md/history/{symbolId}`). Every field has a
 * default so a partial/absent payload never fails to decode. [nextCursor] paginates; [bars] carry the
 * OHLCV timeline. Prices/quantities are integers on the wire (divide by the symbol's price scaler).
 */
@JsonClass(generateAdapter = true)
data class HistoryResponseDto(
    val symbol: Int = 0,
    val interval: String = "",
    val from: Long = 0,
    val to: Long = 0,
    val count: Int = 0,
    @Json(name = "next_cursor") val nextCursor: String? = null,
    val bars: List<HistoryBarDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class HistoryBarDto(
    @Json(name = "ts") val ts: Long = 0,
    @Json(name = "o") val open: Long = 0,
    @Json(name = "h") val high: Long = 0,
    @Json(name = "l") val low: Long = 0,
    @Json(name = "c") val close: Long = 0,
    @Json(name = "v") val volume: Long = 0,
)
