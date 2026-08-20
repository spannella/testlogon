package com.testlogon.android.data.exchange

/** DTO -> domain mappers for the Markets (VIEW-ONLY) data layer. */

fun SymbolDto.toDomain(): Instrument = Instrument(
    symbol = symbol,
    symbolId = symbolId,
    priceScaler = priceScaler.coerceAtLeast(1),
    lotSize = lotSize,
    referencePrice = referencePrice,
    isPerpetual = isPerpetual,
    fundingIntervalS = fundingIntervalS,
)

fun OrderBookDto.toDomain(): OrderBook {
    fun mapLevels(rows: List<List<Long>>): List<OrderBookLevel> =
        rows.filter { it.size >= 2 }.map { OrderBookLevel(price = it[0], qty = it[1]) }
    return OrderBook(
        symbolId = symbol,
        bids = mapLevels(bids),
        asks = mapLevels(asks),
        bestBid = bidPx,
        bestAsk = askPx,
    )
}

fun BarDto.toDomain(): Candle = Candle(
    tsStartNs = tsStartNs,
    open = open,
    high = high,
    low = low,
    close = close,
    volume = volume,
    trades = trades,
)

fun TradeDto.toDomain(): Trade = Trade(
    price = price,
    qty = qty,
    aggressor = when (aggressor.lowercase()) {
        "buy" -> Aggressor.BUY
        "sell" -> Aggressor.SELL
        else -> Aggressor.UNKNOWN
    },
    tsNs = tsNs,
)
