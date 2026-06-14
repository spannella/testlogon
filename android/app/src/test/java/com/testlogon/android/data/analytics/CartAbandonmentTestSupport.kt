package com.testlogon.android.data.analytics

import com.testlogon.android.data.cart.CartItem
import com.testlogon.android.data.cart.FullCart

/** AND-216 / AND-217 — shared fakes + fixtures for the abandonment tests (no DataStore/network I/O). */

/** In-memory marker store; [failReads]/[failWrites] simulate DataStore degradation (section 7). */
class FakeAbandonmentMarkerStore(
    var failReads: Boolean = false,
    var failWrites: Boolean = false,
) : AbandonmentMarkerStore {
    private var lastHash: String? = null
    private var lastEpisode: String? = null
    private var bgMark: BackgroundMark? = null

    var resetCalls = 0

    override suspend fun lastEmittedHash(): String? {
        if (failReads) return null // degrades to "no marker"
        return lastHash
    }

    override suspend fun recordEmitted(hash: String, episodeId: String) {
        if (failWrites) return
        lastHash = hash
        lastEpisode = episodeId
    }

    override suspend fun markBackgrounded(atEpochMs: Long, hash: String) {
        bgMark = BackgroundMark(atEpochMs, hash)
    }

    override suspend fun backgroundMark(): BackgroundMark? = bgMark

    override suspend fun clearBackgroundMark() {
        bgMark = null
    }

    override suspend fun reset() {
        resetCalls++
        lastHash = null
        lastEpisode = null
        bgMark = null
    }
}

/** A mutable fixed clock for deterministic timing. */
class FakeClock(var now: Long = 1_000_000L) : AbandonmentClock {
    override fun nowEpochMs(): Long = now
}

fun sampleCart(
    cartId: String = "cart_1",
    currency: String = "USD",
    items: List<CartItem> = listOf(
        CartItem(sku = "SKU-1", name = "Widget", quantity = 2, unitPriceCents = 999, lineTotalCents = 1998),
        CartItem(sku = "SKU-2", name = "Gadget", quantity = 2, unitPriceCents = 1650, lineTotalCents = 3300),
    ),
): FullCart = FullCart(
    cartId = cartId,
    items = items,
    totalCents = items.sumOf { it.lineTotalCents },
    currency = currency,
)
