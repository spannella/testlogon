package com.testlogon.android.data.analytics

import com.testlogon.android.data.cart.FullCart
import java.util.UUID
import javax.inject.Inject

/**
 * AND-216 — builds a [CartAbandonedEvent] from a cart snapshot. `subtotalCents` is the sum of line
 * totals (== the server total when present); `itemCount` sums quantities; `lineCount` is the distinct
 * SKU count. No SKUs are placed in the payload (PII-free, section 8).
 */
fun FullCart.toAbandonedEvent(
    reason: AbandonmentReason,
    nowEpochMs: Long,
    episodeStartedAtEpochMs: Long,
    episodeId: String,
): CartAbandonedEvent = CartAbandonedEvent(
    episodeId = episodeId,
    cartId = cartId,
    itemCount = items.sumOf { it.quantity },
    lineCount = items.map { it.sku }.distinct().size,
    subtotalCents = items.sumOf { it.lineTotalCents },
    currency = currency,
    reason = reason,
    contentsHash = contentsHash(),
    episodeStartedAtEpochMs = episodeStartedAtEpochMs,
    abandonedAtEpochMs = nowEpochMs,
)

/**
 * AND-216 — emits exactly one abandonment event per unchanged cart contents.
 *
 * Short-circuits on an empty cart; suppresses when the contents hash matches the last emitted hash
 * (exactly-once across process restarts, since the marker is durable). Returns true iff an event was
 * emitted.
 */
class EmitCartAbandonmentUseCase @Inject constructor(
    private val sink: CartEventSink,
    private val store: AbandonmentMarkerStore,
    private val clock: AbandonmentClock,
) {
    suspend operator fun invoke(
        cart: FullCart,
        reason: AbandonmentReason,
        episodeStartedAtEpochMs: Long = clock.nowEpochMs(),
        episodeId: String = UUID.randomUUID().toString(),
    ): Boolean {
        if (cart.items.isEmpty()) return false
        val hash = cart.contentsHash()
        // DataStore read failure degrades to null (no prior marker) -> prefer a possible duplicate.
        if (store.lastEmittedHash() == hash) return false
        val event = cart.toAbandonedEvent(
            reason = reason,
            nowEpochMs = clock.nowEpochMs(),
            episodeStartedAtEpochMs = episodeStartedAtEpochMs,
            episodeId = episodeId,
        )
        sink.emit(event)
        store.recordEmitted(hash, event.episodeId)
        return true
    }
}
