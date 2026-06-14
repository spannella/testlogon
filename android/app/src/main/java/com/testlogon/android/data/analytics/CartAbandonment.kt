package com.testlogon.android.data.analytics

import com.testlogon.android.data.cart.FullCart
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import java.security.MessageDigest
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-216 — cart-abandonment event model + in-app event sink.
 *
 * This is a NEW Android-specific client signal (spec section 16): `cartAbandonment.ts` is a backend
 * status/stats/sweep API client only — there is NO `cart_abandoned` event in the web codebase, and this
 * ticket performs no network I/O. Money is carried in minor units (cents) sourced from AND-210's cart
 * DTOs (`*_cents`). The event carries no PII (no SKUs in the payload; SKUs feed only the opaque hash).
 */
enum class AbandonmentReason {
    BACKGROUND_TIMEOUT, FOREGROUND_INACTIVITY, NAV_AWAY, PROCESS_KILLED
}

/** The emitted abandonment event. Field names mirror the spec's internal JSON contract (section 5). */
data class CartAbandonedEvent(
    val episodeId: String,
    val cartId: String,
    val itemCount: Int,
    val lineCount: Int,
    val subtotalCents: Long,
    val currency: String,
    val reason: AbandonmentReason,
    val contentsHash: String,
    val episodeStartedAtEpochMs: Long,
    val abandonedAtEpochMs: Long,
)

/**
 * In-app event sink. Lives in data/analytics so any module can subscribe without depending on the cart
 * feature. `replay = 0` (a moment-in-time signal); a bounded buffer with DROP_OLDEST guarantees `emit`
 * never suspends a lifecycle callback.
 */
interface CartEventSink {
    val events: SharedFlow<CartAbandonedEvent>
    suspend fun emit(event: CartAbandonedEvent)
}

@Singleton
class DefaultCartEventSink @Inject constructor() : CartEventSink {
    private val _events = MutableSharedFlow<CartAbandonedEvent>(
        replay = 0,
        extraBufferCapacity = 16,
        onBufferOverflow = BufferOverflow.DROP_OLDEST,
    )
    override val events: SharedFlow<CartAbandonedEvent> = _events.asSharedFlow()
    override suspend fun emit(event: CartAbandonedEvent) {
        _events.emit(event)
    }
}

/** Injectable clock so abandonment timing is deterministic in tests. */
fun interface AbandonmentClock {
    fun nowEpochMs(): Long
}

@Singleton
class SystemAbandonmentClock @Inject constructor() : AbandonmentClock {
    override fun nowEpochMs(): Long = System.currentTimeMillis()
}

/**
 * Deterministic SHA-256 (hex) over the sorted `(sku, quantity)` set — stable across process restarts and
 * order-independent, so duplicate suppression survives kills. The hash output is opaque (no SKUs leak).
 */
fun FullCart.contentsHash(): String {
    val canonical = items
        .map { it.sku to it.quantity }
        .sortedBy { it.first }
        .joinToString(separator = "|") { "${it.first}:${it.second}" }
    val digest = MessageDigest.getInstance("SHA-256").digest(canonical.toByteArray(Charsets.UTF_8))
    return digest.joinToString("") { "%02x".format(it) }
}
