package com.testlogon.android.data.analytics

import com.testlogon.android.data.cart.FullCart
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-216 / AND-217 — [EmitCartAbandonmentUseCase] + [contentsHash] + [toAbandonedEvent]:
 * happy path, exactly-once, empty short-circuit, field mapping, hash order-independence/qty-sensitivity,
 * and DataStore-read-failure degradation.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class EmitCartAbandonmentUseCaseTest {

    private fun useCase(
        sink: CartEventSink,
        store: AbandonmentMarkerStore,
        clock: AbandonmentClock = FakeClock(),
    ) = EmitCartAbandonmentUseCase(sink, store, clock)

    @Test
    fun emitsOnce_forNonEmptyCart_andReturnsTrue() = runTest {
        val sink = DefaultCartEventSink()
        val store = FakeAbandonmentMarkerStore()
        val uc = useCase(sink, store, FakeClock(now = 5_000L))

        val received = mutableListOf<CartAbandonedEvent>()
        // Subscribe BEFORE emitting (replay=0); unconfined so the collector is active immediately.
        val collector = CoroutineScope(UnconfinedTestDispatcher(testScheduler))
        val job = collector.launch { sink.events.collect { received += it } }

        val emitted = uc(sampleCart(), AbandonmentReason.BACKGROUND_TIMEOUT)
        advanceUntilIdle()

        assertTrue(emitted)
        val event = received.single()
        assertEquals("cart_1", event.cartId)
        assertEquals(4, event.itemCount)
        assertEquals(2, event.lineCount)
        assertEquals(5298L, event.subtotalCents)
        assertEquals("USD", event.currency)
        assertEquals(AbandonmentReason.BACKGROUND_TIMEOUT, event.reason)
        assertEquals(5_000L, event.abandonedAtEpochMs)
        assertTrue(event.episodeId.isNotBlank())
        assertTrue(event.contentsHash.isNotBlank())
        job.cancel()
    }

    @Test
    fun duplicateContents_suppressesSecondEmit() = runTest {
        val sink = DefaultCartEventSink()
        val store = FakeAbandonmentMarkerStore()
        val uc = useCase(sink, store)

        val first = uc(sampleCart(), AbandonmentReason.NAV_AWAY)
        val second = uc(sampleCart(), AbandonmentReason.NAV_AWAY)
        assertTrue(first)
        assertFalse(second)
    }

    @Test
    fun emptyCart_shortCircuits_noEmit_noMarker() = runTest {
        val sink = DefaultCartEventSink()
        val store = FakeAbandonmentMarkerStore()
        val uc = useCase(sink, store)
        val empty = FullCart.empty("cart_1")
        assertFalse(uc(empty, AbandonmentReason.NAV_AWAY))
        assertEquals(null, store.lastEmittedHash())
    }

    @Test
    fun contentsHash_isOrderIndependent_andQuantitySensitive() {
        val a = sampleCart()
        val reordered = sampleCart(items = a.items.reversed())
        val changedQty = sampleCart(
            items = a.items.mapIndexed { i, item -> if (i == 0) item.copy(quantity = 99) else item },
        )
        assertEquals(a.contentsHash(), reordered.contentsHash())
        assertNotEquals(a.contentsHash(), changedQty.contentsHash())
    }

    @Test
    fun storeReadFailure_degradesToEmit() = runTest {
        val sink = DefaultCartEventSink()
        val store = FakeAbandonmentMarkerStore(failReads = true)
        val uc = useCase(sink, store)
        // Even after a prior "emit", the failing read returns null -> prefers a (possible) duplicate.
        assertTrue(uc(sampleCart(), AbandonmentReason.PROCESS_KILLED))
        assertTrue(uc(sampleCart(), AbandonmentReason.PROCESS_KILLED))
    }
}
