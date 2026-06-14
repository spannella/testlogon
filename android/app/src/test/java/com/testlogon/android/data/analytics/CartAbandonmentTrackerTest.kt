package com.testlogon.android.data.analytics

import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.LifecycleRegistry
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.cart.CartItem
import com.testlogon.android.data.cart.CartRepository
import com.testlogon.android.data.cart.FullCart
import com.testlogon.android.data.catalog.CatalogItem
import com.testlogon.android.data.cart.OkRespDto
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-216 / AND-217 — [CartAbandonmentTracker] lifecycle behavior driven by [onStop]/[onStart] directly
 * (ProcessLifecycleOwner registration is not exercised on the JVM). Uses an injected unconfined scope +
 * fake clock/store/cart so emissions are deterministic.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class CartAbandonmentTrackerTest {

    @get:Rule
    val mainRule = com.testlogon.android.core.testing.MainDispatcherRule()

    // The tracker's onStop/onStart never read the owner; a minimal stub is sufficient.
    private val owner: LifecycleOwner = object : LifecycleOwner {
        private val registry = LifecycleRegistry.createUnsafe(this)
        override val lifecycle: Lifecycle get() = registry
    }

    private fun tracker(
        cart: FullCart?,
        store: FakeAbandonmentMarkerStore,
        clock: FakeClock,
        scope: CoroutineScope,
    ): Pair<CartAbandonmentTracker, DefaultCartEventSink> {
        val sink = DefaultCartEventSink()
        val emit = EmitCartAbandonmentUseCase(sink, store, clock)
        val repo = FakeCartRepo(cart)
        return CartAbandonmentTracker(repo, emit, store, clock, scope) to sink
    }

    @Test
    fun backgroundThenForeground_pastThreshold_emitsBackgroundTimeout() = runTest {
        val store = FakeAbandonmentMarkerStore()
        val clock = FakeClock(now = 1_000L)
        val scope = CoroutineScope(UnconfinedTestDispatcher(testScheduler))
        val (t, sink) = tracker(sampleCart(), store, clock, scope)

        val received = mutableListOf<CartAbandonedEvent>()
        val job = scope.launch { sink.events.collect { received += it } }

        // First foreground (so a subsequent onStart is NOT a fresh launch -> BACKGROUND_TIMEOUT).
        t.onStart(owner)
        advanceUntilIdle()
        t.onStop(owner)
        advanceUntilIdle()
        clock.now += CartAbandonmentTracker.INACTIVITY_THRESHOLD_MS + 1
        t.onStart(owner)
        advanceUntilIdle()

        assertEquals(1, received.size)
        assertEquals(AbandonmentReason.BACKGROUND_TIMEOUT, received.single().reason)
        job.cancel()
    }

    @Test
    fun backgroundThenForeground_underThreshold_doesNotEmit() = runTest {
        val store = FakeAbandonmentMarkerStore()
        val clock = FakeClock(now = 1_000L)
        val scope = CoroutineScope(UnconfinedTestDispatcher(testScheduler))
        val (t, sink) = tracker(sampleCart(), store, clock, scope)

        val received = mutableListOf<CartAbandonedEvent>()
        val job = scope.launch { sink.events.collect { received += it } }

        t.onStart(owner)
        t.onStop(owner)
        clock.now += 1_000L // under threshold
        t.onStart(owner)
        advanceUntilIdle()

        assertTrue(received.isEmpty())
        job.cancel()
    }

    @Test
    fun cartChangedWhileBackgrounded_suppressesEmit() = runTest {
        val store = FakeAbandonmentMarkerStore()
        val clock = FakeClock(now = 1_000L)
        val scope = CoroutineScope(UnconfinedTestDispatcher(testScheduler))
        val sink = DefaultCartEventSink()
        val emit = EmitCartAbandonmentUseCase(sink, store, clock)
        val repo = FakeCartRepo(sampleCart())
        val t = CartAbandonmentTracker(repo, emit, store, clock, scope)

        val received = mutableListOf<CartAbandonedEvent>()
        val job = scope.launch { sink.events.collect { received += it } }

        t.onStart(owner)
        t.onStop(owner) // marks with the original hash
        advanceUntilIdle()
        // Cart contents change while backgrounded.
        repo.cart = sampleCart(items = listOf(CartItem("SKU-9", "New", 1, 100, 100)))
        clock.now += CartAbandonmentTracker.INACTIVITY_THRESHOLD_MS + 1
        t.onStart(owner)
        advanceUntilIdle()

        assertTrue(received.isEmpty()) // hash mismatch
        job.cancel()
    }

    @Test
    fun freshLaunch_withAgedMark_emitsProcessKilled() = runTest {
        val store = FakeAbandonmentMarkerStore()
        val clock = FakeClock(now = 1_000L)
        val scope = CoroutineScope(UnconfinedTestDispatcher(testScheduler))
        val (t, sink) = tracker(sampleCart(), store, clock, scope)

        val received = mutableListOf<CartAbandonedEvent>()
        val job = scope.launch { sink.events.collect { received += it } }

        // Simulate a mark left by a prior process, aged past threshold; first onStart == fresh launch.
        store.markBackgrounded(clock.now, sampleCart().contentsHash())
        clock.now += CartAbandonmentTracker.INACTIVITY_THRESHOLD_MS + 1
        t.onStart(owner)
        advanceUntilIdle()

        assertEquals(1, received.size)
        assertEquals(AbandonmentReason.PROCESS_KILLED, received.single().reason)
        job.cancel()
    }

    @Test
    fun onCheckoutCompleted_resetsStore() = runTest {
        val store = FakeAbandonmentMarkerStore()
        val clock = FakeClock()
        val scope = CoroutineScope(UnconfinedTestDispatcher(testScheduler))
        val (t, _) = tracker(sampleCart(), store, clock, scope)
        t.onCheckoutCompleted()
        advanceUntilIdle()
        assertEquals(1, store.resetCalls)
    }
}

/** Fake cart repo exposing a mutable current cart; only [loadCart] is used by the tracker. */
private class FakeCartRepo(var cart: FullCart?) : CartRepository {
    override suspend fun addToCart(item: CatalogItem, quantity: Int): ApiResult<CartItem> =
        ApiResult.Success(CartItem("s", "n", 1, 1, 1))

    override suspend fun loadCart(): ApiResult<FullCart> =
        cart?.let { ApiResult.Success(it) } ?: ApiResult.Success(FullCart.empty("cart_1"))

    override suspend fun setQuantity(sku: String, quantity: Int): ApiResult<FullCart> =
        ApiResult.Success(cart ?: FullCart.empty("cart_1"))

    override suspend fun removeLine(sku: String): ApiResult<FullCart> =
        ApiResult.Success(cart ?: FullCart.empty("cart_1"))

    override suspend fun clearCart(): ApiResult<OkRespDto> = ApiResult.Success(OkRespDto(ok = true))
}
