package com.testlogon.android.data.analytics

import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.auth.AppScope
import com.testlogon.android.data.cart.CartRepository
import com.testlogon.android.data.cart.FullCart
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-216 — lifecycle-driven cart-abandonment tracker.
 *
 * Registers against [ProcessLifecycleOwner]: on background (ON_STOP) with a non-empty cart it persists a
 * durable background mark; on foreground (ON_START) it emits BACKGROUND_TIMEOUT (or PROCESS_KILLED on a
 * fresh launch with an aged mark) when the cart is unchanged and the threshold has elapsed. Checkout
 * success resets the episode (FR-6). Exactly-once is enforced by the use case + durable marker.
 *
 * The tracker reads the current cart on demand via [CartRepository.loadCart] (the active cart); a
 * fetch failure simply skips emission for that transition. No new coupling to cart internals.
 *
 * Started once from [com.testlogon.android.TestLogonApp.onCreate] via [start]; idempotent + non-blocking.
 */
@Singleton
class CartAbandonmentTracker @Inject constructor(
    private val cartRepository: CartRepository,
    private val emit: EmitCartAbandonmentUseCase,
    private val store: AbandonmentMarkerStore,
    private val clock: AbandonmentClock,
    @AppScope private val scope: CoroutineScope,
) : DefaultLifecycleObserver {

    @Volatile
    private var started = false

    /** True once the process has foregrounded at least once; lets onStart distinguish a fresh launch. */
    @Volatile
    private var sawForeground = false

    fun start() {
        if (started) return
        started = true
        scope.launch {
            // ProcessLifecycleOwner must be observed on the main thread.
            withContext(Dispatchers.Main.immediate) {
                ProcessLifecycleOwner.get().lifecycle.addObserver(this@CartAbandonmentTracker)
            }
        }
    }

    override fun onStop(owner: LifecycleOwner) {
        scope.launch {
            val cart = currentCart() ?: return@launch
            if (cart.items.isNotEmpty()) {
                store.markBackgrounded(clock.nowEpochMs(), cart.contentsHash())
            }
        }
    }

    override fun onStart(owner: LifecycleOwner) {
        val freshLaunch = !sawForeground
        sawForeground = true
        scope.launch {
            val mark = store.backgroundMark() ?: return@launch
            val cart = currentCart()
            // Clamp negative/zero elapsed (clock skew) so it never trips the threshold.
            val elapsed = (clock.nowEpochMs() - mark.atEpochMs).coerceAtLeast(0L)
            if (cart != null &&
                cart.items.isNotEmpty() &&
                cart.contentsHash() == mark.hash &&
                elapsed >= INACTIVITY_THRESHOLD_MS
            ) {
                // A mark surviving a fresh process launch implies the process was killed while aged.
                val reason =
                    if (freshLaunch) AbandonmentReason.PROCESS_KILLED else AbandonmentReason.BACKGROUND_TIMEOUT
                emit(cart, reason, episodeStartedAtEpochMs = mark.atEpochMs)
            }
            store.clearBackgroundMark()
        }
    }

    /** FR-6 — checkout finalized: close the episode so a later identical cart can re-emit. */
    fun onCheckoutCompleted() {
        scope.launch { store.reset() }
    }

    private suspend fun currentCart(): FullCart? =
        when (val r = cartRepository.loadCart()) {
            is ApiResult.Success -> r.data
            else -> null
        }

    companion object {
        /** Background inactivity threshold (product decision; no web counterpart — section 13). */
        const val INACTIVITY_THRESHOLD_MS = 5 * 60 * 1000L
    }
}
