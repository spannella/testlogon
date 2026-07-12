package com.testlogon.android.feature.vod.rental

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.data.cache.Clock
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.vod.rental.RentOutcome
import com.testlogon.android.data.vod.rental.RentalAccess
import com.testlogon.android.data.vod.rental.RentalConsumeResult
import com.testlogon.android.data.vod.rental.RentalPlayback
import com.testlogon.android.data.vod.rental.RentalReceipt
import com.testlogon.android.data.vod.rental.VodRentalRepository
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/** A mutable fake [Clock] (epoch millis) for deterministic countdown ticks. */
private class FakeClock(var nowMs: Long) : Clock {
    override fun now(): Long = nowMs
}

private class FakeRentalRepo : VodRentalRepository {
    var statusResult: ApiResult<RentalAccess> = ApiResult.Success(locked())
    var rentOutcome: RentOutcome = RentOutcome.PaymentsUnavailable
    var playbackResult: ApiResult<RentalPlayback>? = null
    var accessResult: ApiResult<RentalAccess>? = null

    override suspend fun status(videoId: String) = statusResult
    override suspend fun access(videoId: String) = accessResult ?: statusResult
    override suspend fun rent(videoId: String, tier: String, durationHours: Int?) = rentOutcome
    override suspend fun beginPlayback(videoId: String) =
        playbackResult ?: ApiResult.Failure(com.testlogon.android.core.model.ApiError(500, "x"))
    override suspend fun finishPlayback(videoId: String) =
        ApiResult.Success(RentalConsumeResult(ok = true, viewsRemaining = 0, consumed = true))
    override suspend fun list() = ApiResult.Success(emptyList<RentalAccess>())
    override suspend fun listItems() = ApiResult.Success(emptyList<com.testlogon.android.data.vod.rental.RentalListItem>())

    companion object {
        fun locked() = RentalAccess(false, null, "not_rented", null, 0L, -1, null, false)
    }
}

@OptIn(ExperimentalCoroutinesApi::class)
class VodRentalViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private val clock = FakeClock(0L)
    private val repo = FakeRentalRepo()

    private fun vm() = VodRentalViewModel(repo, clock, SavedStateHandle(mapOf("videoId" to "v1")))

    @Test
    fun load_lockedAccess_emitsLocked() = runTest {
        repo.statusResult = ApiResult.Success(FakeRentalRepo.locked())
        val vm = vm()
        advanceUntilIdle()
        assertTrue(vm.state.value is VodRentalUiState.Locked)
    }

    @Test
    fun load_activeAccess_emitsActiveWithCountdown() = runTest {
        repo.statusResult = ApiResult.Success(
            RentalAccess(true, "rental", null, expiresAt = 100L, 0L, -1, "r1", true),
        )
        val vm = vm()
        runCurrent() // run load + first ticker emit (NOT advanceUntilIdle: ticker would loop)
        val s = vm.state.value
        assertTrue(s is VodRentalUiState.Active)
        assertEquals("00:01:40", (s as VodRentalUiState.Active).countdownLabel)
        drainTicker()
    }

    @Test
    fun rent_withPaymentsUnavailable_emitsEffect_andStaysLocked() = runTest {
        repo.statusResult = ApiResult.Success(FakeRentalRepo.locked())
        repo.rentOutcome = RentOutcome.PaymentsUnavailable
        val vm = vm()
        advanceUntilIdle()

        val effects = mutableListOf<VodRentalEffect>()
        val job = launch { vm.effects.collect { effects += it } }
        vm.rent("rental")
        advanceUntilIdle()
        job.cancel()

        assertTrue(effects.any { it is VodRentalEffect.PaymentsUnavailable })
        assertTrue(vm.state.value is VodRentalUiState.Locked)
    }

    @Test
    fun rent_success_transitionsToActive() = runTest {
        repo.statusResult = ApiResult.Success(FakeRentalRepo.locked())
        val active = RentalAccess(true, "rental", null, expiresAt = 100L, 0L, -1, "r1", true)
        repo.rentOutcome = RentOutcome.Active(
            RentalReceipt("v1", "r1", "rental", false, 100L, -1, 399, 48), active,
        )
        val vm = vm()
        advanceUntilIdle() // load -> Locked (no ticker yet)
        vm.rent("rental")
        runCurrent() // rent -> reduceAccess -> Active + first ticker emit
        assertTrue(vm.state.value is VodRentalUiState.Active)
        drainTicker()
    }

    @Test
    fun countdown_crossesZero_reLocksWithoutRestart() = runTest {
        // TC-AND-192-04: active with a 3s window; advancing the clock past zero re-locks in-process.
        repo.statusResult = ApiResult.Success(
            RentalAccess(true, "rental", null, expiresAt = 3L, 0L, -1, "r1", true),
        )
        val vm = vm()
        runCurrent() // load -> Active + first ticker emit (do NOT advanceUntilIdle: ticker loops)
        assertTrue(vm.state.value is VodRentalUiState.Active)

        // Advance wall clock past the 3s window, then let the ticker fire and re-lock.
        clock.nowMs = 4_000L
        advanceTimeBy(1_100L)
        runCurrent()

        val s = vm.state.value
        assertTrue(s is VodRentalUiState.Locked)
        assertEquals("expired", (s as VodRentalUiState.Locked).lastReason)
    }

    @Test
    fun beginPlayback_emitsPlaybackReady() = runTest {
        repo.statusResult = ApiResult.Success(
            RentalAccess(true, "rental", null, expiresAt = 100L, 0L, -1, "r1", true),
        )
        repo.playbackResult = ApiResult.Success(
            RentalPlayback(
                "v1", "https://x/m.m3u8?tok=z", null, "dev", null, 999L,
                RentalAccess(true, "rental", null, 100L, 90L, -1, "r1", true),
            ),
        )
        val vm = vm()
        runCurrent() // load -> Active + first ticker emit

        val effects = mutableListOf<VodRentalEffect>()
        val job = launch { vm.effects.collect { effects += it } }
        vm.beginPlayback()
        runCurrent()
        job.cancel()

        val ready = effects.filterIsInstance<VodRentalEffect.PlaybackReady>().single()
        assertEquals("https://x/m.m3u8?tok=z", ready.url)
        drainTicker()
    }

    /**
     * Stops the perpetual countdown ticker so [runTest] can complete: advance the FakeClock past any
     * expiry, then let the ticker fire once and break (re-lock). The state ends Locked.
     */
    private fun kotlinx.coroutines.test.TestScope.drainTicker() {
        clock.nowMs = Long.MAX_VALUE / 2
        advanceUntilIdle()
    }
}
