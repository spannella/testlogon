package com.testlogon.android.feature.broadcast.host.ads

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.data.broadcast.AdBreak
import com.testlogon.android.data.broadcast.AdConfig
import com.testlogon.android.data.broadcast.HostAdRepository
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-316 — unit tests for [AdControlViewModel]. Uses MainDispatcherRule + runCurrent + an injectable now
 * clock (NEVER advanceUntilIdle). The fake [HostAdRepository] returns canned outcomes + records calls. The
 * countdown ticker is exercised with BOUNDED advanceTimeBy and ALWAYS reaches inactive (cancelling the
 * ticker) before the test finishes, so runTest's end-of-test drain never spins the parked delay loop.
 */
class AdControlViewModelTest {

    @get:Rule
    val mainDispatcher = MainDispatcherRule()

    /** Fake ad repository: canned outcomes + a record of the last PATCH fields + the end/trigger call counts. */
    private class FakeAdRepo(
        var config: AdConfig = inactiveConfig(),
    ) : HostAdRepository {
        var getResult: ApiResult<AdConfig> = ApiResult.Success(config)
        var updateResult: ApiResult<AdConfig> = ApiResult.Success(config)
        var triggerResult: ApiResult<AdBreak> = ApiResult.Success(
            AdBreak(durationSeconds = 30, startedAt = 1_000L, skipAfterSeconds = 5),
        )
        var endResult: ApiResult<Unit> = ApiResult.Success(Unit)

        var getCalls = 0
        var endCalls = 0
        var lastPreRoll: Boolean? = null
        var lastDuration: Int? = null
        var lastSkip: Int? = null

        override suspend fun getAdConfig(sessionId: String): ApiResult<AdConfig> {
            getCalls++
            return getResult
        }

        override suspend fun updateAdConfig(
            sessionId: String,
            preRollEnabled: Boolean?,
            durationSeconds: Int?,
            skipAfterSeconds: Int?,
        ): ApiResult<AdConfig> {
            lastPreRoll = preRollEnabled
            lastDuration = durationSeconds
            lastSkip = skipAfterSeconds
            return updateResult
        }

        override suspend fun triggerAdBreak(sessionId: String): ApiResult<AdBreak> = triggerResult

        override suspend fun endAdBreak(sessionId: String): ApiResult<Unit> {
            endCalls++
            return endResult
        }
    }

    private fun vm(
        repo: HostAdRepository,
        sessionId: String? = SESSION,
        nowSeconds: Long = 1_000L,
    ): AdControlViewModel {
        val saved = SavedStateHandle(
            if (sessionId != null) mapOf(AdControlViewModel.ARG_SESSION_ID to sessionId) else emptyMap(),
        )
        return AdControlViewModel(repo, saved).also {
            it.now = { nowSeconds }
            it.tickIntervalMillis = 1_000L
        }
    }

    @Test
    fun refresh_loadsConfig() = runTest {
        val repo = FakeAdRepo()
        val vm = vm(repo)
        runCurrent()

        val state = vm.uiState.value
        assertFalse(state.loading)
        assertTrue(state.config.preRollEnabled)
        assertEquals(30, state.config.midRollDurationSeconds)
        assertEquals(5, state.config.skipAfterSeconds)
        assertEquals(2, state.totalAdBreaks)
        assertFalse(state.adBreakActive)
    }

    @Test
    fun validation_outOfRange_disablesSave() = runTest {
        val repo = FakeAdRepo()
        val vm = vm(repo)
        runCurrent()

        vm.onDurationChanged(99)
        runCurrent()
        assertFalse(vm.uiState.value.config.durationValid)
        assertFalse(vm.uiState.value.config.canSave)

        vm.onSkipAfterChanged(1)
        runCurrent()
        assertFalse(vm.uiState.value.config.skipValid)
        assertFalse(vm.uiState.value.config.canSave)
    }

    @Test
    fun saveConfig_sendsOnlyChangedFields() = runTest {
        val repo = FakeAdRepo()
        val vm = vm(repo)
        runCurrent()

        // Only change the duration to a valid value.
        vm.onDurationChanged(45)
        runCurrent()
        assertTrue(vm.uiState.value.config.canSave)

        vm.saveConfig()
        runCurrent()

        assertEquals(45, repo.lastDuration)
        assertEquals(null, repo.lastPreRoll)
        assertEquals(null, repo.lastSkip)
        // Reconciled from the response -> no longer dirty.
        assertFalse(vm.uiState.value.config.dirty)
    }

    @Test
    fun triggerAdBreak_setsActive_startsCountdown_thenEndStopsTicker() = runTest {
        // started_at = 1000, duration = 30, now = 1000 -> remaining starts at 30.
        val repo = FakeAdRepo()
        repo.triggerResult = ApiResult.Success(
            AdBreak(durationSeconds = 30, startedAt = 1_000L, skipAfterSeconds = 5),
        )
        val vm = vm(repo, nowSeconds = 1_000L)
        runCurrent()

        vm.triggerAdBreak()
        runCurrent()
        assertTrue(vm.uiState.value.adBreakActive)
        assertEquals(30, vm.uiState.value.remainingSeconds)

        // Advance the wall clock by 5s as well as the scheduler so a tick recomputes a lower remaining.
        vm.now = { 1_005L }
        advanceTimeBy(1_000)
        runCurrent()
        assertEquals(25, vm.uiState.value.remainingSeconds)

        // End early -> active cleared + ticker stopped (reached inactive before the test finishes).
        vm.endAdBreak()
        runCurrent()
        assertFalse(vm.uiState.value.adBreakActive)
        assertEquals(1, repo.endCalls)
    }

    @Test
    fun autoExpire_clearsActive_andReconciles() = runTest {
        // started_at = 1000, duration = 30; now is already past expiry (1100) -> immediate auto-expire.
        val repo = FakeAdRepo()
        repo.triggerResult = ApiResult.Success(
            AdBreak(durationSeconds = 30, startedAt = 1_000L, skipAfterSeconds = 5),
        )
        val vm = vm(repo, nowSeconds = 1_100L)
        runCurrent()
        val getsBefore = repo.getCalls

        vm.triggerAdBreak()
        runCurrent()

        // The immediate recompute sees remaining <= 0 -> clears active + calls refresh (FR-5 auto-expire).
        assertFalse(vm.uiState.value.adBreakActive)
        assertTrue(repo.getCalls > getsBefore)
    }

    @Test
    fun refresh_failure_setsError() = runTest {
        val repo = FakeAdRepo()
        repo.getResult = ApiResult.Failure(ApiError(500, "boom"))
        val vm = vm(repo)
        runCurrent()

        assertFalse(vm.uiState.value.loading)
        assertEquals("boom", vm.uiState.value.error)
    }

    private companion object {
        const val SESSION = "bcs_1"

        fun inactiveConfig() = AdConfig(
            sessionId = SESSION,
            preRollEnabled = true,
            midRollDurationSeconds = 30,
            skipAfterSeconds = 5,
            adBreakActive = false,
            adBreakStartedAt = null,
            totalAdBreaks = 2,
        )
    }
}
