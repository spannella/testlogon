package com.testlogon.android.feature.vod.adsupported

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.vod.adsupported.AdBreak
import com.testlogon.android.data.vod.adsupported.AdBreakReport
import com.testlogon.android.data.vod.adsupported.AdSupportedSession
import com.testlogon.android.data.vod.adsupported.VodAdSupportedApi
import com.testlogon.android.data.vod.adsupported.VodAdSupportedRepository
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

private class FakeAdRepo : VodAdSupportedRepository {
    var startResult: ApiResult<AdSupportedSession> = ApiResult.Failure(ApiError(500, "x"))
    var reportResult: ApiResult<AdBreakReport> =
        ApiResult.Success(AdBreakReport(true, "br_pre", true, 1, 1, null, true))
    val reported = mutableListOf<Pair<String, String>>()

    override suspend fun getSession(videoId: String) = startResult
    override suspend fun start(videoId: String, resumePositionSeconds: Int) = startResult
    override suspend fun reportBreak(videoId: String, breakId: String, eventType: String): ApiResult<AdBreakReport> {
        reported += breakId to eventType
        return reportResult
    }
}

@OptIn(ExperimentalCoroutinesApi::class)
class AdSupportedPlayerViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private val repo = FakeAdRepo()
    private fun vm() = AdSupportedPlayerViewModel(repo, SavedStateHandle(mapOf("videoId" to "v1")))

    private fun session(adsFree: Boolean = false, breaks: List<AdBreak>) = AdSupportedSession(
        sessionId = "s1", videoId = "v1", status = "active", playbackUrl = "https://cdn/m.m3u8",
        adSchedule = breaks, breaksTotal = breaks.size, breaksCompleted = 0,
        nextRequiredBreakId = breaks.firstOrNull()?.breakId, playbackUnlocked = false,
        adsFree = adsFree, tokenExpiresAt = 999L,
    )

    private fun preRoll() = AdBreak(
        "br_pre", VodAdSupportedApi.SLOT_PRE_ROLL, 0L, 15_000L, "c", "u", "video", 5_000L, 0, false,
    )

    @Test
    fun start_withPreRoll_entersAdPhase() = runTest {
        repo.startResult = ApiResult.Success(session(breaks = listOf(preRoll())))
        val vm = vm()
        advanceUntilIdle()
        val s = vm.uiState.value
        assertTrue(s is AdSupportedUiState.Ready)
        assertEquals(PlaybackPhase.AD, (s as AdSupportedUiState.Ready).phase)
    }

    @Test
    fun start_adsFree_entersContentDirectly() = runTest {
        repo.startResult = ApiResult.Success(session(adsFree = true, breaks = listOf(preRoll())))
        val vm = vm()
        advanceUntilIdle()
        val s = vm.uiState.value as AdSupportedUiState.Ready
        assertEquals(PlaybackPhase.CONTENT, s.phase)
    }

    @Test
    fun start_failure_thenRetrySucceeds() = runTest {
        repo.startResult = ApiResult.Failure(ApiError(500, "boom"))
        val vm = vm()
        advanceUntilIdle()
        assertTrue(vm.uiState.value is AdSupportedUiState.Error)

        repo.startResult = ApiResult.Success(session(adsFree = true, breaks = emptyList()))
        vm.retry()
        advanceUntilIdle()
        assertTrue(vm.uiState.value is AdSupportedUiState.Ready)
    }

    @Test
    fun skip_enabledOnlyAfterSkipOffset() = runTest {
        repo.startResult = ApiResult.Success(session(breaks = listOf(preRoll())))
        val vm = vm()
        advanceUntilIdle()

        vm.onAdPosition(2_000L) // before 5s skip offset
        assertFalse((vm.uiState.value as AdSupportedUiState.Ready).skipEnabled)

        vm.onAdPosition(5_000L) // at the skip offset
        assertTrue((vm.uiState.value as AdSupportedUiState.Ready).skipEnabled)
    }

    @Test
    fun adCompleted_appliesServerUnlock_andResumesContent() = runTest {
        repo.startResult = ApiResult.Success(session(breaks = listOf(preRoll())))
        repo.reportResult = ApiResult.Success(AdBreakReport(true, "br_pre", true, 1, 1, null, true))
        val vm = vm()
        advanceUntilIdle()

        vm.onAdCompleted()
        advanceUntilIdle()
        val s = vm.uiState.value as AdSupportedUiState.Ready
        assertEquals(PlaybackPhase.CONTENT, s.phase)
        assertTrue(s.playbackUnlocked)
        assertTrue(repo.reported.any { it == "br_pre" to "complete" })
    }

    @Test
    fun seekRequested_acrossUnwatchedMid_blocksAndEntersAd() = runTest {
        val mid = AdBreak("br_mid", VodAdSupportedApi.SLOT_MID_ROLL, 900_000L, 30_000L, "c", "u", "video", 5_000L, 1, false)
        repo.startResult = ApiResult.Success(session(adsFree = true, breaks = listOf(mid)))
        val vm = vm()
        advanceUntilIdle()
        // ads_free => starts in content; a forward seek past the mid cue is gated.
        val allowed = vm.onSeekRequested(currentMs = 0L, targetMs = 1_000_000L)
        assertFalse(allowed)
        advanceUntilIdle()
        assertEquals(PlaybackPhase.AD, (vm.uiState.value as AdSupportedUiState.Ready).phase)
    }
}
