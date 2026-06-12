package com.testlogon.android.feature.broadcast.host

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.data.broadcast.BroadcastInput
import com.testlogon.android.data.broadcast.BroadcastPlaybackUrl
import com.testlogon.android.data.broadcast.BroadcastRepository
import com.testlogon.android.data.broadcast.BroadcastScheduledPage
import com.testlogon.android.data.broadcast.BroadcastSession
import com.testlogon.android.data.broadcast.BroadcastSessionPage
import com.testlogon.android.data.webrtc.BroadcastPublisher
import com.testlogon.android.data.webrtc.GoLiveResult
import com.testlogon.android.data.webrtc.PublishState
import com.testlogon.android.data.webrtc.StubBroadcastPublisher
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-308 — unit tests for [IngestViewModel]. The FLAGGED happy path: createInput succeeds, the FLAGGED
 * publisher returns NotConfigured -> phase Unavailable && mediaUnavailable == true. Uses MainDispatcherRule
 * + runCurrent (NEVER advanceUntilIdle on the publisher's hot StateFlow collection).
 */
class IngestViewModelTest {

    @get:Rule
    val mainDispatcher = MainDispatcherRule()

    private fun input(id: String = "in_1") = BroadcastInput(
        inputId = id,
        sessionId = "bcs_1",
        inputType = "primary",
        label = "Host camera",
        ingestUrl = "rtmps://ingest/app",
        streamKey = "sk_1",
        position = 0,
    )

    /** A configurable repo: only the inputs control-plane methods are exercised. */
    private class FakeRepo(
        var createResult: ApiResult<BroadcastInput>,
    ) : BroadcastRepository {
        var createCalls = 0
        var deactivateCalls = 0
        var removeCalls = 0
        var lastInputType: String? = null
        var lastLabel: String? = null

        override suspend fun sessions(status: String?, limit: Int?) =
            ApiResult.Success(BroadcastSessionPage(emptyList(), false))
        override suspend fun scheduledSessions(limit: Int?): ApiResult<BroadcastScheduledPage> =
            ApiResult.Success(BroadcastScheduledPage(emptyList(), 0))
        override suspend fun upcomingSessions(limit: Int?): ApiResult<BroadcastScheduledPage> =
            ApiResult.Success(BroadcastScheduledPage(emptyList(), 0))
        override suspend fun session(sessionId: String): ApiResult<BroadcastSession> =
            ApiResult.Failure(ApiError(404, "nope"))
        override suspend fun mintPlaybackUrl(sessionId: String): ApiResult<BroadcastPlaybackUrl> =
            ApiResult.Failure(ApiError(404, "nope"))
        override suspend fun create(profileId: String): ApiResult<BroadcastSession> =
            ApiResult.Failure(ApiError(404, "nope"))
        override suspend fun schedule(
            sessionId: String,
            scheduledAtEpochSeconds: Long,
            name: String?,
            description: String?,
        ): ApiResult<BroadcastSession> = ApiResult.Failure(ApiError(404, "nope"))
        override suspend fun cancelSchedule(sessionId: String): ApiResult<BroadcastSession> =
            ApiResult.Failure(ApiError(404, "nope"))

        override suspend fun createInput(
            sessionId: String,
            inputType: String,
            label: String?,
        ): ApiResult<BroadcastInput> {
            createCalls++
            lastInputType = inputType
            lastLabel = label
            return createResult
        }
        override suspend fun activateInput(sessionId: String, inputId: String): ApiResult<Unit> =
            ApiResult.Success(Unit)
        override suspend fun deactivateInput(sessionId: String, inputId: String): ApiResult<Unit> {
            deactivateCalls++
            return ApiResult.Success(Unit)
        }
        override suspend fun removeInput(sessionId: String, inputId: String): ApiResult<Unit> {
            removeCalls++
            return ApiResult.Success(Unit)
        }
    }

    /** A publisher whose goLive result and state are configurable (for the non-FLAGGED-only branches). */
    private class FakePublisher(
        private val result: GoLiveResult,
        initial: PublishState = PublishState.Idle,
    ) : BroadcastPublisher {
        var stopCalls = 0
        private val _state = MutableStateFlow(initial)
        override val state: StateFlow<PublishState> = _state.asStateFlow()
        override suspend fun goLive(sessionId: String, inputId: String): GoLiveResult = result
        override fun stop() { stopCalls++ }
    }

    private fun vm(
        repo: BroadcastRepository,
        publisher: BroadcastPublisher,
        sessionId: String? = "bcs_1",
    ): IngestViewModel {
        val saved = SavedStateHandle(
            if (sessionId != null) mapOf(IngestViewModel.ARG_SESSION_ID to sessionId) else emptyMap(),
        )
        return IngestViewModel(repo, publisher, saved)
    }

    @Test
    fun start_createsPrimaryInput_thenFlaggedPublisher_isUnavailable() = runTest {
        val repo = FakeRepo(createResult = ApiResult.Success(input()))
        // The REAL bound seam: StubBroadcastPublisher always returns NotConfigured / Unavailable.
        val vm = vm(repo, StubBroadcastPublisher())
        vm.start()
        runCurrent()

        assertEquals(1, repo.createCalls)
        assertEquals("primary", repo.lastInputType)
        assertEquals("Host camera", repo.lastLabel)
        val state = vm.uiState.value
        assertEquals(IngestPhase.Unavailable, state.phase)
        assertTrue(state.mediaUnavailable)
        assertEquals("in_1", state.inputId)
    }

    @Test
    fun start_createInputFailure_isFailed() = runTest {
        val repo = FakeRepo(createResult = ApiResult.Failure(ApiError(403, "denied")))
        val vm = vm(repo, FakePublisher(GoLiveResult.NotConfigured))
        vm.start()
        runCurrent()

        assertEquals(IngestPhase.Failed, vm.uiState.value.phase)
        assertFalse(vm.uiState.value.mediaUnavailable)
        assertEquals("denied", vm.uiState.value.error)
    }

    @Test
    fun start_noSession_isFailed_noCreate() = runTest {
        val repo = FakeRepo(createResult = ApiResult.Success(input()))
        val vm = vm(repo, FakePublisher(GoLiveResult.NotConfigured), sessionId = null)
        vm.start()
        runCurrent()

        assertEquals(0, repo.createCalls)
        assertEquals(IngestPhase.Failed, vm.uiState.value.phase)
    }

    @Test
    fun start_publisherStarted_reachesConnected() = runTest {
        val repo = FakeRepo(createResult = ApiResult.Success(input()))
        val vm = vm(repo, FakePublisher(GoLiveResult.Started))
        vm.start()
        runCurrent()

        assertEquals(IngestPhase.Connected, vm.uiState.value.phase)
        assertNull(vm.uiState.value.error)
    }

    @Test
    fun stop_callsPublisherStop_andTearsDownInput() = runTest {
        val repo = FakeRepo(createResult = ApiResult.Success(input()))
        val publisher = FakePublisher(GoLiveResult.NotConfigured)
        val vm = vm(repo, publisher)
        vm.start()
        runCurrent()

        vm.stop()
        runCurrent()
        assertEquals(1, publisher.stopCalls)
        assertEquals(1, repo.deactivateCalls)
        assertEquals(1, repo.removeCalls)
        assertEquals(IngestPhase.PreviewReady, vm.uiState.value.phase)
    }
}
