package com.testlogon.android.feature.call.group

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.call.group.ConnQuality
import com.testlogon.android.data.call.group.GroupCall
import com.testlogon.android.data.call.group.GroupCallActive
import com.testlogon.android.data.call.group.GroupCallEnd
import com.testlogon.android.data.call.group.GroupCallLeave
import com.testlogon.android.data.call.group.GroupCallMedia
import com.testlogon.android.data.call.group.GroupCallRepository
import com.testlogon.android.data.call.group.GroupCallSignal
import com.testlogon.android.data.call.group.GroupParticipant
import com.testlogon.android.data.call.group.ParticipantState
import com.testlogon.android.data.webrtc.StubMeshConnectionManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-299 — [GroupCallViewModel] tests. A fake [GroupCallRepository] returns a 3-participant Connected call
 * (encodes AC-1) and counts leave() calls; the FLAGGED [StubMeshConnectionManager] never emits, so
 * mediaUnavailable stays true and no real peer is started.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class GroupCallViewModelTest {

    @get:Rule
    val mainDispatcher = MainDispatcherRule(UnconfinedTestDispatcher())

    private class FakeRepo : GroupCallRepository {
        var leaveCount = 0
        var lastMediaAudio: Boolean? = null

        private fun connected(userId: String, joinedAt: Long) = GroupParticipant(
            userId = userId,
            displayName = userId,
            isSelf = userId == "self",
            isHost = userId == "self",
            state = ParticipantState.Connected,
            micMuted = false,
            cameraOff = false,
            quality = ConnQuality.Good,
            joinedAt = joinedAt,
        )

        private fun call(callId: String, conversationId: String) = GroupCall(
            callId = callId,
            conversationId = conversationId,
            creatorUserId = "self",
            mode = "video",
            maxParticipants = 8,
            state = "active",
            participants = listOf(
                connected("self", 1),
                connected("u2", 2),
                connected("u3", 3),
            ),
            iceServers = emptyList(),
        )

        override suspend fun create(
            conversationId: String,
            mode: String,
            maxParticipants: Int,
            selfUserId: String?,
        ): ApiResult<GroupCall> = ApiResult.Success(call("call_new", conversationId))

        override suspend fun get(callId: String, selfUserId: String?): ApiResult<GroupCall> =
            ApiResult.Success(call(callId, "conv"))

        override suspend fun participants(
            callId: String,
            creatorUserId: String,
            selfUserId: String?,
        ): ApiResult<List<GroupParticipant>> = ApiResult.Success(call(callId, "conv").participants)

        override suspend fun active(conversationId: String): ApiResult<GroupCallActive> =
            ApiResult.Success(GroupCallActive(false, null, null, null, null))

        override suspend fun join(
            callId: String,
            conversationId: String,
            creatorUserId: String,
            selfUserId: String?,
        ): ApiResult<GroupCall> = ApiResult.Success(call(callId, conversationId))

        override suspend fun leave(callId: String): ApiResult<GroupCallLeave> {
            leaveCount++
            return ApiResult.Success(GroupCallLeave(ok = true, callEnded = false, remainingParticipants = 2))
        }

        override suspend fun end(callId: String): ApiResult<GroupCallEnd> =
            ApiResult.Success(GroupCallEnd(ok = true, callId = callId, durationSeconds = 0, totalParticipants = 3))

        override suspend fun media(
            callId: String,
            audio: Boolean?,
            video: Boolean?,
            screen: Boolean?,
        ): ApiResult<GroupCallMedia> {
            lastMediaAudio = audio
            return ApiResult.Success(GroupCallMedia(ok = true, audio = audio ?: true, video = video ?: true, screen = false))
        }

        override suspend fun signal(
            callId: String,
            type: String,
            targetUserId: String,
            payload: Map<String, Any?>?,
        ): ApiResult<GroupCallSignal> = ApiResult.Success(GroupCallSignal(ok = true, relayedTo = targetUserId))
    }

    private fun vm(savedState: SavedStateHandle, repo: FakeRepo): GroupCallViewModel =
        GroupCallViewModel(repository = repo, mesh = StubMeshConnectionManager(), savedState = savedState)

    private fun createSavedState() = SavedStateHandle(
        mapOf(
            GroupCallViewModel.ARG_CONVERSATION_ID to "conv_1",
            GroupCallViewModel.ARG_MODE to "video",
        ),
    )

    @Test
    fun create_resolvesActive_with3ConnectedParticipants_andMediaUnavailable() = runTest {
        val scope = CoroutineScope(UnconfinedTestDispatcher(testScheduler))
        val repo = FakeRepo()
        val viewModel = vm(createSavedState(), repo)

        val job = launch { viewModel.uiState.collect {} }
        runCurrent()

        val state = viewModel.uiState.value
        assertEquals(GroupCallPhase.Active, state.phase)
        assertTrue(state.participants.count { it.state == ParticipantState.Connected } >= 3)
        assertTrue(state.mediaUnavailable)

        job.cancel()
        scope.coroutineContext[Job]?.cancel()
    }

    @Test
    fun toggleMic_flipsMicEnabled_andPushesMedia() = runTest {
        val scope = CoroutineScope(UnconfinedTestDispatcher(testScheduler))
        val repo = FakeRepo()
        val viewModel = vm(createSavedState(), repo)

        val job = launch { viewModel.uiState.collect {} }
        runCurrent()

        assertTrue(viewModel.uiState.value.micEnabled)
        viewModel.onAction(GroupCallAction.ToggleMic)
        runCurrent()
        assertFalse(viewModel.uiState.value.micEnabled)
        // The optimistic mute pushes audio=false to the control plane.
        assertEquals(false, repo.lastMediaAudio)

        job.cancel()
        scope.coroutineContext[Job]?.cancel()
    }

    @Test
    fun leave_isIdempotent_callsRepositoryLeaveExactlyOnce() = runTest {
        val scope = CoroutineScope(UnconfinedTestDispatcher(testScheduler))
        val repo = FakeRepo()
        val viewModel = vm(createSavedState(), repo)

        val job = launch { viewModel.uiState.collect {} }
        runCurrent()

        viewModel.onAction(GroupCallAction.Leave)
        viewModel.onAction(GroupCallAction.Leave)
        runCurrent()

        assertEquals(1, repo.leaveCount)
        assertEquals(GroupCallPhase.Ended, viewModel.uiState.value.phase)

        job.cancel()
        scope.coroutineContext[Job]?.cancel()
    }
}
