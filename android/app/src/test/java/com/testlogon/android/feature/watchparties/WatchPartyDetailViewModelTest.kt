package com.testlogon.android.feature.watchparties

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.watchparties.ParticipantRole
import com.testlogon.android.data.watchparties.ParticipantStatus
import com.testlogon.android.data.watchparties.WatchParty
import com.testlogon.android.data.watchparties.WatchPartyParticipant
import com.testlogon.android.data.watchparties.WatchPartyStatus
import com.testlogon.android.data.messaging.realtime.MessagingEvent
import com.testlogon.android.data.messaging.realtime.MessagingStreamEvent
import com.testlogon.android.feature.messaging.FakeMessagingEventStream
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class WatchPartyDetailViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private fun party(id: String = "wp_1") = WatchParty(
        id = id,
        hostUserSub = "host",
        videoId = "vid_1",
        videoTitle = "Video",
        videoDurationSeconds = 120,
        title = "Party",
        inviteCode = "ABC123",
        status = WatchPartyStatus.WAITING,
        maxParticipants = 50,
        participantCount = 1,
        positionSeconds = 0,
        positionUpdatedAtSeconds = 0,
        createdAtSeconds = 1,
        endedAtSeconds = null,
    )

    private fun participant(
        sub: String = "u1",
        role: ParticipantRole = ParticipantRole.MEMBER,
        status: ParticipantStatus = ParticipantStatus.ACTIVE,
    ) = WatchPartyParticipant(
        userSub = sub,
        role = role,
        status = status,
        joinedAtSeconds = 1,
    )

    private fun handle(partyId: String = "wp_1") =
        SavedStateHandle(mapOf(WatchPartyDetailViewModel.ARG_PARTY_ID to partyId))

    private val stream = FakeMessagingEventStream()

    /** Minimal AuthStateStore double seeded with a fixed signed-in user (host-gating source). */
    private fun authStore(userSub: String?) = object : com.testlogon.android.data.auth.AuthStateStore {
        override val isAuthenticated =
            kotlinx.coroutines.flow.MutableStateFlow(userSub != null)
        override val userSub =
            kotlinx.coroutines.flow.MutableStateFlow(userSub)
        override suspend fun setAuthenticated(userSub: String) {}
        override suspend fun clear(reason: com.testlogon.android.core.model.LogoutReason) {}
        override suspend fun lastLogoutReason(): com.testlogon.android.core.model.LogoutReason? = null
        override suspend fun clearLogoutReason() {}
    }

    private fun vmOf(
        repo: WatchPartiesViewModelTest.FakeWatchPartiesRepository,
        partyId: String = "wp_1",
        currentUserSub: String? = "host",
    ) = WatchPartyDetailViewModel(repo, stream, authStore(currentUserSub), handle(partyId))

    @Test
    fun load_success_movesToContent_withPartyAndParticipants() = runTest {
        val repo = WatchPartiesViewModelTest.FakeWatchPartiesRepository().apply {
            getResult = ApiResult.Success(party())
            participantsResult = ApiResult.Success(listOf(participant("a"), participant("b")))
        }
        val vm = vmOf(repo)
        advanceUntilIdle()

        assertEquals(WatchPartyDetailUiState.Phase.Content, vm.uiState.value.phase)
        assertNotNull(vm.uiState.value.party)
        assertEquals("wp_1", vm.uiState.value.party?.id)
        assertEquals(2, vm.uiState.value.participants.size)
    }

    @Test
    fun load_failure401_movesToSessionExpired() = runTest {
        val repo = WatchPartiesViewModelTest.FakeWatchPartiesRepository().apply {
            getResult = ApiResult.Failure(ApiError(401, "nope"))
        }
        val vm = vmOf(repo)
        advanceUntilIdle()

        assertEquals(WatchPartyDetailUiState.Phase.SessionExpired, vm.uiState.value.phase)
    }

    @Test
    fun load_failure500_movesToError() = runTest {
        val repo = WatchPartiesViewModelTest.FakeWatchPartiesRepository().apply {
            getResult = ApiResult.Failure(ApiError(500, "boom"))
        }
        val vm = vmOf(repo)
        advanceUntilIdle()

        assertEquals(WatchPartyDetailUiState.Phase.Error, vm.uiState.value.phase)
        assertEquals("boom", vm.uiState.value.errorMessage)
    }

    @Test
    fun join_callsRepoJoin_emitsMessage_andReloads() = runTest {
        val repo = WatchPartiesViewModelTest.FakeWatchPartiesRepository().apply {
            getResult = ApiResult.Success(party())
            participantsResult = ApiResult.Success(listOf(participant("a")))
            joinResult = ApiResult.Success(Unit)
        }
        val vm = vmOf(repo, "wp_join")
        advanceUntilIdle()

        val effects = mutableListOf<WatchPartyDetailEffect>()
        val job = CoroutineScope(UnconfinedTestDispatcher(testScheduler)).launch {
            vm.effects.collect { effects += it }
        }
        vm.onJoin()
        advanceUntilIdle()
        job.cancel()

        assertEquals(1, repo.joinCalls)
        assertEquals("wp_join", repo.lastJoinPartyId)
        assertTrue(effects.any { it is WatchPartyDetailEffect.ShowMessage })
        assertFalse(vm.uiState.value.isMutating)
        assertEquals(WatchPartyDetailUiState.Phase.Content, vm.uiState.value.phase)
    }

    @Test
    fun join_failure_emitsMessage_andClearsMutating() = runTest {
        val repo = WatchPartiesViewModelTest.FakeWatchPartiesRepository().apply {
            getResult = ApiResult.Success(party())
            participantsResult = ApiResult.Success(emptyList())
            joinResult = ApiResult.Failure(ApiError(500, "join failed"))
        }
        val vm = vmOf(repo)
        advanceUntilIdle()

        val effects = mutableListOf<WatchPartyDetailEffect>()
        val job = CoroutineScope(UnconfinedTestDispatcher(testScheduler)).launch {
            vm.effects.collect { effects += it }
        }
        vm.onJoin()
        advanceUntilIdle()
        job.cancel()

        assertEquals(1, repo.joinCalls)
        assertTrue(effects.any { it is WatchPartyDetailEffect.ShowMessage })
        assertFalse(vm.uiState.value.isMutating)
    }

    @Test
    fun leave_callsRepoLeave_emitsMessage_andReloads() = runTest {
        val repo = WatchPartiesViewModelTest.FakeWatchPartiesRepository().apply {
            getResult = ApiResult.Success(party())
            participantsResult = ApiResult.Success(emptyList())
            leaveResult = ApiResult.Success(Unit)
        }
        val vm = vmOf(repo, "wp_leave")
        advanceUntilIdle()

        val effects = mutableListOf<WatchPartyDetailEffect>()
        val job = CoroutineScope(UnconfinedTestDispatcher(testScheduler)).launch {
            vm.effects.collect { effects += it }
        }
        vm.onLeave()
        advanceUntilIdle()
        job.cancel()

        assertEquals(1, repo.leaveCalls)
        assertEquals("wp_leave", repo.lastLeavePartyId)
        assertTrue(effects.any { it is WatchPartyDetailEffect.ShowMessage })
        assertFalse(vm.uiState.value.isMutating)
    }

    @Test
    fun activeParticipants_filtersNonActive() = runTest {
        val repo = WatchPartiesViewModelTest.FakeWatchPartiesRepository().apply {
            getResult = ApiResult.Success(party())
            participantsResult = ApiResult.Success(
                listOf(
                    participant("active"),
                    WatchPartyParticipant("left", ParticipantRole.MEMBER, ParticipantStatus.LEFT, 1),
                ),
            )
        }
        val vm = vmOf(repo)
        advanceUntilIdle()

        assertEquals(2, vm.uiState.value.participants.size)
        assertEquals(1, vm.uiState.value.activeParticipants.size)
        assertEquals("active", vm.uiState.value.activeParticipants.single().userSub)
    }
    @Test
    fun playbackSync_hostPlayFrameForThisParty_updatesLivePlaybackState() = runTest {
        val repo = WatchPartiesViewModelTest.FakeWatchPartiesRepository().apply {
            getResult = ApiResult.Success(party("wp_sync"))
            participantsResult = ApiResult.Success(listOf(participant("me")))
        }
        val vm = vmOf(repo, "wp_sync")
        advanceUntilIdle()
        assertEquals(null, vm.uiState.value.playbackSync)

        stream.send(
            MessagingStreamEvent.Event(
                MessagingEvent.PlaybackSync(
                    partyId = "wp_sync",
                    action = "play",
                    status = "playing",
                    positionSeconds = 123.5,
                    positionUpdatedAtEpochSeconds = 1_000L,
                    controlledBy = "host",
                    serverTimeEpochSeconds = 1_000L,
                ),
            ),
        )
        advanceUntilIdle()

        val sync = vm.uiState.value.playbackSync
        assertNotNull(sync)
        assertTrue(sync!!.isPlaying)
        assertEquals(123.5, sync.positionSeconds, 0.001)
        assertEquals("host", sync.controlledBy)
        assertEquals("play", sync.lastAction)
        // Extrapolation advances while playing; drift beyond tolerance triggers a re-seek.
        assertEquals(133.5, sync.targetPositionSeconds(1_010L), 0.001)
        assertTrue(sync.shouldReseek(localPositionSeconds = 100.0, nowEpochSeconds = 1_000L))
        assertFalse(sync.shouldReseek(localPositionSeconds = 123.0, nowEpochSeconds = 1_000L))
    }

    @Test
    fun playbackSync_frameForDifferentParty_isIgnored() = runTest {
        val repo = WatchPartiesViewModelTest.FakeWatchPartiesRepository().apply {
            getResult = ApiResult.Success(party("wp_mine"))
            participantsResult = ApiResult.Success(emptyList())
        }
        val vm = vmOf(repo, "wp_mine")
        advanceUntilIdle()

        stream.send(
            MessagingStreamEvent.Event(
                MessagingEvent.PlaybackSync(
                    partyId = "wp_other",
                    action = "pause",
                    status = "paused",
                    positionSeconds = 42.0,
                    positionUpdatedAtEpochSeconds = 5L,
                    controlledBy = "host",
                    serverTimeEpochSeconds = 5L,
                ),
            ),
        )
        advanceUntilIdle()

        assertEquals(null, vm.uiState.value.playbackSync)
    }

    // ---- Host controls ----

    @Test
    fun onPlay_asHost_postsControl_andReflectsPlayback() = runTest {
        val repo = WatchPartiesViewModelTest.FakeWatchPartiesRepository().apply {
            getResult = ApiResult.Success(party())
            participantsResult = ApiResult.Success(listOf(participant("host", ParticipantRole.HOST)))
            controlResult = ApiResult.Success(
                party().copy(status = WatchPartyStatus.PLAYING, positionSeconds = 5, positionUpdatedAtSeconds = 100),
            )
        }
        val vm = vmOf(repo, currentUserSub = "host")
        advanceUntilIdle()
        assertTrue(vm.uiState.value.canControlPlayback)

        vm.onPlay()
        advanceUntilIdle()

        assertEquals(1, repo.controlCalls)
        assertEquals("play", repo.lastControlAction)
        assertFalse(vm.uiState.value.isControlling)
        assertTrue(vm.uiState.value.playbackSync?.isPlaying == true)
    }

    @Test
    fun onSeek_asActiveCoHost_postsSeekWithPosition() = runTest {
        val repo = WatchPartiesViewModelTest.FakeWatchPartiesRepository().apply {
            getResult = ApiResult.Success(party())
            participantsResult = ApiResult.Success(listOf(participant("bob", ParticipantRole.CO_HOST)))
            controlResult = ApiResult.Success(party())
        }
        val vm = vmOf(repo, currentUserSub = "bob")
        advanceUntilIdle()
        assertTrue(vm.uiState.value.canControlPlayback)

        vm.onSeek(42.0)
        advanceUntilIdle()

        assertEquals(1, repo.controlCalls)
        assertEquals("seek", repo.lastControlAction)
        assertEquals(42.0, repo.lastControlPosition!!, 0.001)
    }

    @Test
    fun onPlay_asPlainMember_isRejected_noRepoCall() = runTest {
        val repo = WatchPartiesViewModelTest.FakeWatchPartiesRepository().apply {
            getResult = ApiResult.Success(party())
            participantsResult = ApiResult.Success(listOf(participant("mallory", ParticipantRole.MEMBER)))
        }
        val vm = vmOf(repo, currentUserSub = "mallory")
        advanceUntilIdle()
        assertFalse(vm.uiState.value.canControlPlayback)

        val effects = mutableListOf<WatchPartyDetailEffect>()
        val job = CoroutineScope(UnconfinedTestDispatcher(testScheduler)).launch { vm.effects.collect { effects += it } }
        vm.onPlay()
        advanceUntilIdle()
        job.cancel()

        assertEquals(0, repo.controlCalls)
        assertTrue(effects.any { it is WatchPartyDetailEffect.ShowMessage })
    }

    @Test
    fun onGrantCoHost_asHost_postsAndReloads() = runTest {
        val repo = WatchPartiesViewModelTest.FakeWatchPartiesRepository().apply {
            getResult = ApiResult.Success(party())
            participantsResult = ApiResult.Success(listOf(participant("bob")))
            coHostResult = ApiResult.Success(Unit)
        }
        val vm = vmOf(repo, currentUserSub = "host")
        advanceUntilIdle()

        vm.onGrantCoHost("bob")
        advanceUntilIdle()

        assertEquals(1, repo.coHostCalls)
        assertEquals("bob", repo.lastCoHostTarget)
        assertFalse(vm.uiState.value.isControlling)
    }

    @Test
    fun onGrantCoHost_asNonHost_isRejected() = runTest {
        val repo = WatchPartiesViewModelTest.FakeWatchPartiesRepository().apply {
            getResult = ApiResult.Success(party())
            participantsResult = ApiResult.Success(listOf(participant("bob", ParticipantRole.CO_HOST)))
        }
        val vm = vmOf(repo, currentUserSub = "bob")
        advanceUntilIdle()

        vm.onGrantCoHost("someone")
        advanceUntilIdle()

        assertEquals(0, repo.coHostCalls)
    }

    @Test
    fun onKick_asHost_postsAndReloads() = runTest {
        val repo = WatchPartiesViewModelTest.FakeWatchPartiesRepository().apply {
            getResult = ApiResult.Success(party())
            participantsResult = ApiResult.Success(listOf(participant("bob")))
            kickResult = ApiResult.Success(Unit)
        }
        val vm = vmOf(repo, currentUserSub = "host")
        advanceUntilIdle()

        vm.onKick("bob")
        advanceUntilIdle()

        assertEquals(1, repo.kickCalls)
        assertEquals("bob", repo.lastKickTarget)
    }

    @Test
    fun onEnd_asHost_postsAndSetsEndedParty() = runTest {
        val repo = WatchPartiesViewModelTest.FakeWatchPartiesRepository().apply {
            getResult = ApiResult.Success(party())
            participantsResult = ApiResult.Success(emptyList())
            endResult = ApiResult.Success(party().copy(status = WatchPartyStatus.ENDED, endedAtSeconds = 999))
        }
        val vm = vmOf(repo, currentUserSub = "host")
        advanceUntilIdle()

        vm.onEnd()
        advanceUntilIdle()

        assertEquals(1, repo.endCalls)
    }

    @Test
    fun onEnd_asNonHost_isRejected() = runTest {
        val repo = WatchPartiesViewModelTest.FakeWatchPartiesRepository().apply {
            getResult = ApiResult.Success(party())
            participantsResult = ApiResult.Success(listOf(participant("bob", ParticipantRole.CO_HOST)))
        }
        val vm = vmOf(repo, currentUserSub = "bob")
        advanceUntilIdle()

        vm.onEnd()
        advanceUntilIdle()

        assertEquals(0, repo.endCalls)
    }
}
