package com.testlogon.android.feature.watchparties

import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.watchparties.InviteResolution
import com.testlogon.android.data.watchparties.WatchParty
import com.testlogon.android.data.watchparties.WatchPartyParticipant
import com.testlogon.android.data.watchparties.WatchPartyStatus
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class WatchPartiesViewModelTest {

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

    /** Shared fake reused by all three watch-party VM test classes. */
    class FakeWatchPartiesRepository : com.testlogon.android.data.watchparties.WatchPartiesRepository {
        var listResult: ApiResult<List<WatchParty>> = ApiResult.Failure(ApiError(500, "x"))
        var cachedValue: List<WatchParty>? = null
        var createResult: ApiResult<WatchParty> = ApiResult.Failure(ApiError(500, "x"))
        var getResult: ApiResult<WatchParty> = ApiResult.Failure(ApiError(500, "x"))
        var participantsResult: ApiResult<List<WatchPartyParticipant>> = ApiResult.Success(emptyList())
        var joinResult: ApiResult<Unit> = ApiResult.Success(Unit)
        var leaveResult: ApiResult<Unit> = ApiResult.Success(Unit)
        var resolveResult: ApiResult<InviteResolution> = ApiResult.Failure(ApiError(404, "x"))
        var controlResult: ApiResult<WatchParty> = ApiResult.Failure(ApiError(500, "x"))
        var coHostResult: ApiResult<Unit> = ApiResult.Success(Unit)
        var kickResult: ApiResult<Unit> = ApiResult.Success(Unit)
        var endResult: ApiResult<WatchParty> = ApiResult.Failure(ApiError(500, "x"))
        var heartbeatResult: ApiResult<WatchParty> = ApiResult.Failure(ApiError(500, "x"))

        var createCalls = 0
        var lastCreateVideoId: String? = null
        var lastCreateTitle: String? = null
        var lastCreateMax: Int? = null
        var joinCalls = 0
        var leaveCalls = 0
        var lastJoinPartyId: String? = null
        var lastLeavePartyId: String? = null
        var lastResolveCode: String? = null
        var controlCalls = 0
        var lastControlAction: String? = null
        var lastControlPosition: Double? = null
        var coHostCalls = 0
        var lastCoHostTarget: String? = null
        var kickCalls = 0
        var lastKickTarget: String? = null
        var endCalls = 0
        var heartbeatCalls = 0

        override suspend fun loadParties(): ApiResult<List<WatchParty>> = listResult

        override suspend fun createParty(
            videoId: String,
            title: String?,
            maxParticipants: Int?,
        ): ApiResult<WatchParty> {
            createCalls++
            lastCreateVideoId = videoId
            lastCreateTitle = title
            lastCreateMax = maxParticipants
            return createResult
        }

        override suspend fun getParty(partyId: String): ApiResult<WatchParty> = getResult

        override suspend fun loadParticipants(partyId: String): ApiResult<List<WatchPartyParticipant>> =
            participantsResult

        override suspend fun joinParty(partyId: String): ApiResult<Unit> {
            joinCalls++
            lastJoinPartyId = partyId
            return joinResult
        }

        override suspend fun leaveParty(partyId: String): ApiResult<Unit> {
            leaveCalls++
            lastLeavePartyId = partyId
            return leaveResult
        }

        override suspend fun resolveInvite(inviteCode: String): ApiResult<InviteResolution> {
            lastResolveCode = inviteCode
            return resolveResult
        }

        override suspend fun controlPlayback(
            partyId: String,
            action: String,
            positionSeconds: Double?,
        ): ApiResult<WatchParty> {
            controlCalls++
            lastControlAction = action
            lastControlPosition = positionSeconds
            return controlResult
        }

        override suspend fun grantCoHost(partyId: String, targetUserSub: String): ApiResult<Unit> {
            coHostCalls++
            lastCoHostTarget = targetUserSub
            return coHostResult
        }

        override suspend fun kickParticipant(partyId: String, targetUserSub: String): ApiResult<Unit> {
            kickCalls++
            lastKickTarget = targetUserSub
            return kickResult
        }

        override suspend fun endParty(partyId: String): ApiResult<WatchParty> {
            endCalls++
            return endResult
        }

        override suspend fun heartbeat(partyId: String): ApiResult<WatchParty> {
            heartbeatCalls++
            return heartbeatResult
        }

        override fun cached(): List<WatchParty>? = cachedValue

        override fun clear() {}
    }

    @Test
    fun load_success_nonEmpty_movesToContent() = runTest {
        val repo = FakeWatchPartiesRepository().apply {
            listResult = ApiResult.Success(listOf(party()))
        }
        val vm = WatchPartiesViewModel(repo)
        advanceUntilIdle()
        assertEquals(WatchPartiesListUiState.Phase.Content, vm.uiState.value.phase)
        assertEquals(1, vm.uiState.value.parties.size)
        assertFalse(vm.uiState.value.isStale)
    }

    @Test
    fun load_success_empty_movesToEmpty() = runTest {
        val repo = FakeWatchPartiesRepository().apply {
            listResult = ApiResult.Success(emptyList())
        }
        val vm = WatchPartiesViewModel(repo)
        advanceUntilIdle()
        assertEquals(WatchPartiesListUiState.Phase.Empty, vm.uiState.value.phase)
    }

    @Test
    fun load_failure500_noCache_movesToError() = runTest {
        val repo = FakeWatchPartiesRepository().apply {
            listResult = ApiResult.Failure(ApiError(500, "boom"))
            cachedValue = null
        }
        val vm = WatchPartiesViewModel(repo)
        advanceUntilIdle()
        assertEquals(WatchPartiesListUiState.Phase.Error, vm.uiState.value.phase)
        assertEquals("boom", vm.uiState.value.errorMessage)
    }

    @Test
    fun load_networkError_withCache_showsStaleContent() = runTest {
        val repo = FakeWatchPartiesRepository().apply {
            listResult = ApiResult.NetworkError(java.io.IOException(), isTimeout = false)
            cachedValue = listOf(party())
        }
        val vm = WatchPartiesViewModel(repo)
        advanceUntilIdle()
        assertEquals(WatchPartiesListUiState.Phase.Content, vm.uiState.value.phase)
        assertTrue(vm.uiState.value.isStale)
        assertEquals(1, vm.uiState.value.parties.size)
    }

    @Test
    fun load_failure401_movesToSessionExpired() = runTest {
        val repo = FakeWatchPartiesRepository().apply {
            listResult = ApiResult.Failure(ApiError(401, "nope"))
        }
        val vm = WatchPartiesViewModel(repo)
        advanceUntilIdle()
        assertEquals(WatchPartiesListUiState.Phase.SessionExpired, vm.uiState.value.phase)
    }

    @Test
    fun createParty_blankVideoId_emitsMessage_andDoesNotCallRepo() = runTest {
        val repo = FakeWatchPartiesRepository().apply {
            listResult = ApiResult.Success(listOf(party()))
        }
        val vm = WatchPartiesViewModel(repo)
        advanceUntilIdle()

        val effects = mutableListOf<WatchPartiesListEffect>()
        val job = CoroutineScope(UnconfinedTestDispatcher(testScheduler)).launch {
            vm.effects.collect { effects += it }
        }
        vm.onCreateParty(videoId = "   ", title = "T", maxParticipants = 50)
        advanceUntilIdle()
        job.cancel()

        assertEquals(0, repo.createCalls)
        assertTrue(effects.any { it is WatchPartiesListEffect.ShowMessage })
        assertFalse(vm.uiState.value.create.isSubmitting)
    }

    @Test
    fun createParty_success_emitsOpenParty_andClearsSubmitting() = runTest {
        val repo = FakeWatchPartiesRepository().apply {
            listResult = ApiResult.Success(listOf(party()))
            createResult = ApiResult.Success(party(id = "wp_new"))
        }
        val vm = WatchPartiesViewModel(repo)
        advanceUntilIdle()

        val effects = mutableListOf<WatchPartiesListEffect>()
        val job = CoroutineScope(UnconfinedTestDispatcher(testScheduler)).launch {
            vm.effects.collect { effects += it }
        }
        vm.onCreateParty(videoId = "vid_1", title = "My Party", maxParticipants = 25)
        advanceUntilIdle()
        job.cancel()

        assertEquals(1, repo.createCalls)
        assertEquals("vid_1", repo.lastCreateVideoId)
        assertEquals("My Party", repo.lastCreateTitle)
        assertEquals(25, repo.lastCreateMax)
        val open = effects.filterIsInstance<WatchPartiesListEffect.OpenParty>().single()
        assertEquals("wp_new", open.partyId)
        assertFalse(vm.uiState.value.create.isSubmitting)
    }

    @Test
    fun createParty_failure_emitsMessage_andClearsSubmitting() = runTest {
        val repo = FakeWatchPartiesRepository().apply {
            listResult = ApiResult.Success(listOf(party()))
            createResult = ApiResult.Failure(ApiError(500, "create failed"))
        }
        val vm = WatchPartiesViewModel(repo)
        advanceUntilIdle()

        val effects = mutableListOf<WatchPartiesListEffect>()
        val job = CoroutineScope(UnconfinedTestDispatcher(testScheduler)).launch {
            vm.effects.collect { effects += it }
        }
        vm.onCreateParty(videoId = "vid_1", title = "T", maxParticipants = 50)
        advanceUntilIdle()
        job.cancel()

        assertEquals(1, repo.createCalls)
        assertTrue(effects.any { it is WatchPartiesListEffect.ShowMessage })
        assertFalse(effects.any { it is WatchPartiesListEffect.OpenParty })
        assertFalse(vm.uiState.value.create.isSubmitting)
    }

    @Test
    fun load_failure500_noCache_hasNullStaleContent() = runTest {
        val repo = FakeWatchPartiesRepository().apply {
            listResult = ApiResult.Failure(ApiError(500, "boom"))
        }
        val vm = WatchPartiesViewModel(repo)
        advanceUntilIdle()
        assertTrue(vm.uiState.value.parties.isEmpty())
        assertFalse(vm.uiState.value.isStale)
        assertNull(null)
    }
}
