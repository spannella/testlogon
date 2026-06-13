package com.testlogon.android.feature.guest

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-312 — unit tests for [GuestManageViewModel]. Uses MainDispatcherRule + runCurrent (never
 * advanceUntilIdle, which would spin the Eager flow + the poll loop). A fake [GuestRepository] exposes a
 * mutable guests Flow so the test drives cache emissions; polling is started explicitly, a SINGLE iteration
 * is driven by runCurrent, then stopped before the test ends.
 */
class GuestManageViewModelTest {

    @get:Rule
    val mainDispatcher = MainDispatcherRule()

    private fun guest(
        inputId: String,
        status: GuestStatus = GuestStatus.JOINED,
        muted: Boolean = false,
    ) = Guest(
        inputId = inputId,
        inviteId = "inv_$inputId",
        sessionId = SESSION,
        displayName = "Guest $inputId",
        status = status,
        mutedAudio = muted,
        connectedAt = null,
        isLive = status == GuestStatus.ONAIR,
    )

    private class FakeRepo : GuestRepository {
        val guests = MutableStateFlow<List<Guest>>(emptyList())

        var refreshResult: ApiResult<List<Guest>> = ApiResult.Success(emptyList())
        var promoteResult: ApiResult<Unit> = ApiResult.Success(Unit)
        var muteResult: ApiResult<Unit> = ApiResult.Success(Unit)
        var removeResult: ApiResult<Unit> = ApiResult.Success(Unit)

        var refreshCalls = 0
        var promoteCalls = 0
        var lastMuteValue: Boolean? = null
        var removeCalls = 0

        /** Optional gate to PARK promote() so a test can observe the in-flight window; null = resolve immediately. */
        var promoteGate: CompletableDeferred<Unit>? = null

        override fun observeGuests(sessionId: String): Flow<List<Guest>> = guests

        override suspend fun refreshGuests(sessionId: String): ApiResult<List<Guest>> {
            refreshCalls++
            return refreshResult
        }

        override suspend fun createInvite(
            sessionId: String,
            joinMode: String,
            label: String,
            expiryMinutes: Int,
        ): ApiResult<GuestInvite> = ApiResult.Success(
            GuestInvite(
                inviteId = "inv_new",
                sessionId = sessionId,
                inputId = null,
                url = "https://testlogon.app/guest/accept?inviteId=inv_new",
                ingestUrl = null,
                streamKey = null,
                joinMode = joinMode,
                status = InviteStatus.PENDING,
                expiresAt = null,
                createdAt = "",
                guestDisplayName = null,
            ),
        )

        override suspend fun revokeInvite(sessionId: String, inviteId: String): ApiResult<Unit> =
            ApiResult.Success(Unit)

        override suspend fun promote(sessionId: String, inputId: String): ApiResult<Unit> {
            promoteCalls++
            promoteGate?.await()
            return promoteResult
        }

        override suspend fun remove(sessionId: String, inputId: String): ApiResult<Unit> {
            removeCalls++
            return removeResult
        }

        override suspend fun setMuted(
            sessionId: String,
            inputId: String,
            muted: Boolean,
        ): ApiResult<Unit> {
            lastMuteValue = muted
            return muteResult
        }

        override suspend fun acceptInvite(
            sessionId: String,
            inviteId: String,
            displayName: String,
        ): ApiResult<GuestAcceptResult> =
            ApiResult.Success(GuestAcceptResult(inviteId, "in_x", "browser", sessionId, null))
    }

    private fun vm(repo: GuestRepository, sessionId: String? = SESSION): GuestManageViewModel {
        val saved = SavedStateHandle(
            if (sessionId != null) mapOf(GuestManageViewModel.ARG_SESSION_ID to sessionId) else emptyMap(),
        )
        return GuestManageViewModel(repo, saved)
    }

    @Test
    fun guests_emit_intoState() = runTest {
        val repo = FakeRepo()
        val vm = vm(repo)
        repo.guests.value = listOf(guest("a"))
        runCurrent()
        assertEquals("a", vm.uiState.value.guests.single().inputId)
    }

    @Test
    fun promote_optimistic_inFlightThenClearedAndReconciled() = runTest {
        val repo = FakeRepo()
        repo.guests.value = listOf(guest("a"))
        // Park promote() so the in-flight window is observable (uiState is a combine().stateIn — the inFlight
        // update only reaches uiState.value after a scheduler tick, and an un-parked fake would resolve fully
        // in that same runCurrent, clearing it before we can assert).
        repo.promoteGate = CompletableDeferred()
        val vm = vm(repo)
        runCurrent()

        vm.onPromote("a")
        runCurrent()
        assertTrue(vm.uiState.value.inFlight.contains("a"))

        // Release the parked call -> success path clears in-flight and reconciles.
        repo.promoteGate!!.complete(Unit)
        runCurrent()

        assertEquals(1, repo.promoteCalls)
        assertFalse(vm.uiState.value.inFlight.contains("a"))
        // A successful mutation triggers an immediate reconcile refresh.
        assertTrue(repo.refreshCalls >= 1)
    }

    @Test
    fun promote_failure_rollsBack_andErrors() = runTest {
        val repo = FakeRepo()
        repo.guests.value = listOf(guest("a"))
        repo.promoteResult = ApiResult.Failure(ApiError(409, "conflict"))
        val vm = vm(repo)
        runCurrent()

        vm.onPromote("a")
        runCurrent()

        assertFalse(vm.uiState.value.inFlight.contains("a"))
        assertEquals("conflict", vm.uiState.value.error)
    }

    @Test
    fun toggleMute_sendsRequestedValue() = runTest {
        val repo = FakeRepo()
        repo.guests.value = listOf(guest("a", muted = false))
        val vm = vm(repo)
        runCurrent()

        vm.onToggleMute("a", muted = true)
        runCurrent()
        assertEquals(true, repo.lastMuteValue)
    }

    @Test
    fun remove_onlyAfterConfirm_callsRepo() = runTest {
        val repo = FakeRepo()
        repo.guests.value = listOf(guest("a"))
        val vm = vm(repo)
        runCurrent()

        // The screen calls onRemove only after the confirm dialog is accepted; the VM has no separate
        // "request" step, so a direct onRemove represents the post-confirm action.
        assertEquals(0, repo.removeCalls)
        vm.onRemove("a")
        runCurrent()
        assertEquals(1, repo.removeCalls)
    }

    @Test
    fun polling_singleIteration_setsStaleOnFailure() = runTest {
        val repo = FakeRepo()
        repo.guests.value = listOf(guest("a"))
        repo.refreshResult = ApiResult.NetworkError(java.io.IOException("offline"), isTimeout = false)
        val vm = vm(repo)

        // Drive exactly one poll iteration via the start/stop seam, then stop so runTest's end-of-test
        // drain doesn't spin the parked delay loop forever.
        vm.startPolling()
        runCurrent()
        vm.stopPolling()

        assertTrue(vm.uiState.value.isStale)
        assertTrue(repo.refreshCalls >= 1)
    }

    @Test
    fun noSession_isError_noMutations() = runTest {
        val repo = FakeRepo()
        val vm = vm(repo, sessionId = null)
        runCurrent()

        assertFalse(vm.uiState.value.isLoading)
        assertEquals("No broadcast session is available.", vm.uiState.value.error)
        vm.onPromote("a")
        runCurrent()
        assertEquals(0, repo.promoteCalls)
    }

    @Test
    fun createInvite_surfacesInviteCard() = runTest {
        val repo = FakeRepo()
        val vm = vm(repo)
        runCurrent()

        vm.onCreateInvite()
        runCurrent()
        assertEquals("inv_new", vm.uiState.value.invite?.inviteId)
        assertNull(vm.uiState.value.error)
    }

    private companion object {
        const val SESSION = "bcs_1"
    }
}
