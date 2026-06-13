package com.testlogon.android.feature.guest

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
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
 * AND-312 — unit tests for [GuestAcceptViewModel]. A blank display name is blocked; an accept success exposes
 * the input_id / ingest_url (for the AND-308 handoff); a failure surfaces an error. MainDispatcherRule +
 * runCurrent (never advanceUntilIdle).
 */
class GuestAcceptViewModelTest {

    @get:Rule
    val mainDispatcher = MainDispatcherRule()

    private class FakeRepo : GuestRepository {
        var acceptResult: ApiResult<GuestAcceptResult> =
            ApiResult.Success(GuestAcceptResult("inv_1", "in_9", "rtmp", "bcs_1", "rtmps://ingest/app"))
        var acceptCalls = 0
        var lastDisplayName: String? = null

        override fun observeGuests(sessionId: String): Flow<List<Guest>> = MutableStateFlow(emptyList())
        override suspend fun refreshGuests(sessionId: String): ApiResult<List<Guest>> =
            ApiResult.Success(emptyList())
        override suspend fun createInvite(
            sessionId: String,
            joinMode: String,
            label: String,
            expiryMinutes: Int,
        ): ApiResult<GuestInvite> = throw UnsupportedOperationException()
        override suspend fun revokeInvite(sessionId: String, inviteId: String): ApiResult<Unit> =
            ApiResult.Success(Unit)
        override suspend fun promote(sessionId: String, inputId: String): ApiResult<Unit> =
            ApiResult.Success(Unit)
        override suspend fun remove(sessionId: String, inputId: String): ApiResult<Unit> =
            ApiResult.Success(Unit)
        override suspend fun setMuted(
            sessionId: String,
            inputId: String,
            muted: Boolean,
        ): ApiResult<Unit> = ApiResult.Success(Unit)

        override suspend fun acceptInvite(
            sessionId: String,
            inviteId: String,
            displayName: String,
        ): ApiResult<GuestAcceptResult> {
            acceptCalls++
            lastDisplayName = displayName
            return acceptResult
        }
    }

    private fun vm(repo: GuestRepository): GuestAcceptViewModel {
        val saved = SavedStateHandle(
            mapOf(
                GuestAcceptViewModel.ARG_SESSION_ID to "bcs_1",
                GuestAcceptViewModel.ARG_INVITE_ID to "inv_1",
            ),
        )
        return GuestAcceptViewModel(repo, saved)
    }

    @Test
    fun blankName_blocksAccept() = runTest {
        val repo = FakeRepo()
        val vm = vm(repo)
        assertFalse(vm.uiState.value.canSubmit)

        vm.onAccept()
        runCurrent()
        assertEquals(0, repo.acceptCalls)

        vm.onDisplayNameChange("   ")
        assertFalse(vm.uiState.value.canSubmit)
        vm.onAccept()
        runCurrent()
        assertEquals(0, repo.acceptCalls)
    }

    @Test
    fun accept_success_exposesInputAndIngest() = runTest {
        val repo = FakeRepo()
        val vm = vm(repo)
        vm.onDisplayNameChange("Ada")
        assertTrue(vm.uiState.value.canSubmit)

        vm.onAccept()
        runCurrent()

        assertEquals("Ada", repo.lastDisplayName)
        val accepted = vm.uiState.value.accepted
        assertEquals("in_9", accepted?.inputId)
        assertEquals("rtmps://ingest/app", accepted?.ingestUrl)
        assertFalse(vm.uiState.value.isSubmitting)
    }

    @Test
    fun accept_failure_surfacesError() = runTest {
        val repo = FakeRepo()
        repo.acceptResult = ApiResult.Failure(ApiError(410, "gone"))
        val vm = vm(repo)
        vm.onDisplayNameChange("Ada")

        vm.onAccept()
        runCurrent()

        assertEquals("gone", vm.uiState.value.error)
        assertNull(vm.uiState.value.accepted)
    }
}
