package com.testlogon.android.feature.privacy.deletion

import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.privacy.DeletionStatus
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-386 - AccountDeletionViewModel unit tests (TC-AND-386-03, 04, 05, 06, 07, 08, 09). Uses a fake
 * repository; no nested runTest; the StandardTestDispatcher is driven with runCurrent (NOT advanceUntilIdle).
 * The VM exposes a plain MutableStateFlow so no hot collector is needed.
 */
class AccountDeletionViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private val repo = FakeAccountDeletionRepository()

    private fun vm() = AccountDeletionViewModel(repo)

    private fun ready(state: AccountDeletionUiState): AccountDeletionUiState.Ready =
        state as AccountDeletionUiState.Ready

    // Entry fetch -> Ready(Active).
    @Test
    fun load_active_mapsToReadyActive() = runTest {
        repo.statusResult = ApiResult.Success(DeletionStatus.Active)
        val vm = vm()
        vm.load()
        runCurrent()
        assertEquals(DeletionStatus.Active, ready(vm.uiState.value).status)
    }

    // Entry with pending -> Ready(Pending).
    @Test
    fun load_pending_mapsToReadyPending() = runTest {
        val pending = DeletionStatus.Pending("del_1", 1_000L, 2_000L, 14, true)
        repo.statusResult = ApiResult.Success(pending)
        val vm = vm()
        vm.load()
        runCurrent()
        assertEquals(pending, ready(vm.uiState.value).status)
    }

    // TC-AND-386-03: multi-step gating; case sensitivity; empty password.
    @Test
    fun showFinalDialog_noopUnlessSentinelAndPassword() = runTest {
        val vm = vm()
        vm.load(); runCurrent()
        vm.onEvent(AccountDeletionEvent.StartRequest)
        vm.onEvent(AccountDeletionEvent.AdvanceFromWarning)

        // Wrong case + empty password -> still locked, ShowFinalDialog is a no-op.
        vm.onEvent(AccountDeletionEvent.TypedConfirmationChanged("delete my account"))
        vm.onEvent(AccountDeletionEvent.ShowFinalDialog)
        assertEquals(ConfirmStep.TypeToConfirm, ready(vm.uiState.value).confirmStep)
        assertFalse(ready(vm.uiState.value).confirmUnlocked)

        // Exact sentinel but empty password -> still locked.
        vm.onEvent(AccountDeletionEvent.TypedConfirmationChanged(DELETE_SENTINEL))
        vm.onEvent(AccountDeletionEvent.ShowFinalDialog)
        assertEquals(ConfirmStep.TypeToConfirm, ready(vm.uiState.value).confirmStep)

        // Sentinel + password -> unlocked, advances to FinalDialog.
        vm.onEvent(AccountDeletionEvent.PasswordChanged("pw"))
        vm.onEvent(AccountDeletionEvent.ShowFinalDialog)
        assertEquals(ConfirmStep.FinalDialog, ready(vm.uiState.value).confirmStep)
        assertEquals(0, repo.requestCount)
    }

    // TC-AND-386-04: a confirmed request sends the right body once and transitions to pending.
    @Test
    fun confirmDelete_sendsBodyOnce_andTransitionsToPending() = runTest {
        val vm = vm()
        vm.load(); runCurrent()
        drive(vm, password = "pw", reason = "leaving")
        vm.onEvent(AccountDeletionEvent.ConfirmDelete)
        runCurrent()

        assertEquals(1, repo.requestCount)
        assertEquals("pw", repo.lastPassword)
        assertEquals(DELETE_SENTINEL, repo.lastConfirmText)
        assertEquals("leaving", repo.lastReason)
        val st = ready(vm.uiState.value)
        assertTrue(st.status is DeletionStatus.Pending)
        assertEquals(AccountDeletionViewModel.MSG_REQUEST_OK, st.transient?.text)
        assertFalse(st.transient!!.isError)
    }

    // TC-AND-386-05: double-submit guard.
    @Test
    fun confirmDelete_secondWhileInFlight_isIgnored() = runTest {
        val vm = vm()
        vm.load(); runCurrent()
        drive(vm, password = "pw")
        vm.onEvent(AccountDeletionEvent.ConfirmDelete)
        // Without runCurrent the first mutation is still in-flight; a second confirm must be ignored.
        vm.onEvent(AccountDeletionEvent.ConfirmDelete)
        runCurrent()
        assertEquals(1, repo.requestCount)
    }

    // TC-AND-386-06: a request failure shows an error and does not flip to pending.
    @Test
    fun confirmDelete_failure_showsErrorAndStaysActive() = runTest {
        repo.requestResult = ApiResult.Failure(ApiError(status = 422, message = "bad pw"))
        val vm = vm()
        vm.load(); runCurrent()
        drive(vm, password = "wrong")
        vm.onEvent(AccountDeletionEvent.ConfirmDelete)
        runCurrent()
        assertEquals(1, repo.requestCount)
        val st = ready(vm.uiState.value)
        assertEquals(DeletionStatus.Active, st.status)
        assertTrue(st.transient!!.isError)
        assertEquals(AccountDeletionViewModel.MSG_REQUEST_FAILED, st.transient.text)
    }

    // TC-AND-386-07: cancel happy path.
    @Test
    fun confirmCancel_happyPath_returnsToActive() = runTest {
        repo.statusResult = ApiResult.Success(DeletionStatus.Pending("del_x", 1L, 2L, 14, true))
        repo.cancelResult = ApiResult.Success(DeletionStatus.Active)
        val vm = vm()
        vm.load(); runCurrent()
        vm.onEvent(AccountDeletionEvent.StartCancel)
        assertEquals(ConfirmStep.CancelDialog, ready(vm.uiState.value).confirmStep)
        vm.onEvent(AccountDeletionEvent.ConfirmCancel)
        runCurrent()
        assertEquals(listOf("del_x"), repo.cancelCalls)
        val st = ready(vm.uiState.value)
        assertEquals(DeletionStatus.Active, st.status)
        assertEquals(AccountDeletionViewModel.MSG_CANCEL_OK, st.transient?.text)
    }

    // TC-AND-386-09: offline -> stale; a mutation while stale does NOT hit the network.
    @Test
    fun offline_showsStale_andMutationDoesNotHitNetwork() = runTest {
        repo.statusResult = ApiResult.NetworkError(java.io.IOException("down"))
        repo.lastKnown = DeletionStatus.Active
        val vm = vm()
        vm.load(); runCurrent()
        assertTrue(ready(vm.uiState.value).isStale)

        drive(vm, password = "pw")
        vm.onEvent(AccountDeletionEvent.ConfirmDelete)
        runCurrent()
        assertEquals(0, repo.requestCount)
        val st = ready(vm.uiState.value)
        assertTrue(st.transient!!.isError)
        assertEquals(AccountDeletionViewModel.MSG_OFFLINE, st.transient.text)
    }

    // Offline with no last-known -> Error(retryable).
    @Test
    fun offline_noLastKnown_showsRetryableError() = runTest {
        repo.statusResult = ApiResult.NetworkError(java.io.IOException("down"))
        repo.lastKnown = null
        val vm = vm()
        vm.load(); runCurrent()
        val st = vm.uiState.value
        assertTrue(st is AccountDeletionUiState.Error)
        assertTrue((st as AccountDeletionUiState.Error).retryable)
    }

    // Dismiss clears the confirm progress.
    @Test
    fun dismiss_resetsConfirmProgress() = runTest {
        val vm = vm()
        vm.load(); runCurrent()
        drive(vm, password = "pw", reason = "r")
        vm.onEvent(AccountDeletionEvent.Dismiss)
        val st = ready(vm.uiState.value)
        assertEquals(ConfirmStep.None, st.confirmStep)
        assertEquals("", st.typedConfirmation)
        assertEquals("", st.password)
        assertEquals("", st.reason)
        assertNull(st.transient)
    }

    /** Drives the request gates up to (but not through) the final dialog. */
    private fun drive(vm: AccountDeletionViewModel, password: String, reason: String? = null) {
        vm.onEvent(AccountDeletionEvent.StartRequest)
        vm.onEvent(AccountDeletionEvent.AdvanceFromWarning)
        vm.onEvent(AccountDeletionEvent.TypedConfirmationChanged(DELETE_SENTINEL))
        vm.onEvent(AccountDeletionEvent.PasswordChanged(password))
        reason?.let { vm.onEvent(AccountDeletionEvent.ReasonChanged(it)) }
        vm.onEvent(AccountDeletionEvent.ShowFinalDialog)
    }
}
