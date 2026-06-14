package com.testlogon.android.feature.account.closure

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.account.ClosureStartResult
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-387 - AccountLifecycleViewModel state-machine unit tests (TC-AND-387-01, 02, 03, 04, 05, 06, 08, 09,
 * 11, 15). Uses a fake repository; no nested runTest; the StandardTestDispatcher is driven with runCurrent
 * (NOT advanceUntilIdle). The VM exposes a plain MutableStateFlow so no hot collector is needed.
 */
class AccountLifecycleViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private val repo = FakeAccountLifecycleRepository()

    private fun vm(saved: SavedStateHandle = SavedStateHandle()) =
        AccountLifecycleViewModel(repo, saved)

    private fun ready(vm: AccountLifecycleViewModel): AccountLifecycleUiState.Ready =
        vm.uiState.value as AccountLifecycleUiState.Ready

    // TC-01: status read -> Ready(ACTIVE).
    @Test
    fun load_active_mapsToReadyActive() = runTest {
        repo.statusResult = ApiResult.Success(FakeAccountLifecycleRepository.active())
        val vm = vm()
        vm.load(); runCurrent()
        assertEquals(FakeAccountLifecycleRepository.active(), ready(vm).status)
        assertEquals(ActionState.Idle, ready(vm).action)
    }

    // TC-10: status read transport failure -> Offline, no destructive action available.
    @Test
    fun load_networkError_mapsToOffline() = runTest {
        repo.statusResult = ApiResult.NetworkError(RuntimeException("no net"), isTimeout = false)
        val vm = vm()
        vm.load(); runCurrent()
        assertEquals(AccountLifecycleUiState.Offline, vm.uiState.value)
    }

    // status read server failure -> Error.
    @Test
    fun load_failure_mapsToError() = runTest {
        repo.statusResult = ApiResult.Failure(ApiError(500, "boom"))
        val vm = vm()
        vm.load(); runCurrent()
        assertTrue(vm.uiState.value is AccountLifecycleUiState.Error)
    }

    // TC-02: suspend happy path -> exactly one call, reason forwarded, outcome SUSPENDED_SIGNED_OUT.
    @Test
    fun suspend_happyPath_oneCall_doneSignedOut() = runTest {
        val vm = vm()
        vm.load(); runCurrent()
        vm.requestSuspend()
        assertEquals(ActionState.ConfirmSuspend, ready(vm).action)
        vm.confirmSuspend("taking a break"); runCurrent()
        assertEquals(1, repo.suspendCount)
        assertEquals("taking a break", repo.lastSuspendReason)
        assertEquals(ActionState.Done(Outcome.SUSPENDED_SIGNED_OUT), ready(vm).action)
    }

    // TC-09: a second confirm while in flight is ignored (no double submit). The fake returns instantly, so
    // we assert the count never exceeds one across repeated confirms.
    @Test
    fun suspend_doubleConfirm_doesNotDoubleSubmit() = runTest {
        val vm = vm()
        vm.load(); runCurrent()
        vm.requestSuspend()
        vm.confirmSuspend(null)
        vm.confirmSuspend(null)
        runCurrent()
        assertEquals(1, repo.suspendCount)
    }

    // TC-03: closure start with auth_required -> ReAuthRequired(challengeId).
    @Test
    fun closureStart_authRequired_movesToReAuth() = runTest {
        repo.startClosureResult = ApiResult.Success(
            ClosureStartResult(authRequired = true, challengeId = "ch_re_19", requiredFactors = listOf("password")),
        )
        val vm = vm()
        vm.load(); runCurrent()
        vm.requestClosure(); runCurrent()
        val action = ready(vm).action
        assertTrue(action is ActionState.ReAuthRequired)
        assertEquals("ch_re_19", (action as ActionState.ReAuthRequired).challengeId)
    }

    // closure start with auth NOT required -> straight to the typed-token finalize confirm.
    @Test
    fun closureStart_noAuth_movesToFinalizeConfirm() = runTest {
        repo.startClosureResult = ApiResult.Success(
            ClosureStartResult(authRequired = false, challengeId = "ch_22", requiredFactors = emptyList()),
        )
        val vm = vm()
        vm.load(); runCurrent()
        vm.requestClosure(); runCurrent()
        val action = ready(vm).action
        assertTrue(action is ActionState.ConfirmClosureFinalize)
        assertEquals("ch_22", (action as ActionState.ConfirmClosureFinalize).challengeId)
        assertFalse(action.tokenValid)
    }

    // TC-03 + AC-3: typed-token gate; finalize is a no-op until the token is exactly CLOSE.
    @Test
    fun finalize_gatedOnExactCloseToken() = runTest {
        repo.startClosureResult = ApiResult.Success(
            ClosureStartResult(authRequired = true, challengeId = "ch_re_19", requiredFactors = listOf("password")),
        )
        val vm = vm()
        vm.load(); runCurrent()
        vm.requestClosure(); runCurrent()
        vm.submitReAuth()
        assertTrue(ready(vm).action is ActionState.ConfirmClosureFinalize)

        // Wrong-case token: still locked, finalize is a no-op.
        vm.onTypedTokenChange("close")
        assertFalse((ready(vm).action as ActionState.ConfirmClosureFinalize).tokenValid)
        vm.confirmClosureFinalize(); runCurrent()
        assertEquals(0, repo.finalizeCount)

        // Exact CLOSE: unlocked; finalize fires with the carried challenge id.
        vm.onTypedTokenChange(CLOSE_TOKEN)
        assertTrue((ready(vm).action as ActionState.ConfirmClosureFinalize).tokenValid)
        vm.confirmClosureFinalize(); runCurrent()
        assertEquals(1, repo.finalizeCount)
        assertEquals("ch_re_19", repo.lastFinalizeChallenge)
        assertEquals(ActionState.Done(Outcome.CLOSED_SIGNED_OUT), ready(vm).action)
    }

    // TC-06: a 422 on finalize -> Failed, prior status retained, no Done/teardown.
    @Test
    fun finalize_422_failedAndRetainsStatus() = runTest {
        repo.startClosureResult = ApiResult.Success(
            ClosureStartResult(authRequired = false, challengeId = "ch_22", requiredFactors = emptyList()),
        )
        repo.finalizeResult = ApiResult.Failure(ApiError(422, "challenge_id is required"))
        val vm = vm()
        vm.load(); runCurrent()
        vm.requestClosure(); runCurrent()
        vm.onTypedTokenChange(CLOSE_TOKEN)
        vm.confirmClosureFinalize(); runCurrent()
        val action = ready(vm).action
        assertTrue(action is ActionState.Failed)
        assertEquals("challenge_id is required", (action as ActionState.Failed).message)
        assertEquals(FakeAccountLifecycleRepository.active(), ready(vm).status)
    }

    // TC-05: reactivate happy path -> REACTIVATED, status reflects active, one call.
    @Test
    fun reactivate_happyPath() = runTest {
        repo.statusResult = ApiResult.Success(FakeAccountLifecycleRepository.suspended())
        repo.reactivateResult = ApiResult.Success(FakeAccountLifecycleRepository.active())
        val vm = vm()
        vm.load(); runCurrent()
        vm.requestReactivate()
        assertEquals(ActionState.ConfirmReactivate, ready(vm).action)
        vm.confirmReactivate(); runCurrent()
        assertEquals(1, repo.reactivateCount)
        assertEquals(ActionState.Done(Outcome.REACTIVATED), ready(vm).action)
        assertEquals(FakeAccountLifecycleRepository.active(), ready(vm).status)
    }

    // TC-08: undocumented 409 already-in-state on suspend -> reconcile via reload (no hard error).
    @Test
    fun suspend_409_reconcilesViaReload() = runTest {
        repo.statusResult = ApiResult.Success(FakeAccountLifecycleRepository.active())
        repo.suspendResult = ApiResult.Failure(ApiError(409, "already_suspended", code = "already_suspended"))
        val vm = vm()
        vm.load(); runCurrent()
        val before = repo.statusCount
        // After the 409, the VM re-reads status; point status to suspended so the reconcile lands there.
        repo.statusResult = ApiResult.Success(FakeAccountLifecycleRepository.suspended())
        vm.requestSuspend()
        vm.confirmSuspend(null); runCurrent()
        assertTrue(repo.statusCount > before) // reload happened
        assertEquals(FakeAccountLifecycleRepository.suspended(), ready(vm).status)
        assertEquals(ActionState.Idle, ready(vm).action)
    }

    // TC-11: ambiguous transport failure after a finalize submit -> Failed(ambiguous) + reconcile reload.
    @Test
    fun finalize_networkError_ambiguous_reconciles() = runTest {
        repo.startClosureResult = ApiResult.Success(
            ClosureStartResult(authRequired = false, challengeId = "ch_22", requiredFactors = emptyList()),
        )
        repo.finalizeResult = ApiResult.NetworkError(RuntimeException("timeout"), isTimeout = true)
        val vm = vm()
        vm.load(); runCurrent()
        val before = repo.statusCount
        vm.requestClosure(); runCurrent()
        vm.onTypedTokenChange(CLOSE_TOKEN)
        vm.confirmClosureFinalize(); runCurrent()
        val action = ready(vm).action
        assertTrue(action is ActionState.Failed)
        assertEquals(AccountLifecycleViewModel.MSG_AMBIGUOUS, (action as ActionState.Failed).message)
        assertTrue(repo.statusCount > before) // reconcile reload happened
    }

    // TC-15: the typed-token step survives process recreation via SavedStateHandle; Submitting is not persisted.
    @Test
    fun finalizeStep_survivesProcessRecreation() = runTest {
        repo.startClosureResult = ApiResult.Success(
            ClosureStartResult(authRequired = false, challengeId = "ch_55", requiredFactors = emptyList()),
        )
        val saved = SavedStateHandle()
        val vm1 = vm(saved)
        vm1.load(); runCurrent()
        vm1.requestClosure(); runCurrent()
        vm1.onTypedTokenChange("CL")

        // Recreate the VM with the SAME SavedStateHandle (status re-loads active).
        val vm2 = vm(saved)
        vm2.load(); runCurrent()
        val action = ready(vm2).action
        assertTrue(action is ActionState.ConfirmClosureFinalize)
        assertEquals("ch_55", (action as ActionState.ConfirmClosureFinalize).challengeId)
        assertEquals("CL", action.typed)
    }

    // dismiss returns to Idle and clears the saved step.
    @Test
    fun dismiss_returnsToIdle() = runTest {
        val vm = vm()
        vm.load(); runCurrent()
        vm.requestSuspend()
        assertEquals(ActionState.ConfirmSuspend, ready(vm).action)
        vm.dismissDialog()
        assertEquals(ActionState.Idle, ready(vm).action)
    }
}
