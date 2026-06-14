package com.testlogon.android.feature.settings.account

import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.AccountState
import com.testlogon.android.core.model.AccountStatus
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.preferences.AccountStatusRepository
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

class AccountSettingsViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private class FakeRepo(var result: ApiResult<AccountStatus>) : AccountStatusRepository {
        override suspend fun getStatus() = result
    }

    private fun status(state: AccountState) =
        AccountStatus(state = state, rawState = state.name.lowercase())

    @Test
    fun active_showsClose_hidesReactivate() = runTest(mainRule.dispatcher) {
        val vm = AccountSettingsViewModel(FakeRepo(ApiResult.Success(status(AccountState.ACTIVE))))
        advanceUntilIdle()
        val ready = vm.state.value as AccountUiState.Ready
        assertTrue(ready.showClose)
        assertFalse(ready.showReactivate)
    }

    @Test
    fun closed_hidesClose_showsReactivate() = runTest(mainRule.dispatcher) {
        val vm = AccountSettingsViewModel(FakeRepo(ApiResult.Success(status(AccountState.CLOSED))))
        advanceUntilIdle()
        val ready = vm.state.value as AccountUiState.Ready
        assertFalse(ready.showClose)
        assertTrue(ready.showReactivate)
    }

    @Test
    fun suspended_showsBoth() = runTest(mainRule.dispatcher) {
        val vm = AccountSettingsViewModel(FakeRepo(ApiResult.Success(status(AccountState.SUSPENDED))))
        advanceUntilIdle()
        val ready = vm.state.value as AccountUiState.Ready
        assertTrue(ready.showClose)
        assertTrue(ready.showReactivate)
    }

    @Test
    fun error_whenLoadFails() = runTest(mainRule.dispatcher) {
        val vm = AccountSettingsViewModel(FakeRepo(ApiResult.Failure(ApiError(500, "boom"))))
        advanceUntilIdle()
        assertTrue(vm.state.value is AccountUiState.Error)
    }

    @Test
    fun confirmGate_setAndDismiss() = runTest(mainRule.dispatcher) {
        val vm = AccountSettingsViewModel(FakeRepo(ApiResult.Success(status(AccountState.ACTIVE))))
        advanceUntilIdle()
        vm.requestDestructive(DestructiveAction.CLOSE_ACCOUNT)
        assertEquals(
            DestructiveAction.CLOSE_ACCOUNT,
            (vm.state.value as AccountUiState.Ready).pendingConfirm,
        )
        vm.dismissConfirm()
        assertNull((vm.state.value as AccountUiState.Ready).pendingConfirm)
    }
}
