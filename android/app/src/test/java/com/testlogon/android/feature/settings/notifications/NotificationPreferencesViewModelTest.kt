package com.testlogon.android.feature.settings.notifications

import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.NotificationChannel
import com.testlogon.android.core.model.NotificationTypePreference
import com.testlogon.android.data.preferences.NotificationPreferencesRepository
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

class NotificationPreferencesViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private class FakeRepo(
        var getResult: ApiResult<List<NotificationTypePreference>>,
        var updateResult: ApiResult<List<NotificationTypePreference>>,
    ) : NotificationPreferencesRepository {
        var updateCalls = 0
        override suspend fun getTypePreferences() = getResult
        override suspend fun updateTypePreference(
            pref: NotificationTypePreference,
        ): ApiResult<List<NotificationTypePreference>> {
            updateCalls++
            return updateResult
        }
    }

    private fun pref(type: String, push: Boolean = false) =
        NotificationTypePreference(alertType = type, push = push)

    @Test
    fun load_success_rendersRows() = runTest(mainRule.dispatcher) {
        val repo = FakeRepo(
            getResult = ApiResult.Success(listOf(pref("security_alerts"))),
            updateResult = ApiResult.Success(emptyList()),
        )
        val vm = NotificationPreferencesViewModel(repo)
        advanceUntilIdle()
        val state = vm.state.value
        assertTrue(state is NotificationPrefsUiState.Ready)
        assertEquals(1, (state as NotificationPrefsUiState.Ready).rows.size)
    }

    @Test
    fun load_empty_rendersEmpty() = runTest(mainRule.dispatcher) {
        val repo = FakeRepo(ApiResult.Success(emptyList()), ApiResult.Success(emptyList()))
        val vm = NotificationPreferencesViewModel(repo)
        advanceUntilIdle()
        assertTrue(vm.state.value is NotificationPrefsUiState.Empty)
    }

    @Test
    fun toggle_optimistic_thenReconcile() = runTest(mainRule.dispatcher) {
        val repo = FakeRepo(
            getResult = ApiResult.Success(listOf(pref("marketing", push = false))),
            updateResult = ApiResult.Success(listOf(pref("marketing", push = true))),
        )
        val vm = NotificationPreferencesViewModel(repo)
        advanceUntilIdle()
        vm.onToggle("marketing", NotificationChannel.PUSH, true)
        advanceUntilIdle()
        val row = (vm.state.value as NotificationPrefsUiState.Ready).rows.first()
        assertTrue(row.pref.push)
        assertEquals(1, repo.updateCalls)
    }

    @Test
    fun toggle_failure_rollsBack() = runTest(mainRule.dispatcher) {
        val repo = FakeRepo(
            getResult = ApiResult.Success(listOf(pref("billing", push = false))),
            updateResult = ApiResult.Failure(ApiError(500, "boom")),
        )
        val vm = NotificationPreferencesViewModel(repo)
        advanceUntilIdle()
        vm.onToggle("billing", NotificationChannel.PUSH, true)
        advanceUntilIdle()
        val row = (vm.state.value as NotificationPrefsUiState.Ready).rows.first()
        assertFalse(row.pref.push) // reverted to last persisted value
        assertTrue(row.savingChannels.isEmpty())
    }
}
