package com.testlogon.android.feature.appeals

import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.R
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.appeals.Appeal
import com.testlogon.android.data.appeals.AppealStatus
import com.testlogon.android.data.appeals.AppealsPage
import com.testlogon.android.data.appeals.AppealsRepository
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
class AppealsViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private fun appeal(
        id: String = "apl_1",
        status: AppealStatus = AppealStatus.SUBMITTED,
    ) = Appeal(
        id = id,
        enforcementId = "enf_1",
        enforcementType = "suspension",
        sourceTicketId = null,
        appealText = "Please reconsider.",
        status = status,
        createdAtSeconds = 1_700_000_000L,
        updatedAtSeconds = 1_700_000_100L,
        decidedAtSeconds = null,
        decisionNote = null,
        modifiedEnforcementType = null,
        modifiedDurationDays = null,
    )

    private fun page(appeals: List<Appeal>, nextCursor: String? = null) =
        AppealsPage(appeals = appeals, nextCursor = nextCursor)

    private class FakeAppealsRepository : AppealsRepository {
        var loadResult: ApiResult<AppealsPage> = ApiResult.Failure(ApiError(500, "x"))
        var submitResult: ApiResult<Unit> = ApiResult.Success(Unit)
        var withdrawResult: ApiResult<Unit> = ApiResult.Success(Unit)
        var cacheValue: AppealsPage? = null

        var loadCount = 0
        var submitCount = 0
        var withdrawCount = 0
        var lastEnforcementId: String? = null
        var lastAppealText: String? = null
        var lastWithdrawId: String? = null
        var cleared = false

        override suspend fun loadAppeals(): ApiResult<AppealsPage> {
            loadCount++
            return loadResult
        }

        var optionsResult: ApiResult<List<com.testlogon.android.data.appeals.EnforcementOption>> =
            ApiResult.Success(emptyList())

        override suspend fun loadEnforcementOptions(): ApiResult<List<com.testlogon.android.data.appeals.EnforcementOption>> =
            optionsResult

        override suspend fun submitAppeal(enforcementId: String, appealText: String): ApiResult<Unit> {
            submitCount++
            lastEnforcementId = enforcementId
            lastAppealText = appealText
            return submitResult
        }

        override suspend fun withdrawAppeal(appealId: String): ApiResult<Unit> {
            withdrawCount++
            lastWithdrawId = appealId
            return withdrawResult
        }

        override fun cached(): AppealsPage? = cacheValue

        override fun clear() {
            cleared = true
        }
    }

    // ---- init load ----

    @Test
    fun load_success_nonEmpty_movesToContent() = runTest {
        val repo = FakeAppealsRepository().apply { loadResult = ApiResult.Success(page(listOf(appeal()))) }
        val vm = AppealsViewModel(repo)
        advanceUntilIdle()
        assertEquals(AppealsUiState.Phase.Content, vm.uiState.value.phase)
        assertFalse(vm.uiState.value.isStale)
        assertEquals(1, repo.loadCount)
    }

    @Test
    fun load_successEmpty_movesToEmpty() = runTest {
        val repo = FakeAppealsRepository().apply { loadResult = ApiResult.Success(page(emptyList())) }
        val vm = AppealsViewModel(repo)
        advanceUntilIdle()
        assertEquals(AppealsUiState.Phase.Empty, vm.uiState.value.phase)
    }

    @Test
    fun load_failure500_movesToError() = runTest {
        val repo = FakeAppealsRepository().apply { loadResult = ApiResult.Failure(ApiError(500, "boom")) }
        val vm = AppealsViewModel(repo)
        advanceUntilIdle()
        assertEquals(AppealsUiState.Phase.Error, vm.uiState.value.phase)
        assertEquals("boom", vm.uiState.value.errorMessage)
    }

    @Test
    fun load_networkError_withCache_showsStaleContent() = runTest {
        val repo = FakeAppealsRepository().apply {
            loadResult = ApiResult.NetworkError(java.io.IOException(), isTimeout = false)
            cacheValue = page(listOf(appeal()))
        }
        val vm = AppealsViewModel(repo)
        advanceUntilIdle()
        assertEquals(AppealsUiState.Phase.Content, vm.uiState.value.phase)
        assertTrue(vm.uiState.value.isStale)
    }

    @Test
    fun load_networkError_noCache_movesToOffline() = runTest {
        val repo = FakeAppealsRepository().apply {
            loadResult = ApiResult.NetworkError(java.io.IOException(), isTimeout = false)
            cacheValue = null
        }
        val vm = AppealsViewModel(repo)
        advanceUntilIdle()
        assertEquals(AppealsUiState.Phase.Offline, vm.uiState.value.phase)
    }

    @Test
    fun load_failure401_movesToSessionExpired() = runTest {
        val repo = FakeAppealsRepository().apply { loadResult = ApiResult.Failure(ApiError(401, "nope")) }
        val vm = AppealsViewModel(repo)
        advanceUntilIdle()
        assertEquals(AppealsUiState.Phase.SessionExpired, vm.uiState.value.phase)
    }

    // ---- submit form ----

    @Test
    fun onOpenSubmit_opensForm() = runTest {
        val repo = FakeAppealsRepository().apply { loadResult = ApiResult.Success(page(listOf(appeal()))) }
        val vm = AppealsViewModel(repo)
        advanceUntilIdle()
        vm.onOpenSubmit()
        assertTrue(vm.uiState.value.submit.isOpen)
    }

    @Test
    fun submit_fieldChanges_enableCanSubmit() = runTest {
        val repo = FakeAppealsRepository().apply { loadResult = ApiResult.Success(page(listOf(appeal()))) }
        val vm = AppealsViewModel(repo)
        advanceUntilIdle()
        vm.onOpenSubmit()
        assertFalse(vm.uiState.value.submit.canSubmit)
        vm.onEnforcementIdChange("enf_42")
        vm.onAppealTextChange("I disagree")
        assertEquals("enf_42", vm.uiState.value.submit.enforcementId)
        assertEquals("I disagree", vm.uiState.value.submit.appealText)
        assertTrue(vm.uiState.value.submit.canSubmit)
    }

    @Test
    fun submit_success_closesForm_reloads_emitsSuccessMessage() = runTest {
        val repo = FakeAppealsRepository().apply {
            loadResult = ApiResult.Success(page(listOf(appeal())))
            submitResult = ApiResult.Success(Unit)
        }
        val vm = AppealsViewModel(repo)
        advanceUntilIdle()
        val loadsBefore = repo.loadCount

        val effects = mutableListOf<AppealsEffect>()
        val job = CoroutineScope(UnconfinedTestDispatcher(testScheduler)).launch {
            vm.effects.collect { effects += it }
        }

        vm.onOpenSubmit()
        vm.onEnforcementIdChange("enf_42")
        vm.onAppealTextChange("I disagree")
        vm.onSubmit()
        advanceUntilIdle()
        job.cancel()

        assertEquals(1, repo.submitCount)
        assertEquals("enf_42", repo.lastEnforcementId)
        assertEquals("I disagree", repo.lastAppealText)
        assertFalse(vm.uiState.value.submit.isOpen)
        assertEquals(loadsBefore + 1, repo.loadCount)
        val msg = effects.filterIsInstance<AppealsEffect.ShowMessage>().single()
        assertEquals(R.string.appeals_submit_success, msg.resId)
    }

    @Test
    fun submit_failure_keepsFormOpen_emitsFailureMessage() = runTest {
        val repo = FakeAppealsRepository().apply {
            loadResult = ApiResult.Success(page(listOf(appeal())))
            submitResult = ApiResult.Failure(ApiError(500, "bad"))
        }
        val vm = AppealsViewModel(repo)
        advanceUntilIdle()
        val loadsBefore = repo.loadCount

        val effects = mutableListOf<AppealsEffect>()
        val job = CoroutineScope(UnconfinedTestDispatcher(testScheduler)).launch {
            vm.effects.collect { effects += it }
        }

        vm.onOpenSubmit()
        vm.onEnforcementIdChange("enf_42")
        vm.onAppealTextChange("I disagree")
        vm.onSubmit()
        advanceUntilIdle()
        job.cancel()

        assertEquals(1, repo.submitCount)
        assertFalse(vm.uiState.value.submit.isSubmitting)
        assertTrue(vm.uiState.value.submit.isOpen)
        assertEquals(loadsBefore, repo.loadCount)
        val msg = effects.filterIsInstance<AppealsEffect.ShowMessage>().single()
        assertEquals(R.string.appeals_submit_failed, msg.resId)
    }

    @Test
    fun submit_failure401_movesToSessionExpired() = runTest {
        val repo = FakeAppealsRepository().apply {
            loadResult = ApiResult.Success(page(listOf(appeal())))
            submitResult = ApiResult.Failure(ApiError(401, "nope"))
        }
        val vm = AppealsViewModel(repo)
        advanceUntilIdle()

        vm.onOpenSubmit()
        vm.onEnforcementIdChange("enf_42")
        vm.onAppealTextChange("I disagree")
        vm.onSubmit()
        advanceUntilIdle()

        assertEquals(AppealsUiState.Phase.SessionExpired, vm.uiState.value.phase)
    }

    @Test
    fun submit_whenFormBlank_isNoOp() = runTest {
        val repo = FakeAppealsRepository().apply { loadResult = ApiResult.Success(page(listOf(appeal()))) }
        val vm = AppealsViewModel(repo)
        advanceUntilIdle()
        vm.onOpenSubmit()
        vm.onSubmit()
        advanceUntilIdle()
        assertEquals(0, repo.submitCount)
    }

    // ---- withdraw ----

    @Test
    fun withdraw_eligibleAppeal_callsRepo_reloads_emitsSuccessMessage() = runTest {
        val repo = FakeAppealsRepository().apply {
            loadResult = ApiResult.Success(page(listOf(appeal(id = "apl_7", status = AppealStatus.SUBMITTED))))
            withdrawResult = ApiResult.Success(Unit)
        }
        val vm = AppealsViewModel(repo)
        advanceUntilIdle()
        val loadsBefore = repo.loadCount

        val effects = mutableListOf<AppealsEffect>()
        val job = CoroutineScope(UnconfinedTestDispatcher(testScheduler)).launch {
            vm.effects.collect { effects += it }
        }

        vm.onWithdraw("apl_7")
        advanceUntilIdle()
        job.cancel()

        assertEquals(1, repo.withdrawCount)
        assertEquals("apl_7", repo.lastWithdrawId)
        assertEquals(loadsBefore + 1, repo.loadCount)
        assertFalse(vm.uiState.value.isMutating)
        val msg = effects.filterIsInstance<AppealsEffect.ShowMessage>().single()
        assertEquals(R.string.appeals_withdraw_success, msg.resId)
    }

    @Test
    fun withdraw_failure_emitsFailureMessage_doesNotReload() = runTest {
        val repo = FakeAppealsRepository().apply {
            loadResult = ApiResult.Success(page(listOf(appeal(id = "apl_7", status = AppealStatus.SUBMITTED))))
            withdrawResult = ApiResult.Failure(ApiError(500, "bad"))
        }
        val vm = AppealsViewModel(repo)
        advanceUntilIdle()
        val loadsBefore = repo.loadCount

        val effects = mutableListOf<AppealsEffect>()
        val job = CoroutineScope(UnconfinedTestDispatcher(testScheduler)).launch {
            vm.effects.collect { effects += it }
        }

        vm.onWithdraw("apl_7")
        advanceUntilIdle()
        job.cancel()

        assertEquals(1, repo.withdrawCount)
        assertEquals(loadsBefore, repo.loadCount)
        assertFalse(vm.uiState.value.isMutating)
        val msg = effects.filterIsInstance<AppealsEffect.ShowMessage>().single()
        assertEquals(R.string.appeals_withdraw_failed, msg.resId)
    }

    @Test
    fun withdraw_ineligibleAppeal_isNoOp() = runTest {
        val repo = FakeAppealsRepository().apply {
            loadResult = ApiResult.Success(page(listOf(appeal(id = "apl_8", status = AppealStatus.UPHELD))))
        }
        val vm = AppealsViewModel(repo)
        advanceUntilIdle()

        vm.onWithdraw("apl_8")
        advanceUntilIdle()

        assertEquals(0, repo.withdrawCount)
    }

    @Test
    fun withdraw_unknownId_isNoOp() = runTest {
        val repo = FakeAppealsRepository().apply {
            loadResult = ApiResult.Success(page(listOf(appeal(id = "apl_7"))))
        }
        val vm = AppealsViewModel(repo)
        advanceUntilIdle()

        vm.onWithdraw("does_not_exist")
        advanceUntilIdle()

        assertEquals(0, repo.withdrawCount)
    }

    @Test
    fun withdraw_failure401_movesToSessionExpired() = runTest {
        val repo = FakeAppealsRepository().apply {
            loadResult = ApiResult.Success(page(listOf(appeal(id = "apl_7", status = AppealStatus.SUBMITTED))))
            withdrawResult = ApiResult.Failure(ApiError(401, "nope"))
        }
        val vm = AppealsViewModel(repo)
        advanceUntilIdle()

        vm.onWithdraw("apl_7")
        advanceUntilIdle()

        assertEquals(AppealsUiState.Phase.SessionExpired, vm.uiState.value.phase)
    }

    // ---- refresh / retry ----

    @Test
    fun onRetry_afterError_reloadsToContent() = runTest {
        val repo = FakeAppealsRepository().apply { loadResult = ApiResult.Failure(ApiError(500, "boom")) }
        val vm = AppealsViewModel(repo)
        advanceUntilIdle()
        assertEquals(AppealsUiState.Phase.Error, vm.uiState.value.phase)

        repo.loadResult = ApiResult.Success(page(listOf(appeal())))
        vm.onRetry()
        advanceUntilIdle()

        assertEquals(AppealsUiState.Phase.Content, vm.uiState.value.phase)
        assertNull(vm.uiState.value.errorMessage)
    }
}
