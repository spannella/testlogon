package com.testlogon.android.feature.ideas

import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.R
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.ideas.Idea
import com.testlogon.android.data.ideas.IdeaStatus
import com.testlogon.android.data.ideas.IdeasPage
import com.testlogon.android.data.ideas.IdeasRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class IdeasViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private fun idea(id: String = "idea_1") = Idea(
        id = id,
        title = "Dark mode",
        description = "Please add a dark theme to the app.",
        status = IdeaStatus.SUBMITTED,
        prioritySuggestion = null,
        rejectionReason = null,
        createdAtSeconds = 1_750_000_000L,
        updatedAtSeconds = 1_750_000_000L,
    )

    private fun page(ideas: List<Idea>, nextCursor: String? = null) =
        IdeasPage(ideas = ideas, nextCursor = nextCursor)

    private class FakeIdeasRepository : IdeasRepository {
        var loadResult: ApiResult<IdeasPage> = ApiResult.Failure(ApiError(500, "x"))
        var submitResult: ApiResult<Unit> = ApiResult.Success(Unit)
        var cacheValue: IdeasPage? = null

        var loadCalls = 0
        var submitCalls = 0
        var lastSubmitTitle: String? = null
        var lastSubmitDescription: String? = null

        override suspend fun loadIdeas(): ApiResult<IdeasPage> {
            loadCalls++
            return loadResult
        }

        override suspend fun submitIdea(title: String, description: String): ApiResult<Unit> {
            submitCalls++
            lastSubmitTitle = title
            lastSubmitDescription = description
            return submitResult
        }

        override fun cached(): IdeasPage? = cacheValue
        override fun clear() {}
    }

    // ---- Initial load ----

    @Test
    fun load_success_nonEmpty_movesToContent() = runTest {
        val repo = FakeIdeasRepository().apply { loadResult = ApiResult.Success(page(listOf(idea()))) }
        val vm = IdeasViewModel(repo)
        advanceUntilIdle()
        assertEquals(IdeasUiState.Phase.Content, vm.uiState.value.phase)
    }

    @Test
    fun load_success_empty_movesToEmpty() = runTest {
        val repo = FakeIdeasRepository().apply { loadResult = ApiResult.Success(page(emptyList())) }
        val vm = IdeasViewModel(repo)
        advanceUntilIdle()
        assertEquals(IdeasUiState.Phase.Empty, vm.uiState.value.phase)
    }

    @Test
    fun load_failure500_movesToError() = runTest {
        val repo = FakeIdeasRepository().apply { loadResult = ApiResult.Failure(ApiError(500, "boom")) }
        val vm = IdeasViewModel(repo)
        advanceUntilIdle()
        assertEquals(IdeasUiState.Phase.Error, vm.uiState.value.phase)
    }

    @Test
    fun load_networkError_withCache_showsStaleContent() = runTest {
        val repo = FakeIdeasRepository().apply {
            loadResult = ApiResult.NetworkError(java.io.IOException(), isTimeout = false)
            cacheValue = page(listOf(idea()))
        }
        val vm = IdeasViewModel(repo)
        advanceUntilIdle()
        assertEquals(IdeasUiState.Phase.Content, vm.uiState.value.phase)
        assertTrue(vm.uiState.value.isStale)
    }

    @Test
    fun load_failure401_movesToSessionExpired() = runTest {
        val repo = FakeIdeasRepository().apply { loadResult = ApiResult.Failure(ApiError(401, "nope")) }
        val vm = IdeasViewModel(repo)
        advanceUntilIdle()
        assertEquals(IdeasUiState.Phase.SessionExpired, vm.uiState.value.phase)
    }

    // ---- Submit form: open / validation gating ----

    @Test
    fun onOpenSubmit_opensForm() = runTest {
        val repo = FakeIdeasRepository().apply { loadResult = ApiResult.Success(page(listOf(idea()))) }
        val vm = IdeasViewModel(repo)
        advanceUntilIdle()

        vm.onOpenSubmit()

        assertTrue(vm.uiState.value.submit.isOpen)
    }

    @Test
    fun onSubmit_titleTooShort_isNoOp() = runTest {
        val repo = FakeIdeasRepository().apply { loadResult = ApiResult.Success(page(listOf(idea()))) }
        val vm = IdeasViewModel(repo)
        advanceUntilIdle()

        vm.onOpenSubmit()
        vm.onTitleChange("ab") // < 3 chars
        vm.onDescriptionChange("A perfectly long description here.")
        assertFalse(vm.uiState.value.submit.canSubmit)

        vm.onSubmit()
        advanceUntilIdle()

        assertEquals(0, repo.submitCalls)
    }

    @Test
    fun onSubmit_descriptionTooShort_isNoOp() = runTest {
        val repo = FakeIdeasRepository().apply { loadResult = ApiResult.Success(page(listOf(idea()))) }
        val vm = IdeasViewModel(repo)
        advanceUntilIdle()

        vm.onOpenSubmit()
        vm.onTitleChange("Valid title")
        vm.onDescriptionChange("too short") // < 10 chars
        assertFalse(vm.uiState.value.submit.canSubmit)

        vm.onSubmit()
        advanceUntilIdle()

        assertEquals(0, repo.submitCalls)
    }

    // ---- Submit form: valid submit outcomes ----

    @Test
    fun onSubmit_valid_success_closesForm_emitsSuccess_andReloads() = runTest {
        val repo = FakeIdeasRepository().apply {
            loadResult = ApiResult.Success(page(listOf(idea())))
            submitResult = ApiResult.Success(Unit)
        }
        val vm = IdeasViewModel(repo)
        advanceUntilIdle()
        val loadsAfterInit = repo.loadCalls

        val effects = mutableListOf<IdeasEffect>()
        val job = CoroutineScope(UnconfinedTestDispatcher(testScheduler)).launch {
            vm.effects.collect { effects += it }
        }

        vm.onOpenSubmit()
        vm.onTitleChange("Dark mode")
        vm.onDescriptionChange("Please add a dark theme to the app.")
        assertTrue(vm.uiState.value.submit.canSubmit)
        vm.onSubmit()
        advanceUntilIdle()
        job.cancel()

        assertEquals(1, repo.submitCalls)
        assertEquals("Dark mode", repo.lastSubmitTitle)
        assertFalse(vm.uiState.value.submit.isOpen)
        val msg = effects.filterIsInstance<IdeasEffect.ShowMessage>().single()
        assertEquals(R.string.ideas_submit_success, msg.resId)
        assertTrue(repo.loadCalls > loadsAfterInit) // reloaded after success
    }

    @Test
    fun onSubmit_valid_failure401_movesToSessionExpired() = runTest {
        val repo = FakeIdeasRepository().apply {
            loadResult = ApiResult.Success(page(listOf(idea())))
            submitResult = ApiResult.Failure(ApiError(401, "expired"))
        }
        val vm = IdeasViewModel(repo)
        advanceUntilIdle()

        vm.onOpenSubmit()
        vm.onTitleChange("Dark mode")
        vm.onDescriptionChange("Please add a dark theme to the app.")
        vm.onSubmit()
        advanceUntilIdle()

        assertEquals(1, repo.submitCalls)
        assertEquals(IdeasUiState.Phase.SessionExpired, vm.uiState.value.phase)
    }

    @Test
    fun onSubmit_valid_otherFailure_emitsFailureMessage() = runTest {
        val repo = FakeIdeasRepository().apply {
            loadResult = ApiResult.Success(page(listOf(idea())))
            submitResult = ApiResult.Failure(ApiError(422, "invalid"))
        }
        val vm = IdeasViewModel(repo)
        advanceUntilIdle()

        val effects = mutableListOf<IdeasEffect>()
        val job = CoroutineScope(UnconfinedTestDispatcher(testScheduler)).launch {
            vm.effects.collect { effects += it }
        }

        vm.onOpenSubmit()
        vm.onTitleChange("Dark mode")
        vm.onDescriptionChange("Please add a dark theme to the app.")
        vm.onSubmit()
        advanceUntilIdle()
        job.cancel()

        assertEquals(1, repo.submitCalls)
        val msg = effects.filterIsInstance<IdeasEffect.ShowMessage>().single()
        assertEquals(R.string.ideas_submit_failed, msg.resId)
        assertFalse(vm.uiState.value.submit.isSubmitting)
    }
}
