package com.testlogon.android.feature.broadcast.qna

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.data.broadcast.qna.LiveQaRepository
import com.testlogon.android.data.broadcast.qna.QaQuestion
import com.testlogon.android.data.broadcast.qna.QaSnapshot
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

class LiveQaViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private fun q(id: String, votes: Int) =
        QaQuestion(id, "q $id", "Mira", upvotes = votes, featured = false, pinned = false, createdAtEpochSeconds = 1)

    private class FakeRepo : LiveQaRepository {
        var modeResult: ApiResult<Boolean> = ApiResult.Success(true)
        var questionsResult: ApiResult<QaSnapshot> = ApiResult.Success(QaSnapshot(null, emptyList()))
        var askResult: ApiResult<QaQuestion>? = null
        var upvoteResult: ApiResult<QaQuestion>? = null
        var setUpvoteCalls = 0

        override suspend fun mode(sessionId: String): ApiResult<Boolean> = modeResult
        override suspend fun questions(sessionId: String): ApiResult<QaSnapshot> = questionsResult
        override suspend fun ask(sessionId: String, text: String): ApiResult<QaQuestion> =
            askResult ?: ApiResult.Success(
                QaQuestion("new", text, "me", 0, false, false, 1),
            )
        override suspend fun setUpvote(
            sessionId: String,
            questionId: String,
            voted: Boolean,
        ): ApiResult<QaQuestion> {
            setUpvoteCalls++
            return upvoteResult ?: error("set upvoteResult")
        }
    }

    @Test
    fun modeOff_rendersDisabled_doesNotLoadList() = runTest {
        val repo = FakeRepo().apply { modeResult = ApiResult.Success(false) }
        val vm = LiveQaViewModel("s1", repo)
        advanceUntilIdle()
        assertEquals(LiveQaUiState.Phase.Disabled, vm.uiState.value.phase)
    }

    @Test
    fun load_populatesContent_withFeaturedBanner() = runTest {
        val repo = FakeRepo().apply {
            questionsResult = ApiResult.Success(QaSnapshot(featured = q("f1", 9), questions = listOf(q("q2", 2))))
        }
        val vm = LiveQaViewModel("s1", repo)
        advanceUntilIdle()
        assertEquals(LiveQaUiState.Phase.Content, vm.uiState.value.phase)
        assertNotNull(vm.uiState.value.featured)
        assertEquals(listOf("q2"), vm.uiState.value.questions.map { it.id })
    }

    @Test
    fun optimisticUpvote_incrementsImmediately_thenAdoptsServerCount() = runTest {
        val repo = FakeRepo().apply {
            questionsResult = ApiResult.Success(QaSnapshot(null, listOf(q("q1", 10))))
            upvoteResult = ApiResult.Success(q("q1", 11))
        }
        val vm = LiveQaViewModel("s1", repo)
        advanceUntilIdle()

        vm.toggleUpvote("q1")
        // The increment + voted flip happen synchronously before the server responds.
        assertEquals(11, vm.uiState.value.questions.single().upvotes)
        assertTrue("q1" in vm.uiState.value.upvotedIds)

        advanceUntilIdle()
        assertEquals(11, vm.uiState.value.questions.single().upvotes)
        assertEquals(1, repo.setUpvoteCalls)
    }

    @Test
    fun upvoteFailure_rollsBack() = runTest {
        val repo = FakeRepo().apply {
            questionsResult = ApiResult.Success(QaSnapshot(null, listOf(q("q1", 10))))
            upvoteResult = ApiResult.Failure(ApiError(status = 500, message = "boom"))
        }
        val vm = LiveQaViewModel("s1", repo)
        advanceUntilIdle()

        vm.toggleUpvote("q1")
        advanceUntilIdle()

        assertEquals(10, vm.uiState.value.questions.single().upvotes)
        assertFalse("q1" in vm.uiState.value.upvotedIds)
        assertNotNull(vm.uiState.value.transientMessage)
    }

    @Test
    fun submitQuestion_success_clearsComposer_mergesItem() = runTest {
        val repo = FakeRepo().apply {
            questionsResult = ApiResult.Success(QaSnapshot(null, emptyList()))
        }
        val vm = LiveQaViewModel("s1", repo)
        advanceUntilIdle()

        vm.onComposerChange("Can you show the setup?")
        assertTrue(vm.uiState.value.canSubmit)
        vm.submitQuestion()
        advanceUntilIdle()

        assertEquals("", vm.uiState.value.composerText)
        assertEquals(listOf("new"), vm.uiState.value.questions.map { it.id })
    }

    @Test
    fun canSubmit_falseForBlankAndOverLimit() = runTest {
        val repo = FakeRepo().apply { questionsResult = ApiResult.Success(QaSnapshot(null, emptyList())) }
        val vm = LiveQaViewModel("s1", repo)
        advanceUntilIdle()

        vm.onComposerChange("   ")
        assertFalse(vm.uiState.value.canSubmit)
        vm.onComposerChange("x".repeat(LiveQaUiState.MAX_LEN + 1))
        assertFalse(vm.uiState.value.canSubmit)
        vm.onComposerChange("valid")
        assertTrue(vm.uiState.value.canSubmit)
    }
}
