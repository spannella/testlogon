package com.testlogon.android.feature.feed

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.navigation.PostDetailDest
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/** AND-100 / AND-104 — [PostDetailViewModel] state-transition tests. */
class PostDetailViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private fun vm(
        repo: FakeFeedRepository,
        engagement: FakeEngagementRepository = FakeEngagementRepository(),
        postId: String = "post_1",
    ) = PostDetailViewModel(
        repo,
        engagement,
        FakeRepostRepository(),
        fakeDisplayNameResolver(),
        fakeCurrentUserRepository(),
        SavedStateHandle(mapOf(PostDetailDest.ARG_POST_ID to postId)),
    )

    @Test
    fun success_emitsContent() = runTest {
        val repo = FakeFeedRepository(postResult = ApiResult.Success(FakeFeedRepository.post("post_1")))
        val sut = vm(repo)
        advanceUntilIdle()
        val state = sut.uiState.value
        assertTrue(state is PostDetailUiState.Content)
        assertEquals("post_1", (state as PostDetailUiState.Content).post.id)
    }

    @Test
    fun http404_emitsNotFound() = runTest {
        val repo = FakeFeedRepository(postResult = FakeFeedRepository.failure(404))
        val sut = vm(repo)
        advanceUntilIdle()
        assertTrue(sut.uiState.value is PostDetailUiState.NotFound)
    }

    @Test
    fun http403_emitsForbidden() = runTest {
        val repo = FakeFeedRepository(postResult = FakeFeedRepository.failure(403))
        val sut = vm(repo)
        advanceUntilIdle()
        assertTrue(sut.uiState.value is PostDetailUiState.Forbidden)
    }

    @Test
    fun serverError_emitsRetryableError() = runTest {
        val repo = FakeFeedRepository(postResult = FakeFeedRepository.failure(500))
        val sut = vm(repo)
        advanceUntilIdle()
        val state = sut.uiState.value
        assertTrue(state is PostDetailUiState.Error)
        assertTrue((state as PostDetailUiState.Error).retryable)
    }

    @Test
    fun networkError_emitsRetryableError() = runTest {
        val repo = FakeFeedRepository(postResult = FakeFeedRepository.network())
        val sut = vm(repo)
        advanceUntilIdle()
        val state = sut.uiState.value
        assertTrue(state is PostDetailUiState.Error)
        assertTrue((state as PostDetailUiState.Error).retryable)
    }

    @Test
    fun malformedId_shortCircuitsToNotFound_withNoNetworkCall() = runTest {
        val repo = FakeFeedRepository(postResult = ApiResult.Success(FakeFeedRepository.post("x")))
        val sut = vm(repo, postId = "../../etc/passwd")
        advanceUntilIdle()
        assertTrue(sut.uiState.value is PostDetailUiState.NotFound)
        assertEquals(0, repo.postCalls)
    }

    @Test
    fun blankId_notFound_noNetwork() = runTest {
        val repo = FakeFeedRepository(postResult = ApiResult.Success(FakeFeedRepository.post("x")))
        val sut = vm(repo, postId = "")
        advanceUntilIdle()
        assertTrue(sut.uiState.value is PostDetailUiState.NotFound)
        assertEquals(0, repo.postCalls)
    }

    @Test
    fun refresh_reFetches() = runTest {
        val repo = FakeFeedRepository(postResult = ApiResult.Success(FakeFeedRepository.post("post_1")))
        val sut = vm(repo)
        advanceUntilIdle()
        val before = repo.postCalls
        sut.refresh()
        advanceUntilIdle()
        assertTrue(repo.postCalls > before)
    }

    @Test
    fun onLikeToggle_optimistic_thenReconcilesServerCount() = runTest {
        val post = FakeFeedRepository.post("post_1").copy(likedByMe = false, likeCount = 10)
        val repo = FakeFeedRepository(postResult = ApiResult.Success(post))
        val engagement = FakeEngagementRepository(result = { _, liked, _ ->
            ApiResult.Success(com.testlogon.android.data.feed.LikeState(liked, 99))
        })
        val sut = vm(repo, engagement)
        advanceUntilIdle()

        sut.onLikeToggle()
        advanceUntilIdle()

        val content = sut.uiState.value as PostDetailUiState.Content
        assertTrue(content.post.likedByMe)
        assertEquals(99, content.post.likeCount)
    }

    @Test
    fun onLikeToggle_failure_rollsBack() = runTest {
        val post = FakeFeedRepository.post("post_1").copy(likedByMe = false, likeCount = 10)
        val repo = FakeFeedRepository(postResult = ApiResult.Success(post))
        val engagement = FakeEngagementRepository(result = { _, _, _ -> FakeFeedRepository.failure(500) })
        val sut = vm(repo, engagement)
        advanceUntilIdle()

        sut.onLikeToggle()
        advanceUntilIdle()

        val content = sut.uiState.value as PostDetailUiState.Content
        assertFalse(content.post.likedByMe)
        assertEquals(10, content.post.likeCount)
    }

    @Test
    fun onCommentCountChanged_adjustsCount() = runTest {
        val post = FakeFeedRepository.post("post_1").copy(commentCount = 3)
        val sut = vm(FakeFeedRepository(postResult = ApiResult.Success(post)))
        advanceUntilIdle()

        sut.onCommentCountChanged(+1)
        assertEquals(4, (sut.uiState.value as PostDetailUiState.Content).post.commentCount)
        sut.onCommentCountChanged(-1)
        assertEquals(3, (sut.uiState.value as PostDetailUiState.Content).post.commentCount)
    }
}
