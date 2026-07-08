package com.testlogon.android.feature.feed

import androidx.lifecycle.SavedStateHandle
import androidx.paging.testing.asSnapshot
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.data.feed.CommentPage
import com.testlogon.android.navigation.PostDetailDest
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/** AND-174 — [CommentsViewModel] optimistic add / reconcile / retry / discard / delete tests. */
class CommentsViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private fun vm(repo: FakeCommentsRepository) =
        CommentsViewModel(
            repo,
            com.testlogon.android.feature.messaging.FakeMessagingRepository(),
            fakeDisplayNameResolver(),
            FakeCommentImageUploader(),
            // Debug-parity billing: authorizes with a blank PM id (matches StubBillingAuthorizer in debug).
            object : com.testlogon.android.data.messaging.BillingAuthorizer {
                override suspend fun authorize(amountMinorUnits: Long, currency: String, memo: String?) =
                    com.testlogon.android.data.messaging.BillingResult.Authorized(paymentMethodId = "", authorizedMinorUnits = amountMinorUnits)
            },
            SavedStateHandle(mapOf(PostDetailDest.ARG_POST_ID to "post_1")),
        )

    @Test
    fun send_insertsPendingHeader_clearsComposer() = runTest {
        // Repo add never returns until we let it; gate via failure so the pending stays visible.
        val repo = FakeCommentsRepository(addResult = FakeCommentsRepository.failure(500))
        val sut = vm(repo)
        sut.onBodyChange("hello")
        assertTrue(sut.composer.value.canSend)

        sut.send()
        // Immediately after send the composer text is cleared (optimistic).
        assertEquals("", sut.composer.value.text)

        advanceUntilIdle()
        val items = sut.comments.asSnapshot()
        assertEquals(1, items.size)
        assertTrue(items[0].failed) // post failed -> flagged for Retry/Discard
        assertEquals("hello", items[0].body)
    }

    @Test
    fun send_success_removesPending_emitsCountIncrement() = runTest {
        val repo = FakeCommentsRepository()
        val sut = vm(repo)
        sut.onBodyChange("hi")
        sut.send()
        advanceUntilIdle()

        // Pending entry removed after success.
        assertTrue(sut.comments.asSnapshot().none { it.pending })
        assertEquals(Triple("post_1", "hi", null), repo.addCalls.single())
        // Refresh signal bumped to reconcile.
        assertTrue(sut.refreshSignal.value > 0)
        // Effect fired: +1 count.
        val effect = sut.effects.first()
        assertTrue(effect is CommentsEffect.CommentCountChanged)
        assertEquals(1, (effect as CommentsEffect.CommentCountChanged).delta)
    }

    @Test
    fun retry_reissuesAdd_thenSucceeds() = runTest {
        val repo = FakeCommentsRepository(addResult = FakeCommentsRepository.failure(503))
        val sut = vm(repo)
        sut.onBodyChange("retryme")
        sut.send()
        advanceUntilIdle()
        val failed = sut.comments.asSnapshot().single()
        assertTrue(failed.failed)

        // Now make the repo succeed and retry.
        repo.addResult = null
        sut.retry(failed.localKey)
        advanceUntilIdle()

        assertTrue(sut.comments.asSnapshot().none { it.pending || it.failed })
        assertEquals(2, repo.addCalls.size)
    }

    @Test
    fun discard_removesFailedEntry() = runTest {
        val repo = FakeCommentsRepository(addResult = FakeCommentsRepository.failure(500))
        val sut = vm(repo)
        sut.onBodyChange("nope")
        sut.send()
        advanceUntilIdle()
        val failed = sut.comments.asSnapshot().single()

        sut.discard(failed.localKey)
        advanceUntilIdle()
        assertTrue(sut.comments.asSnapshot().isEmpty())
    }

    @Test
    fun delete_ownComment_emitsDecrement() = runTest {
        val repo = FakeCommentsRepository()
        val sut = vm(repo)
        val mine = FakeCommentsRepository.comment("c1", canDelete = true)

        sut.delete(mine)
        advanceUntilIdle()

        assertEquals(listOf("post_1" to "c1"), repo.deleteCalls)
        val effect = sut.effects.first()
        assertTrue(effect is CommentsEffect.CommentCountChanged)
        assertEquals(-1, (effect as CommentsEffect.CommentCountChanged).delta)
    }

    @Test
    fun delete_nonOwn_isNoOp() = runTest {
        val repo = FakeCommentsRepository()
        val sut = vm(repo)
        sut.delete(FakeCommentsRepository.comment("c2", canDelete = false))
        advanceUntilIdle()
        assertTrue(repo.deleteCalls.isEmpty())
    }

    @Test
    fun startReply_noOp_whenRepliesUnsupported() = runTest {
        val repo = FakeCommentsRepository(repliesSupported = false)
        val sut = vm(repo)
        sut.startReply(FakeCommentsRepository.comment("c1"))
        assertFalse(sut.composer.value.replyTo != null)
    }

    @Test
    fun pagingFlow_mergesServerPage() = runTest {
        val repo = FakeCommentsRepository(
            pagesByCursor = mapOf(
                null to CommentPage(
                    listOf(
                        FakeCommentsRepository.comment("c1"),
                        FakeCommentsRepository.comment("c2"),
                    ),
                    nextCursor = null,
                ),
            ),
        )
        val sut = vm(repo)
        val items = sut.comments.asSnapshot()
        assertEquals(listOf("c1", "c2"), items.map { it.id })
    }
}
