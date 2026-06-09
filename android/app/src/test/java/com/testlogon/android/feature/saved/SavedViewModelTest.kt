package com.testlogon.android.feature.saved

import com.testlogon.android.core.testing.MainDispatcherRule
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/** AND-096 — [SavedViewModel] optimistic-unsave / rollback / undo unit tests. */
class SavedViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private val b1 = FakeBookmarksRepository.bookmark(contentId = "post_1")
    private val b2 = FakeBookmarksRepository.bookmark(contentId = "post_2")

    @Test
    fun onUnsave_optimisticallyHidesImmediately_beforeNetworkResolves() = runTest {
        val repo = FakeBookmarksRepository(items = listOf(b1, b2)).apply {
            unsaveGate = CompletableDeferred()
        }
        val vm = SavedViewModel(repo)

        vm.onUnsave(b1)
        // Network is gated (still in flight): the key must already be hidden.
        assertTrue(b1.key in vm.state.value.removedKeys)
        assertEquals(b1, vm.state.value.undoTarget)

        repo.unsaveGate?.complete(Unit)
        advanceUntilIdle()
        assertEquals(listOf("post" to "post_1"), repo.unsaveCalls)
    }

    @Test
    fun onUnsave_success_emitsUndoEffect() = runTest {
        val repo = FakeBookmarksRepository(items = listOf(b1))
        val vm = SavedViewModel(repo)
        vm.onUnsave(b1)
        val event = vm.events.first()
        advanceUntilIdle()
        assertTrue(event is SavedEvent.ShowUndo)
        assertTrue(b1.key in vm.state.value.removedKeys)
    }

    @Test
    fun onUnsave_failure_rollsBack_andEmitsError() = runTest {
        val repo = FakeBookmarksRepository(items = listOf(b1)).apply {
            unsaveResult = FakeBookmarksRepository.failure(500)
        }
        val vm = SavedViewModel(repo)
        vm.onUnsave(b1)
        val event = vm.events.first()
        advanceUntilIdle()
        assertTrue(event is SavedEvent.ShowError)
        assertFalse(b1.key in vm.state.value.removedKeys) // restored
        assertNull(vm.state.value.undoTarget)
    }

    @Test
    fun onUnsave_404_toleratedAsSuccess_rowStaysGone() = runTest {
        // Repository maps 404 -> Success, so the VM keeps the row removed with no error.
        val repo = FakeBookmarksRepository(items = listOf(b1)) // unsaveResult defaults to Success
        val vm = SavedViewModel(repo)
        vm.onUnsave(b1)
        advanceUntilIdle()
        assertTrue(b1.key in vm.state.value.removedKeys)
    }

    @Test
    fun onUndo_resaves_andUnhidesRow() = runTest {
        val repo = FakeBookmarksRepository(items = listOf(b1))
        val vm = SavedViewModel(repo)
        vm.onUnsave(b1)
        advanceUntilIdle()
        assertTrue(b1.key in vm.state.value.removedKeys)

        vm.onUndo()
        advanceUntilIdle()
        assertEquals(1, repo.resaveCalls)
        assertFalse(b1.key in vm.state.value.removedKeys) // re-shown
    }
}
