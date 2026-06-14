package com.testlogon.android.feature.activity

import androidx.paging.testing.asSnapshot
import com.testlogon.android.core.testing.MainDispatcherRule
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/** AND-096 — [ActivityViewModel] paging + refresh unit tests. */
class ActivityViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    @Test
    fun items_emitFirstPage_inOrder() = runTest {
        val repo = FakeActivityRepository(
            pagesByCursor = mapOf(
                null to FakeActivityRepository.page(
                    listOf(FakeActivityRepository.event("a1"), FakeActivityRepository.event("a2")),
                    nextCursor = null,
                ),
            ),
        )
        val vm = ActivityViewModel(repo)
        advanceUntilIdle()

        val snapshot = vm.items.asSnapshot()
        assertEquals(listOf("a1", "a2"), snapshot.map { it.id })
    }

    @Test
    fun refresh_reTriggersPager() = runTest {
        val repo = FakeActivityRepository(
            pagesByCursor = mapOf(
                null to FakeActivityRepository.page(listOf(FakeActivityRepository.event("a1")), null),
            ),
        )
        val vm = ActivityViewModel(repo)
        advanceUntilIdle()
        vm.items.asSnapshot()
        val callsBefore = repo.feedCalls

        vm.refresh()
        vm.items.asSnapshot()
        advanceUntilIdle()

        assertTrue("refresh should re-issue at least one feed call", repo.feedCalls > callsBefore)
    }
}
