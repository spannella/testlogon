package com.testlogon.android.feature.messaging.thread

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.messaging.MessageSearchMatch
import com.testlogon.android.feature.messaging.FakeMessagingRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class ThreadSearchControllerTest {

    private val repo = FakeMessagingRepository()

    private fun match(id: String, occ: Int = 0, createdAt: Long = 100L) = MessageSearchMatch(
        messageId = id,
        occurrenceIndex = occ,
        start = 0,
        end = 3,
        createdAtEpochSeconds = createdAt,
        text = "deploy",
    )

    // The engine runs on an UnconfinedTestDispatcher bound to the test scheduler: the launched
    // collector starts eagerly and its debounce delay() is driven by advanceUntilIdle/advanceTimeBy.
    // (TestScope.backgroundScope did NOT get advanced for this injected-scope collector.)
    private fun TestScope.controller(
        scope: CoroutineScope = CoroutineScope(UnconfinedTestDispatcher(testScheduler)),
        saved: SavedStateHandle = SavedStateHandle(),
    ) = ThreadSearchController(
        conversationId = "conv_1",
        repository = repo,
        saved = saved,
        scope = scope,
    )

    @Test
    fun happyPath_debouncesToOneCall_setsLoadedAndCursor() = runTest {
        repo.searchInConversationResult = ApiResult.Success(
            listOf(match("m1"), match("m2", createdAt = 200), match("m3", createdAt = 300)),
        )
        val c = controller()
        c.open()
        c.onQueryChange("deploy")
        advanceUntilIdle()

        assertEquals(1, repo.searchInConversationCalls.size)
        assertEquals("conv_1" to "deploy", repo.searchInConversationCalls.single())
        val s = c.state.value
        assertTrue(s.phase is SearchPhase.Loaded)
        assertEquals(3, s.total)
        assertEquals(0, s.activeIndex)
        assertEquals("1 of 3", s.cursorLabel)
    }

    @Test
    fun rapidTyping_coalescesToSingleCallForSettledQuery() = runTest {
        repo.searchInConversationResult = ApiResult.Success(listOf(match("m1")))
        val c = controller()
        c.open()
        c.onQueryChange("de")
        advanceTimeBy(100)
        c.onQueryChange("dep")
        advanceTimeBy(100)
        c.onQueryChange("deploy")
        advanceUntilIdle()

        assertEquals(1, repo.searchInConversationCalls.size)
        assertEquals("deploy", repo.searchInConversationCalls.single().second)
    }

    @Test
    fun shortQuery_issuesNoCall_clearsResultsWithTooShortHint() = runTest {
        repo.searchInConversationResult = ApiResult.Success(listOf(match("m1")))
        val c = controller()
        c.open()
        c.onQueryChange("deploy")
        advanceUntilIdle()
        assertEquals(1, repo.searchInConversationCalls.size)

        c.onQueryChange("d")
        advanceUntilIdle()
        assertEquals(1, repo.searchInConversationCalls.size) // no new call
        assertTrue(c.state.value.tooShort)
        assertEquals(0, c.state.value.total)
        assertEquals(-1, c.state.value.activeIndex)
    }

    @Test
    fun blankQuery_issuesNoCall_clearsResults() = runTest {
        val c = controller()
        c.open()
        c.onQueryChange("   ")
        advanceUntilIdle()
        assertTrue(repo.searchInConversationCalls.isEmpty())
        assertFalse(c.state.value.tooShort)
        assertTrue(c.state.value.matches.isEmpty())
    }

    @Test
    fun nextPrev_wrapAround() = runTest {
        repo.searchInConversationResult = ApiResult.Success(
            listOf(match("m1"), match("m2", createdAt = 200), match("m3", createdAt = 300)),
        )
        val c = controller()
        c.open()
        c.onQueryChange("deploy")
        advanceUntilIdle()

        assertEquals(0, c.state.value.activeIndex)
        c.next(); assertEquals(1, c.state.value.activeIndex)
        c.next(); assertEquals(2, c.state.value.activeIndex)
        c.next(); assertEquals(0, c.state.value.activeIndex) // wrap last -> first
        c.prev(); assertEquals(2, c.state.value.activeIndex) // wrap first -> last
    }

    @Test
    fun nextPrev_noOpWithZeroMatches() = runTest {
        repo.searchInConversationResult = ApiResult.Success(emptyList())
        val c = controller()
        c.open()
        c.onQueryChange("deploy")
        advanceUntilIdle()
        assertEquals(-1, c.state.value.activeIndex)
        assertFalse(c.state.value.hasMatches)
        c.next(); assertEquals(-1, c.state.value.activeIndex)
        c.prev(); assertEquals(-1, c.state.value.activeIndex)
    }

    @Test
    fun emptyResult_resetsActiveIndexToMinusOne() = runTest {
        repo.searchInConversationResult = ApiResult.Success(emptyList())
        val c = controller()
        c.open()
        c.onQueryChange("nope")
        advanceUntilIdle()
        assertTrue(c.state.value.phase is SearchPhase.Loaded)
        assertEquals(0, c.state.value.total)
        assertEquals(-1, c.state.value.activeIndex)
    }

    @Test
    fun failure_setsErrorPhase_clearsMatches() = runTest {
        repo.searchInConversationResult = ApiResult.Failure(ApiError(status = 404, message = "gone"))
        val c = controller()
        c.open()
        c.onQueryChange("deploy")
        advanceUntilIdle()
        assertTrue(c.state.value.phase is SearchPhase.Error)
        assertTrue(c.state.value.matches.isEmpty())
    }

    @Test
    fun networkError_setsErrorPhase() = runTest {
        repo.searchInConversationResult = ApiResult.NetworkError(java.io.IOException("x"), isTimeout = true)
        val c = controller()
        c.open()
        c.onQueryChange("deploy")
        advanceUntilIdle()
        assertTrue(c.state.value.phase is SearchPhase.Error)
    }

    @Test
    fun close_resetsState() = runTest {
        repo.searchInConversationResult = ApiResult.Success(listOf(match("m1")))
        val c = controller()
        c.open()
        c.onQueryChange("deploy")
        advanceUntilIdle()
        assertTrue(c.state.value.active)

        c.close()
        assertFalse(c.state.value.active)
        assertEquals("", c.state.value.query)
        assertTrue(c.state.value.matches.isEmpty())
    }

    @Test
    fun savedState_persistsActiveQueryAndIndex() = runTest {
        val saved = SavedStateHandle()
        repo.searchInConversationResult = ApiResult.Success(
            listOf(match("m1"), match("m2", createdAt = 200)),
        )
        val c = controller(saved = saved)
        c.open()
        c.onQueryChange("deploy")
        advanceUntilIdle()
        c.next()
        assertEquals(true, saved.get<Boolean>("search_active"))
        assertEquals("deploy", saved.get<String>("search_query"))
        assertEquals(1, saved.get<Int>("search_active_index"))
    }
}
