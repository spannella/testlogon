package com.testlogon.android.feature.call.history

import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.call.CallAction
import com.testlogon.android.data.call.CallBillingStatus
import com.testlogon.android.data.call.CallDirection
import com.testlogon.android.data.call.CallHeartbeat
import com.testlogon.android.data.call.CallHistoryEntry
import com.testlogon.android.data.call.CallHistoryPage
import com.testlogon.android.data.call.CallInvited
import com.testlogon.android.data.call.CallMode
import com.testlogon.android.data.call.CallRepository
import com.testlogon.android.data.call.CallStats
import com.testlogon.android.data.call.CallStatus
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-303 — [CallHistoryViewModel] tests: manual cursor paging (append + stop at next_cursor == null),
 * pull-to-refresh replace, optimistic delete (+ restore on failure), and the empty / refresh / append
 * error surfaces. Uses [MainDispatcherRule] + runCurrent (NEVER advanceUntilIdle — the VM holds no infinite
 * flow but runCurrent keeps the paging assertions deterministic).
 */
@OptIn(ExperimentalCoroutinesApi::class)
class CallHistoryViewModelTest {

    @get:Rule
    val mainDispatcher = MainDispatcherRule()

    private fun entry(id: String, status: CallStatus = CallStatus.COMPLETED) = CallHistoryEntry(
        callId = id,
        callerId = "u1",
        calleeId = "u2",
        mode = CallMode.AUDIO,
        direction = CallDirection.OUTGOING,
        status = status,
        durationSeconds = 30,
        createdAtEpochSeconds = 1000,
        rawStatus = status.name.lowercase(),
    )

    /** A scripted repo: history() pops the next queued page; delete()/stats() configurable. */
    private class FakeRepo(
        private val pages: ArrayDeque<ApiResult<CallHistoryPage>>,
        var firstPage: ApiResult<CallHistoryPage>,
        var deleteResult: ApiResult<Unit> = ApiResult.Success(Unit),
        var statsResult: ApiResult<CallStats> = ApiResult.Success(CallStats(0, emptyMap(), emptyMap(), 0)),
    ) : CallRepository {
        var lastDeleteId: String? = null

        override suspend fun history(cursor: String?, limit: Int?): ApiResult<CallHistoryPage> =
            if (cursor == null) firstPage else pages.removeFirst()

        override suspend fun detail(callId: String): ApiResult<CallHistoryEntry> =
            ApiResult.Failure(ApiError(status = 500, message = "unused"))

        override suspend fun deleteRecord(callId: String): ApiResult<Unit> {
            lastDeleteId = callId
            return deleteResult
        }

        override suspend fun stats(): ApiResult<CallStats> = statsResult

        // ─── Unused control-plane members ───────────────────────────────────────────────────────────
        override suspend fun invite(
            callId: String, conversationId: String, calleeUserId: String, mode: CallMode,
            idempotencyKey: String?, paid: Boolean, rateCentsPerMin: Int?,
        ): ApiResult<CallInvited> = error("unused")
        override suspend fun accept(callId: String, idempotencyKey: String?): ApiResult<CallAction> = error("unused")
        override suspend fun decline(callId: String, reason: String): ApiResult<CallAction> = error("unused")
        override suspend fun end(callId: String, reason: String, idempotencyKey: String?): ApiResult<CallAction> = error("unused")
        override suspend fun timeout(callId: String, reason: String, idempotencyKey: String?): ApiResult<CallAction> = error("unused")
        override suspend fun heartbeat(callId: String, clientTsEpochSeconds: Long?): ApiResult<CallHeartbeat> = error("unused")
        override suspend fun billing(callId: String): ApiResult<CallBillingStatus> = error("unused")
    }

    private fun page(vararg ids: String, next: String?) =
        ApiResult.Success(CallHistoryPage(ids.map { entry(it) }, next))

    @Test
    fun init_loadsFirstPage_andStats() = runTest {
        val repo = FakeRepo(
            pages = ArrayDeque(),
            firstPage = page("a", "b", next = "cur2"),
            statsResult = ApiResult.Success(CallStats(5, mapOf("completed" to 5), emptyMap(), 600)),
        )
        val vm = CallHistoryViewModel(repo)
        runCurrent()

        val s = vm.state.value
        assertEquals(listOf("a", "b"), s.entries.map { it.callId })
        assertEquals("cur2", s.nextCursor)
        assertTrue(s.canLoadMore)
        assertTrue(s.loaded)
        assertNotNull(s.stats)
        assertEquals(5, s.stats?.totalCalls)
    }

    @Test
    fun loadMore_appends_andStopsWhenCursorNull() = runTest {
        val repo = FakeRepo(
            pages = ArrayDeque(listOf(page("c", "d", next = null))),
            firstPage = page("a", "b", next = "cur2"),
        )
        val vm = CallHistoryViewModel(repo)
        runCurrent()

        vm.loadMore()
        runCurrent()

        val s = vm.state.value
        assertEquals(listOf("a", "b", "c", "d"), s.entries.map { it.callId })
        assertNull(s.nextCursor)
        assertFalse(s.canLoadMore)
    }

    @Test
    fun refresh_replacesEntries() = runTest {
        val repo = FakeRepo(
            pages = ArrayDeque(),
            firstPage = page("a", "b", next = "cur2"),
        )
        val vm = CallHistoryViewModel(repo)
        runCurrent()

        // The server returns a different first page on refresh; entries are REPLACED (not appended).
        repo.firstPage = page("x", "y", "z", next = null)
        vm.refresh()
        runCurrent()

        val s = vm.state.value
        assertEquals(listOf("x", "y", "z"), s.entries.map { it.callId })
        assertNull(s.nextCursor)
        assertFalse(s.isRefreshing)
    }

    @Test
    fun delete_removesRow_optimistically() = runTest {
        val repo = FakeRepo(
            pages = ArrayDeque(),
            firstPage = page("a", "b", "c", next = null),
        )
        val vm = CallHistoryViewModel(repo)
        runCurrent()

        vm.delete("b")
        runCurrent()

        assertEquals(listOf("a", "c"), vm.state.value.entries.map { it.callId })
        assertEquals("b", repo.lastDeleteId)
    }

    @Test
    fun delete_restoresRow_onFailure() = runTest {
        val repo = FakeRepo(
            pages = ArrayDeque(),
            firstPage = page("a", "b", "c", next = null),
            deleteResult = ApiResult.Failure(ApiError(status = 500, message = "boom")),
        )
        val vm = CallHistoryViewModel(repo)
        runCurrent()

        vm.delete("b")
        runCurrent()

        val s = vm.state.value
        assertEquals(listOf("a", "b", "c"), s.entries.map { it.callId })
        assertEquals("boom", s.error)
    }

    @Test
    fun firstLoadFailure_whenEmpty_setsRefreshError() = runTest {
        val repo = FakeRepo(
            pages = ArrayDeque(),
            firstPage = ApiResult.Failure(ApiError(status = 503, message = "down")),
        )
        val vm = CallHistoryViewModel(repo)
        runCurrent()

        val s = vm.state.value
        assertEquals("down", s.refreshError)
        assertTrue(s.loaded)
        assertTrue(s.entries.isEmpty())
    }

    @Test
    fun loadMoreFailure_setsAppendError_keepsRows() = runTest {
        val repo = FakeRepo(
            pages = ArrayDeque(listOf(ApiResult.Failure(ApiError(status = 500, message = "later")))),
            firstPage = page("a", "b", next = "cur2"),
        )
        val vm = CallHistoryViewModel(repo)
        runCurrent()

        vm.loadMore()
        runCurrent()

        val s = vm.state.value
        assertEquals(listOf("a", "b"), s.entries.map { it.callId })
        assertEquals("later", s.appendError)
        assertNull(s.refreshError)
    }

    @Test
    fun emptyResult_isEmptyTrue() = runTest {
        val repo = FakeRepo(
            pages = ArrayDeque(),
            firstPage = ApiResult.Success(CallHistoryPage(emptyList(), null)),
        )
        val vm = CallHistoryViewModel(repo)
        runCurrent()

        assertTrue(vm.state.value.isEmpty)
    }
}
