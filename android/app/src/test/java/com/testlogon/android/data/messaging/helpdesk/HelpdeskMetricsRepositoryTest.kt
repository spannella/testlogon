package com.testlogon.android.data.messaging.helpdesk

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.subscriptions.FakeAuthStateStore
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException

/**
 * AND-377 — repository tests for the Q1 client-side metrics derivation (TC-04) + 403 gate + stale cache.
 *
 * Uses a recording fake [HelpdeskRepository] (the queue source) — NO MockWebServer needed because the
 * derivation is pure and the queue stack is already covered by AND-161's contract tests.
 */
class HelpdeskMetricsRepositoryTest {

    private fun item(
        id: String,
        routing: HelpdeskRoutingState = HelpdeskRoutingState.AWAITING_AGENT,
        claim: ClaimState = ClaimState.UNASSIGNED,
    ) = HelpdeskQueueItem(
        conversationId = id, title = "T", preview = "p",
        routingState = routing, claimState = claim,
        activeAgentUserId = if (claim == ClaimState.UNASSIGNED) null else "agent",
        unreadCount = 0, lastMessageAtEpochSeconds = 1,
    )

    private class FakeQueueRepo(var result: ApiResult<List<HelpdeskQueueItem>>) : HelpdeskRepository {
        var calls = 0
        override suspend fun loadQueue(state: String?, limit: Int): ApiResult<List<HelpdeskQueueItem>> {
            calls++
            return result
        }
        override suspend fun claim(conversationId: String) = error("unused")
        override suspend fun refreshAssignment(conversationId: String) = error("unused")
    }

    private fun repo(
        queueResult: ApiResult<List<HelpdeskQueueItem>>,
        userSub: String? = "usr_me",
    ): Pair<HelpdeskMetricsRepositoryImpl, FakeQueueRepo> {
        val queue = FakeQueueRepo(queueResult)
        val impl = HelpdeskMetricsRepositoryImpl(queue, FakeAuthStateStore(userSub))
        impl.nowSeconds = { 1234L }
        return impl to queue
    }

    @Test
    fun derive_countsFromQueue_timeMetricsNull() = runBlocking {
        val items = listOf(
            item("a", HelpdeskRoutingState.AWAITING_AGENT, ClaimState.UNASSIGNED),
            item("b", HelpdeskRoutingState.ASSIGNED, ClaimState.CLAIMED_BY_ME),
            item("c", HelpdeskRoutingState.ASSIGNED, ClaimState.CLAIMED_BY_OTHER),
            item("d", HelpdeskRoutingState.CLOSED, ClaimState.CLAIMED_BY_OTHER),
        )
        val (impl, _) = repo(ApiResult.Success(items))
        val r = impl.refreshMetrics()
        assertTrue(r is ApiResult.Success)
        val m = (r as ApiResult.Success).data.metrics
        assertEquals(3, m.openCount) // a, b, c (d is closed)
        assertEquals(1, m.unassignedCount) // a
        assertEquals(1, m.assignedToMeCount) // b
        assertEquals(1, m.slaAtRiskCount) // a (awaiting + unassigned)
        assertNull(m.avgFirstResponseSeconds)
        assertNull(m.avgResolutionSeconds)
        assertNull(m.resolvedByMeToday)
        assertEquals(1234L, m.generatedAtEpochSeconds)
    }

    @Test
    fun refresh_403_returnsFailure_andCachesNothing() = runBlocking {
        val (impl, queue) = repo(ApiResult.Failure(ApiError(status = 403, message = "forbidden")))
        val r = impl.refreshMetrics()
        assertTrue(r is ApiResult.Failure)
        assertEquals(403, (r as ApiResult.Failure).error.status)
        assertEquals(1, queue.calls)
        assertNull(impl.cachedMetrics().value)
    }

    @Test
    fun refresh_success_populatesCache_thenFailureFallsBack() = runBlocking {
        val (impl, queue) = repo(ApiResult.Success(listOf(item("a"))))
        impl.refreshMetrics()
        assertEquals(1, impl.cachedMetrics().value?.data?.metrics?.openCount)

        // Subsequent transport failure leaves the cache intact (caller reads it for stale fallback).
        queue.result = ApiResult.NetworkError(IOException("offline"))
        val r = impl.refreshMetrics()
        assertTrue(r is ApiResult.NetworkError)
        assertEquals(1, impl.cachedMetrics().value?.data?.metrics?.openCount)
    }

    @Test
    fun agentChange_clearsCache() = runBlocking {
        val queue = FakeQueueRepo(ApiResult.Success(listOf(item("a"))))
        val auth = FakeAuthStateStore("usr_a")
        val impl = HelpdeskMetricsRepositoryImpl(queue, auth)
        impl.nowSeconds = { 1234L }
        impl.refreshMetrics()
        assertEquals(1, impl.cachedMetrics().value?.data?.metrics?.openCount)

        // Different agent + a failing fetch -> the previous agent's cache must be cleared first.
        auth.setUser("usr_b")
        queue.result = ApiResult.NetworkError(IOException("offline"))
        impl.refreshMetrics()
        assertNull(impl.cachedMetrics().value)
    }

    @Test
    fun derive_isEmpty_whenAllZero() {
        val m = HelpdeskMetricsRepositoryImpl.deriveMetrics(
            items = emptyList(),
            currentUserId = "usr_me",
            generatedAtEpochSeconds = 1L,
        )
        assertTrue(m.isEmpty)
        assertFalse(
            HelpdeskMetricsRepositoryImpl.deriveMetrics(
                items = listOf(item("a")),
                currentUserId = "usr_me",
                generatedAtEpochSeconds = 1L,
            ).isEmpty,
        )
    }
}
