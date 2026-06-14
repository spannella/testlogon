package com.testlogon.android.data.broadcast.tips

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-282 — contract tests for [TipsRepositoryImpl]: tip POST -> TipMessage, refresh re-GETs summary +
 * goals into the observed flows, 422 -> Failure, and that a failed tip POST is surfaced (not retried).
 */
class TipsRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): TipsRepositoryImpl {
        val api = backend.retrofit(moshi).create(BroadcastTipsApi::class.java)
        return TipsRepositoryImpl(api = api, errorParser = ApiErrorParser(moshi))
    }

    @Test
    fun submitTip_success_mapsTipMessage() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"message_id":"m1","kind":"tip","created_at":1,"tip_amount_cents":2500,
                   "tip_total_cents":50000}""",
                code = 201,
            ),
        )
        val result = repo().submitTip("s1", 2500, "pm_1", "hi")
        assertTrue(result is ApiResult.Success)
        val tip = (result as ApiResult.Success).data
        assertEquals(2500L, tip.tipAmountCents)
        assertEquals(50000L, tip.tipTotalCents)
    }

    @Test
    fun submitTip_422_mapsFailure() = runTest {
        backend.enqueue(
            Fixtures.error(
                """[{"type":"greater_than_equal","loc":["body","amount_cents"],
                   "msg":"Input should be greater than or equal to 100"}]""",
                code = 422,
            ),
        )
        val result = repo().submitTip("s1", 1, "pm_1", null)
        assertTrue(result is ApiResult.Failure)
        assertEquals(422, (result as ApiResult.Failure).error.status)
        // Exactly one POST issued (no auto-retry on the non-idempotent tip).
        assertEquals(1, backend.requestCount)
    }

    @Test
    fun refresh_populatesSummaryAndGoalsFlows() = runTest {
        backend.enqueue(
            Fixtures.okBody("""{"session_id":"s1","total_cents":1000,"tip_count":4,"currency":"USD"}"""),
        )
        backend.enqueue(
            Fixtures.okBody(
                """{"session_id":"s1","goals":[{"goal_id":"g1","session_id":"s1","label":"mic",
                   "current_cents":500,"target_cents":1000,"reached":false,"sort_order":0,
                   "created_at":1}]}""",
            ),
        )
        val repo = repo()
        val result = repo.refresh("s1")
        assertTrue(result is ApiResult.Success)
        assertEquals(1000L, repo.observeTipsSummary().first()!!.totalCents)
        assertEquals("mic", repo.observeGoals().first().single().label)
    }
}
