package com.testlogon.android.data.tipinsights

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.RecordedRequest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * TIPX-D3/D4 — contract tests for [TipInsightsRepositoryImpl].
 *
 * Proves the combined load fans out to the 3 ledger-backed GETs and maps them to domain:
 *  - received summary: NET total, only non-empty surfaces, sorted by total desc
 *  - sent summary + receipts: gross amounts + platform fee preserved
 * A path-based dispatcher is used because the GETs race.
 */
class TipInsightsRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun installDispatcher() {
        backend.server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse {
                val path = request.path.orEmpty()
                return when {
                    path.startsWith("/ui/tips/received") -> json(RECEIVED)
                    path.startsWith("/ui/tips/sent/summary") -> json(SENT_SUMMARY)
                    path.startsWith("/ui/tips/sent") -> json(SENT)
                    else -> MockResponse().setResponseCode(404)
                }
            }
        }
    }

    private fun repo(): TipInsightsRepositoryImpl {
        val api = backend.retrofit(moshi).create(TipInsightsApi::class.java)
        return TipInsightsRepositoryImpl(api = api, errorParser = ApiErrorParser(moshi))
    }

    private fun json(body: String) =
        MockResponse().setResponseCode(200).setHeader("Content-Type", "application/json").setBody(body)

    @Test
    fun load_combinesAllThreeCalls_andMapsToDomain() = runTest {
        installDispatcher()
        val result = repo().load("30d")
        assertTrue(result is ApiResult.Success)
        val d = (result as ApiResult.Success).data

        // Received: NET total reconciles (800 + 1600 + 240 = 2640)
        assertEquals(2640L, d.received.totalNetCents)
        assertEquals(3, d.received.tipCount)
        assertEquals(2, d.received.uniqueTippers)
        // Only non-empty surfaces surface, sorted by total desc (comment 1600 > post 800 > video 240)
        assertEquals(3, d.received.bySurface.size)
        assertEquals("comment", d.received.bySurface[0].surface)
        assertEquals("post", d.received.bySurface[1].surface)
        assertEquals("video", d.received.bySurface[2].surface)
        // Top supporters mapped
        assertEquals("Tipper Two", d.received.topSupporters[0].displayName)

        // Sent: gross total + receipt fee preserved
        assertEquals(3000L, d.sentSummary.totalSentCents)
        assertEquals(1, d.sentReceipts.size)
        assertEquals(1000L, d.sentReceipts[0].amountCents)
        assertEquals(200L, d.sentReceipts[0].platformFeeCents)
        assertEquals("Cool Creator", d.sentReceipts[0].counterpartyDisplayName)
        assertEquals("post", d.sentReceipts[0].surface)
    }

    @Test
    fun load_httpError_mapsToFailure() = runTest {
        backend.server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse =
                MockResponse().setResponseCode(500).setBody("{}")
        }
        val result = repo().load("30d")
        assertTrue(result is ApiResult.Failure)
    }

    private companion object {
        const val RECEIVED = """
            {
              "period": "30d",
              "total_net_cents": 2640,
              "tip_count": 3,
              "unique_tippers": 2,
              "by_type": {
                "post": {"count": 1, "total_cents": 800},
                "comment": {"count": 1, "total_cents": 1600},
                "video": {"count": 1, "total_cents": 240},
                "message": {"count": 0, "total_cents": 0}
              },
              "top_tippers": [
                {"user_id": "t2", "display_name": "Tipper Two", "total_cents": 1840, "tip_count": 2},
                {"user_id": "t1", "display_name": "Tipper One", "total_cents": 800, "tip_count": 1}
              ],
              "source": "ledger"
            }
        """

        const val SENT_SUMMARY = """
            {"period": "all", "total_sent_cents": 3000, "tip_count": 2, "unique_recipients": 1, "source": "ledger"}
        """

        const val SENT = """
            {
              "items": [
                {
                  "entry_id": "e1", "ts": 1784200000, "amount_cents": 1000, "reason": "Tip: post",
                  "content_type": "post", "content_id": "post_A", "counterparty_user_id": "creator1",
                  "counterparty_display_name": "Cool Creator", "platform_fee_cents": 200,
                  "tip_payment_id": "tip_1", "currency": "USD"
                }
              ],
              "next_cursor": null
            }
        """
    }
}
