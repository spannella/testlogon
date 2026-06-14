package com.testlogon.android.data.broadcast.tips

import com.squareup.moshi.Moshi
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-282 — MockWebServer contract test for [BroadcastTipsApi]. Verifies the tip POST verb/path/body
 * (amount_cents/payment_method_id/text), the 201 BroadcastChatMessageOut parse (tip_amount_cents /
 * tip_total_cents), and the summary + goals GET envelopes (cents, sort_order).
 */
class BroadcastTipsApiContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun api(): BroadcastTipsApi = backend.retrofit(moshi).create(BroadcastTipsApi::class.java)

    @Test
    fun submitTip_postsBody_parses201ChatMessage() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"message_id":"msg_001","session_id":"s1","text":"great stream!","kind":"tip",
                   "created_at":1749146521,"tip_amount_cents":2500,"tip_currency":"USD",
                   "tip_total_cents":127500}""",
                code = 201,
            ),
        )
        val resp = api().submitTip("s1", BroadcastChatTipDto(2500, "pm_1", "great stream!", "USD"))
        assertTrue(resp.isSuccessful)
        val body = resp.body()!!
        assertEquals("msg_001", body.messageId)
        assertEquals(2500L, body.tipAmountCents)
        assertEquals(127500L, body.tipTotalCents)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/broadcast/sessions/s1/chat/tip", req.requestUrl?.encodedPath)
        val sent = req.body.readUtf8()
        assertTrue(sent.contains("\"amount_cents\":2500"))
        assertTrue(sent.contains("\"payment_method_id\":\"pm_1\""))
        assertTrue(sent.contains("\"text\":\"great stream!\""))
    }

    @Test
    fun getTipsSummary_parsesEnvelope() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"session_id":"s1","total_cents":125000,"tip_count":141,"currency":"USD"}""",
            ),
        )
        val resp = api().getTipsSummary("s1")
        assertTrue(resp.isSuccessful)
        val body = resp.body()!!
        assertEquals(125000L, body.totalCents)
        assertEquals(141, body.tipCount)

        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/broadcast/sessions/s1/tips/summary", req.requestUrl?.encodedPath)
    }

    @Test
    fun getGoals_parsesListEnvelope() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"session_id":"s1","goals":[{"goal_id":"g1","session_id":"s1","label":"New mic",
                   "current_cents":125000,"target_cents":200000,"reached":false,"reached_at":null,
                   "sort_order":0,"created_at":1749100000}]}""",
            ),
        )
        val resp = api().getGoals("s1")
        assertTrue(resp.isSuccessful)
        val goals = resp.body()!!.goals
        assertEquals(1, goals.size)
        assertEquals("New mic", goals[0].label)
        assertEquals(200000L, goals[0].targetCents)

        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/broadcast/sessions/s1/goals", req.requestUrl?.encodedPath)
    }
}
