package com.testlogon.android.data.messaging

import com.testlogon.android.testutil.testMoshi

import com.squareup.moshi.Moshi
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.bodyJson
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Rule
import org.junit.Test

/** AND-137/139 — MockWebServer contract tests for countdown / tip / unlock / lottery endpoints. */
class PaidMessageApiContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = testMoshi()
    private fun api(): MessagingApi = backend.retrofit(moshi).create(MessagingApi::class.java)

    @Test
    fun sendCountdown_postsTitleAndTarget_decodesCountdown() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"message_id":"msg_cd","conversation_id":"c1","sender_id":"u1","created_at":1780000000,
                    "kind":"countdown","countdown_title":"Launch","target_datetime":1780000000,
                    "associated_event_type":"custom","associated_event_id":null}""",
                code = 201,
            ),
        )
        val msg = api().sendCountdown(
            "c1",
            SendCountdownMessageReq(title = "Launch", targetDatetime = 1780000000),
        )
        assertEquals("countdown", msg.kind)
        assertEquals(1780000000L, msg.targetDatetime)

        val req = backend.takeRequest()
        assertEquals("/messaging/conversations/c1/messages/countdown", req.requestUrl?.encodedPath)
        val body = req.bodyJson()
        assertEquals("Launch", body["title"])
        // target_datetime is an integer epoch on the wire.
        assertEquals(1780000000.0, (body["target_datetime"] as Number).toDouble(), 0.0)
        assertEquals("custom", body["associated_event_type"])
        assertNull(body["conversation_id"]) // path param
        assertNull(body["client_id"]) // no idempotency key
    }

    @Test
    fun tipMessage_postsAmountCents_decodesReceipt() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"ok":true,"conversation_id":"c1","message_id":"m1","tip_payment_id":"tpay_1",
                    "amount_cents":500,"currency":"USD"}""",
            ),
        )
        val out = api().tipMessage(
            "c1", "m1",
            SendTipReq(amountCents = 500, currency = "USD", note = "great post", paymentMethodId = "pm_1"),
        )
        assertEquals("tpay_1", out.tipPaymentId)
        assertEquals(500L, out.amountCents)

        val req = backend.takeRequest()
        assertEquals("/messaging/conversations/c1/messages/m1/tip", req.requestUrl?.encodedPath)
        val body = req.bodyJson()
        assertEquals(500.0, (body["amount_cents"] as Number).toDouble(), 0.0)
        assertEquals("USD", body["currency"])
        assertEquals("pm_1", body["payment_method_id"])
        assertNull(body["client_id"]) // no idempotency key on tip
    }

    @Test
    fun unlockMessage_postsPaymentMethodId_decodesReceiptOnly() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"ok":true,"conversation_id":"c1","message_id":"m1","unlock_payment_id":"upay_1","amount_cents":500}""",
            ),
        )
        val out = api().unlockMessage("c1", "m1", UnlockMessageReq(paymentMethodId = "pm_1"))
        assertEquals("upay_1", out.unlockPaymentId)
        assertEquals(500L, out.amountCents)

        val req = backend.takeRequest()
        assertEquals("/messaging/conversations/c1/messages/m1/unlock", req.requestUrl?.encodedPath)
        val body = req.bodyJson()
        assertEquals("pm_1", body["payment_method_id"])
    }

    @Test
    fun unlockLottery_postsEmptyBody_toMessageScopedPath() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"message_id":"m1","lock_state":"unlocked",
                    "selected_outcome":{"outcome_id":"o1","payload_type":"text","text_content":"You win"},
                    "unlocked_at":1717600000}""",
            ),
        )
        val out = api().unlockLottery("m1")
        assertEquals("unlocked", out.lockState)
        assertEquals("You win", out.selectedOutcome?.textContent)

        val req = backend.takeRequest()
        // NO conversation in the path.
        assertEquals("/messaging/messages/m1/lottery/unlock", req.requestUrl?.encodedPath)
        // Empty body (just {}).
        assertEquals("{}", req.body.readUtf8())
    }
}
