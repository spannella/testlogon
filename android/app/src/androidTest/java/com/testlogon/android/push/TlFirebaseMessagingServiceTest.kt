package com.testlogon.android.push

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.google.firebase.messaging.RemoteMessage
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith

/**
 * AND-110 (Tier B) / AND-105 — instrumented glue test for the FCM service.
 *
 * Verifies that onNewToken/onMessageReceived forward to the injectable sinks (the real behavior is
 * JVM-tested via the registrar/repository; this covers the thin service mapping that needs the
 * Android RemoteMessage type). Sinks are set directly (no Hilt graph) and a sink that throws must not
 * propagate out of the callback (spec §7 resilience).
 */
@RunWith(AndroidJUnit4::class)
class TlFirebaseMessagingServiceTest {

    private class CapturingTokenSink : PushTokenSink {
        var token: String? = null
        override fun onTokenRefreshed(token: String) {
            this.token = token
        }
    }

    private class CapturingMessageSink : PushMessageSink {
        var message: PushMessage? = null
        override fun onMessage(message: PushMessage) {
            this.message = message
        }
    }

    @Test
    fun onNewToken_forwards_exact_token_to_sink() {
        val service = TlFirebaseMessagingService()
        val sink = CapturingTokenSink()
        service.tokenSink = sink
        service.messageSink = CapturingMessageSink()

        service.onNewToken("ABC123token")

        assertEquals("ABC123token", sink.token)
    }

    @Test
    fun onMessageReceived_maps_and_forwards_payload() {
        val service = TlFirebaseMessagingService()
        val tokenSink = CapturingTokenSink()
        val msgSink = CapturingMessageSink()
        service.tokenSink = tokenSink
        service.messageSink = msgSink

        val rm = RemoteMessage.Builder("test@fcm")
            .addData("kind", "message")
            .addData("entity_id", "msg_1")
            .addData("title", "t")
            .addData("body", "b")
            .build()

        service.onMessageReceived(rm)

        val captured = msgSink.message
        assertEquals("msg_1", captured?.data?.get("entity_id"))
        assertEquals("message", captured?.data?.get("kind"))
    }

    @Test
    fun throwing_sink_does_not_crash_callback() {
        val service = TlFirebaseMessagingService()
        service.tokenSink = CapturingTokenSink()
        service.messageSink = PushMessageSink { error("boom") }

        val rm = RemoteMessage.Builder("test@fcm").addData("k", "v").build()
        // Must not throw out of the callback.
        service.onMessageReceived(rm)
        assertNull(null)
    }
}
