package com.testlogon.android.data.messaging.realtime

import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.EOFException
import java.io.IOException
import java.net.SocketTimeoutException

/**
 * AND-149 / AND-150 — failure-classification policy: 5xx/timeout retry, 401 refresh, 4xx fatal
 * (TC-AND-149-02). Pins the chosen (hardened) behavior; the web SSE client has no status branching.
 */
class SseRetryClassifierTest {

    @Test
    fun timeoutsAndIoErrors_areRetryable() {
        assertEquals(SseRetryability.RETRYABLE, SseRetryClassifier.classify(SocketTimeoutException(), null))
        assertEquals(SseRetryability.RETRYABLE, SseRetryClassifier.classify(IOException("drop"), null))
        assertEquals(SseRetryability.RETRYABLE, SseRetryClassifier.classify(EOFException(), null))
        assertEquals(SseRetryability.RETRYABLE, SseRetryClassifier.classify(null, null))
    }

    @Test
    fun retryable5xxStatuses() {
        listOf(500, 502, 503, 504).forEach {
            assertEquals("status $it", SseRetryability.RETRYABLE, SseRetryClassifier.classify(null, it))
        }
    }

    @Test
    fun unauthorizedTriggersAuthRefresh() {
        assertEquals(SseRetryability.AUTH_REFRESH, SseRetryClassifier.classify(null, 401))
    }

    @Test
    fun fatal4xxStatuses() {
        listOf(400, 403, 404, 405, 410).forEach {
            assertEquals("status $it", SseRetryability.FATAL, SseRetryClassifier.classify(null, it))
        }
    }

    @Test
    fun rateLimitIsRetryable() {
        assertEquals(SseRetryability.RETRYABLE, SseRetryClassifier.classify(null, 429))
    }

    @Test
    fun unknown4xxIsFatal_unknown5xxIsRetryable() {
        assertEquals(SseRetryability.FATAL, SseRetryClassifier.classify(null, 451))
        assertEquals(SseRetryability.RETRYABLE, SseRetryClassifier.classify(null, 599))
    }
}
