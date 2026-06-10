package com.testlogon.android.data.messaging.realtime

import java.io.IOException

/**
 * AND-149 — pure, JVM-testable failure classifier for the SSE stream.
 *
 * Maps a transport throwable / HTTP status to how the resilient stream should react. The web SSE
 * client treats every `onerror` uniformly as "reconnect with backoff" (it has no status branching —
 * AND-149 audit #10/#11); the native client deliberately HARDENS this for the flaky dev host:
 *  - timeouts / IOExceptions / premature EOF and retryable 5xx (502/503/504) -> RETRYABLE (backoff),
 *  - 401 -> AUTH_REFRESH (one /ui/session/refresh + retry, per the project auth rule),
 *  - 403/404/410 (and a malformed stream after a successful auth) -> FATAL (Offline, stop dialing).
 *
 * Keeping this a pure function makes the policy assertable without a socket (TC-AND-149-02).
 */
enum class SseRetryability { RETRYABLE, AUTH_REFRESH, FATAL }

object SseRetryClassifier {

    private val RETRYABLE_STATUSES = setOf(408, 425, 429, 500, 502, 503, 504)
    private val FATAL_STATUSES = setOf(400, 403, 404, 405, 410)

    /**
     * @param throwable the transport failure, if the call threw before/while reading.
     * @param httpStatus the HTTP status of a non-2xx stream open, if known (else null).
     */
    fun classify(throwable: Throwable?, httpStatus: Int?): SseRetryability {
        if (httpStatus != null) {
            return when {
                httpStatus == 401 -> SseRetryability.AUTH_REFRESH
                httpStatus in RETRYABLE_STATUSES -> SseRetryability.RETRYABLE
                httpStatus in FATAL_STATUSES -> SseRetryability.FATAL
                httpStatus in 500..599 -> SseRetryability.RETRYABLE
                httpStatus in 400..499 -> SseRetryability.FATAL
                else -> SseRetryability.RETRYABLE
            }
        }
        // No status: a transport-level failure (drop, timeout, EOF) is always retryable.
        return when (throwable) {
            is IOException -> SseRetryability.RETRYABLE
            null -> SseRetryability.RETRYABLE
            else -> SseRetryability.RETRYABLE
        }
    }
}
