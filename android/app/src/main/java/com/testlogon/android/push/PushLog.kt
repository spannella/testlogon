package com.testlogon.android.push

import android.util.Log
import com.testlogon.android.BuildConfig

/**
 * AND-105/106/109 — push logging helpers.
 *
 * The FCM registration token is a device-routing secret and MUST NEVER be logged in full
 * (spec §8). [redactToken] yields a short, non-identifying prefix used everywhere a token would
 * otherwise be logged. All push logging is DEBUG-only and gated on [BuildConfig.DEBUG].
 *
 * NOTE: android.util.Log is referenced here only from Android components (the service / sinks /
 * registrar). Pure-logic classes that are JVM-unit-tested (PushPayloadParser, the deep-link
 * mapper) do not depend on this file, keeping those tests free of android.util.*.
 */
internal object PushLog {
    const val TAG = "TlPush"

    /** Redacts a token to its first 6 chars + ellipsis; safe to log. Never log the raw token. */
    fun redactToken(token: String?): String =
        if (token.isNullOrEmpty()) "<none>" else token.take(6) + "…"

    fun d(message: String) {
        if (!BuildConfig.DEBUG) return
        // android.util.Log is not mocked under JVM unit tests; swallow the "not mocked" error so the
        // logging contract never affects test outcomes (repository/registrar are JVM-unit-tested).
        runCatching { Log.d(TAG, message) }
    }
}

/** AND-105 — default token sink: logs a redacted prefix only (DEBUG), no upload. */
class LoggingPushTokenSink : PushTokenSink {
    override fun onTokenRefreshed(token: String) {
        PushLog.d("fcm_token_refreshed ${PushLog.redactToken(token)}")
    }
}

/** AND-105 — default message sink: logs messageId + data key set (never values), no display. */
class LoggingPushMessageSink : PushMessageSink {
    override fun onMessage(message: PushMessage) {
        PushLog.d(
            "fcm_message_received id=${message.messageId} priority=${message.priority} " +
                "dataKeys=${message.data.keys}",
        )
    }
}
