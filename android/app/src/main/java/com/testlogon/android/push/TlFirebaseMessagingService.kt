package com.testlogon.android.push

import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage
import dagger.hilt.android.AndroidEntryPoint
import javax.inject.Inject

/**
 * AND-105/107/108/109 — the app's [FirebaseMessagingService].
 *
 * Registered in the manifest with the `com.google.firebase.MESSAGING_EVENT` intent filter and
 * `exported="false"` (only the signed Firebase intent can reach it). It is intentionally thin: it
 * maps the Firebase [RemoteMessage] to the framework-free [PushMessage] and the token string, then
 * forwards to injectable sinks so all real behavior is JVM-unit-testable with fakes (the service
 * glue itself is verified instrumented).
 *
 *  - [onNewToken] → [PushTokenSink] (bound to the AND-106/109 registrar: persist + re-register).
 *  - [onMessageReceived] → [PushMessageSink] (bound to the AND-107 channel-aware display).
 *
 * Resilience (spec §7): the sink calls are wrapped so a sink bug can never crash the messaging
 * process. CancellationException is not a concern here (sinks are non-suspending).
 */
@AndroidEntryPoint
class TlFirebaseMessagingService : FirebaseMessagingService() {

    @Inject lateinit var tokenSink: PushTokenSink

    @Inject lateinit var messageSink: PushMessageSink

    override fun onNewToken(token: String) {
        runCatching { tokenSink.onTokenRefreshed(token) }
            .onFailure { PushLog.d("onNewToken sink failed: ${it.javaClass.simpleName}") }
    }

    override fun onMessageReceived(message: RemoteMessage) {
        runCatching { messageSink.onMessage(PushMessage.from(message)) }
            .onFailure { PushLog.d("onMessageReceived sink failed: ${it.javaClass.simpleName}") }
    }
}
