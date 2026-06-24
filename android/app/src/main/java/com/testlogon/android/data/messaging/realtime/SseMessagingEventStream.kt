package com.testlogon.android.data.messaging.realtime

import com.testlogon.android.core.network.SettingsStore
import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.IOException
import java.util.concurrent.TimeUnit
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-123 (realtime) — SSE realtime client over the SHARED core-network [OkHttpClient].
 *
 * Implements the REAL transport verified against reference/src/hooks/useMessagingStream.ts: an
 * EventSource on `GET messaging/events/stream` with cookie credentials. There is NO WebSocket — the
 * backend speaks Server-Sent Events. We therefore stream the response body and parse SSE frames
 * (`event:` / `data:` lines separated by blank lines) ourselves; no new dependency is added.
 *
 * Behaviour:
 *  - connect/auth: cookies + CSRF ride the shared OkHttp interceptor chain automatically.
 *  - the read timeout is disabled for this one streaming call (the stream is intentionally long-lived).
 *  - reconnect with exponential backoff capped at 30s, mirroring the web client.
 *  - lifecycle-aware: the flow is cold; cancelling the collector cancels the call and stops reconnecting.
 *  - message content is never logged.
 */
@Singleton
class SseMessagingEventStream @Inject constructor(
    private val baseClient: OkHttpClient,
    private val settingsStore: SettingsStore,
    private val parser: SseEnvelopeParser,
    private val foregroundState: ForegroundState,
    moshi: com.squareup.moshi.Moshi,
) : MessagingEventStream {

    // For the poll backstop below: parse the raw events/poll JSON the same way as an SSE frame.
    private val mapAdapter = moshi.adapter<Map<String, Any?>>(
        com.squareup.moshi.Types.newParameterizedType(Map::class.java, String::class.java, Any::class.java),
    )

    // A dedicated client view with no read timeout so the long-lived stream is not killed at 20s.
    private val streamClient: OkHttpClient by lazy {
        baseClient.newBuilder()
            .readTimeout(0, TimeUnit.MILLISECONDS)
            .build()
    }

    private val backoff = SseBackoffPolicy()

    override fun events(): Flow<MessagingStreamEvent> = callbackFlow {
        var attempt = 0
        var running = true
        // AND-143 — retained across reconnects so we replay `Last-Event-ID` and floor the next
        // backoff on the server `retry:` hint. The pure line parser owns id/retry retention.
        val lineParser = SseLineParser()

        val worker = Thread {
            while (running) {
                // AND-149 FR-6 — lifecycle gate: do not dial while backgrounded. Park (Idle) until the
                // process returns to the foreground, so no socket/thread is held while background.
                if (!foregroundState.isForeground.value) {
                    trySend(MessagingStreamEvent.State(StreamConnectionState.DISCONNECTED))
                    if (!waitForForeground { running }) break
                    if (!running) break
                    attempt = 0 // a clean foreground resume starts backoff from base.
                }
                trySend(MessagingStreamEvent.State(StreamConnectionState.CONNECTING))
                val builder = Request.Builder()
                    .url(settingsStore.baseUrl.trimEnd('/') + "/" + STREAM_PATH)
                    .header("Accept", "text/event-stream")
                    .header("Cache-Control", "no-cache")
                // AND-143 FR-3/FR-5 — resume from the last delivered frame id on reconnect.
                lineParser.lastEventId?.let { builder.header("Last-Event-ID", it) }
                val call = streamClient.newCall(builder.build())
                // AND-149 — classify the failure so a FATAL (4xx) stops dialing instead of looping.
                var retryability = SseRetryability.RETRYABLE
                try {
                    call.execute().use { response ->
                        if (!response.isSuccessful) {
                            retryability = SseRetryClassifier.classify(null, response.code)
                            error("stream HTTP ${response.code}")
                        }
                        val body = response.body ?: error("empty stream body")
                        attempt = 0
                        trySend(MessagingStreamEvent.State(StreamConnectionState.CONNECTED))
                        lineParser.readFrames(body.source()) { frame ->
                            // Stop reading on teardown OR when the process backgrounds (FR-6).
                            if (!running || !foregroundState.isForeground.value) return@readFrames false
                            parser.parse(frame.event, frame.data)?.let {
                                trySend(MessagingStreamEvent.Event(it))
                            }
                            true
                        }
                    }
                } catch (_: IOException) {
                    retryability = SseRetryClassifier.classify(IOException(), null)
                } catch (_: IllegalStateException) {
                    // non-2xx / empty body — retryability already set above (or default RETRYABLE).
                } finally {
                    call.cancel()
                }
                if (!running) break
                trySend(MessagingStreamEvent.State(StreamConnectionState.DISCONNECTED))
                // AND-149 — a FATAL (4xx) classification surfaces Offline and stops reconnecting until
                // re-collected; otherwise back off (jittered, capped) and retry. 401 refresh is handled
                // by the shared OkHttp authenticator on the next dial.
                if (retryability == SseRetryability.FATAL) break
                attempt++
                val backoffMs = backoff.nextDelayMillis(attempt, serverRetryMillis = lineParser.retryMillis)
                try {
                    Thread.sleep(backoffMs)
                } catch (_: InterruptedException) {
                    break
                }
            }
        }
        worker.isDaemon = true
        worker.start()

        // RELIABLE POLL BACKSTOP. The long-lived SSE connection is auth-flaky on this backend and
        // churns (reconnect storms), so live messages are missed. A short authenticated GET of
        // events/poll over the SAME client (cookies + interceptors) re-delivers any not-yet-seen
        // event, parsed identically to an SSE frame, so the thread updates in realtime regardless.
        val pollWorker = Thread {
            val seenPoll = HashSet<String>()
            while (running) {
                if (foregroundState.isForeground.value) {
                    try {
                        val req = Request.Builder()
                            .url(settingsStore.baseUrl.trimEnd('/') + "/" + POLL_PATH)
                            .build()
                        baseClient.newCall(req).execute().use { resp ->
                            if (resp.isSuccessful) {
                                val bodyStr = resp.body?.string().orEmpty()
                                val root = runCatching { mapAdapter.fromJson(bodyStr) }.getOrNull()
                                @Suppress("UNCHECKED_CAST")
                                val events = root?.get("events") as? List<Map<String, Any?>> ?: emptyList()
                                for (ev in events) {
                                    val eid = ev["event_id"] as? String ?: continue
                                    if (!seenPoll.add(eid)) continue
                                    val type = ev["type"] as? String ?: continue
                                    parser.parse(type, mapAdapter.toJson(ev))?.let {
                                        trySend(MessagingStreamEvent.Event(it))
                                    }
                                }
                            }
                        }
                    } catch (_: Throwable) {
                    }
                }
                try {
                    Thread.sleep(POLL_INTERVAL_MS)
                } catch (_: InterruptedException) {
                    break
                }
            }
        }
        pollWorker.isDaemon = true
        pollWorker.start()

        awaitClose {
            running = false
            worker.interrupt()
            pollWorker.interrupt()
        }
    }

    /**
     * Park the worker thread until the process returns to the foreground (or [keepGoing] turns false).
     * Returns true if it became foreground, false if collection was cancelled while parked. A short
     * poll keeps the helper transport-free and interrupt-cancellable; no socket is held while parked.
     */
    private fun waitForForeground(keepGoing: () -> Boolean): Boolean {
        while (keepGoing() && !foregroundState.isForeground.value) {
            try {
                Thread.sleep(FOREGROUND_POLL_MS)
            } catch (_: InterruptedException) {
                return false
            }
        }
        return keepGoing()
    }

    private companion object {
        const val STREAM_PATH = "messaging/events/stream"
        const val POLL_PATH = "messaging/events/poll?limit=100"
        const val POLL_INTERVAL_MS = 600L

        /** AND-149 — poll cadence while parked in the background (cheap; the thread is otherwise idle). */
        const val FOREGROUND_POLL_MS = 250L
    }
}

/** Binds the SSE implementation as the realtime [MessagingEventStream]. */
@Module
@InstallIn(SingletonComponent::class)
abstract class MessagingRealtimeModule {

    @Binds
    @Singleton
    abstract fun bindMessagingEventStream(impl: SseMessagingEventStream): MessagingEventStream
}
