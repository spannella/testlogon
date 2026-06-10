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
) : MessagingEventStream {

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
                trySend(MessagingStreamEvent.State(StreamConnectionState.CONNECTING))
                val builder = Request.Builder()
                    .url(settingsStore.baseUrl.trimEnd('/') + "/" + STREAM_PATH)
                    .header("Accept", "text/event-stream")
                    .header("Cache-Control", "no-cache")
                // AND-143 FR-3/FR-5 — resume from the last delivered frame id on reconnect.
                lineParser.lastEventId?.let { builder.header("Last-Event-ID", it) }
                val call = streamClient.newCall(builder.build())
                try {
                    call.execute().use { response ->
                        if (!response.isSuccessful) error("stream HTTP ${response.code}")
                        val body = response.body ?: error("empty stream body")
                        attempt = 0
                        trySend(MessagingStreamEvent.State(StreamConnectionState.CONNECTED))
                        lineParser.readFrames(body.source()) { frame ->
                            if (!running) return@readFrames false
                            parser.parse(frame.event, frame.data)?.let {
                                trySend(MessagingStreamEvent.Event(it))
                            }
                            true
                        }
                    }
                } catch (_: IOException) {
                    // transport drop — fall through to backoff + reconnect
                } catch (_: IllegalStateException) {
                    // non-2xx / empty body — fall through to backoff + reconnect
                } finally {
                    call.cancel()
                }
                if (!running) break
                trySend(MessagingStreamEvent.State(StreamConnectionState.DISCONNECTED))
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

        awaitClose {
            running = false
            worker.interrupt()
        }
    }

    private companion object {
        const val STREAM_PATH = "messaging/events/stream"
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
