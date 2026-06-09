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
import okio.BufferedSource
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

    override fun events(): Flow<MessagingStreamEvent> = callbackFlow {
        var attempt = 0
        var running = true

        val worker = Thread {
            while (running) {
                trySend(MessagingStreamEvent.State(StreamConnectionState.CONNECTING))
                val request = Request.Builder()
                    .url(settingsStore.baseUrl.trimEnd('/') + "/" + STREAM_PATH)
                    .header("Accept", "text/event-stream")
                    .build()
                val call = streamClient.newCall(request)
                try {
                    call.execute().use { response ->
                        if (!response.isSuccessful) error("stream HTTP ${response.code}")
                        val body = response.body ?: error("empty stream body")
                        attempt = 0
                        trySend(MessagingStreamEvent.State(StreamConnectionState.CONNECTED))
                        readFrames(body.source()) { event, data ->
                            if (!running) return@readFrames false
                            parser.parse(event, data)?.let {
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
                val backoffMs = minOf(BASE_BACKOFF_MS * (1L shl attempt.coerceAtMost(MAX_SHIFT)), MAX_BACKOFF_MS)
                attempt++
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

    /**
     * Reads SSE frames from [source], invoking [onFrame] with the accumulated event type + data per
     * blank-line-delimited frame. Stops when [onFrame] returns false or the stream ends.
     */
    private fun readFrames(source: BufferedSource, onFrame: (event: String, data: String) -> Boolean) {
        var eventType = ""
        val data = StringBuilder()
        while (!source.exhausted()) {
            val line = source.readUtf8Line() ?: break
            when {
                line.isEmpty() -> {
                    if (data.isNotEmpty() || eventType.isNotEmpty()) {
                        val keepGoing = onFrame(eventType, data.toString())
                        if (!keepGoing) return
                    }
                    eventType = ""
                    data.setLength(0)
                }
                line.startsWith(":") -> Unit // heartbeat / comment
                line.startsWith("event:") -> eventType = line.removePrefix("event:").trim()
                line.startsWith("data:") -> {
                    if (data.isNotEmpty()) data.append('\n')
                    data.append(line.removePrefix("data:").trim())
                }
                else -> Unit // id:, retry:, unknown fields — ignored
            }
        }
    }

    private companion object {
        const val STREAM_PATH = "messaging/events/stream"
        const val BASE_BACKOFF_MS = 1_000L
        const val MAX_BACKOFF_MS = 30_000L
        const val MAX_SHIFT = 5 // 1s,2s,4s,8s,16s,32s->capped at 30s
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
