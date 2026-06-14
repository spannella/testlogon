package com.testlogon.android.data.broadcast.chat

import com.testlogon.android.core.network.SettingsStore
import com.testlogon.android.data.messaging.realtime.SseBackoffPolicy
import com.testlogon.android.data.messaging.realtime.SseLineParser
import com.testlogon.android.data.messaging.realtime.SseRetryClassifier
import com.testlogon.android.data.messaging.realtime.SseRetryability
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
 * AND-281 — testable seam over the broadcast live-chat SSE transport. A cold [Flow]: collecting opens
 * the per-session stream, cancelling disconnects it (so it is lifecycle-aware via repeatOnLifecycle).
 * Distinct from the messaging stream (different URL + its OWN event catalog), but REUSES the AND-143
 * pure SSE core: [SseLineParser], [SseBackoffPolicy], [SseRetryClassifier]. No new transport code or
 * dependency is added.
 */
interface BroadcastChatStream {
    /** Emits connection-state transitions interleaved with decoded chat domain events. */
    fun events(sessionId: String, selfId: String?): Flow<ChatStreamSignal>
}

@Singleton
class SseBroadcastChatStream @Inject constructor(
    private val baseClient: OkHttpClient,
    private val settingsStore: SettingsStore,
    private val parser: ChatEventParser,
) : BroadcastChatStream {

    /** A client view with no read timeout so the long-lived chat stream is not killed at 20s. */
    private val streamClient: OkHttpClient by lazy {
        baseClient.newBuilder().readTimeout(0, TimeUnit.MILLISECONDS).build()
    }

    private val backoff = SseBackoffPolicy()

    override fun events(sessionId: String, selfId: String?): Flow<ChatStreamSignal> = callbackFlow {
        var attempt = 0
        var running = true
        val lineParser = SseLineParser()

        val worker = Thread {
            while (running) {
                trySend(ChatStreamSignal.Connection(ChatConnectionState.CONNECTING))
                val builder = Request.Builder()
                    .url(streamUrl(sessionId))
                    .header("Accept", "text/event-stream")
                    .header("Cache-Control", "no-cache")
                lineParser.lastEventId?.let { builder.header("Last-Event-ID", it) }
                val call = streamClient.newCall(builder.build())
                var retryability = SseRetryability.RETRYABLE
                try {
                    call.execute().use { response ->
                        if (!response.isSuccessful) {
                            retryability = SseRetryClassifier.classify(null, response.code)
                            error("chat stream HTTP ${response.code}")
                        }
                        val body = response.body ?: error("empty chat stream body")
                        attempt = 0
                        trySend(ChatStreamSignal.Connection(ChatConnectionState.LIVE))
                        lineParser.readFrames(body.source()) { frame ->
                            if (!running) return@readFrames false
                            val decoded = parser.parse(frame, selfId)
                            if (decoded !is ChatStreamEvent.Unknown) {
                                trySend(ChatStreamSignal.Decoded(decoded))
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
                if (retryability == SseRetryability.FATAL) {
                    trySend(ChatStreamSignal.Connection(ChatConnectionState.OFFLINE))
                    break
                }
                trySend(ChatStreamSignal.Connection(ChatConnectionState.RECONNECTING))
                attempt++
                if (attempt >= backoff.maxConsecutiveFailures) {
                    trySend(ChatStreamSignal.Connection(ChatConnectionState.OFFLINE))
                }
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

    private fun streamUrl(sessionId: String): String =
        settingsStore.baseUrl.trimEnd('/') + "/" + STREAM_PATH_PREFIX + sessionId + STREAM_PATH_SUFFIX

    private companion object {
        const val STREAM_PATH_PREFIX = "broadcast/sessions/"
        const val STREAM_PATH_SUFFIX = "/chat/stream?poll_ms=500"
    }
}
