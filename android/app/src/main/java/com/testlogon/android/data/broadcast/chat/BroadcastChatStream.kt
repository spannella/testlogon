package com.testlogon.android.data.broadcast.chat

import com.squareup.moshi.Moshi
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
    moshi: Moshi,
) : BroadcastChatStream {

    /** A client view with no read timeout so the long-lived chat stream is not killed at 20s. */
    private val streamClient: OkHttpClient by lazy {
        baseClient.newBuilder().readTimeout(0, TimeUnit.MILLISECONDS).build()
    }

    // For the poll backstop below: parse the plain history JSON the same way as the loadHistory GET.
    private val historyAdapter = moshi.adapter(ChatHistoryDto::class.java)

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

        // RELIABLE POLL BACKSTOP (mirrors SseMessagingEventStream /events/poll). The long-lived chat
        // SSE is auth-flaky / does not connect on-device, so live frames are missed and the panel stays
        // RECONNECTING (canSend never true). A short authenticated GET of the chat HISTORY over the SAME
        // client (cookies + interceptors) re-delivers any not-yet-seen message as a MessageReceived event,
        // deduped by message_id here (the VM also dedups + reconciles optimistic sends by senderId+text).
        // Each successful poll emits PollAlive(true) so the VM can enable send + present the transport as
        // usable even when the SSE is not LIVE. Works even if the SSE returns 403 (session-not-live gate),
        // because the history GET has no live gate.
        val pollWorker = Thread {
            val seenIds = HashSet<String>()
            while (running) {
                try {
                    val req = Request.Builder().url(historyUrl(sessionId)).build()
                    baseClient.newCall(req).execute().use { resp ->
                        if (resp.isSuccessful) {
                            trySend(ChatStreamSignal.PollAlive(true))
                            val bodyStr = resp.body?.string().orEmpty()
                            val history = runCatching { historyAdapter.fromJson(bodyStr) }.getOrNull()
                            history?.messages?.forEach { dto ->
                                if (dto.messageId.isNotEmpty() && seenIds.add(dto.messageId)) {
                                    trySend(
                                        ChatStreamSignal.Decoded(
                                            ChatStreamEvent.MessageReceived(dto.toDomain(selfId)),
                                        ),
                                    )
                                }
                            }
                        }
                    }
                } catch (_: Throwable) {
                    // best-effort backstop; the SSE worker owns the authoritative connection state.
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

    private fun streamUrl(sessionId: String): String =
        settingsStore.baseUrl.trimEnd('/') + "/" + STREAM_PATH_PREFIX + sessionId + STREAM_PATH_SUFFIX

    private fun historyUrl(sessionId: String): String =
        settingsStore.baseUrl.trimEnd('/') + "/" + STREAM_PATH_PREFIX + sessionId + HISTORY_PATH_SUFFIX

    private companion object {
        const val STREAM_PATH_PREFIX = "broadcast/sessions/"
        const val STREAM_PATH_SUFFIX = "/chat/stream?poll_ms=500"
        const val HISTORY_PATH_SUFFIX = "/chat?limit=100"
        const val POLL_INTERVAL_MS = 1500L
    }
}
