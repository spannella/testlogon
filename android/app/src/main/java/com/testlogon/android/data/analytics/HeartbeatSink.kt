package com.testlogon.android.data.analytics

import com.testlogon.android.data.auth.AppScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import retrofit2.Response
import java.io.IOException
import java.util.concurrent.atomic.AtomicInteger
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-171 §4.3 — fire-and-forget sink that posts playback events FIFO without ever applying
 * backpressure to playback. A bounded [Channel] with [BufferOverflow.DROP_OLDEST] guarantees the
 * reporter never blocks the player thread (§7). Maps each [PlaybackSnapshot] to the verified server
 * call ([PlaybackAnalyticsApi]); failures are retried per §7 then dropped. START/STOP are best-effort
 * even when offline; HEARTBEATs short-circuit while offline.
 */
interface HeartbeatSink {
    /** Enqueues a snapshot for FIFO delivery; returns immediately, never throws. */
    fun enqueue(snapshot: PlaybackSnapshot)

    /** Drop/diagnostic counters (in-memory, debug inspector; §10). */
    val counters: HeartbeatCounters
}

/** AND-171 §10 — in-memory drop/diagnostic counters. */
class HeartbeatCounters {
    val droppedOffline = AtomicInteger(0)
    val droppedOverflow = AtomicInteger(0)
    val dropped4xx = AtomicInteger(0)
    val droppedRetryExhausted = AtomicInteger(0)
    val sent = AtomicInteger(0)
}

/** AND-171 §7 — connectivity gate so HEARTBEATs short-circuit while offline. */
fun interface OfflineGate {
    /** True when the device is currently offline (best-effort). */
    fun isOffline(): Boolean
}

@Singleton
class CoroutineHeartbeatSink @Inject constructor(
    private val api: PlaybackAnalyticsApi,
    private val offlineGate: OfflineGate,
    @AppScope private val scope: CoroutineScope,
) : HeartbeatSink {

    override val counters = HeartbeatCounters()

    /**
     * Broadcast-only: the viewer_id minted by `viewers/join` for the active session, reused by the
     * heartbeat/leave calls. Single active session (FR-9) so a single field is sufficient.
     */
    @Volatile
    private var activeViewerId: String? = null

    private val channel = Channel<PlaybackSnapshot>(
        capacity = CAPACITY,
        onBufferOverflow = BufferOverflow.DROP_OLDEST,
    )

    init {
        scope.launch {
            channel.receiveAsFlow().collect { snapshot ->
                runCatching { process(snapshot) }
            }
        }
    }

    override fun enqueue(snapshot: PlaybackSnapshot) {
        val result = channel.trySend(snapshot)
        if (result.isFailure) counters.droppedOverflow.incrementAndGet()
    }

    private suspend fun process(snapshot: PlaybackSnapshot) {
        // Offline: HEARTBEATs are dropped; START/STOP are still attempted once (best effort, §7).
        if (offlineGate.isOffline() && snapshot.phase == HeartbeatPhase.HEARTBEAT) {
            counters.droppedOffline.incrementAndGet()
            return
        }
        when (val target = snapshot.target) {
            is PlaybackTarget.Content -> processContent(snapshot, target)
            is PlaybackTarget.Broadcast -> processBroadcast(snapshot, target)
        }
    }

    private suspend fun processContent(snapshot: PlaybackSnapshot, target: PlaybackTarget.Content) {
        // VOD: one-shot view record at START only; HEARTBEAT/STOP have no server call.
        if (snapshot.phase == HeartbeatPhase.START) {
            send { api.recordVideoView(target.id) }
        }
    }

    private suspend fun processBroadcast(snapshot: PlaybackSnapshot, target: PlaybackTarget.Broadcast) {
        when (snapshot.phase) {
            HeartbeatPhase.START -> {
                val join = send { api.viewerJoin(target.id) }
                activeViewerId = join?.body()?.viewerId
            }
            HeartbeatPhase.HEARTBEAT -> {
                val viewerId = activeViewerId ?: return
                send { api.viewerHeartbeat(target.id, viewerId) }
            }
            HeartbeatPhase.STOP -> {
                val viewerId = activeViewerId
                if (viewerId != null) {
                    send { api.viewerLeave(target.id, viewerId) }
                }
                activeViewerId = null
            }
        }
    }

    /**
     * Bounded retry (§7): retries on transport/IO + 5xx up to [MAX_RETRIES] with jittered backoff;
     * 4xx (except the 401 handled by the global authenticator) is dropped immediately. The player
     * thread is never awaited — this runs on the sink's own [scope]. Returns the successful response
     * or null when dropped.
     */
    private suspend fun <T> send(call: suspend () -> Response<T>): Response<T>? {
        var attempt = 0
        while (true) {
            val outcome = runCatching { call() }
            val response = outcome.getOrNull()
            when {
                response != null && response.isSuccessful -> {
                    counters.sent.incrementAndGet()
                    return response
                }
                response != null && response.code() in 400..499 -> {
                    counters.dropped4xx.incrementAndGet()
                    return null
                }
                else -> {
                    // 5xx or transport error -> retry until exhausted.
                    val cause = outcome.exceptionOrNull()
                    if (cause is CancellationException) throw cause
                    if (cause != null && cause !is IOException) {
                        counters.droppedRetryExhausted.incrementAndGet()
                        return null
                    }
                    if (attempt >= MAX_RETRIES) {
                        counters.droppedRetryExhausted.incrementAndGet()
                        return null
                    }
                    delay(BACKOFF_MS[attempt])
                    attempt++
                }
            }
        }
    }

    companion object {
        const val CAPACITY = 64
        const val MAX_RETRIES = 2
        val BACKOFF_MS = longArrayOf(1_000L, 3_000L)
    }
}
