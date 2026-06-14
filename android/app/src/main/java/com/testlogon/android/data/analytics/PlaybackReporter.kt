package com.testlogon.android.data.analytics

import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleOwner
import androidx.media3.common.PlaybackException
import androidx.media3.common.Player
import com.testlogon.android.core.data.cache.Clock
import com.testlogon.android.data.auth.AppScope
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.util.UUID
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-171 §4.1 — opt-in, lifecycle-scoped playback reporter. A surface attaches via [attach] and
 * detaches in onDispose; only one active session exists at a time (FR-9). It is NOT an eager player —
 * it observes an externally-owned [Player] and never creates one. The ticker is lifecycle-scoped: it
 * runs only while actually playing AND foreground (>= STARTED), and stops on pause/stop/end/error/
 * background (FR-5). All scheduling/accounting decisions are the pure [HeartbeatLogic]; this class is
 * the Media3 + lifecycle wiring (runtime-only, like the player controller).
 */
interface PlaybackReporter {
    fun attach(player: Player, target: PlaybackTarget, owner: LifecycleOwner)
    fun detach()
}

@Singleton
class DefaultPlaybackReporter @Inject constructor(
    private val sink: HeartbeatSink,
    private val config: HeartbeatConfigStore,
    private val clock: Clock,
    @AppScope private val scope: CoroutineScope,
) : PlaybackReporter, Player.Listener {

    private var player: Player? = null
    private var session: SessionState? = null
    private var lifecycleOwner: LifecycleOwner? = null
    private var tickerJob: Job? = null
    private var foreground: Boolean = true

    private val lifecycleObserver = object : DefaultLifecycleObserver {
        override fun onStart(owner: LifecycleOwner) {
            foreground = true
            reevaluate()
        }

        override fun onStop(owner: LifecycleOwner) {
            foreground = false
            // FR-3/FR-5: leaving foreground emits a STOP and pauses the ticker.
            stopSession(emitStop = true)
        }
    }

    override fun attach(player: Player, target: PlaybackTarget, owner: LifecycleOwner) {
        detach()
        this.player = player
        this.lifecycleOwner = owner
        this.session = SessionState(sessionId = UUID.randomUUID().toString(), target = target)
        foreground = owner.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)
        owner.lifecycle.addObserver(lifecycleObserver)
        player.addListener(this)
        reevaluate()
    }

    override fun detach() {
        stopSession(emitStop = true)
        player?.removeListener(this)
        lifecycleOwner?.lifecycle?.removeObserver(lifecycleObserver)
        player = null
        lifecycleOwner = null
        session = null
    }

    // --- Player.Listener: translate raw state to the pure playing edge, react to its edges. ---

    override fun onPlaybackStateChanged(playbackState: Int) {
        if (playbackState == Player.STATE_ENDED) {
            stopSession(emitStop = true)
            return
        }
        reevaluate()
    }

    override fun onPlayWhenReadyChanged(playWhenReady: Boolean, reason: Int) {
        reevaluate()
    }

    override fun onMediaItemTransition(mediaItem: androidx.media3.common.MediaItem?, reason: Int) {
        // FR-7: switching media ends the current session and begins a new one (new session id).
        val target = session?.target ?: return
        stopSession(emitStop = true)
        session = SessionState(sessionId = UUID.randomUUID().toString(), target = target)
        reevaluate()
    }

    override fun onPlayerError(error: PlaybackException) {
        stopSession(emitStop = true)
    }

    /** Re-derives the playing edge and starts/stops the ticker accordingly. */
    private fun reevaluate() {
        val p = player ?: return
        val playing = foreground && HeartbeatLogic.isPlaying(p.playbackState, p.playWhenReady)
        if (playing) startSession() else stopSession(emitStop = true)
    }

    private fun startSession() {
        val s = session ?: return
        if (tickerJob?.isActive == true) return
        if (!s.startSent) {
            s.startSent = true
            s.lastReportPositionMs = positionMs()
            s.lastReportWallMs = clock.now()
            emit(HeartbeatPhase.START, watchedMsDelta = 0L)
        }
        startTicker()
    }

    private fun startTicker() {
        tickerJob = scope.launch(Dispatchers.Main.immediate) {
            while (isActive) {
                // Re-read the interval each tick so a local config change is picked up (§6).
                val interval = config.intervalMs()
                delay(interval)
                if (!isActive) break
                if (config.enabled()) emitHeartbeat(interval)
            }
        }
    }

    private fun emitHeartbeat(intervalMs: Long) {
        val s = session ?: return
        val p = player ?: return
        val nowWall = clock.now()
        val nowPos = positionMs()
        val wallElapsed = nowWall - s.lastReportWallMs
        val posDelta = nowPos - s.lastReportPositionMs
        val watched = HeartbeatLogic.watchedMsDelta(
            wallElapsedMs = wallElapsed,
            intervalMs = intervalMs,
            positionDeltaMs = posDelta,
            isLive = p.isCurrentMediaItemLive,
            speed = p.playbackParameters.speed,
        )
        s.lastReportWallMs = nowWall
        s.lastReportPositionMs = nowPos
        emit(HeartbeatPhase.HEARTBEAT, watched)
    }

    private fun stopSession(emitStop: Boolean) {
        tickerJob?.cancel()
        tickerJob = null
        val s = session ?: return
        if (emitStop && s.startSent) {
            s.startSent = false
            emit(HeartbeatPhase.STOP, watchedMsDelta = maxOf(0L, positionMs() - s.lastReportPositionMs))
        }
    }

    private fun emit(phase: HeartbeatPhase, watchedMsDelta: Long) {
        val s = session ?: return
        val p = player
        val isLive = p?.isCurrentMediaItemLive ?: false
        val duration = p?.duration?.takeIf { it != androidx.media3.common.C.TIME_UNSET }
        sink.enqueue(
            PlaybackSnapshot(
                sessionId = s.sessionId,
                target = s.target,
                phase = phase,
                positionMs = positionMs(),
                durationMs = duration,
                watchedMsDelta = watchedMsDelta,
                isLive = isLive,
                playbackSpeed = p?.playbackParameters?.speed ?: 1f,
                clientEventId = UUID.randomUUID().toString(),
                occurredAtEpochMs = clock.now(),
            ),
        )
    }

    private fun positionMs(): Long = player?.currentPosition?.coerceAtLeast(0L) ?: 0L
}
