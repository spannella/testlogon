package com.testlogon.android.feature.call.incall

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.data.call.CallMode
import com.testlogon.android.feature.call.billing.BillingCalculator
import com.testlogon.android.feature.call.billing.BillingCondition
import com.testlogon.android.feature.call.domain.CallEndReason
import com.testlogon.android.feature.call.domain.CallManager
import com.testlogon.android.feature.call.domain.CallPhase
import com.testlogon.android.feature.call.domain.CallSessionState
import com.testlogon.android.feature.call.recording.RecordingController
import com.testlogon.android.feature.call.recording.RecordingUiState
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-298 — view model for the in-call (1:1) screen.
 *
 * Reads the app-scoped lifecycle from [CallManager] (the "CallSessionController" of the spec) and merges it
 * with LOCAL, optimistic media-control state (mic/camera/route/pip/controls) held in [localUi] and mirrored
 * into [SavedStateHandle] so rotation survives. Native media is FLAGGED — the toggles never touch a real
 * track — but they are fully functioning UI state (icon + contentDescription flip on tap, debounced flip,
 * camera disabled in audio-only, flip disabled when the camera is off). [CallManager] media-control methods
 * deliberately do NOT exist, so this VM never calls them.
 *
 * Duration is derived from [CallSessionState.elapsedSeconds] when the heartbeat has reported it; otherwise a
 * bounded 1Hz ticker counts up from [CallPhase.Connected.sinceEpochMs]. The displayed value is frozen while
 * quality is LOST (Reconnecting) although the underlying counter keeps advancing.
 *
 * Terminal navigation is a one-shot [callEnded] effect (Channel + receiveAsFlow), mirroring
 * [com.testlogon.android.feature.call.ui.OutgoingCallViewModel].
 */
@HiltViewModel
class InCallViewModel @Inject constructor(
    private val callManager: CallManager,
    private val statsSampler: CallStatsSampler,
    private val recordingController: RecordingController,
    private val callMediaHolder: com.testlogon.android.data.webrtc.CallMediaHolder,
    private val savedState: SavedStateHandle,
    // The real native-WebRTC renderer (RealVideoRenderer) bound in WebRtcApiModule; the screen passes it
    // to the local/remote video composables so they host a SurfaceViewRenderer instead of the placeholder.
    val videoRenderer: com.testlogon.android.core.webrtc.ui.VideoRenderer,
) : ViewModel() {

    /**
     * AND-302 — the call-recording consent + upload sub-state (additive to the call lifecycle). The screen
     * mounts the Record control / consent dialog / upload status off this. Capture is FLAGGED, so this stays
     * Idle in production until consent succeeds; on Granted the controller surfaces "recording unavailable".
     */
    val recordingState: StateFlow<RecordingUiState> = recordingController.state

    /** Local, optimistic UI-control state (not part of the domain call state). */
    private data class LocalUi(
        val micEnabled: Boolean,
        val cameraEnabled: Boolean,
        val flipInFlight: Boolean,
        val audioRoute: AudioRoute,
        val pipCorner: PipCorner,
        val controlsVisible: Boolean,
    )

    private val localUi = MutableStateFlow(
        LocalUi(
            micEnabled = savedState[KEY_MIC] ?: true,
            cameraEnabled = savedState[KEY_CAMERA] ?: true,
            flipInFlight = false,
            audioRoute = savedState.get<String>(KEY_ROUTE)?.let { runCatching { AudioRoute.valueOf(it) }.getOrNull() }
                ?: AudioRoute.EARPIECE,
            pipCorner = savedState.get<String>(KEY_PIP)?.let { runCatching { PipCorner.valueOf(it) }.getOrNull() }
                ?: PipCorner.TOP_END,
            controlsVisible = savedState[KEY_CONTROLS] ?: true,
        ),
    )

    private val effects = Channel<Unit>(Channel.BUFFERED)

    /** One-shot terminal effect: emits once when the call reaches a terminal phase so the Route can pop. */
    val callEnded = effects.receiveAsFlow()

    private var terminalEmitted = false
    private var endRequested = false

    // Last duration shown before entering Reconnecting; the displayed value freezes here while LOST.
    private var frozenDurationSeconds = 0L

    // Bounded 1Hz ticker. It lives inside the WhileSubscribed stateIn below, so it stops when nothing
    // collects — never an unbounded background loop.
    private val durationTicker = flow {
        var tick = 0L
        while (true) {
            emit(tick)
            tick++
            kotlinx.coroutines.delay(1_000)
        }
    }

    val uiState: StateFlow<InCallUiState> = combine(
        callManager.state,
        localUi,
        statsSampler.quality(),
        durationTicker,
        callMediaHolder.remoteVideo,
    ) { session, local, quality, tick, remoteVid ->
        session.toUi(local, quality, tick, remoteVid != null)
    }.stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5_000),
        initialValue = CallSessionState().toUi(localUi.value, ConnectionQuality.UNKNOWN, 0L, false),
    )

    init {
        // Emit the one-shot terminal effect exactly once when the manager reaches a terminal phase.
        viewModelScope.launch {
            callManager.state.collect { session ->
                if (session.phase.isTerminal && !terminalEmitted) {
                    terminalEmitted = true
                    effects.send(Unit)
                }
            }
        }
    }

    fun onAction(action: InCallAction) {
        when (action) {
            InCallAction.ToggleMic -> localUi.update {
                it.copy(micEnabled = !it.micEnabled).also { next -> savedState[KEY_MIC] = next.micEnabled }
            }
            InCallAction.ToggleCamera -> {
                if (!isVideoCall()) return
                localUi.update {
                    it.copy(cameraEnabled = !it.cameraEnabled).also { next -> savedState[KEY_CAMERA] = next.cameraEnabled }
                }
            }
            InCallAction.FlipCamera -> {
                val cur = localUi.value
                // Debounce: ignore while a flip is in flight, when the camera is off, or with one camera.
                if (cur.flipInFlight || !cur.cameraEnabled || !hasMultipleCameras()) return
                // Media is FLAGGED: there is no real track to switch, so the in-flight window opens and
                // immediately closes (a real impl awaits the SDK camera-switch callback).
                localUi.update { it.copy(flipInFlight = false) }
            }
            is InCallAction.SetRoute -> localUi.update {
                it.copy(audioRoute = action.route).also { next -> savedState[KEY_ROUTE] = next.audioRoute.name }
            }
            InCallAction.CycleRoute -> localUi.update {
                val next = nextRoute(it.audioRoute)
                it.copy(audioRoute = next).also { n -> savedState[KEY_ROUTE] = n.audioRoute.name }
            }
            is InCallAction.MoveLocalTile -> localUi.update {
                it.copy(pipCorner = action.corner).also { next -> savedState[KEY_PIP] = next.pipCorner.name }
            }
            InCallAction.ToggleControls -> localUi.update {
                it.copy(controlsVisible = !it.controlsVisible).also { next -> savedState[KEY_CONTROLS] = next.controlsVisible }
            }
            InCallAction.EndCall -> {
                if (endRequested) return
                endRequested = true
                callManager.endCall(CallEndReason.HANGUP)
            }
        }
    }

    // ─── AND-302: call-recording sub-state actions (delegate to RecordingController) ───────────────

    /** Requester taps Record (after RECORD_AUDIO is granted, handled in the Route). No-op if no active call. */
    fun onRecordRequest() {
        val callId = callManager.state.value.call?.callId ?: return
        recordingController.request(callId)
    }

    /** Callee accepts the consent prompt -> POST consent (the server consent GATE). */
    fun onRecordConsent() {
        val callId = callManager.state.value.call?.callId ?: return
        recordingController.consent(callId)
    }

    /** Either side declines the recording. */
    fun onRecordDecline() {
        val callId = callManager.state.value.call?.callId ?: return
        recordingController.decline(callId)
    }

    /** Cancel an in-flight/queued recording upload. */
    fun onRecordCancel() = recordingController.cancel()

    /** Retry a failed recording upload (re-runs presign -> PUT -> complete from the durable queue). */
    fun onRecordRetry() {
        val callId = callManager.state.value.call?.callId ?: return
        recordingController.retry(callId)
    }

    private fun isVideoCall(): Boolean = callManager.state.value.call?.mode == CallMode.VIDEO

    private fun hasMultipleCameras(): Boolean = true

    /** Cycle through the available routes in EARPIECE -> SPEAKER -> (BLUETOOTH/WIRED) -> back order. */
    private fun nextRoute(current: AudioRoute): AudioRoute {
        val order = ROUTE_CYCLE.filter { it == current || it in defaultAvailableRoutes() }
        if (order.isEmpty()) return current
        val idx = order.indexOf(current)
        return order[(idx + 1) % order.size]
    }

    private fun defaultAvailableRoutes(): Set<AudioRoute> = setOf(AudioRoute.EARPIECE, AudioRoute.SPEAKER)

    private fun CallSessionState.toUi(local: LocalUi, quality: ConnectionQuality, tick: Long, hasRemote: Boolean): InCallUiState {
        val video = call?.mode == CallMode.VIDEO
        val lifecycle = deriveLifecycle(phase, quality)
        val effectiveCamera = video && local.cameraEnabled
        // Duration: prefer the heartbeat-driven elapsedSeconds; otherwise the local 1Hz ticker counting up
        // from the moment Connected was observed. While Reconnecting the displayed value freezes, but the
        // underlying counter keeps advancing (so it resumes correctly once quality recovers).
        val connected = phase is CallPhase.Connected
        val baseSeconds = when {
            elapsedSeconds > 0 -> elapsedSeconds
            connected -> tick
            else -> 0L
        }
        val durationLabel = if (lifecycle == InCallLifecycle.Reconnecting) {
            CallDurationFormatter.format(frozenDurationSeconds)
        } else {
            frozenDurationSeconds = baseSeconds
            CallDurationFormatter.format(baseSeconds)
        }
        // AND-301: billing for the running-cost overlay. The authoritative cost/balance/warnings are
        // copied from each heartbeat into the session (CallManager); between heartbeats we bridge with the
        // local estimate (ceil(elapsed/60) * rate). On Ended we surface the final cost (authoritative if
        // billed, otherwise the last running value labelled an estimate).
        val hasHeartbeat = totalCostCents > 0 || balanceRemainingCents > 0
        val runningCost = if (hasHeartbeat) {
            totalCostCents
        } else {
            BillingCalculator.estimateCents(baseSeconds, rateCentsPerMinute)
        }
        val billingCondition = when {
            maxDurationWarning -> BillingCondition.MaxDurationWarning
            warnLowBalance -> BillingCondition.LowBalance
            else -> BillingCondition.None
        }
        val ended = phase is CallPhase.Ended
        return InCallUiState(
            callId = call?.callId.orEmpty(),
            peerName = peerName,
            peerAvatarUrl = null,
            lifecycle = lifecycle,
            isVideoCall = video,
            hasLocalVideo = effectiveCamera,
            hasRemoteVideo = hasRemote,
            micEnabled = local.micEnabled,
            cameraEnabled = local.cameraEnabled,
            flipInFlight = local.flipInFlight,
            hasMultipleCameras = hasMultipleCameras(),
            audioRoute = local.audioRoute,
            availableRoutes = defaultAvailableRoutes(),
            quality = quality,
            showWeakBanner = quality == ConnectionQuality.POOR && lifecycle == InCallLifecycle.Connected,
            mediaUnavailable = mediaUnavailable,
            durationLabel = durationLabel,
            controlsVisible = if (video) local.controlsVisible else true,
            localTileCorner = local.pipCorner,
            endedReason = (phase as? CallPhase.Ended)?.reason ?: (phase as? CallPhase.Failed)?.reason,
            paid = paid,
            runningCostCents = runningCost,
            isEstimate = !hasHeartbeat,
            billingCondition = billingCondition,
            finalCostCents = if (ended && paid) runningCost else null,
            finalIsEstimate = !hasHeartbeat,
        )
    }

    private fun deriveLifecycle(phase: CallPhase, quality: ConnectionQuality): InCallLifecycle = when (phase) {
        CallPhase.Idle, CallPhase.Inviting, CallPhase.Ringing, CallPhase.Connecting -> InCallLifecycle.Connecting
        is CallPhase.Connected ->
            if (quality == ConnectionQuality.LOST) InCallLifecycle.Reconnecting else InCallLifecycle.Connected
        CallPhase.Ending -> InCallLifecycle.Ending
        is CallPhase.Ended, is CallPhase.Failed -> InCallLifecycle.Ended
    }

    companion object {
        const val ARG_CALL_ID = "callId"

        private const val KEY_MIC = "incall_mic"
        private const val KEY_CAMERA = "incall_camera"
        private const val KEY_ROUTE = "incall_route"
        private const val KEY_PIP = "incall_pip"
        private const val KEY_CONTROLS = "incall_controls"

        private val ROUTE_CYCLE = listOf(
            AudioRoute.EARPIECE,
            AudioRoute.SPEAKER,
            AudioRoute.BLUETOOTH,
            AudioRoute.WIRED,
        )
    }
}
