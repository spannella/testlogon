package com.testlogon.android.feature.broadcast.host

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.broadcast.BroadcastInputType
import com.testlogon.android.data.broadcast.BroadcastRepository
import com.testlogon.android.data.broadcast.HostControlRepository
import com.testlogon.android.data.webrtc.BroadcastPublisher
import com.testlogon.android.data.webrtc.GoLiveResult
import com.testlogon.android.data.webrtc.PublishState
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-308 — host broadcast INGEST presentation logic (camera/mic publish driver).
 *
 * Drives the broadcast INPUTS control plane (REAL) + the FLAGGED publish engine:
 *  1. [start] creates the host's "primary" ingest input via [BroadcastRepository.createInput] (REAL POST).
 *  2. On success it hands the allocated inputId to the FLAGGED [BroadcastPublisher.goLive].
 *  3. The bound publisher is [com.testlogon.android.data.webrtc.StubBroadcastPublisher], which ALWAYS
 *     returns [GoLiveResult.NotConfigured] and stays in [PublishState.Unavailable] — it NEVER opens a
 *     camera/mic, NEVER creates a PeerConnection, NEVER produces an SDP offer. So [start] resolves to
 *     [IngestPhase.Unavailable] with [IngestUiState.mediaUnavailable] = true and the screen shows the
 *     "broadcasting unavailable — not configured" banner. STOP-AND-FLAG.
 *
 * The REAL publish path (once the native WebRTC SDK is added) would, from the primary input: open the
 * front camera + mic, build a PeerConnection, produce an SDP offer, exchange it via the AND-290
 * [com.testlogon.android.data.webrtc.SignalingRepository.exchangeBroadcastOffer] host-publish path
 * (POST broadcast/sessions/{sessionId}/inputs/{inputId}/webrtc-offer), apply the SFU answer, then
 * activate the input. AND-308 deliberately does NOT add that dependency; the offer/answer endpoint is
 * already modeled and REUSED rather than duplicated.
 *
 * [stop] stops the publisher and best-effort deactivates + removes the created input. State updates use
 * MutableStateFlow + update (no distinctUntilChanged on a StateFlow). The publisher's hot [state] is
 * collected and folded into the phase machine.
 */
@HiltViewModel
class IngestViewModel @Inject constructor(
    private val broadcastRepository: BroadcastRepository,
    private val hostControlRepository: HostControlRepository,
    private val broadcastPublisher: BroadcastPublisher,
    savedState: SavedStateHandle,
    val videoRenderer: com.testlogon.android.core.webrtc.ui.VideoRenderer,
) : ViewModel() {

    val sessionId: String = savedState.get<String>(ARG_SESSION_ID).orEmpty()

    private val _uiState = MutableStateFlow(IngestUiState())
    val uiState: StateFlow<IngestUiState> = _uiState.asStateFlow()

    /**
     * T3 — guards the one-shot `POST broadcast/sessions/{id}/start` that flips the session to `live` on
     * the backend once the WHIP publish actually connects. Without this call the session stays `draft`,
     * so it never appears in the `/broadcast/live` discovery feed and no viewer can find it. Both the
     * goLive() Started result and the publisher's PublishState.Live emission funnel through
     * [markSessionLive], so we only fire the start once per publish.
     */
    private var startInvoked = false

    init {
        // Fold the FLAGGED publisher's hot state into the phase machine. The stub stays Unavailable.
        viewModelScope.launch {
            broadcastPublisher.state.collect { publishState ->
                _uiState.update { current -> current.reduce(publishState) }
                // T3 — the publisher can reach Live via its own connection callback (not only the goLive()
                // return). Fire the one-shot backend go-live from here too so the session becomes
                // discoverable regardless of which path signalled the connection.
                if (publishState == PublishState.Live) markSessionLive()
            }
        }
    }

    /**
     * #7a — open the local camera preview so the host sees themselves BEFORE going live (CAMERA +
     * RECORD_AUDIO assumed already granted by the screen). This only opens capture + publishes the
     * local track to the shared media holder (no peer, no publish); the real renderer in the screen
     * then shows the live self-view. With the FLAGGED stub publisher this is a no-op (placeholder).
     */
    fun startPreview() {
        viewModelScope.launch {
            broadcastPublisher.startPreview()
        }
    }

    /**
     * The host tapped "Go Live" (CAMERA + RECORD_AUDIO assumed already granted by the screen). Creates the
     * primary ingest input, then drives the FLAGGED publisher.
     */
    fun start() {
        if (!_uiState.value.canStart) return
        if (sessionId.isBlank()) {
            _uiState.update { it.copy(phase = IngestPhase.Failed, error = NO_SESSION) }
            return
        }
        startInvoked = false
        _uiState.update { it.copy(phase = IngestPhase.CreatingInput, error = null) }
        viewModelScope.launch {
            when (val created = broadcastRepository.createInput(sessionId, BroadcastInputType.PRIMARY, HOST_LABEL)) {
                is ApiResult.Success -> {
                    val inputId = created.data.inputId
                    _uiState.update { it.copy(phase = IngestPhase.Negotiating, inputId = inputId) }
                    goLive(inputId)
                }
                is ApiResult.Failure ->
                    _uiState.update { it.copy(phase = IngestPhase.Failed, error = created.error.message) }
                is ApiResult.NetworkError ->
                    _uiState.update { it.copy(phase = IngestPhase.Failed, error = OFFLINE) }
            }
        }
    }

    /**
     * Drives the FLAGGED publisher. The stub returns [GoLiveResult.NotConfigured] -> Unavailable +
     * mediaUnavailable. A real engine would reach [GoLiveResult.Started] -> Connected.
     */
    private suspend fun goLive(inputId: String) {
        when (val result = broadcastPublisher.goLive(sessionId, inputId)) {
            GoLiveResult.Started -> {
                _uiState.update { it.copy(phase = IngestPhase.Connected) }
                markSessionLive()
            }
            is GoLiveResult.Failed ->
                _uiState.update {
                    it.copy(phase = IngestPhase.Failed, error = humanizePublishFailure(result.reason))
                }
            GoLiveResult.NotConfigured ->
                _uiState.update {
                    it.copy(phase = IngestPhase.Unavailable, mediaUnavailable = true)
                }
        }
    }

    /**
     * T3 — flips the backend session to `live` (POST broadcast/sessions/{id}/start) exactly once, after the
     * WHIP publish is actually connected. The backend then surfaces this session in `GET /broadcast/live`,
     * which is how a second-user VIEWER discovers and watches the host. Best-effort: a failure here does not
     * tear the running publish down (the host still streams), it only means discovery may lag; the ingest
     * phase is unaffected.
     */
    private fun markSessionLive() {
        if (startInvoked || sessionId.isBlank()) return
        startInvoked = true
        viewModelScope.launch {
            when (hostControlRepository.start(sessionId)) {
                is ApiResult.Success -> Unit // session is now `live` and discoverable via /broadcast/live
                // Do NOT surface as a hard failure: the media publish is up; only discovery is affected.
                // Allow a later retry (e.g. the PublishState.Live emission) by clearing the guard.
                else -> startInvoked = false
            }
        }
    }

    /** Stops the publisher and best-effort deactivates + removes the created input. Idempotent. */
    fun stop() {
        broadcastPublisher.stop()
        startInvoked = false
        val inputId = _uiState.value.inputId
        _uiState.update { it.copy(phase = IngestPhase.PreviewReady, inputId = null) }
        // T3 — flip the backend session out of `live` so it drops from the /broadcast/live discovery feed.
        if (sessionId.isNotBlank()) {
            viewModelScope.launch { hostControlRepository.stop(sessionId) }
        }
        if (inputId != null && sessionId.isNotBlank()) {
            viewModelScope.launch {
                // Best-effort teardown; failures here do not surface to the user.
                broadcastRepository.deactivateInput(sessionId, inputId)
                broadcastRepository.removeInput(sessionId, inputId)
            }
        }
    }

    override fun onCleared() {
        broadcastPublisher.stop()
    }

    /**
     * Folds the FLAGGED publisher [PublishState] into the phase machine WITHOUT overriding a terminal
     * control-plane Failed or a resolved Unavailable. The stub only ever emits [PublishState.Unavailable].
     */
    private fun IngestUiState.reduce(publishState: PublishState): IngestUiState = when (publishState) {
        PublishState.Idle -> this
        PublishState.Starting ->
            if (phase == IngestPhase.Failed) this else copy(phase = IngestPhase.Negotiating)
        PublishState.Live -> copy(phase = IngestPhase.Connected)
        is PublishState.Failed ->
            copy(phase = IngestPhase.Failed, error = humanizePublishFailure(publishState.reason))
        PublishState.Unavailable ->
            // The FLAGGED engine reports not-configured: surface the banner, but only once a start
            // attempt has been made (Idle/PreviewReady should not show the banner pre-emptively).
            if (phase == IngestPhase.Idle || phase == IngestPhase.PreviewReady) this
            else copy(phase = IngestPhase.Unavailable, mediaUnavailable = true)
    }

    /**
     * Translates the [BroadcastPublisher] failure reason into a clear, honest, user-facing message.
     *
     * [com.testlogon.android.data.webrtc.RealBroadcastPublisher.REASON_SERVER_UNREACHABLE] means the live
     * streaming media server (WHIP ingest) is not reachable: the host's camera preview is running locally
     * but no stream reaches viewers — the streaming infrastructure is not deployed yet. We do NOT tear the
     * preview down so the host still sees a real camera feed.
     */
    private fun humanizePublishFailure(reason: String): String = when (reason) {
        com.testlogon.android.data.webrtc.RealBroadcastPublisher.REASON_SERVER_UNREACHABLE ->
            SERVER_UNREACHABLE
        com.testlogon.android.data.webrtc.RealBroadcastPublisher.REASON_WHIP_REJECTED ->
            WHIP_REJECTED
        else -> GO_LIVE_FAILED
    }

    companion object {
        /** Nav arg carrying the broadcast session id (the session created by AND-307). */
        const val ARG_SESSION_ID = "sessionId"

        /** Label for the host's own primary camera/mic input. */
        private const val HOST_LABEL = "Host camera"

        // Non-resource fallbacks (the screen prefers stringResource where it has a Context).
        private const val NO_SESSION = "No broadcast session is available."
        private const val GO_LIVE_FAILED = "Couldn't start your broadcast. Try again."

        /**
         * Honest copy for the no-infrastructure case: the WHIP ingest server is unreachable. The local
         * camera preview keeps running; viewers cannot watch because live streaming is not deployed.
         */
        private const val SERVER_UNREACHABLE =
            "Your camera preview is running, but the live streaming server can't be reached, " +
                "so viewers can't watch yet. Live streaming isn't available on this server."
        private const val WHIP_REJECTED =
            "The live streaming server rejected the broadcast. Try again."
        private const val OFFLINE = "Couldn't reach the server. Try again."
    }
}
