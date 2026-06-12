package com.testlogon.android.feature.call.group

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.call.group.ConnQuality
import com.testlogon.android.data.call.group.GroupCall
import com.testlogon.android.data.call.group.GroupCallRepository
import com.testlogon.android.data.call.group.ParticipantState
import com.testlogon.android.data.webrtc.MeshConnectionManager
import com.testlogon.android.data.webrtc.MeshEvent
import com.testlogon.android.feature.call.incall.AudioRoute
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-299 — view model for the GROUP-call screen.
 *
 * The CONTROL PLANE is REAL: on init the VM either creates a group call (when started with a
 * conversationId) or joins one (when started with a callId), then collects the [MeshConnectionManager]
 * events into the pure [GroupCallReducer] to keep the roster live. Native media is FLAGGED — the mesh stub
 * returns NotConfigured and never emits — so [GroupCallUiState.mediaUnavailable] is set true and NO real
 * peer is ever started (mirrors CallManager's mediaUnavailable pattern).
 *
 * Local controls (mic/camera) flip optimistic UI state AND fire a best-effort repository.media() PATCH;
 * route/flip are local-only. Leave calls repository.leave() exactly once (guarded by [endRequested]) then
 * emits the one-shot [callEnded] effect (Channel + receiveAsFlow) so the Route pops.
 *
 * [uiState] is a combine(...).stateIn(WhileSubscribed) — there is NO unbounded ticker here.
 */
@HiltViewModel
class GroupCallViewModel @Inject constructor(
    private val repository: GroupCallRepository,
    private val mesh: MeshConnectionManager,
    private val savedState: SavedStateHandle,
) : ViewModel() {

    /** Local, optimistic media-control state (not part of the control-plane roster). */
    private data class LocalControls(
        val micEnabled: Boolean = true,
        val cameraEnabled: Boolean = true,
        val audioRoute: AudioRoute = AudioRoute.SPEAKER,
    )

    private val callId: String? = savedState[ARG_CALL_ID]
    private val conversationId: String? = savedState[ARG_CONVERSATION_ID]
    private val mode: String = savedState.get<String>(ARG_MODE) ?: "video"

    /** The reducer-owned roster snapshot (phase + participants + active speaker). */
    private val callState = MutableStateFlow(
        GroupCallUiState(
            callId = callId,
            phase = if (callId != null) GroupCallPhase.Joining else GroupCallPhase.Creating,
            // Media is FLAGGED (mesh NotConfigured): surface "media unavailable" up front.
            mediaUnavailable = true,
        ),
    )

    private val localControls = MutableStateFlow(LocalControls())

    private val effects = Channel<Unit>(Channel.BUFFERED)

    /** One-shot terminal effect: emits once after Leave so the Route can pop. */
    val callEnded = effects.receiveAsFlow()

    private var endRequested = false

    // The active call id once create/join resolves (needed by the local media toggles + Leave).
    @Volatile
    private var activeCallId: String? = callId

    // The host id, captured from create/join, so roster reducer events keep deriving isHost correctly.
    @Volatile
    private var creatorUserId: String? = null

    val uiState: StateFlow<GroupCallUiState> = combine(callState, localControls) { state, controls ->
        state.copy(
            micEnabled = controls.micEnabled,
            cameraEnabled = controls.cameraEnabled,
            audioRoute = controls.audioRoute,
        )
    }.stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5_000),
        initialValue = callState.value,
    )

    init {
        viewModelScope.launch { start() }
        // Fold mesh events into the reducer. The FLAGGED stub never emits, but the wiring is real so the
        // real mesh slots in without VM changes.
        viewModelScope.launch {
            mesh.events.collect { event -> applyEvent(event.toGroupCallEvent()) }
        }
    }

    private suspend fun start() {
        val joinId = callId
        when {
            joinId != null -> {
                // Join: the join body carries no creator id, so resolve it from get() first (best-effort).
                val hostId = (repository.get(joinId).successOrNull())?.creatorUserId
                creatorUserId = hostId
                when (val res = repository.join(
                    callId = joinId,
                    conversationId = conversationId.orEmpty(),
                    creatorUserId = hostId.orEmpty(),
                )) {
                    is ApiResult.Success -> onCallResolved(res.data, GroupCallPhase.Active)
                    is ApiResult.Failure -> callState.update { it.copy(phase = GroupCallPhase.Ended, error = res.error.message) }
                    is ApiResult.NetworkError -> callState.update { it.copy(phase = GroupCallPhase.Ended, error = res.cause.message) }
                }
            }

            conversationId != null -> {
                when (val res = repository.create(conversationId = conversationId, mode = mode)) {
                    is ApiResult.Success -> onCallResolved(res.data, GroupCallPhase.Active)
                    is ApiResult.Failure -> callState.update { it.copy(phase = GroupCallPhase.Ended, error = res.error.message) }
                    is ApiResult.NetworkError -> callState.update { it.copy(phase = GroupCallPhase.Ended, error = res.cause.message) }
                }
            }

            else -> callState.update { it.copy(phase = GroupCallPhase.Ended, error = "Missing call arguments") }
        }
    }

    private fun onCallResolved(call: GroupCall, phase: GroupCallPhase) {
        activeCallId = call.callId
        creatorUserId = call.creatorUserId
        callState.update {
            it.copy(
                callId = call.callId,
                phase = phase,
                participants = call.participants.sortedWith(
                    compareBy({ p -> p.joinedAt }, { p -> p.displayName ?: "" }, { p -> p.userId }),
                ),
                // Media stays FLAGGED — never start a real peer.
                mediaUnavailable = true,
            )
        }
    }

    fun onAction(action: GroupCallAction) {
        when (action) {
            GroupCallAction.ToggleMic -> {
                val next = !localControls.value.micEnabled
                localControls.update { it.copy(micEnabled = next) }
                mesh.setLocalMute(muted = !next)
                pushMedia(audio = next)
            }
            GroupCallAction.ToggleCamera -> {
                val next = !localControls.value.cameraEnabled
                localControls.update { it.copy(cameraEnabled = next) }
                mesh.setLocalVideo(on = next)
                pushMedia(video = next)
            }
            GroupCallAction.CycleRoute -> localControls.update { it.copy(audioRoute = nextRoute(it.audioRoute)) }
            GroupCallAction.FlipCamera -> Unit // local-only; native flip is FLAGGED.
            GroupCallAction.Leave -> leave()
        }
    }

    private fun pushMedia(audio: Boolean? = null, video: Boolean? = null) {
        val id = activeCallId ?: return
        viewModelScope.launch {
            // Best-effort: a failed media PATCH never blocks the local optimistic toggle.
            repository.media(callId = id, audio = audio, video = video)
        }
    }

    private fun leave() {
        if (endRequested) return
        endRequested = true
        callState.update { it.copy(phase = GroupCallPhase.Ending) }
        viewModelScope.launch {
            activeCallId?.let { repository.leave(it) }
            callState.update { it.copy(phase = GroupCallPhase.Ended) }
            effects.send(Unit)
        }
    }

    private fun applyEvent(event: GroupCallEvent) {
        callState.update { GroupCallReducer.reduce(it, event) }
    }

    private fun nextRoute(current: AudioRoute): AudioRoute {
        val order = listOf(AudioRoute.SPEAKER, AudioRoute.EARPIECE)
        val idx = order.indexOf(current).coerceAtLeast(0)
        return order[(idx + 1) % order.size]
    }

    private fun <T> ApiResult<T>.successOrNull(): T? = (this as? ApiResult.Success)?.data

    private fun MeshEvent.toGroupCallEvent(): GroupCallEvent = when (this) {
        is MeshEvent.PeerConnected -> GroupCallEvent.StateChanged(userId, ParticipantState.Connected)
        is MeshEvent.PeerDisconnected -> GroupCallEvent.StateChanged(userId, ParticipantState.Left)
        is MeshEvent.QualityChanged -> GroupCallEvent.QualityChanged(userId, ConnQuality.fromWire(quality))
        is MeshEvent.Speaking -> GroupCallEvent.Speaking(userId, speaking)
        is MeshEvent.RemoteTrack -> GroupCallEvent.MediaStatusChanged(
            userId = userId,
            micMuted = false,
            cameraOff = !hasVideo,
        )
    }

    companion object {
        const val ARG_CALL_ID = "callId"
        const val ARG_CONVERSATION_ID = "conversationId"
        const val ARG_MODE = "mode"
    }
}
