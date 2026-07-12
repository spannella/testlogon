package com.testlogon.android.feature.broadcast.audioroom

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * #104 AUDIO ROOM — orchestrates the LiveKit transport + the backend #102 stage control plane for one
 * audio room. Role is server-authoritative (from GET livekit-token); the stage roster (GET stage) is the
 * source of truth for who is on stage, enriched with LIVE speaking + mic state from [LiveKitRoomController].
 *
 * Realtime: stage.* events arrive over messaging/events/poll ([AudioRoomRepository.stageEvents]). On a
 * self-promote we re-fetch the token + enable the mic (become a speaker); on self-demote we stop
 * publishing; on mute/unmute/hand we re-fetch the roster so the server-authoritative state is reflected.
 */
@HiltViewModel
class AudioRoomViewModel @Inject constructor(
    savedStateHandle: SavedStateHandle,
    private val repo: AudioRoomRepository,
    private val room: LiveKitRoomController,
) : ViewModel() {

    val sessionId: String = requireNotNull(savedStateHandle[ARG_SESSION_ID]) {
        "audio room route requires a sessionId arg"
    }

    private val _uiState = MutableStateFlow(AudioRoomUiState(sessionId = sessionId))
    val uiState: StateFlow<AudioRoomUiState> = _uiState.asStateFlow()

    private var latestRoster: StageRosterDto? = null
    private var viewerId: String? = null
    private var presenceJob: Job? = null
    private var left = false

    init {
        observeTransport()
        join()
    }

    /** Merge LiveKit connection + live participant state into the UI as it mutates. */
    private fun observeTransport() {
        viewModelScope.launch { room.participants.collect { recompute() } }
        viewModelScope.launch {
            room.state.collect { st ->
                _uiState.update {
                    it.copy(
                        connState = st,
                        connecting = st == LiveKitRoomController.ConnState.CONNECTING ||
                            st == LiveKitRoomController.ConnState.IDLE,
                        fatalError = if (st == LiveKitRoomController.ConnState.FAILED) {
                            it.fatalError ?: "Could not connect to the audio room"
                        } else {
                            it.fatalError
                        },
                    )
                }
            }
        }
        viewModelScope.launch {
            room.localMicEnabled.collect { on -> _uiState.update { it.copy(micEnabled = on) } }
        }
    }

    fun join() {
        _uiState.update { it.copy(connecting = true, fatalError = null) }
        viewModelScope.launch {
            when (val t = repo.token(sessionId)) {
                is ApiResult.Success -> connectWithToken(t.data)
                is ApiResult.Failure -> _uiState.update {
                    it.copy(connecting = false, fatalError = t.error.message)
                }
                is ApiResult.NetworkError -> _uiState.update {
                    it.copy(connecting = false, fatalError = "Network error joining the room")
                }
            }
        }
    }

    private suspend fun connectWithToken(t: LivekitTokenDto) {
        val role = when (t.role) {
            "host" -> AudioRole.HOST
            "speaker" -> AudioRole.SPEAKER
            else -> AudioRole.LISTENER
        }
        _uiState.update {
            it.copy(selfId = t.identity, role = role, isHost = role == AudioRole.HOST)
        }
        // Speakers/host publish mic-only; listeners are subscribe-only. LiveKit renders remote audio
        // automatically (no track plumbing needed for listening).
        runCatching {
            room.connect(url = t.url, token = t.token, enableMic = t.canPublish, scope = viewModelScope)
        }.onFailure { e ->
            _uiState.update { it.copy(connecting = false, fatalError = e.message ?: "Connect failed") }
            return
        }
        refreshRoster()
        startPresence()
        collectStageEvents()
    }

    private fun collectStageEvents() {
        viewModelScope.launch {
            repo.stageEvents(sessionId).collect { ev -> onStageEvent(ev) }
        }
    }

    private suspend fun onStageEvent(ev: StageEvent) {
        val selfId = _uiState.value.selfId
        when (ev) {
            is StageEvent.Promote -> {
                if (ev.userId == selfId) {
                    // become a speaker: re-fetch token (updated grant) + start publishing mic
                    when (val t = repo.token(sessionId)) {
                        is ApiResult.Success -> {
                            _uiState.update {
                                it.copy(role = AudioRole.SPEAKER, handRaised = false)
                            }
                            enableMicOrPrompt()
                        }
                        else -> Unit
                    }
                }
                refreshRoster()
            }
            is StageEvent.Demote -> {
                if (ev.userId == selfId) {
                    room.setMicrophoneEnabled(false)
                    _uiState.update { it.copy(role = AudioRole.LISTENER, handRaised = false) }
                }
                refreshRoster()
            }
            is StageEvent.Mute, is StageEvent.Unmute, is StageEvent.Hand -> refreshRoster()
        }
    }

    private suspend fun refreshRoster() {
        when (val r = repo.roster(sessionId)) {
            is ApiResult.Success -> {
                latestRoster = r.data
                recompute()
            }
            else -> Unit
        }
    }

    private fun applyRoster(roster: StageRosterDto?) {
        if (roster != null) {
            latestRoster = roster
            recompute()
        }
    }

    /** Recompute the speaker tiles + hands from the authoritative roster enriched with live LiveKit state. */
    private fun recompute() {
        val roster = latestRoster
        val live = room.participants.value.associateBy { it.identity }
        val selfId = _uiState.value.selfId
        val speakers = roster?.speakers?.map { m ->
            val lk = live[m.userId]
            SpeakerUi(
                identity = m.userId,
                displayName = labelFor(m.userId),
                isHost = m.role == "host",
                isSelf = m.userId == selfId,
                micMuted = lk?.micMuted ?: m.micMuted,
                isSpeaking = lk?.isSpeaking ?: false,
            )
        }.orEmpty()
        val hands = roster?.hands?.map { HandUi(it.userId, labelFor(it.userId)) }.orEmpty()
        _uiState.update {
            it.copy(
                connecting = false,
                speakers = speakers,
                hands = hands,
                listenerCount = roster?.listenerCount ?: it.listenerCount,
                speakerCount = roster?.speakerCount ?: speakers.size,
                stageMaxSlots = roster?.stageMaxSlots ?: it.stageMaxSlots,
            )
        }
    }

    // ---- Listener actions ----

    fun raiseHand() {
        if (_uiState.value.canPublish) return
        _uiState.update { it.copy(handRaised = true) }
        viewModelScope.launch { repo.raiseHand(sessionId) }
    }

    // ---- Speaker/host self-mic ----

    fun toggleMic() {
        if (!_uiState.value.canPublish) return
        val target = !_uiState.value.micEnabled
        if (target && _uiState.value.needsMicPermission) return
        viewModelScope.launch { room.setMicrophoneEnabled(target) }
    }

    /** Called by the screen once RECORD_AUDIO is (or is not) granted. */
    fun onMicPermission(granted: Boolean) {
        _uiState.update { it.copy(needsMicPermission = !granted) }
        if (granted && _uiState.value.canPublish) {
            viewModelScope.launch { room.setMicrophoneEnabled(true) }
        }
    }

    fun setNeedsMicPermission(needs: Boolean) {
        _uiState.update { it.copy(needsMicPermission = needs) }
    }

    private fun enableMicOrPrompt() {
        if (_uiState.value.needsMicPermission) return
        viewModelScope.launch { room.setMicrophoneEnabled(true) }
    }

    // ---- Host controls (backend stage endpoints = server-authoritative + drive LiveKit RoomService) ----

    fun hostPromote(userId: String) = hostAction { repo.promote(sessionId, userId) }
    fun hostDemote(userId: String) = hostAction { repo.demote(sessionId, userId) }

    private fun hostAction(block: suspend () -> ApiResult<StageRosterDto?>) {
        if (!_uiState.value.isHost) return
        viewModelScope.launch {
            when (val r = block()) {
                is ApiResult.Success -> {
                    if (r.data != null) applyRoster(r.data) else refreshRoster()
                }
                else -> refreshRoster()
            }
        }
    }

    fun hostMute(userId: String) {
        if (!_uiState.value.isHost) return
        viewModelScope.launch { repo.mute(sessionId, userId); refreshRoster() }
    }

    fun hostUnmute(userId: String) {
        if (!_uiState.value.isHost) return
        viewModelScope.launch { repo.unmute(sessionId, userId); refreshRoster() }
    }

    // ---- Presence (listener count) ----

    private fun startPresence() {
        presenceJob?.cancel()
        presenceJob = viewModelScope.launch {
            when (val j = repo.viewerJoin(sessionId)) {
                is ApiResult.Success -> viewerId = j.data?.viewerId
                else -> Unit
            }
            while (true) {
                delay(20_000L)
                val vid = viewerId ?: continue
                repo.viewerHeartbeat(sessionId, vid)
            }
        }
    }

    fun leave() {
        if (left) return
        left = true
        val onStage = _uiState.value.canPublish
        val vid = viewerId
        // Fire-and-forget on a NonCancellable-ish best-effort basis; the room disconnect is synchronous.
        viewModelScope.launch {
            if (onStage) repo.leaveStage(sessionId)
            if (vid != null) repo.viewerLeave(sessionId, vid)
        }
        presenceJob?.cancel()
        room.disconnect()
    }

    override fun onCleared() {
        super.onCleared()
        room.disconnect()
        // best-effort leave without a scope (VM is dying) — the presence TTL will also reap us
    }

    private fun labelFor(userId: String): String {
        val at = userId.indexOf('@')
        val base = if (at > 0) userId.substring(0, at) else userId
        return if (base.length > 18) base.take(18) else base
    }

    companion object {
        const val ARG_SESSION_ID = "sessionId"
    }
}
