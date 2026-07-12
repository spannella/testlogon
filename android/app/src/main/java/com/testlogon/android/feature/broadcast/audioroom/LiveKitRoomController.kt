package com.testlogon.android.feature.broadcast.audioroom

import dagger.hilt.android.qualifiers.ApplicationContext
import io.livekit.android.LiveKit
import io.livekit.android.room.Room
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import android.content.Context
import javax.inject.Inject

/**
 * #104 AUDIO ROOM — a thin, per-screen wrapper over the LiveKit Android SDK [Room] for AUDIO-ONLY rooms.
 * Not a singleton (each audio-room screen/ViewModel gets its own; the [Room] holds native resources and is
 * released in [disconnect]). No video renderers — LiveKit's AudioHandler renders the subscribed remote mic
 * tracks automatically on connect, so listeners simply hear the speakers with no track plumbing.
 *
 * Wiring:
 *  - [connect] : LiveKit.create(appContext) -> room.connect(url, token). Speakers/host pass enableMic=true
 *    -> localParticipant.setMicrophoneEnabled(true) (mic-only publish). Listeners connect subscribe-only.
 *  - We collect room.events (a SharedFlow<RoomEvent>) and re-SNAPSHOT the participant set on every event
 *    (active speakers, per-participant mic-mute + speaking + audio level) — a role/subtype-agnostic
 *    projection that stays correct across connect/publish/mute/speaking/participant-join transitions.
 *  - [setMicrophoneEnabled] toggles the local mic (self-mute or, after a host promote, start publishing).
 */
class LiveKitRoomController @Inject constructor(
    @ApplicationContext private val appContext: Context,
) {
    enum class ConnState { IDLE, CONNECTING, CONNECTED, DISCONNECTED, FAILED }

    /** A projected participant tile source (audio-first): who is on the SFU + their live mic/speaking state. */
    data class LkParticipant(
        val identity: String,
        val name: String?,
        val isLocal: Boolean,
        val isSpeaking: Boolean,
        val micMuted: Boolean,
        val audioLevel: Float,
    )

    private var room: Room? = null
    private var eventJob: Job? = null

    private val _state = MutableStateFlow(ConnState.IDLE)
    val state: StateFlow<ConnState> = _state.asStateFlow()

    private val _participants = MutableStateFlow<List<LkParticipant>>(emptyList())
    val participants: StateFlow<List<LkParticipant>> = _participants.asStateFlow()

    private val _localMicEnabled = MutableStateFlow(false)
    val localMicEnabled: StateFlow<Boolean> = _localMicEnabled.asStateFlow()

    /** Connect (idempotent). [scope] owns the event-collection job (the caller's viewModelScope). */
    suspend fun connect(url: String, token: String, enableMic: Boolean, scope: CoroutineScope) {
        if (room != null) return
        _state.value = ConnState.CONNECTING
        val r = LiveKit.create(appContext)
        room = r
        eventJob = scope.launch {
            try {
                r.events.events.collect { snapshot(r) }
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                // event stream ended; snapshots stop but the room stays usable
            }
        }
        try {
            r.connect(url, token)
            _state.value = ConnState.CONNECTED
            if (enableMic) setMicrophoneEnabled(true)
            snapshot(r)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            _state.value = ConnState.FAILED
            throw e
        }
    }

    /** Publish/unpublish the local mic (mic-only). Safe no-op if not connected or not permitted. */
    suspend fun setMicrophoneEnabled(enabled: Boolean) {
        val r = room ?: return
        try {
            r.localParticipant.setMicrophoneEnabled(enabled)
            _localMicEnabled.value = enabled
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            // server may not have granted can_publish yet (pre-promote) — ignore
        }
        snapshot(r)
    }

    private fun snapshot(r: Room) {
        val speaking = r.activeSpeakers.mapNotNull { it.identity?.value }.toSet()
        val out = ArrayList<LkParticipant>()
        val lp = r.localParticipant
        val localId = lp.identity?.value
        if (localId != null) {
            out.add(
                LkParticipant(
                    identity = localId,
                    name = lp.name,
                    isLocal = true,
                    isSpeaking = localId in speaking || lp.isSpeaking,
                    micMuted = !lp.isMicrophoneEnabled,
                    audioLevel = lp.audioLevel,
                ),
            )
        }
        for (p in r.remoteParticipants.values) {
            val id = p.identity?.value ?: continue
            out.add(
                LkParticipant(
                    identity = id,
                    name = p.name,
                    isLocal = false,
                    isSpeaking = id in speaking || p.isSpeaking,
                    micMuted = !p.isMicrophoneEnabled,
                    audioLevel = p.audioLevel,
                ),
            )
        }
        _participants.value = out
        _localMicEnabled.value = lp.isMicrophoneEnabled
    }

    fun disconnect() {
        eventJob?.cancel()
        eventJob = null
        try {
            room?.disconnect()
        } catch (_: Exception) {
        }
        room = null
        _participants.value = emptyList()
        _localMicEnabled.value = false
        _state.value = ConnState.DISCONNECTED
    }
}
