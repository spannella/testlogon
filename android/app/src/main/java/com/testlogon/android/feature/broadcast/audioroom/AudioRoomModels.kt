package com.testlogon.android.feature.broadcast.audioroom

/** #104 — the caller's role in the audio room (server-authoritative; derived from the livekit-token). */
enum class AudioRole { HOST, SPEAKER, LISTENER }

/** A speaker/host tile (audio-first: no video surface — avatar + mic state + speaking ring). */
data class SpeakerUi(
    val identity: String,
    val displayName: String,
    val isHost: Boolean,
    val isSelf: Boolean,
    /** True when the mic track is muted (self-mute OR host force-mute — both reflect here). */
    val micMuted: Boolean,
    /** True when this participant is an active speaker on the SFU (drives the speaking ring). */
    val isSpeaking: Boolean,
)

/** A raised-hand entry shown to the host (tap -> promote / dismiss). */
data class HandUi(
    val userId: String,
    val displayName: String,
)

/**
 * #104 — the full audio-room UI state. A single data class (not a sealed hierarchy) because the room is a
 * live surface that continuously mutates roster + connection + mic in place; the screen renders a spinner
 * on [connecting] and a retry on [fatalError].
 */
data class AudioRoomUiState(
    val sessionId: String = "",
    val selfId: String = "",
    val role: AudioRole = AudioRole.LISTENER,
    val isHost: Boolean = false,
    val connecting: Boolean = true,
    val connState: LiveKitRoomController.ConnState = LiveKitRoomController.ConnState.IDLE,
    val fatalError: String? = null,
    val speakers: List<SpeakerUi> = emptyList(),
    val hands: List<HandUi> = emptyList(),
    val listenerCount: Int = 0,
    val speakerCount: Int = 0,
    val stageMaxSlots: Int = 20,
    /** Local mic publishing state (speakers/host only). */
    val micEnabled: Boolean = false,
    /** Optimistic listener raised-hand flag (cleared on promote/demote). */
    val handRaised: Boolean = false,
    /** True when the mic permission is needed but not yet granted (screen prompts). */
    val needsMicPermission: Boolean = false,
) {
    val canPublish: Boolean get() = role == AudioRole.HOST || role == AudioRole.SPEAKER
}
