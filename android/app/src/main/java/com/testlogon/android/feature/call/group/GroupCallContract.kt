package com.testlogon.android.feature.call.group

import com.testlogon.android.data.call.group.ConnQuality
import com.testlogon.android.data.call.group.GroupParticipant
import com.testlogon.android.data.call.group.ParticipantState
import com.testlogon.android.feature.call.incall.AudioRoute

/**
 * AND-299 — pure (android-free, Compose-free) UI contract for the GROUP-call screen.
 *
 * [GroupCallUiState] is the single immutable snapshot the screen renders; it merges the REAL control-plane
 * roster (create/join/leave/media) with the LOCAL, optimistic media-control state owned by the view model
 * (mic/camera/route). Native media is FLAGGED (the mesh seam returns NotConfigured) so [mediaUnavailable]
 * is surfaced and the toggles are real UI state but do not touch a real track. Kept pure/JVM-friendly so
 * [GroupCallReducer] is unit-testable; [AudioRoute] is reused from the 1:1 in-call feature.
 */
data class GroupCallUiState(
    val callId: String?,
    val phase: GroupCallPhase = GroupCallPhase.Idle,
    val participants: List<GroupParticipant> = emptyList(),
    val micEnabled: Boolean = true,
    val cameraEnabled: Boolean = true,
    val audioRoute: AudioRoute = AudioRoute.SPEAKER,
    val mediaUnavailable: Boolean = false,
    val activeSpeakerUserId: String? = null,
    // AND-300 — userId of the pinned/focused participant, or null for grid mode. Held by the view model so
    // it survives rotation; cleared automatically if the pinned participant leaves.
    val pinnedUserId: String? = null,
    val error: String? = null,
)

/** Coarse, UI-rendered group-call lifecycle. */
enum class GroupCallPhase { Idle, Creating, Joining, Active, Ending, Ended }

/** Roster/media events folded into the state by [GroupCallReducer] (from the mesh + control-plane roster). */
sealed interface GroupCallEvent {
    data class ParticipantJoined(val participant: GroupParticipant) : GroupCallEvent
    data class ParticipantLeft(val userId: String) : GroupCallEvent
    data class MediaStatusChanged(val userId: String, val micMuted: Boolean, val cameraOff: Boolean) :
        GroupCallEvent
    data class StateChanged(val userId: String, val state: ParticipantState) : GroupCallEvent
    data class QualityChanged(val userId: String, val quality: ConnQuality) : GroupCallEvent
    data class Speaking(val userId: String, val speaking: Boolean) : GroupCallEvent
    data class CallEnded(val reason: String?) : GroupCallEvent
}

/** User intents the screen forwards to the view model. */
sealed interface GroupCallAction {
    data object ToggleMic : GroupCallAction
    data object ToggleCamera : GroupCallAction
    data object CycleRoute : GroupCallAction
    data object FlipCamera : GroupCallAction
    data object Leave : GroupCallAction

    // AND-300 — pin/focus mode. Pin(userId) promotes a participant to the focus area + filmstrip; Unpin
    // returns to the equal grid.
    data class Pin(val userId: String) : GroupCallAction
    data object Unpin : GroupCallAction
}
