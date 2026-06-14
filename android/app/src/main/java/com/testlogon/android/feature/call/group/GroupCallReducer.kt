package com.testlogon.android.feature.call.group

import com.testlogon.android.data.call.group.GroupParticipant

/**
 * AND-299 — PURE (android-free) reducer folding [GroupCallEvent]s into a [GroupCallUiState].
 *
 * Fully unit-testable. Roster updates are immutable and idempotent:
 *  - [GroupCallEvent.ParticipantJoined] dedupes by userId (updates the existing entry rather than adding a
 *    duplicate).
 *  - [GroupCallEvent.ParticipantLeft] removes by userId (and clears [GroupCallUiState.activeSpeakerUserId]
 *    if that participant was the active speaker).
 *  - MediaStatusChanged / StateChanged / QualityChanged / Speaking update only the matching participant.
 *  - [GroupCallEvent.CallEnded] moves the phase to [GroupCallPhase.Ended].
 *
 * Participants are kept stable-sorted by joinedAt, then displayName, so the grid order is deterministic.
 * Speaking(true) sets the active speaker (latest wins); Speaking(false) clears it only if it was that user.
 */
object GroupCallReducer {

    fun reduce(state: GroupCallUiState, event: GroupCallEvent): GroupCallUiState = when (event) {
        is GroupCallEvent.ParticipantJoined -> state.copy(
            participants = state.participants.upsert(event.participant).sortedStable(),
        )

        is GroupCallEvent.ParticipantLeft -> state.copy(
            participants = state.participants.filterNot { it.userId == event.userId },
            activeSpeakerUserId = state.activeSpeakerUserId.takeUnless { it == event.userId },
        )

        is GroupCallEvent.MediaStatusChanged -> state.copy(
            participants = state.participants.mutate(event.userId) {
                it.copy(micMuted = event.micMuted, cameraOff = event.cameraOff)
            },
        )

        is GroupCallEvent.StateChanged -> state.copy(
            participants = state.participants.mutate(event.userId) { it.copy(state = event.state) },
        )

        is GroupCallEvent.QualityChanged -> state.copy(
            participants = state.participants.mutate(event.userId) { it.copy(quality = event.quality) },
        )

        is GroupCallEvent.Speaking -> state.copy(
            participants = state.participants.mutate(event.userId) { it.copy(speaking = event.speaking) },
            activeSpeakerUserId = when {
                event.speaking -> event.userId
                state.activeSpeakerUserId == event.userId -> null
                else -> state.activeSpeakerUserId
            },
        )

        is GroupCallEvent.CallEnded -> state.copy(
            phase = GroupCallPhase.Ended,
            error = event.reason ?: state.error,
        )
    }

    /** Insert [participant], or replace the existing entry with the same userId (idempotent join). */
    private fun List<GroupParticipant>.upsert(participant: GroupParticipant): List<GroupParticipant> =
        if (any { it.userId == participant.userId }) {
            map { if (it.userId == participant.userId) participant else it }
        } else {
            this + participant
        }

    /** Apply [transform] to the participant matching [userId]; a no-op when absent. */
    private inline fun List<GroupParticipant>.mutate(
        userId: String,
        transform: (GroupParticipant) -> GroupParticipant,
    ): List<GroupParticipant> = map { if (it.userId == userId) transform(it) else it }

    private fun List<GroupParticipant>.sortedStable(): List<GroupParticipant> =
        sortedWith(compareBy({ it.joinedAt }, { it.displayName ?: "" }, { it.userId }))
}
