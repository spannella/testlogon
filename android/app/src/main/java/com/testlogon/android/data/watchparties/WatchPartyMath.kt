package com.testlogon.android.data.watchparties

/**
 * Framework-free watch-party control math: host-permission gating and playback-position sync.
 *
 * Kept dependency-free (pure Kotlin, no Android/coroutines) so it is JVM-unit-testable and so the
 * ViewModel and Composables can share ONE source of truth for "may I drive playback?" and "where
 * should the participant's player be right now?". Mirrors the backend contract:
 *   - control is restricted to host / co-host (control_playback in app/services/watch_party.py),
 *   - co-host grant + kick are host-only,
 *   - position is host-authoritative and extrapolates while playing (position + elapsed).
 *
 * All times are epoch-SECONDS to match the DTOs.
 */
object WatchPartyMath {

    /** Re-seek a participant's local player only when drift exceeds this (avoids seek churn). */
    const val DRIFT_TOLERANCE_SECONDS: Double = 2.0

    /** The backend accepts exactly these playback actions (PlaybackControlIn pattern). */
    val VALID_ACTIONS: Set<String> = setOf("play", "pause", "seek")

    /** True when [userSub] is the party host. */
    fun isHost(party: WatchParty, userSub: String?): Boolean =
        !userSub.isNullOrBlank() && party.hostUserSub == userSub

    /**
     * True when [userSub] may DRIVE playback (play/pause/seek): the host, or an ACTIVE co-host
     * participant. A blank/unknown user or a non-participant is never allowed.
     */
    fun canControlPlayback(
        party: WatchParty,
        participants: List<WatchPartyParticipant>,
        userSub: String?,
    ): Boolean {
        if (userSub.isNullOrBlank()) return false
        if (party.isEnded) return false
        if (isHost(party, userSub)) return true
        return participants.any {
            it.userSub == userSub && it.isActive && it.role == ParticipantRole.CO_HOST
        }
    }

    /**
     * True when [userSub] may perform HOST-ONLY moderation (grant co-host, kick, end). Only the host,
     * and only while the party is live.
     */
    fun canManageParty(party: WatchParty, userSub: String?): Boolean =
        !party.isEnded && isHost(party, userSub)

    /**
     * Whether a specific [target] participant is a valid kick / co-host target for [actorSub]. The
     * actor must be the host; the target must be an ACTIVE participant who is neither the host nor
     * the actor themselves.
     */
    fun canTargetParticipant(
        party: WatchParty,
        actorSub: String?,
        target: WatchPartyParticipant,
    ): Boolean {
        if (!canManageParty(party, actorSub)) return false
        if (!target.isActive) return false
        if (target.role == ParticipantRole.HOST) return false
        if (target.userSub == party.hostUserSub) return false
        if (target.userSub == actorSub) return false
        return true
    }

    /** A target is eligible to be PROMOTED to co-host only if not already one (and kick-eligible). */
    fun canPromoteToCoHost(
        party: WatchParty,
        actorSub: String?,
        target: WatchPartyParticipant,
    ): Boolean = canTargetParticipant(party, actorSub, target) && target.role != ParticipantRole.CO_HOST

    /** Normalises a requested action to a valid backend action, or null when unsupported. */
    fun normalizeAction(action: String): String? =
        action.trim().lowercase().takeIf { it in VALID_ACTIONS }

    /**
     * The host-authoritative position at [nowEpochSeconds], extrapolated from the last update. While
     * playing the position advances by the wall-clock elapsed since [positionUpdatedAtEpochSeconds];
     * while paused it is frozen. Never negative.
     */
    fun targetPositionSeconds(
        positionSeconds: Double,
        positionUpdatedAtEpochSeconds: Long,
        isPlaying: Boolean,
        nowEpochSeconds: Long,
    ): Double {
        if (!isPlaying) return positionSeconds.coerceAtLeast(0.0)
        val elapsed = (nowEpochSeconds - positionUpdatedAtEpochSeconds).coerceAtLeast(0L)
        return (positionSeconds + elapsed).coerceAtLeast(0.0)
    }

    /**
     * True when a local player at [localPositionSeconds] has drifted past [DRIFT_TOLERANCE_SECONDS]
     * from the extrapolated host position and should re-seek.
     */
    fun shouldReseek(
        hostPositionSeconds: Double,
        hostPositionUpdatedAtEpochSeconds: Long,
        hostIsPlaying: Boolean,
        localPositionSeconds: Double,
        nowEpochSeconds: Long,
    ): Boolean {
        val target = targetPositionSeconds(
            hostPositionSeconds,
            hostPositionUpdatedAtEpochSeconds,
            hostIsPlaying,
            nowEpochSeconds,
        )
        return kotlin.math.abs(target - localPositionSeconds) > DRIFT_TOLERANCE_SECONDS
    }

    /** Formats a position (seconds) as m:ss / h:mm:ss for display. Negatives clamp to 0. */
    fun formatClock(seconds: Double): String {
        val total = seconds.coerceAtLeast(0.0).toLong()
        val h = total / 3600
        val m = (total % 3600) / 60
        val s = total % 60
        return if (h > 0) "%d:%02d:%02d".format(h, m, s) else "%d:%02d".format(m, s)
    }
}
