package com.testlogon.android.feature.watchparties

import androidx.annotation.StringRes
import com.testlogon.android.data.watchparties.WatchParty
import com.testlogon.android.data.watchparties.WatchPartyParticipant

/**
 * Render-ready state for the watch-parties LIST screen. One immutable data class (not a sealed
 * hierarchy) so content persists across refresh (show the prior [parties] while [isRefreshing]).
 * [phase] enumerates the mutually-exclusive top-level surfaces. The create form lives in its own
 * sub-state so a create error never clobbers the list surface.
 */
data class WatchPartiesListUiState(
    val phase: Phase = Phase.Loading,
    val parties: List<WatchParty> = emptyList(),
    val isRefreshing: Boolean = false,
    val isStale: Boolean = false,
    val errorMessage: String? = null,
    val create: CreateState = CreateState(),
) {
    enum class Phase { Loading, Content, Empty, SessionExpired, Error, Offline }

    /** State of the create-party form/dialog. */
    data class CreateState(
        val isSubmitting: Boolean = false,
    )
}

/** One-shot list effects (Channel-backed so they are not replayed on rotation). */
sealed interface WatchPartiesListEffect {
    data class ShowMessage(@StringRes val resId: Int) : WatchPartiesListEffect

    /** Created OK -> navigate straight into the new party's detail. */
    data class OpenParty(val partyId: String) : WatchPartiesListEffect
}

/**
 * Render-ready state for the party DETAIL screen. [party] + [participants] are the static REST state.
 * [playbackSync] is the LIVE host-authoritative playback state reconciled from the realtime event
 * stream (/messaging/events/poll); null until the first frame arrives. Join/Leave is guarded by
 * [isMutating].
 */
data class WatchPartyDetailUiState(
    val phase: Phase = Phase.Loading,
    val party: WatchParty? = null,
    val participants: List<WatchPartyParticipant> = emptyList(),
    val isMutating: Boolean = false,
    val errorMessage: String? = null,
    val playbackSync: PlaybackSyncState? = null,
) {
    enum class Phase { Loading, Content, SessionExpired, Error, Offline }

    val activeParticipants: List<WatchPartyParticipant>
        get() = participants.filter { it.isActive }

    /**
     * Live playback state pushed from the host over the realtime channel. [isPlaying] drives the
     * participant's player transport; [positionSeconds] + [positionUpdatedAtEpochSeconds] let the UI
     * extrapolate the host's *current* position (position + elapsed-since-update while playing) and
     * only re-seek when the local player drifts beyond [DRIFT_TOLERANCE_SECONDS].
     */
    data class PlaybackSyncState(
        val isPlaying: Boolean,
        val positionSeconds: Double,
        val positionUpdatedAtEpochSeconds: Long,
        val controlledBy: String,
        val lastAction: String,
        val serverTimeEpochSeconds: Long,
    ) {
        /** Host position extrapolated to [nowEpochSeconds] (advances only while playing). */
        fun targetPositionSeconds(nowEpochSeconds: Long): Double {
            if (!isPlaying) return positionSeconds
            val elapsed = (nowEpochSeconds - positionUpdatedAtEpochSeconds).coerceAtLeast(0L)
            return positionSeconds + elapsed
        }

        /** True when a local player at [localPositionSeconds] has drifted past tolerance. */
        fun shouldReseek(localPositionSeconds: Double, nowEpochSeconds: Long): Boolean =
            kotlin.math.abs(targetPositionSeconds(nowEpochSeconds) - localPositionSeconds) > DRIFT_TOLERANCE_SECONDS

        companion object {
            /** Re-seek only when the participant is more than this far from the host (avoids churn). */
            const val DRIFT_TOLERANCE_SECONDS: Double = 2.0
        }
    }
}

/** One-shot detail effects. */
sealed interface WatchPartyDetailEffect {
    data class ShowMessage(@StringRes val resId: Int) : WatchPartyDetailEffect
}
