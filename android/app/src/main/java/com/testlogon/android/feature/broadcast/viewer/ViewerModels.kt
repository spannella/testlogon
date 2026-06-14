package com.testlogon.android.feature.broadcast.viewer

import com.testlogon.android.data.broadcast.BroadcastSessionStatus

/**
 * AND-280 — viewer playback domain projections + view-state.
 *
 * The mint call (POST .../playback-url) is itself the entitlement gate (AND-280 §5/§16): a 200 means
 * authorized and yields the signed HLS URL; a non-2xx means the player is not started. Session
 * live/ended state is derived from [BroadcastSessionStatus] (AND-278), not from a verify call.
 */

/** Why a broadcast can't be played, mapped to a typed, localized message. */
enum class PlaybackUnavailable { NOT_AUTHORIZED, SESSION_ENDED, NOT_STARTED, UNKNOWN }

/** Coarse session playback state derived from the AND-278 status. */
enum class SessionPlaybackState { LIVE, SCHEDULED, ENDED }

/** Maps the verified broadcast status vocabulary onto the coarse playback state. */
fun BroadcastSessionStatus.toPlaybackState(): SessionPlaybackState = when (this) {
    BroadcastSessionStatus.LIVE -> SessionPlaybackState.LIVE
    BroadcastSessionStatus.SCHEDULED,
    BroadcastSessionStatus.PROVISIONING,
    BroadcastSessionStatus.READY,
    BroadcastSessionStatus.DRAFT,
    -> SessionPlaybackState.SCHEDULED
    BroadcastSessionStatus.STOPPING,
    BroadcastSessionStatus.STOPPED,
    BroadcastSessionStatus.CANCELLED,
    BroadcastSessionStatus.ERROR,
    BroadcastSessionStatus.UNKNOWN,
    -> SessionPlaybackState.ENDED
}

/** AND-280 — the viewer screen view-state. */
sealed interface ViewerUiState {
    data object Loading : ViewerUiState
    data class Ready(
        val sessionId: String,
        val title: String,
        val playbackUrl: String,
        val expiresAtEpochMs: Long?,
        val viewerCount: Int?,
        val atLiveEdge: Boolean = true,
        val buffering: Boolean = false,
    ) : ViewerUiState

    data class Unavailable(val reason: PlaybackUnavailable) : ViewerUiState
    data class Error(val retryable: Boolean) : ViewerUiState
    data object Offline : ViewerUiState
}

/**
 * AND-286 §4 (FR-10) — one-shot viewer effects, consumed exactly once via a Channel-backed flow
 * (NEVER a StateFlow / distinctUntilChanged). Transient notices that should not be replayed on
 * recomposition or config change.
 */
sealed interface ViewerEffect {
    /** A non-fatal notice (e.g. presence/count temporarily unavailable). */
    data class Notice(val reason: ViewerNotice) : ViewerEffect
}

/** Typed, localizable reasons for a transient [ViewerEffect.Notice] (no hardcoded copy in the VM). */
enum class ViewerNotice { PRESENCE_DEGRADED }
