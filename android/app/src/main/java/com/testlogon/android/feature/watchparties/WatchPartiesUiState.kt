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
 * Render-ready state for the party DETAIL screen. [party] + [participants] are the static REST state;
 * live playback sync is out of scope (the screen shows an honest note). Join/Leave is guarded by
 * [isMutating].
 */
data class WatchPartyDetailUiState(
    val phase: Phase = Phase.Loading,
    val party: WatchParty? = null,
    val participants: List<WatchPartyParticipant> = emptyList(),
    val isMutating: Boolean = false,
    val errorMessage: String? = null,
) {
    enum class Phase { Loading, Content, SessionExpired, Error, Offline }

    val activeParticipants: List<WatchPartyParticipant>
        get() = participants.filter { it.isActive }
}

/** One-shot detail effects. */
sealed interface WatchPartyDetailEffect {
    data class ShowMessage(@StringRes val resId: Int) : WatchPartyDetailEffect
}
