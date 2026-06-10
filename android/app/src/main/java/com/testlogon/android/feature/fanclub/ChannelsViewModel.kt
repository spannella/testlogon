package com.testlogon.android.feature.fanclub

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.fanclub.FanClubChannelItem
import com.testlogon.android.data.fanclub.FanClubRepository
import com.testlogon.android.data.fanclub.FanClubTierSection
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/** AND-238 — fan-club channels-list UI state (tier-grouped sections + load/empty/error). */
sealed interface ChannelsUiState {
    data object Loading : ChannelsUiState

    data class Content(
        val sections: List<FanClubTierSection>,
        val isRefreshing: Boolean = false,
        val isStale: Boolean = false,
    ) : ChannelsUiState

    data object Empty : ChannelsUiState

    data class Error(val message: String, val retryable: Boolean) : ChannelsUiState
}

/** AND-238 — one-shot effects (Channel-delivered so rotation cannot replay them). */
sealed interface ChannelsEvent {
    /** Tapped an accessible channel — navigate to its AND-239 message thread. */
    data class NavigateToMessages(val channelId: String, val channelName: String) : ChannelsEvent

    /** Tapped a locked channel — surface the upgrade affordance (route to AND-236 subscribe browse). */
    data class ShowUpgrade(val tierId: String?, val tierName: String?) : ChannelsEvent

    /** Tapped a tier section's "members" affordance — open the AND-240 roster. */
    data class NavigateToMembers(val tierId: String, val tierName: String?) : ChannelsEvent

    /** Transient snackbar (e.g. refresh failed while content is shown). */
    data class ShowMessage(val message: String) : ChannelsEvent
}

/**
 * AND-238 — fan-club channels-list presentation logic.
 *
 * Loads a creator's channels grouped/ordered by tier with per-channel access derived in the data layer
 * (which joins AND-234 subscriptions). Distinguishes Loading/Content/Empty/Error; a refresh failure with
 * existing content keeps the list and marks it stale (+ a snackbar) instead of dropping to Error. Tapping
 * an accessible channel emits NavigateToMessages; a locked channel emits ShowUpgrade (and NEVER fetches
 * messages — the locked thread is never requested, per the spec's server-authoritative gating).
 */
@HiltViewModel
class ChannelsViewModel @Inject constructor(
    savedStateHandle: SavedStateHandle,
    private val repository: FanClubRepository,
) : ViewModel() {

    /** Optional creator scope (the More-hub self-browse passes the SELF sentinel -> own context). */
    private val creatorId: String? =
        savedStateHandle.get<String?>(ARG_CREATOR_ID)?.takeIf { it.isNotBlank() && it != SELF }

    val creatorDisplayName: String? = savedStateHandle.get<String?>(ARG_DISPLAY_NAME)

    private val _uiState = MutableStateFlow<ChannelsUiState>(ChannelsUiState.Loading)
    val uiState: StateFlow<ChannelsUiState> = _uiState.asStateFlow()

    private val _events = Channel<ChannelsEvent>(Channel.BUFFERED)
    val events: Flow<ChannelsEvent> = _events.receiveAsFlow()

    init {
        load()
    }

    fun load() {
        // Keep prior content visible on a non-refresh reload only when nothing is shown yet.
        if (_uiState.value !is ChannelsUiState.Content) _uiState.value = ChannelsUiState.Loading
        fetch(isRefresh = false)
    }

    fun refresh() {
        val current = _uiState.value
        if (current is ChannelsUiState.Content) {
            if (current.isRefreshing) return
            _uiState.value = current.copy(isRefreshing = true)
        }
        fetch(isRefresh = true)
    }

    private fun fetch(isRefresh: Boolean) {
        viewModelScope.launch {
            when (val result = repository.getChannelsByTier(creatorId)) {
                is ApiResult.Success -> {
                    val sections = result.data
                    _uiState.value =
                        if (sections.isEmpty()) ChannelsUiState.Empty
                        else ChannelsUiState.Content(sections = sections)
                }
                else -> handleFailure(result, isRefresh)
            }
        }
    }

    private suspend fun handleFailure(result: ApiResult<*>, isRefresh: Boolean) {
        val message = result.messageOrOffline()
        val current = _uiState.value
        if (current is ChannelsUiState.Content && current.sections.isNotEmpty()) {
            // Preserve content; mark stale + surface a transient error.
            _uiState.value = current.copy(isRefreshing = false, isStale = true)
            _events.send(ChannelsEvent.ShowMessage(message))
        } else {
            _uiState.value = ChannelsUiState.Error(message = message, retryable = result.isRetryable())
        }
    }

    fun onChannelClick(item: FanClubChannelItem) {
        viewModelScope.launch {
            if (item.isAccessible) {
                _events.send(
                    ChannelsEvent.NavigateToMessages(
                        channelId = item.channel.id,
                        channelName = item.channel.name,
                    ),
                )
            } else {
                val section = currentSectionFor(item)
                _events.send(
                    ChannelsEvent.ShowUpgrade(
                        tierId = section?.tier?.id,
                        tierName = section?.tier?.name,
                    ),
                )
            }
        }
    }

    fun onMembersClick(section: FanClubTierSection) {
        val tierId = section.tier?.id ?: return
        viewModelScope.launch {
            _events.send(ChannelsEvent.NavigateToMembers(tierId = tierId, tierName = section.tier.name))
        }
    }

    private fun currentSectionFor(item: FanClubChannelItem): FanClubTierSection? =
        (_uiState.value as? ChannelsUiState.Content)
            ?.sections
            ?.firstOrNull { sec -> sec.channels.any { it.channel.id == item.channel.id } }

    private fun ApiResult<*>.messageOrOffline(): String = when (this) {
        is ApiResult.Failure -> error.message
        is ApiResult.NetworkError -> OFFLINE_MESSAGE
        is ApiResult.Success -> ""
    }

    /** Network/timeout/5xx are retryable; 403/404/422 are terminal. */
    private fun ApiResult<*>.isRetryable(): Boolean = when (this) {
        is ApiResult.NetworkError -> true
        is ApiResult.Failure -> error.status >= 500 || error.status == 0
        is ApiResult.Success -> false
    }

    companion object {
        const val ARG_CREATOR_ID = "creatorId"
        const val ARG_DISPLAY_NAME = "creatorDisplayName"

        /** Sentinel creator id for the More-hub self-browse (resolved to own context server-side). */
        const val SELF = "me"
        private const val OFFLINE_MESSAGE = "You're offline"
    }
}
