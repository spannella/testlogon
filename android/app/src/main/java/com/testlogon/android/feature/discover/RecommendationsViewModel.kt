package com.testlogon.android.feature.discover

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.discover.RecommendationItem
import com.testlogon.android.data.discover.Recommendations
import com.testlogon.android.data.discover.RecommendationsRepository
import com.testlogon.android.data.feed.PostActionsRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/** AND-184 — recommendations section state. */
sealed interface RecommendationsUiState {
    data object Loading : RecommendationsUiState
    data class Content(
        val items: List<RecommendationItem>,
        val isTrendingFallback: Boolean = false,
        val isStale: Boolean = false,
    ) : RecommendationsUiState
    data object Empty : RecommendationsUiState
    data class Error(val message: String) : RecommendationsUiState
}

/**
 * AND-184 — recommendations ("for you") presentation logic, a SIBLING of [DiscoverViewModel] scoped to
 * the same Discover entry so a recommendations failure never blocks the discover grid (FR-5). Loads the
 * flat For-You feed, maps to a section-local state, and keeps prior content visible (flagged stale) on a
 * transient failure when a cache exists.
 *
 * Not-interested feedback reuses AND-175 [PostActionsRepository]: the item is dropped locally
 * immediately and the negative signal is sent best-effort (the hide endpoint keys on the item id);
 * failures are swallowed since the local removal is the user-visible effect.
 */
@HiltViewModel
class RecommendationsViewModel @Inject constructor(
    private val repository: RecommendationsRepository,
    private val actions: PostActionsRepository,
) : ViewModel() {

    private val _state = MutableStateFlow<RecommendationsUiState>(RecommendationsUiState.Loading)
    val state: StateFlow<RecommendationsUiState> = _state.asStateFlow()

    /** Ids the user marked not-interested this session; filtered from any emission. */
    private val dismissed = MutableStateFlow<Set<String>>(emptySet())

    init {
        load()
    }

    fun retry() = load()

    private fun load() {
        if (_state.value !is RecommendationsUiState.Content) {
            _state.value = RecommendationsUiState.Loading
        }
        viewModelScope.launch {
            _state.value = repository.getRecommendations().toUiState()
        }
    }

    private fun ApiResult<Recommendations>.toUiState(): RecommendationsUiState = when (this) {
        is ApiResult.Success -> contentOrEmpty(data, stale = false)
        is ApiResult.Failure -> staleOr { RecommendationsUiState.Error(error.message) }
        is ApiResult.NetworkError -> staleOr { RecommendationsUiState.Error(OFFLINE_MESSAGE) }
    }

    private fun contentOrEmpty(recs: Recommendations, stale: Boolean): RecommendationsUiState {
        val visible = recs.items.filter { it.id !in dismissed.value }
        return if (visible.isEmpty()) {
            RecommendationsUiState.Empty
        } else {
            RecommendationsUiState.Content(
                items = visible,
                isTrendingFallback = recs.isTrendingFallback,
                isStale = stale,
            )
        }
    }

    private inline fun staleOr(terminal: () -> RecommendationsUiState): RecommendationsUiState {
        val cached = repository.cached()
        return if (cached != null && cached.items.any { it.id !in dismissed.value }) {
            contentOrEmpty(cached, stale = true)
        } else {
            terminal()
        }
    }

    /** AND-175 — remove an item and send a best-effort negative signal. */
    fun onNotInterested(itemId: String) {
        dismissed.update { it + itemId }
        _state.update { current ->
            if (current is RecommendationsUiState.Content) {
                val remaining = current.items.filter { it.id != itemId }
                if (remaining.isEmpty()) RecommendationsUiState.Empty else current.copy(items = remaining)
            } else {
                current
            }
        }
        viewModelScope.launch {
            // Best-effort: the user-visible effect is the local removal; ignore the network outcome.
            runCatching { actions.notInterested(itemId) }
        }
    }

    companion object {
        const val OFFLINE_MESSAGE = "Couldn't load recommendations."
    }
}
