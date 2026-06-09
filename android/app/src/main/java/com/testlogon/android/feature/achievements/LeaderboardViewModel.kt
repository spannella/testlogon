package com.testlogon.android.feature.achievements

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.achievements.AchievementsRepository
import com.testlogon.android.data.achievements.LeaderboardEntry
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/** Sealed screen state for the achievements leaderboard. */
sealed interface LeaderboardUiState {
    data object Loading : LeaderboardUiState
    data class Content(
        val entries: List<LeaderboardEntry>,
        val me: LeaderboardEntry?,
        val isRefreshing: Boolean = false,
    ) : LeaderboardUiState
    data class Empty(val me: LeaderboardEntry?) : LeaderboardUiState
    data class Error(val message: String) : LeaderboardUiState
}

/**
 * AND-094 — leaderboard presentation logic. A single merged load (ranked list + own rank) with
 * refresh/retry. Loading shows only with no content; a refresh over content keeps the list; empty
 * entries -> Empty (own-rank bar still shown if present); failure with no content -> Error.
 */
@HiltViewModel
class LeaderboardViewModel @Inject constructor(
    private val repository: AchievementsRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow<LeaderboardUiState>(LeaderboardUiState.Loading)
    val uiState: StateFlow<LeaderboardUiState> = _uiState.asStateFlow()

    init {
        load(isRefresh = false)
    }

    fun onRefresh() = load(isRefresh = true)

    fun onRetry() = load(isRefresh = false)

    private fun load(isRefresh: Boolean) {
        val current = _uiState.value
        if (current is LeaderboardUiState.Content) {
            _uiState.update { current.copy(isRefreshing = true) }
        } else if (!isRefresh) {
            _uiState.value = LeaderboardUiState.Loading
        }
        viewModelScope.launch {
            when (val result = repository.getLeaderboard(period = DEFAULT_PERIOD)) {
                is ApiResult.Success -> {
                    val board = result.data
                    _uiState.value = if (board.entries.isEmpty()) {
                        LeaderboardUiState.Empty(board.me)
                    } else {
                        LeaderboardUiState.Content(board.entries, board.me)
                    }
                }
                is ApiResult.Failure -> reduceFailure(result.error.message)
                is ApiResult.NetworkError -> reduceFailure(OFFLINE_MESSAGE)
            }
        }
    }

    private fun reduceFailure(message: String) {
        when (val current = _uiState.value) {
            is LeaderboardUiState.Content -> _uiState.value = current.copy(isRefreshing = false)
            else -> _uiState.value = LeaderboardUiState.Error(message)
        }
    }

    private companion object {
        const val DEFAULT_PERIOD = "alltime"
        const val OFFLINE_MESSAGE = "Couldn't reach the server. Pull down to retry."
    }
}
