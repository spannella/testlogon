package com.testlogon.android.feature.achievements

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.achievements.AchievementCatalog
import com.testlogon.android.data.achievements.AchievementsRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/** Sealed screen state for the achievements catalog. */
sealed interface AchievementsUiState {
    data object Loading : AchievementsUiState
    data class Content(
        val catalog: AchievementCatalog,
        val isRefreshing: Boolean = false,
    ) : AchievementsUiState
    data object Empty : AchievementsUiState
    data class Error(val message: String) : AchievementsUiState
}

/** One-shot effects (transient refresh-failure message). */
sealed interface AchievementsEvent {
    data class ShowError(val message: String) : AchievementsEvent
}

/**
 * AND-095 — Achievements presentation logic. A single GET-fan-out load with refresh/retry.
 *
 * Loading is shown only when there is no existing content; a refresh over content sets isRefreshing
 * without clearing the list, and a transient refresh failure keeps the current Content and emits a
 * one-shot ShowError rather than blowing the screen away. Empty catalog -> Empty; initial failure
 * with no content -> Error. One-shot effects ride a Channel + receiveAsFlow.
 */
@HiltViewModel
class AchievementsViewModel @Inject constructor(
    private val repository: AchievementsRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow<AchievementsUiState>(AchievementsUiState.Loading)
    val uiState: StateFlow<AchievementsUiState> = _uiState.asStateFlow()

    private val _events = Channel<AchievementsEvent>(Channel.BUFFERED)
    val events: Flow<AchievementsEvent> = _events.receiveAsFlow()

    init {
        load(isRefresh = false)
    }

    fun refresh() = load(isRefresh = true)

    fun retry() = load(isRefresh = false)

    private fun load(isRefresh: Boolean) {
        val current = _uiState.value
        if (current is AchievementsUiState.Content) {
            _uiState.update { current.copy(isRefreshing = true) }
        } else if (!isRefresh) {
            _uiState.value = AchievementsUiState.Loading
        }
        viewModelScope.launch {
            when (val result = repository.getCatalog()) {
                is ApiResult.Success ->
                    _uiState.value = if (result.data.isEmpty) {
                        AchievementsUiState.Empty
                    } else {
                        AchievementsUiState.Content(result.data)
                    }
                is ApiResult.Failure -> reduceFailure(result.error.message)
                is ApiResult.NetworkError -> reduceFailure(OFFLINE_MESSAGE)
            }
        }
    }

    private suspend fun reduceFailure(message: String) {
        when (val current = _uiState.value) {
            is AchievementsUiState.Content -> {
                // Keep content visible; surface a one-shot banner.
                _uiState.value = current.copy(isRefreshing = false)
                _events.send(AchievementsEvent.ShowError(message))
            }
            else -> _uiState.value = AchievementsUiState.Error(message)
        }
    }

    private companion object {
        const val OFFLINE_MESSAGE = "Couldn't reach the server. Pull down to retry."
    }
}
