package com.testlogon.android.feature.messaging.helpdesk

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.messaging.helpdesk.HelpdeskQueueItem
import com.testlogon.android.data.messaging.helpdesk.HelpdeskRepository
import com.testlogon.android.data.messaging.helpdesk.HelpdeskRepositoryImpl
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-161 — helpdesk queue UI state. The agent-role check IS the queue call (200 ⇒ agent, 403 ⇒ not):
 * there is no readable role field, so [NotAuthorized] is the 403 outcome.
 */
sealed interface HelpdeskQueueUiState {
    data object Loading : HelpdeskQueueUiState
    data object NotAuthorized : HelpdeskQueueUiState
    data class Ready(
        val items: List<HelpdeskQueueItem>,
        val isRefreshing: Boolean = false,
    ) : HelpdeskQueueUiState
    data class Error(val message: String, val retryable: Boolean) : HelpdeskQueueUiState
}

/**
 * AND-161 — helpdesk queue presentation logic. Single bounded fetch (no Paging). On init / refresh /
 * retry it calls [HelpdeskRepository.loadQueue], mapping: Success([]) -> Ready([]) (empty),
 * Success(list) -> Ready(list), 403 Failure -> NotAuthorized, other errors -> Error.
 */
@HiltViewModel
class HelpdeskQueueViewModel @Inject constructor(
    private val repository: HelpdeskRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow<HelpdeskQueueUiState>(HelpdeskQueueUiState.Loading)
    val uiState: StateFlow<HelpdeskQueueUiState> = _uiState.asStateFlow()

    init {
        load(isRefresh = false)
    }

    fun refresh() {
        // Keep showing existing rows under a refreshing flag where possible.
        val current = _uiState.value
        if (current is HelpdeskQueueUiState.Ready) {
            _uiState.update { current.copy(isRefreshing = true) }
        }
        load(isRefresh = true)
    }

    fun retry() = load(isRefresh = false)

    private fun load(isRefresh: Boolean) {
        if (!isRefresh) _uiState.value = HelpdeskQueueUiState.Loading
        viewModelScope.launch {
            _uiState.value = when (val r = repository.loadQueue()) {
                is ApiResult.Success -> HelpdeskQueueUiState.Ready(items = r.data, isRefreshing = false)
                is ApiResult.Failure ->
                    if (r.error.status == HelpdeskRepositoryImpl.HTTP_FORBIDDEN) {
                        HelpdeskQueueUiState.NotAuthorized
                    } else {
                        HelpdeskQueueUiState.Error(message = r.error.message, retryable = true)
                    }
                is ApiResult.NetworkError ->
                    HelpdeskQueueUiState.Error(message = OFFLINE_MESSAGE, retryable = true)
            }
        }
    }

    companion object {
        const val OFFLINE_MESSAGE = "You're offline. Try again when you're back online."
    }
}
