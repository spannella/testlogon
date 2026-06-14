package com.testlogon.android.feature.calendar.scheduler

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.scheduler.ActionStatuses
import com.testlogon.android.data.scheduler.ScheduledAction
import com.testlogon.android.data.scheduler.SchedulerRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-275 — drives the list of scheduled actions (GET /ui/scheduler/actions), with cancel (DELETE) and a
 * reschedule hand-off (navigates to the edit sheet). Cancel is offered only for `pending` actions (web
 * guard); on success the list refreshes.
 */
sealed interface SchedulerListUiState {
    data object Loading : SchedulerListUiState
    data object Empty : SchedulerListUiState
    data class Error(val message: String, val isOffline: Boolean) : SchedulerListUiState
    data class Content(
        val actions: List<ScheduledAction>,
        val cancellingId: String? = null,
    ) : SchedulerListUiState
}

@HiltViewModel
class SchedulerListViewModel @Inject constructor(
    private val repo: SchedulerRepository,
) : ViewModel() {

    private val _state = MutableStateFlow<SchedulerListUiState>(SchedulerListUiState.Loading)
    val state: StateFlow<SchedulerListUiState> = _state.asStateFlow()

    init {
        load()
    }

    fun retry() = load()

    private fun load() {
        _state.value = SchedulerListUiState.Loading
        viewModelScope.launch {
            _state.value = when (val r = repo.listActions()) {
                is ApiResult.Success ->
                    if (r.data.isEmpty()) {
                        SchedulerListUiState.Empty
                    } else {
                        SchedulerListUiState.Content(r.data)
                    }
                is ApiResult.Failure -> SchedulerListUiState.Error(r.error.message, false)
                is ApiResult.NetworkError -> SchedulerListUiState.Error(OFFLINE_MESSAGE, true)
            }
        }
    }

    fun onCancel(actionId: String) {
        val content = _state.value as? SchedulerListUiState.Content ?: return
        if (content.cancellingId != null) return
        _state.value = content.copy(cancellingId = actionId)
        viewModelScope.launch {
            when (repo.cancel(actionId)) {
                is ApiResult.Success -> load()
                is ApiResult.Failure, is ApiResult.NetworkError ->
                    _state.value = content.copy(cancellingId = null)
            }
        }
    }

    /** Whether the cancel affordance should show for [action] (pending only). */
    fun canCancel(action: ScheduledAction): Boolean = action.status == ActionStatuses.PENDING

    private companion object {
        const val OFFLINE_MESSAGE = "Couldn't reach the server. Try again."
    }
}
