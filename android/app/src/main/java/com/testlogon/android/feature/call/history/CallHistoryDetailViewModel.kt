package com.testlogon.android.feature.call.history

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.call.CallHistoryEntry
import com.testlogon.android.data.call.CallRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-303 — UI state for the single call-history record.
 *
 * [deleted] flips to true once the server DELETE succeeds so the route can pop back. The "Call back"
 * affordance is always disabled (see [CallHistoryDetailScreen]) because a [CallHistoryEntry] carries no
 * conversation_id and the AND-295 invite requires one (AC-2: no resolvable conversation_id => action
 * disabled, no request issued).
 */
data class CallHistoryDetailUiState(
    val isLoading: Boolean = true,
    val entry: CallHistoryEntry? = null,
    val error: String? = null,
    val isDeleting: Boolean = false,
    val deleted: Boolean = false,
)

/**
 * AND-303 — loads one history record (GET ui/calls/history/{id}) and supports deleting it
 * (DELETE ui/calls/history/{id}). Reuses the AND-295 [CallRepository]; reads callId from
 * [SavedStateHandle].
 */
@HiltViewModel
class CallHistoryDetailViewModel @Inject constructor(
    private val repo: CallRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val callId: String = checkNotNull(savedStateHandle[ARG_CALL_ID]) {
        "CallHistoryDetailViewModel requires a '$ARG_CALL_ID' nav argument"
    }

    private val _state = MutableStateFlow(CallHistoryDetailUiState())
    val state: StateFlow<CallHistoryDetailUiState> = _state.asStateFlow()

    init {
        load()
    }

    fun load() {
        _state.update { it.copy(isLoading = true, error = null) }
        viewModelScope.launch {
            when (val result = repo.detail(callId)) {
                is ApiResult.Success ->
                    _state.update { it.copy(isLoading = false, entry = result.data, error = null) }
                is ApiResult.Failure ->
                    _state.update { it.copy(isLoading = false, error = result.error.message) }
                is ApiResult.NetworkError ->
                    _state.update { it.copy(isLoading = false, error = OFFLINE) }
            }
        }
    }

    fun delete() {
        if (_state.value.isDeleting) return
        _state.update { it.copy(isDeleting = true, error = null) }
        viewModelScope.launch {
            when (val result = repo.deleteRecord(callId)) {
                is ApiResult.Success -> _state.update { it.copy(isDeleting = false, deleted = true) }
                is ApiResult.Failure ->
                    _state.update { it.copy(isDeleting = false, error = result.error.message) }
                is ApiResult.NetworkError ->
                    _state.update { it.copy(isDeleting = false, error = OFFLINE) }
            }
        }
    }

    fun dismissError() = _state.update { it.copy(error = null) }

    companion object {
        const val ARG_CALL_ID = "callId"
        private const val OFFLINE = "Couldn't reach the server. Check your connection and try again."
    }
}
