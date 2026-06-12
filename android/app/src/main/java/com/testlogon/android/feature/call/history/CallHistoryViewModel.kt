package com.testlogon.android.feature.call.history

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

/** AND-295/AND-296 — UI state for the call-history list. */
data class CallHistoryUiState(
    val isLoading: Boolean = false,
    val entries: List<CallHistoryEntry> = emptyList(),
    val nextCursor: String? = null,
    val error: String? = null,
    val loaded: Boolean = false,
) {
    val canLoadMore: Boolean get() = nextCursor != null && !isLoading
}

/**
 * AND-296 — lists call history (GET /ui/calls/history) with cursor pagination. Reuses the AND-295
 * [CallRepository.history]; standard @HiltViewModel + StateFlow<UiState> pattern.
 */
@HiltViewModel
class CallHistoryViewModel @Inject constructor(
    private val repo: CallRepository,
) : ViewModel() {

    private val _state = MutableStateFlow(CallHistoryUiState())
    val state: StateFlow<CallHistoryUiState> = _state.asStateFlow()

    init {
        load()
    }

    fun load() {
        if (_state.value.isLoading) return
        _state.update { it.copy(isLoading = true, error = null) }
        viewModelScope.launch {
            when (val result = repo.history(cursor = null, limit = PAGE_SIZE)) {
                is ApiResult.Success -> _state.update {
                    it.copy(
                        isLoading = false,
                        entries = result.data.entries,
                        nextCursor = result.data.nextCursor,
                        loaded = true,
                        error = null,
                    )
                }
                is ApiResult.Failure -> _state.update {
                    it.copy(isLoading = false, error = result.error.message, loaded = true)
                }
                is ApiResult.NetworkError -> _state.update {
                    it.copy(isLoading = false, error = OFFLINE, loaded = true)
                }
            }
        }
    }

    fun loadMore() {
        val cursor = _state.value.nextCursor ?: return
        if (_state.value.isLoading) return
        _state.update { it.copy(isLoading = true) }
        viewModelScope.launch {
            when (val result = repo.history(cursor = cursor, limit = PAGE_SIZE)) {
                is ApiResult.Success -> _state.update {
                    it.copy(
                        isLoading = false,
                        entries = it.entries + result.data.entries,
                        nextCursor = result.data.nextCursor,
                    )
                }
                is ApiResult.Failure -> _state.update { it.copy(isLoading = false, error = result.error.message) }
                is ApiResult.NetworkError -> _state.update { it.copy(isLoading = false, error = OFFLINE) }
            }
        }
    }

    fun dismissError() = _state.update { it.copy(error = null) }

    private companion object {
        const val PAGE_SIZE = 20
        const val OFFLINE = "Couldn't reach the server. Check your connection and try again."
    }
}
