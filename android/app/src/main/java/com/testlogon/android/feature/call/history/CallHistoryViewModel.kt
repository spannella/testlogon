package com.testlogon.android.feature.call.history

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.call.CallHistoryEntry
import com.testlogon.android.data.call.CallRepository
import com.testlogon.android.data.call.CallStats
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-295/AND-296/AND-303 — UI state for the call-history list.
 *
 * AND-303 distinguishes three failure surfaces so the screen can react differently:
 * - [refreshError]: the first/refresh load failed while no rows are shown -> full-screen ErrorState.
 * - [appendError]: a [CallHistoryViewModel.loadMore] page failed -> inline footer "retry" (rows kept).
 * - [error]: the legacy generic field (kept for source compatibility); mirrors whichever surface is active.
 * [isEmpty] is loaded-but-no-rows. [stats] is a best-effort header card (failure-silent).
 */
data class CallHistoryUiState(
    val isLoading: Boolean = false,
    val isRefreshing: Boolean = false,
    val entries: List<CallHistoryEntry> = emptyList(),
    val nextCursor: String? = null,
    val error: String? = null,
    val refreshError: String? = null,
    val appendError: String? = null,
    val loaded: Boolean = false,
    val stats: CallStats? = null,
) {
    val canLoadMore: Boolean get() = nextCursor != null && !isLoading
    val isEmpty: Boolean get() = loaded && entries.isEmpty()
}

/**
 * AND-296/AND-303 — lists call history (GET ui/calls/history) with MANUAL cursor pagination (NOT
 * androidx.paging), pull-to-refresh, optimistic delete, and a best-effort stats header. Reuses the
 * AND-295 [CallRepository]; standard @HiltViewModel + StateFlow of UiState pattern.
 */
@HiltViewModel
class CallHistoryViewModel @Inject constructor(
    private val repo: CallRepository,
) : ViewModel() {

    private val _state = MutableStateFlow(CallHistoryUiState())
    val state: StateFlow<CallHistoryUiState> = _state.asStateFlow()

    init {
        load()
        loadStats()
    }

    /** First (cursor=null) load. Failure shows full-screen when no rows are present. */
    fun load() {
        if (_state.value.isLoading) return
        _state.update { it.copy(isLoading = true, error = null, refreshError = null) }
        viewModelScope.launch {
            when (val result = repo.history(cursor = null, limit = PAGE_SIZE)) {
                is ApiResult.Success -> _state.update {
                    it.copy(
                        isLoading = false,
                        entries = result.data.entries,
                        nextCursor = result.data.nextCursor,
                        loaded = true,
                        error = null,
                        refreshError = null,
                    )
                }
                is ApiResult.Failure -> applyLoadError(result.error.message)
                is ApiResult.NetworkError -> applyLoadError(OFFLINE)
            }
        }
    }

    /** Pull-to-refresh: re-fetch from cursor=null and REPLACE entries in one update. */
    fun refresh() {
        if (_state.value.isRefreshing) return
        _state.update { it.copy(isRefreshing = true, appendError = null) }
        loadStats()
        viewModelScope.launch {
            when (val result = repo.history(cursor = null, limit = PAGE_SIZE)) {
                is ApiResult.Success -> _state.update {
                    it.copy(
                        isRefreshing = false,
                        entries = result.data.entries,
                        nextCursor = result.data.nextCursor,
                        loaded = true,
                        error = null,
                        refreshError = null,
                    )
                }
                is ApiResult.Failure -> applyRefreshError(result.error.message)
                is ApiResult.NetworkError -> applyRefreshError(OFFLINE)
            }
        }
    }

    /** Append the next cursor page; stops when next_cursor == null. Failure shows a footer retry. */
    fun loadMore() {
        val cursor = _state.value.nextCursor ?: return
        if (_state.value.isLoading) return
        _state.update { it.copy(isLoading = true, appendError = null) }
        viewModelScope.launch {
            when (val result = repo.history(cursor = cursor, limit = PAGE_SIZE)) {
                is ApiResult.Success -> _state.update {
                    it.copy(
                        isLoading = false,
                        entries = it.entries + result.data.entries,
                        nextCursor = result.data.nextCursor,
                    )
                }
                is ApiResult.Failure -> applyAppendError(result.error.message)
                is ApiResult.NetworkError -> applyAppendError(OFFLINE)
            }
        }
    }

    /** Retry only the failed append page (keeps existing rows). */
    fun retryLoadMore() {
        _state.update { it.copy(appendError = null) }
        loadMore()
    }

    /**
     * Optimistically remove [callId] from the list, then DELETE on the server. On failure the row is
     * restored at its original index and an error is surfaced.
     */
    fun delete(callId: String) {
        val before = _state.value.entries
        val index = before.indexOfFirst { it.callId == callId }
        if (index < 0) return
        val removed = before[index]
        _state.update { it.copy(entries = before.filterNot { e -> e.callId == callId }, error = null) }
        viewModelScope.launch {
            when (val result = repo.deleteRecord(callId)) {
                is ApiResult.Success -> Unit // already removed
                is ApiResult.Failure -> restoreAfterFailedDelete(index, removed, result.error.message)
                is ApiResult.NetworkError -> restoreAfterFailedDelete(index, removed, OFFLINE)
            }
        }
    }

    fun dismissError() = _state.update { it.copy(error = null, appendError = null) }

    /** Best-effort stats for the header card; failure is swallowed (no error surfaced). */
    private fun loadStats() {
        viewModelScope.launch {
            val result = repo.stats()
            if (result is ApiResult.Success) {
                _state.update { it.copy(stats = result.data) }
            }
        }
    }

    private fun restoreAfterFailedDelete(index: Int, entry: CallHistoryEntry, message: String?) {
        _state.update {
            val restored = it.entries.toMutableList()
            val at = index.coerceIn(0, restored.size)
            restored.add(at, entry)
            it.copy(entries = restored, error = message)
        }
    }

    private fun applyLoadError(message: String?) = _state.update {
        // No rows yet -> full-screen refreshError; rows present -> generic error only.
        if (it.entries.isEmpty()) {
            it.copy(isLoading = false, loaded = true, error = message, refreshError = message)
        } else {
            it.copy(isLoading = false, loaded = true, error = message)
        }
    }

    private fun applyRefreshError(message: String?) = _state.update {
        if (it.entries.isEmpty()) {
            it.copy(isRefreshing = false, loaded = true, error = message, refreshError = message)
        } else {
            it.copy(isRefreshing = false, loaded = true, error = message)
        }
    }

    private fun applyAppendError(message: String?) = _state.update {
        it.copy(isLoading = false, appendError = message, error = message)
    }

    private companion object {
        const val PAGE_SIZE = 20
        const val OFFLINE = "Couldn't reach the server. Check your connection and try again."
    }
}
