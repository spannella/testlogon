package com.testlogon.android.feature.boost.manage

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.boost.data.BoostRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import javax.inject.Inject

/**
 * Presentation logic for the BOOST LIST screen (web parity: ContentBoostPage.tsx list section).
 *
 * On init, loads the caller's boosts via the existing [BoostRepository.listBoosts]. A manual refresh reloads
 * the list (used after returning from the detail screen where a boost may have been cancelled). READ-only;
 * creating a boost stays in the existing per-post BoostScreen flow (BoostViewModel). No polling loop.
 *
 * Dispatcher seam: ioDispatcher defaults to IO and is read inside coroutines so a test can swap it.
 */
@HiltViewModel
class BoostListViewModel @Inject constructor(
    private val repository: BoostRepository,
) : ViewModel() {

    var ioDispatcher: CoroutineDispatcher = Dispatchers.IO

    private val _uiState = MutableStateFlow<BoostListUiState>(BoostListUiState.Loading)
    val uiState: StateFlow<BoostListUiState> = _uiState.asStateFlow()

    init {
        load()
    }

    fun load() {
        _uiState.value = BoostListUiState.Loading
        viewModelScope.launch { fetch() }
    }

    fun refresh() {
        val content = _uiState.value as? BoostListUiState.Content ?: return load()
        if (content.refreshing) return
        _uiState.value = content.copy(refreshing = true)
        viewModelScope.launch { fetch() }
    }

    fun onRetry() = load()

    private suspend fun fetch() {
        when (val r = withContext(ioDispatcher) { repository.listBoosts() }) {
            // De-dup by boostId (a lenient backend may return duplicate rows for the same boost);
            // distinctBy keeps the first occurrence and prevents a duplicate-key LazyColumn crash.
            is ApiResult.Success -> _uiState.value =
                BoostListUiState.Content(boosts = r.data.distinctBy { it.boostId })
            is ApiResult.Failure -> _uiState.value = BoostListUiState.Error(r.error)
            is ApiResult.NetworkError ->
                _uiState.value = BoostListUiState.Error(
                    com.testlogon.android.core.model.ApiError(
                        status = com.testlogon.android.core.model.ApiError.STATUS_NETWORK,
                        message = "Could not reach the server. Try again.",
                    ),
                )
        }
    }
}
