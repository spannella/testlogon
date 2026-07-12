package com.testlogon.android.feature.syndicates.bundles

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Drives the [MyBundlesUiState] for the My Bundles screen (web parity: /syndicates/my-bundles).
 *
 * load() reads the caller's bundles (Loading -> Content/Empty/Error). refresh() keeps the cached list and
 * flips isStale on a non-fatal failure. cancel() POSTs a cancel; on success the row's status flips to the
 * server-returned status (access continues to period end, so it is NOT removed). No poll loop.
 */
@HiltViewModel
class MyBundlesViewModel @Inject constructor(
    private val repo: MyBundlesRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow<MyBundlesUiState>(MyBundlesUiState.Loading)
    val uiState: StateFlow<MyBundlesUiState> = _uiState.asStateFlow()

    private var loadJob: Job? = null

    init {
        load()
    }

    fun load() {
        if (loadJob?.isActive == true) return
        if (_uiState.value !is MyBundlesUiState.Content) _uiState.value = MyBundlesUiState.Loading
        fetch(isRefresh = false)
    }

    fun retry() = load()

    fun refresh() {
        if (loadJob?.isActive == true) return
        val current = _uiState.value as? MyBundlesUiState.Content
        if (current != null) _uiState.value = current.copy(isRefreshing = true)
        fetch(isRefresh = true)
    }

    private fun fetch(isRefresh: Boolean) {
        loadJob = viewModelScope.launch {
            when (val result = repo.listMyBundles()) {
                is ApiResult.Success ->
                    _uiState.value = if (result.data.isEmpty()) {
                        MyBundlesUiState.Empty
                    } else {
                        MyBundlesUiState.Content(items = result.data)
                    }
                is ApiResult.Failure -> emitFailure(isRefresh, result.error.message)
                is ApiResult.NetworkError -> emitFailure(isRefresh, OFFLINE_FALLBACK)
            }
        }
    }

    private fun emitFailure(isRefresh: Boolean, message: String) {
        val prior = _uiState.value as? MyBundlesUiState.Content
        _uiState.value = if (isRefresh && prior != null) {
            prior.copy(isRefreshing = false, isStale = true)
        } else {
            MyBundlesUiState.Error(message)
        }
    }

    fun cancel(subscriptionId: String) {
        val current = _uiState.value as? MyBundlesUiState.Content ?: return
        if (current.cancellingId != null) return
        val bundle = current.items.firstOrNull { it.subscriptionId == subscriptionId } ?: return
        _uiState.value = current.copy(cancellingId = subscriptionId, actionError = null)
        viewModelScope.launch {
            val result = repo.cancelBundle(bundle.syndicateId, subscriptionId)
            val now = _uiState.value as? MyBundlesUiState.Content ?: return@launch
            when (result) {
                is ApiResult.Success -> {
                    val updated = now.items.map {
                        if (it.subscriptionId == subscriptionId) it.copy(status = result.data) else it
                    }
                    _uiState.value = now.copy(items = updated, cancellingId = null)
                }
                is ApiResult.Failure ->
                    _uiState.value = now.copy(cancellingId = null, actionError = result.error.message)
                is ApiResult.NetworkError ->
                    _uiState.value = now.copy(cancellingId = null, actionError = OFFLINE_FALLBACK)
            }
        }
    }

    fun clearActionError() {
        val current = _uiState.value as? MyBundlesUiState.Content ?: return
        _uiState.value = current.copy(actionError = null)
    }

    private companion object {
        const val OFFLINE_FALLBACK = "Couldn't reach the server. Pull down to retry."
    }
}
