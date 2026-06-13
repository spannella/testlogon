package com.testlogon.android.feature.groups

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.groups.Group
import com.testlogon.android.feature.groups.data.GroupsRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-355 - drives the [GroupsListUiState] for the social-groups discovery list (GET ui/groups, the
 * {groups} ENVELOPE).
 *
 * load() is the first read (Loading -> Content/Empty/Error). refresh() is the pull-to-refresh: it keeps
 * the last-cached list while the read is in flight, and on failure it RETAINS that list, surfacing a
 * non-fatal [GroupsListUiState.Content.staleError] banner instead of dropping to a terminal Error. There
 * is NO poll loop.
 */
@HiltViewModel
class GroupsListViewModel @Inject constructor(
    private val repository: GroupsRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow<GroupsListUiState>(GroupsListUiState.Loading)
    val uiState: StateFlow<GroupsListUiState> = _uiState.asStateFlow()

    init {
        load()
    }

    /** First / retry load (drops to Loading when there is no cached content). */
    fun load() {
        if (_uiState.value !is GroupsListUiState.Content) {
            _uiState.value = GroupsListUiState.Loading
        }
        viewModelScope.launch { fetch(isRefresh = false) }
    }

    /** Pull-to-refresh: keeps the cached list; a failure becomes a stale banner, not a terminal error. */
    fun refresh() {
        val cached = _uiState.value as? GroupsListUiState.Content
        if (cached != null) {
            _uiState.value = cached.copy(isRefreshing = true, staleError = null)
        }
        viewModelScope.launch { fetch(isRefresh = true) }
    }

    private suspend fun fetch(isRefresh: Boolean) {
        val cached = _uiState.value as? GroupsListUiState.Content
        when (val result = repository.listMyGroups()) {
            is ApiResult.Success -> _uiState.value = reduceSuccess(result.data)
            is ApiResult.Failure -> _uiState.value = reduceFailure(result.error, isRefresh, cached)
            is ApiResult.NetworkError ->
                _uiState.value = reduceFailure(networkError(), isRefresh, cached)
        }
    }

    private fun reduceSuccess(groups: List<Group>): GroupsListUiState =
        if (groups.isEmpty()) {
            GroupsListUiState.Empty
        } else {
            GroupsListUiState.Content(groups = groups, isRefreshing = false, staleError = null)
        }

    private fun reduceFailure(
        error: ApiError,
        isRefresh: Boolean,
        cached: GroupsListUiState.Content?,
    ): GroupsListUiState =
        // On a pull-to-refresh failure keep the cached list with a stale banner; a cache-less / first-load
        // failure is terminal.
        if (isRefresh && cached != null) {
            cached.copy(isRefreshing = false, staleError = error)
        } else {
            GroupsListUiState.Error(error)
        }

    private fun networkError(): ApiError =
        ApiError(status = ApiError.STATUS_NETWORK, message = OFFLINE_FALLBACK)

    private companion object {
        const val OFFLINE_FALLBACK = "Couldn't reach the server. Pull down to retry."
    }
}
