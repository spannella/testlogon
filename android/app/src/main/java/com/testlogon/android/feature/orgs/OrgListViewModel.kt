package com.testlogon.android.feature.orgs

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.orgs.Org
import com.testlogon.android.feature.orgs.data.OrgsRepository
import com.testlogon.android.feature.orgs.data.SelectedOrgStore
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-361 - drives the single [OrgListUiState] for the caller's ORGANIZATIONS LIST screen (FR-1).
 *
 * load() reads listOrgs (GET ui/orgs) and reduces to: [OrgListUiState.Content] (one or more orgs),
 * [OrgListUiState.Empty] (the read succeeded but the caller belongs to NO org - DISTINCT from an error),
 * or [OrgListUiState.Error] (a terminal read failure). refresh() re-reads while keeping the current list
 * visible (isRefreshing) and, on a refresh failure, KEEPS the shown content rather than dropping to Error;
 * retry() is the from-Error re-attempt (goes back through Loading).
 *
 * REUSE: this is the genuinely-missing LIST state-holder over the existing [OrgsRepository] (AND-353). The
 * single-org OVERVIEW hub is OrgOverviewViewModel [AND-354] and is NOT duplicated here. select(orgId) is an
 * optional convenience that persists the chosen org via the existing [SelectedOrgStore] (AND-353) so the
 * overview / members screens open on it - it performs NO network call.
 *
 * One StateFlow only; there are no one-shot effects for this read-only list (navigation is driven by the
 * screen from the selected id). There is NO poll loop.
 */
@HiltViewModel
class OrgListViewModel @Inject constructor(
    private val repository: OrgsRepository,
    private val selectedOrgStore: SelectedOrgStore,
) : ViewModel() {

    private val _uiState = MutableStateFlow<OrgListUiState>(OrgListUiState.Loading)
    val uiState: StateFlow<OrgListUiState> = _uiState.asStateFlow()

    init {
        load()
    }

    /** First load (or re-attempt with no content): goes through Loading and resolves Content/Empty/Error. */
    fun load() {
        _uiState.value = OrgListUiState.Loading
        fetch()
    }

    /** Pull-to-refresh: keeps the current list visible (isRefreshing) and keeps it on a refresh failure. */
    fun refresh() {
        val content = _uiState.value as? OrgListUiState.Content
        if (content != null) _uiState.value = content.copy(isRefreshing = true)
        fetch()
    }

    /** Re-attempts after a terminal [OrgListUiState.Error] (returns through Loading). */
    fun retry() = load()

    /**
     * Persists [orgId] as the caller's selected org via the existing [SelectedOrgStore] (AND-353) so the
     * overview / members screens open on it. No-op for a blank id; performs NO network call.
     */
    fun select(orgId: String) {
        if (orgId.isBlank()) return
        viewModelScope.launch { selectedOrgStore.setSelectedOrgId(orgId) }
    }

    private fun fetch() {
        viewModelScope.launch {
            _uiState.value = when (val result = repository.listOrgs()) {
                is ApiResult.Success -> reduceSuccess(result.data)
                is ApiResult.Failure -> reduceFailure(result.error)
                is ApiResult.NetworkError -> reduceFailure(networkError())
            }
        }
    }

    private fun reduceSuccess(orgs: List<Org>): OrgListUiState =
        if (orgs.isEmpty()) OrgListUiState.Empty else OrgListUiState.Content(orgs = orgs)

    private fun reduceFailure(error: ApiError): OrgListUiState {
        // A refresh failure keeps the already-shown list (clears the refreshing flag); only a failure with
        // no content in hand is terminal (Empty / Loading have no content to preserve).
        val content = _uiState.value as? OrgListUiState.Content
        return content?.copy(isRefreshing = false) ?: OrgListUiState.Error(error)
    }

    private fun networkError(): ApiError =
        ApiError(status = ApiError.STATUS_NETWORK, message = OFFLINE_FALLBACK)

    private companion object {
        const val OFFLINE_FALLBACK = "Couldn't reach the server. Pull down to retry."
    }
}
