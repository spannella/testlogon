package com.testlogon.android.feature.admin

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.admin.AdminRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-403 - drives the [AdminDashboardUiState] for the READ-ONLY admin alerts/dashboards screen.
 *
 * Role gating (ViewModel layer - AND-403 §4): [load] first consults the client-side [AdminRepository.isAdmin]
 * pre-check; a VERIFIED non-admin emits [AdminDashboardUiState.Forbidden] WITHOUT any network call (AC-2 /
 * TC-03). On the cookie-session client the role is UNKNOWN (no readable token) so the pre-check is permissive
 * and the BACKEND `403` is the authority: a 403 on either concurrent read also maps to Forbidden (defense in
 * depth - FR-8 / TC-04).
 *
 * The repository fetch is ATOMIC (both health reads or fail). Success with an empty dashboard -> Empty (FR-7);
 * else -> Content (FR-2). A first-load failure -> Error (FR-9); a 401-after-refresh -> Error(AUTH) "Session
 * expired" handoff (AC-7). [refresh] re-reads and, on a non-401 failure over existing Content, RETAINS the
 * last-good dashboard with isStale=true + a transient error (FR-9 / AC-6 / TC-08). There is NO poll loop and NO
 * settable seam read synchronously in init (the role check + fetch run inside the load coroutine).
 */
@HiltViewModel
class AdminDashboardViewModel @Inject constructor(
    private val repo: AdminRepository,
) : ViewModel() {

    private val _state = MutableStateFlow<AdminDashboardUiState>(AdminDashboardUiState.Loading)
    val state: StateFlow<AdminDashboardUiState> = _state.asStateFlow()

    /** Collapses concurrent load()/refresh() onto a single in-flight repository read. */
    private var loadJob: Job? = null

    init {
        load()
    }

    /** Initial load + retry. Goes through Loading and resolves to Content / Empty / Forbidden / Error. */
    fun load() {
        if (loadJob?.isActive == true) return
        _state.value = AdminDashboardUiState.Loading
        fetch(isRefresh = false)
    }

    fun retry() = load()

    /** Pull-to-refresh. On a non-401 failure the last-good Content is retained with isStale=true (FR-9). */
    fun refresh() {
        if (loadJob?.isActive == true) return
        val current = _state.value
        if (current is AdminDashboardUiState.Content) {
            _state.value = current.copy(isRefreshing = true, error = null)
        }
        fetch(isRefresh = true)
    }

    /** Clears a transient error overlaid on Content without re-fetching (FR-9). */
    fun dismissTransientError() {
        val current = _state.value
        if (current is AdminDashboardUiState.Content && current.error != null) {
            _state.value = current.copy(error = null)
        }
    }

    private fun fetch(isRefresh: Boolean) {
        loadJob = viewModelScope.launch {
            // Client-side role pre-check INSIDE the load coroutine (not synchronously in init). A verified
            // non-admin emits Forbidden with ZERO admin network calls (AC-2 / TC-03).
            if (!repo.isAdmin()) {
                _state.value = AdminDashboardUiState.Forbidden
                return@launch
            }
            when (val result = repo.loadDashboard()) {
                is ApiResult.Success -> {
                    val dashboard = result.data
                    _state.value = if (dashboard.isEmpty) {
                        AdminDashboardUiState.Empty
                    } else {
                        AdminDashboardUiState.Content(dashboard = dashboard)
                    }
                }
                is ApiResult.Failure -> reduceFailure(isRefresh, result.error.status)
                is ApiResult.NetworkError ->
                    reduceError(isRefresh, AdminUiError(AdminErrorType.NETWORK))
            }
        }
    }

    private fun reduceFailure(isRefresh: Boolean, status: Int) {
        when (status) {
            HTTP_FORBIDDEN -> _state.value = AdminDashboardUiState.Forbidden
            HTTP_UNAUTHORIZED -> reduceError(isRefresh, AdminUiError(AdminErrorType.AUTH))
            else -> reduceError(isRefresh, AdminUiError(AdminErrorType.SERVER))
        }
    }

    /** A non-403 failure: keep stale Content on a refresh that has prior data, else surface Error. */
    private fun reduceError(isRefresh: Boolean, error: AdminUiError) {
        val prior = _state.value as? AdminDashboardUiState.Content
        _state.value = if (isRefresh && prior != null) {
            prior.copy(isRefreshing = false, isStale = true, error = error)
        } else {
            AdminDashboardUiState.Error(error)
        }
    }

    private companion object {
        const val HTTP_UNAUTHORIZED = 401
        const val HTTP_FORBIDDEN = 403
    }
}
