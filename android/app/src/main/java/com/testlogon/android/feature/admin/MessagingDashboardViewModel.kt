package com.testlogon.android.feature.admin

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.admin.DashboardChannel
import com.testlogon.android.data.admin.MessagingDashboardRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/** AND-404 - the nav arg that selects the channel ("email" / "sms") for [MessagingDashboardViewModel]. */
const val ARG_DASHBOARD_CHANNEL = "channel"

/**
 * AND-404 - drives the [MessagingDashboardUiState] for ONE read-only delivery dashboard (email OR sms).
 *
 * The [channel] arrives as a nav arg via [SavedStateHandle] (survives process death) and selects the stats +
 * deliveries endpoint pair in the repository - a single generic VM serves both screens (AND-404 §4, no
 * duplication). Following the established AND-403 admin pattern (plain @HiltViewModel @Inject, NOT
 * assisted-inject), role gating runs INSIDE the load coroutine: a verified non-admin emits [Forbidden] with
 * ZERO admin network calls (AC5 / TC-14); on the cookie client the role is UNKNOWN so the BACKEND `403` is the
 * authority and also maps to Forbidden (FR6). There is NO poll loop and NO settable seam read synchronously in
 * init (the role check + fetch run inside the load coroutine).
 *
 * Success with an empty dashboard -> Empty (FR4); else -> Content. A first-load failure -> Error (FR4); a
 * persistent 401 -> Error(AUTH). [refresh] re-reads and, on a non-401 failure over existing Content, RETAINS the
 * last-good dashboard with isStale=true + a transient error (the offline-stale path, §7 / TC-04).
 */
@HiltViewModel
class MessagingDashboardViewModel @Inject constructor(
    private val repo: MessagingDashboardRepository,
    savedState: SavedStateHandle,
) : ViewModel() {

    val channel: DashboardChannel =
        parseChannel(savedState[ARG_DASHBOARD_CHANNEL])

    private val _state = MutableStateFlow<MessagingDashboardUiState>(MessagingDashboardUiState.Loading)
    val state: StateFlow<MessagingDashboardUiState> = _state.asStateFlow()

    /** Collapses concurrent load()/refresh() onto a single in-flight repository read. */
    private var loadJob: Job? = null

    init {
        load()
    }

    /** Initial load + retry. Goes through Loading and resolves to Content / Empty / Forbidden / Error. */
    fun load() {
        if (loadJob?.isActive == true) return
        _state.value = MessagingDashboardUiState.Loading
        fetch(isRefresh = false)
    }

    fun retry() = load()

    /** Pull-to-refresh. On a non-401 failure the last-good Content is retained with isStale=true (§7). */
    fun refresh() {
        if (loadJob?.isActive == true) return
        val current = _state.value
        if (current is MessagingDashboardUiState.Content) {
            _state.value = current.copy(isRefreshing = true, error = null)
        }
        fetch(isRefresh = true)
    }

    /** Clears a transient error overlaid on Content without re-fetching. */
    fun dismissTransientError() {
        val current = _state.value
        if (current is MessagingDashboardUiState.Content && current.error != null) {
            _state.value = current.copy(error = null)
        }
    }

    private fun fetch(isRefresh: Boolean) {
        loadJob = viewModelScope.launch {
            // Client-side role pre-check INSIDE the load coroutine. A verified non-admin emits Forbidden with
            // ZERO admin network calls (AC5 / TC-14).
            if (!repo.isAdmin()) {
                _state.value = MessagingDashboardUiState.Forbidden
                return@launch
            }
            when (val result = repo.dashboard(channel)) {
                is ApiResult.Success -> {
                    val dashboard = result.data
                    _state.value = if (dashboard.isEmpty) {
                        MessagingDashboardUiState.Empty
                    } else {
                        MessagingDashboardUiState.Content(dashboard = dashboard)
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
            HTTP_FORBIDDEN -> _state.value = MessagingDashboardUiState.Forbidden
            HTTP_UNAUTHORIZED -> reduceError(isRefresh, AdminUiError(AdminErrorType.AUTH))
            else -> reduceError(isRefresh, AdminUiError(AdminErrorType.SERVER))
        }
    }

    /** A non-403 failure: keep stale Content on a refresh that has prior data, else surface Error. */
    private fun reduceError(isRefresh: Boolean, error: AdminUiError) {
        val prior = _state.value as? MessagingDashboardUiState.Content
        _state.value = if (isRefresh && prior != null) {
            prior.copy(isRefreshing = false, isStale = true, error = error)
        } else {
            MessagingDashboardUiState.Error(error)
        }
    }

    private companion object {
        const val HTTP_UNAUTHORIZED = 401
        const val HTTP_FORBIDDEN = 403

        /** Maps the nav-arg string to a [DashboardChannel]; defaults to EMAIL on an unknown/absent value. */
        fun parseChannel(raw: String?): DashboardChannel =
            if (raw?.equals("sms", ignoreCase = true) == true) DashboardChannel.SMS else DashboardChannel.EMAIL
    }
}
