package com.testlogon.android.feature.orgs

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.orgs.Org
import com.testlogon.android.core.model.orgs.OrgRole
import kotlinx.coroutines.channels.Channel
import com.testlogon.android.feature.orgs.data.OrgsRepository
import com.testlogon.android.feature.orgs.data.SelectedOrgStore
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-354 - drives the [OrgOverviewUiState] for the org OVERVIEW hub screen.
 *
 * The overview is DERIVED client-side (there is NO GET ui/orgs/{orgId} detail endpoint): load(orgId)
 * resolves the active org id (the explicit arg, else the SELECTED org from DataStore, defaulting to the
 * caller's PRIMARY org = the first listOrgs entry), finds the matching OrgOut row in listOrgs (which also
 * carries the caller's role), and counts members via listMembers().size.
 *
 * Resilience (FR-9): if a reload fails while [OrgOverviewUiState.Content] is already showing, the prior
 * content is KEPT with isStale = true (a stale banner) instead of dropping to a terminal Error. A first
 * load with no cache surfaces Empty (no orgs) or Error.
 */
/**
 * PAR-35(b) - one-shot effects from the org overview (leave outcome). [Left] pops back to the caller;
 * [Message] surfaces a snackbar (e.g. sole-owner rejection, failure).
 */
sealed interface OrgOverviewEvent {
    data object Left : OrgOverviewEvent
    data class Message(val text: String) : OrgOverviewEvent
}

@HiltViewModel
class OrgOverviewViewModel @Inject constructor(
    private val repository: OrgsRepository,
    private val selectedOrgStore: SelectedOrgStore,
) : ViewModel() {

    private val _uiState = MutableStateFlow<OrgOverviewUiState>(OrgOverviewUiState.Loading)
    val uiState: StateFlow<OrgOverviewUiState> = _uiState.asStateFlow()

    private val _leaving = MutableStateFlow(false)
    val leaving: StateFlow<Boolean> = _leaving.asStateFlow()

    private val _events = Channel<OrgOverviewEvent>(Channel.BUFFERED)
    val events: Flow<OrgOverviewEvent> = _events.receiveAsFlow()

    init {
        load(orgId = null)
    }

    /** Loads (or reloads) the overview for [orgId]; null -> the selected org (default: primary org). */
    fun load(orgId: String?) {
        val cached = _uiState.value as? OrgOverviewUiState.Content
        if (cached == null) _uiState.value = OrgOverviewUiState.Loading
        viewModelScope.launch {
            when (val orgs = repository.listOrgs()) {
                is ApiResult.Success -> reduceWithOrgs(orgs.data, orgId, cached)
                is ApiResult.Failure -> reduceFailure(orgs.error, cached)
                is ApiResult.NetworkError -> reduceFailure(networkError(), cached)
            }
        }
    }

    fun onRetry() = load(orgId = currentOrgId())

    /**
     * PAR-35(b) - the caller leaves the CURRENT org. A sole-owner leave is rejected by the backend (409)
     * and surfaces a "transfer ownership first" message. On success emits [OrgOverviewEvent.Left] so the
     * screen pops. Guarded against re-entrancy via [leaving].
     */
    fun leaveOrg() {
        if (_leaving.value) return
        val orgId = currentOrgId() ?: return
        _leaving.value = true
        viewModelScope.launch {
            val result = repository.leaveOrg(orgId)
            _leaving.value = false
            when (result) {
                is ApiResult.Success -> _events.send(OrgOverviewEvent.Left)
                is ApiResult.Failure -> {
                    val msg = if (result.error.status == STATUS_SOLE_OWNER) SOLE_OWNER else LEAVE_FAILED
                    _events.send(OrgOverviewEvent.Message(msg))
                }
                is ApiResult.NetworkError -> _events.send(OrgOverviewEvent.Message(OFFLINE_FALLBACK))
            }
        }
    }

    /** PAR-35(c) - reload the overview after a transfer changed roles (owner -> admin). */
    fun reloadAfterTransfer() = load(orgId = currentOrgId())

    private suspend fun reduceWithOrgs(
        orgs: List<Org>,
        requestedOrgId: String?,
        cached: OrgOverviewUiState.Content?,
    ) {
        val resolvedId = requestedOrgId
            ?: selectedOrgStore.selectedOrgId.first()
            ?: orgs.firstOrNull()?.orgId
        if (resolvedId == null) {
            // No org could be resolved at all -> Empty (the caller belongs to no organization).
            _uiState.value = OrgOverviewUiState.Empty
            return
        }
        if (requestedOrgId != null) selectedOrgStore.setSelectedOrgId(resolvedId)

        val org = orgs.firstOrNull { it.orgId == resolvedId }
            ?: orgs.firstOrNull()
            ?: Org(orgId = resolvedId, name = null, callerRole = OrgRole.UNKNOWN)

        when (val members = repository.listMembers(org.orgId)) {
            is ApiResult.Success -> _uiState.value = OrgOverviewUiState.Content(
                org = org,
                memberCount = members.data.size,
                callerRole = org.callerRole,
                isStale = false,
            )
            // Org row resolved but the roster read failed: keep an overview (count unknown), stale if
            // we had cached content (FR-9), otherwise show content with a null member count.
            is ApiResult.Failure -> _uiState.value = OrgOverviewUiState.Content(
                org = org,
                memberCount = cached?.memberCount,
                callerRole = org.callerRole,
                isStale = cached != null,
            )
            is ApiResult.NetworkError -> _uiState.value = OrgOverviewUiState.Content(
                org = org,
                memberCount = cached?.memberCount,
                callerRole = org.callerRole,
                isStale = cached != null,
            )
        }
    }

    private fun reduceFailure(error: ApiError, cached: OrgOverviewUiState.Content?) {
        // FR-9: keep cached content with a stale banner; only a cache-less failure is terminal.
        _uiState.value = cached?.copy(isStale = true) ?: OrgOverviewUiState.Error(error)
    }

    private fun networkError(): ApiError =
        ApiError(status = ApiError.STATUS_NETWORK, message = OFFLINE_FALLBACK)

    private fun currentOrgId(): String? =
        (_uiState.value as? OrgOverviewUiState.Content)?.org?.orgId?.takeIf { it.isNotBlank() }

    private companion object {
        const val OFFLINE_FALLBACK = "Couldn't reach the server. Pull down to retry."
        const val LEAVE_FAILED = "Couldn't leave the organization. Please try again."
        const val SOLE_OWNER = "You are the sole owner. Transfer ownership before leaving."
        const val STATUS_SOLE_OWNER = 409
    }
}
