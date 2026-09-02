package com.testlogon.android.feature.jira.ui

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.jira.JiraConstants
import com.testlogon.android.data.jira.JiraMath
import com.testlogon.android.feature.jira.data.JiraRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * JIRA-AND-1 - drives the Jira sync surface for one ticket (screen reachable from the ticket thread). It shows
 * the connection status, the per-ticket sync summary (via [JiraMath.summarize]), and mediates the link / unlink /
 * connect / resolve-conflict actions. The workspace scope is the ticket's SPACE id (nav arg), matching how the
 * web caller supplies a workspace_id.
 *
 * Effects are one-shot: [JiraSyncEffect.OpenConnectUrl] hands the OAuth authorize URL to the screen (which opens
 * a Custom Tab via the shared SsoTabLauncher) and [JiraSyncEffect.NavigateToLogin] is the terminal-401 re-auth
 * handoff. Everything else is reflected in [JiraSyncUiState].
 *
 * DEGRADE-ON-404: the repository already maps a 404 status / sync-status to honest not-connected / not_linked, so
 * the loaded state renders a clean "connect Jira" / "no link yet" surface rather than an error.
 */
@HiltViewModel
class JiraSyncViewModel @Inject constructor(
    private val repository: JiraRepository,
    savedState: SavedStateHandle,
) : ViewModel() {

    val spaceId: String = checkNotNull(savedState[ARG_SPACE_ID]) { "missing $ARG_SPACE_ID nav arg" }
    val ticketId: String = checkNotNull(savedState[ARG_TICKET_ID]) { "missing $ARG_TICKET_ID nav arg" }

    /** The workspace scope used for every Jira call for this ticket. */
    private val workspaceId: String get() = spaceId

    private val _uiState = MutableStateFlow(JiraSyncUiState())
    val uiState: StateFlow<JiraSyncUiState> = _uiState.asStateFlow()

    private val _effects = Channel<JiraSyncEffect>(Channel.BUFFERED)
    val effects: Flow<JiraSyncEffect> = _effects.receiveAsFlow()

    init {
        load()
    }

    /** Load both the connection status and the ticket sync status. */
    fun load() {
        _uiState.update { it.copy(loading = true, error = null) }
        viewModelScope.launch {
            when (val statusRes = repository.status(workspaceId)) {
                is ApiResult.Success -> {
                    val connected = JiraMath.isConnected(statusRes.data.items.map { it.status })
                    val cloudId = statusRes.data.items.firstOrNull { (it.status ?: "") == JiraConstants.ConnectionStatus.ACTIVE }?.cloudId
                    _uiState.update {
                        it.copy(
                            connected = connected,
                            connectionCount = statusRes.data.items.size,
                            cloudId = cloudId,
                        )
                    }
                }
                is ApiResult.Failure -> if (handleTerminal(statusRes.error)) return@launch
                is ApiResult.NetworkError -> {
                    _uiState.update { it.copy(loading = false, error = ApiError(status = ApiError.STATUS_NETWORK, message = "offline")) }
                    return@launch
                }
            }
            refreshSyncStatus(setLoadingFalse = true)
        }
    }

    private suspend fun refreshSyncStatus(setLoadingFalse: Boolean) {
        when (val res = repository.syncStatus(ticketId)) {
            is ApiResult.Success -> {
                val d = res.data
                val summary = JiraMath.summarize(
                    linked = d.linked,
                    rawState = d.syncState,
                    issueKey = d.externalIssueKey,
                    jiraStatus = d.jiraStatus,
                    conflictFields = d.conflictFields,
                    localValues = d.conflictLocalValues,
                    remoteValues = d.conflictRemoteValues,
                )
                _uiState.update {
                    it.copy(
                        loading = if (setLoadingFalse) false else it.loading,
                        summary = summary,
                        linkId = d.linkId,
                        error = null,
                    )
                }
            }
            is ApiResult.Failure -> if (!handleTerminal(res.error)) {
                _uiState.update { it.copy(loading = false, error = res.error) }
            }
            is ApiResult.NetworkError ->
                _uiState.update { it.copy(loading = false, error = ApiError(status = ApiError.STATUS_NETWORK, message = "offline")) }
        }
    }

    /** Update the issue-key draft; clears any prior action error. */
    fun onIssueKeyChanged(value: String) {
        _uiState.update { it.copy(issueKeyDraft = value, actionError = null) }
    }

    /**
     * Link the entered EXISTING Jira issue key to this ticket. The key is client-validated first (server is the
     * authority). On success the sync status is re-read so the summary reflects the new link.
     */
    fun onLinkExisting() {
        val key = JiraMath.normalizeIssueKey(_uiState.value.issueKeyDraft)
        if (key == null) {
            _uiState.update { it.copy(actionError = "Enter a valid Jira issue key, e.g. ABC-123") }
            return
        }
        if (_uiState.value.working) return
        _uiState.update { it.copy(working = true, actionError = null) }
        viewModelScope.launch {
            when (val res = repository.linkExisting(ticketId = ticketId, workspaceId = workspaceId, issueKey = key)) {
                is ApiResult.Success -> {
                    _uiState.update { it.copy(working = false, issueKeyDraft = "") }
                    refreshSyncStatus(setLoadingFalse = false)
                }
                is ApiResult.Failure -> if (!handleTerminal(res.error)) {
                    _uiState.update { it.copy(working = false, actionError = res.error.message) }
                }
                is ApiResult.NetworkError -> _uiState.update { it.copy(working = false, actionError = "offline") }
            }
        }
    }

    /** Unlink the current external link, then re-read the (now not_linked) status. */
    fun onUnlink() {
        val linkId = _uiState.value.linkId ?: return
        if (_uiState.value.working) return
        _uiState.update { it.copy(working = true, actionError = null) }
        viewModelScope.launch {
            when (val res = repository.unlink(ticketId = ticketId, linkId = linkId)) {
                is ApiResult.Success -> {
                    _uiState.update { it.copy(working = false, linkId = null) }
                    refreshSyncStatus(setLoadingFalse = false)
                }
                is ApiResult.Failure -> if (!handleTerminal(res.error)) {
                    _uiState.update { it.copy(working = false, actionError = res.error.message) }
                }
                is ApiResult.NetworkError -> _uiState.update { it.copy(working = false, actionError = "offline") }
            }
        }
    }

    /** Begin the OAuth connect flow; on success emit the authorize URL for the screen to open in a Custom Tab. */
    fun onConnect(redirectUri: String) {
        if (_uiState.value.working) return
        _uiState.update { it.copy(working = true, actionError = null) }
        viewModelScope.launch {
            when (val res = repository.connect(workspaceId = workspaceId, redirectUri = redirectUri)) {
                is ApiResult.Success -> {
                    _uiState.update { it.copy(working = false, pendingState = res.data.state) }
                    _effects.send(JiraSyncEffect.OpenConnectUrl(res.data.connectUrl))
                }
                is ApiResult.Failure -> if (!handleTerminal(res.error)) {
                    _uiState.update { it.copy(working = false, actionError = res.error.message) }
                }
                is ApiResult.NetworkError -> _uiState.update { it.copy(working = false, actionError = "offline") }
            }
        }
    }

    /** Resolve the current conflict with the chosen action (keep_internal / keep_jira). */
    fun onResolveConflict(choice: JiraMath.JiraConflictChoice) {
        val linkId = _uiState.value.linkId ?: return
        if (_uiState.value.working) return
        _uiState.update { it.copy(working = true, actionError = null) }
        viewModelScope.launch {
            when (
                val res = repository.resolveConflict(
                    ticketId = ticketId,
                    linkId = linkId,
                    workspaceId = workspaceId,
                    action = JiraMath.conflictAction(choice),
                )
            ) {
                is ApiResult.Success -> {
                    _uiState.update { it.copy(working = false) }
                    refreshSyncStatus(setLoadingFalse = false)
                }
                is ApiResult.Failure -> if (!handleTerminal(res.error)) {
                    _uiState.update { it.copy(working = false, actionError = res.error.message) }
                }
                is ApiResult.NetworkError -> _uiState.update { it.copy(working = false, actionError = "offline") }
            }
        }
    }

    /**
     * A terminal 401 -> emit NavigateToLogin and return true (caller aborts). Any other status returns false
     * (the caller surfaces it inline).
     */
    private fun handleTerminal(error: ApiError): Boolean {
        if (error.status == HTTP_UNAUTHORIZED) {
            _uiState.update { it.copy(loading = false, working = false) }
            viewModelScope.launch { _effects.send(JiraSyncEffect.NavigateToLogin) }
            return true
        }
        return false
    }

    companion object {
        const val ARG_SPACE_ID = "spaceId"
        const val ARG_TICKET_ID = "ticketId"
        private const val HTTP_UNAUTHORIZED = 401
    }
}

/** JIRA-AND-1 - the Jira sync screen state. */
data class JiraSyncUiState(
    val loading: Boolean = true,
    val connected: Boolean = false,
    val connectionCount: Int = 0,
    val cloudId: String? = null,
    val summary: JiraMath.JiraSyncSummary? = null,
    val linkId: String? = null,
    val issueKeyDraft: String = "",
    val working: Boolean = false,
    val pendingState: String? = null,
    val error: ApiError? = null,
    val actionError: String? = null,
)

/** JIRA-AND-1 - one-shot effects. */
sealed interface JiraSyncEffect {
    data class OpenConnectUrl(val url: String) : JiraSyncEffect
    data object NavigateToLogin : JiraSyncEffect
}
