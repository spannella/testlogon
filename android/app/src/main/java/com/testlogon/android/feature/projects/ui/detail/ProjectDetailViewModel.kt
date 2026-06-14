package com.testlogon.android.feature.projects.ui.detail

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.projects.DriveConnection
import com.testlogon.android.core.model.projects.Project
import com.testlogon.android.core.model.projects.ProviderCallbackParams
import com.testlogon.android.feature.projects.data.ProjectsRepository
import com.testlogon.android.feature.projects.provider.ProjectDriveReturn
import com.testlogon.android.feature.projects.provider.ProjectDriveReturnDispatcher
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-374 - drives the PROJECT DETAIL screen + the account-scoped Google Drive provider flow.
 *
 * projectId arrives as a nav arg via [SavedStateHandle] (survives process death). The state machine is
 * Loading -> Content (the project + the Drive-connection flag) / Error, with retry. The Drive flow is
 * server-mediated OAuth (no Google SDK): [connectGoogleDrive] calls the account-scoped start endpoint, stores
 * the returned `state` in [SavedStateHandle] (so it survives the Custom Tab excursion / process death), and
 * emits a one-shot [ProjectDetailEffect.LaunchAuth]. The Activity delivers the return deep link through the
 * [ProjectDriveReturnDispatcher]; [onProviderCallback] validates the echoed state against the stored value
 * (CSRF/replay protection) BEFORE calling the callback endpoint, then re-reads the connection state.
 *
 * No poll loop; the connect action is double-submit-guarded ([connecting]); the start/callback POSTs are NOT
 * auto-retried (the repo enforces this). A terminal 401 emits the one-shot [ProjectDetailEffect.NavigateToLogin].
 */
@HiltViewModel
class ProjectDetailViewModel @Inject constructor(
    private val repository: ProjectsRepository,
    private val savedState: SavedStateHandle,
    returnDispatcher: ProjectDriveReturnDispatcher,
) : ViewModel() {

    val projectId: String =
        checkNotNull(savedState[ARG_PROJECT_ID]) { "missing $ARG_PROJECT_ID nav arg" }

    private val _state = MutableStateFlow<ProjectDetailUiState>(ProjectDetailUiState.Loading)
    val state: StateFlow<ProjectDetailUiState> = _state.asStateFlow()

    private val _effects = Channel<ProjectDetailEffect>(Channel.BUFFERED)
    val effects: Flow<ProjectDetailEffect> = _effects.receiveAsFlow()

    /**
     * AND-375 (FR-7 / AC-3) - the in-flight detail-load guard: a rapid load()/retry() while a read is still
     * running collapses onto it (a single getProjectDetail), rather than firing parallel reads.
     */
    private var loadJob: Job? = null

    init {
        load()
        // The deep-link return path: the Activity emits the parsed return; act on it for THIS project only.
        viewModelScope.launch {
            returnDispatcher.returns.collect { ret ->
                if (ret.projectId == projectId) onProviderCallback(ret.toParams())
            }
        }
    }

    /** First load (or retry): Loading -> the detail read + the Drive-connection read -> Content / Error. */
    fun load() {
        if (loadJob?.isActive == true) return // AND-375 FR-7: collapse onto the in-flight detail read.
        _state.value = ProjectDetailUiState.Loading
        loadJob = viewModelScope.launch { fetch() }
    }

    fun retry() = load()

    private suspend fun fetch() {
        when (val result = repository.getProjectDetail(projectId)) {
            is ApiResult.Success -> emitContent(result.data)
            is ApiResult.Failure ->
                if (result.error.status == HTTP_UNAUTHORIZED) {
                    _effects.send(ProjectDetailEffect.NavigateToLogin)
                } else {
                    emitFailure(result.error.message)
                }
            is ApiResult.NetworkError -> emitFailure(OFFLINE_MESSAGE, isOffline = true)
        }
    }

    /** Loads the project into Content, then folds in the (best-effort) Drive-connection read. */
    private suspend fun emitContent(project: Project) {
        val connected = readDriveConnected()
        _state.value = ProjectDetailUiState.Content(
            project = project,
            driveConnected = connected,
            isStale = false,
            connecting = false,
        )
    }

    /** A non-401 detail failure: keep the last-good Content as stale if present, else surface Error. */
    private fun emitFailure(message: String, isOffline: Boolean = false) {
        val prior = _state.value as? ProjectDetailUiState.Content
        _state.value = if (prior != null) {
            prior.copy(isStale = true, connecting = false)
        } else {
            ProjectDetailUiState.Error(if (isOffline) OFFLINE_MESSAGE else message)
        }
    }

    /** Best-effort Drive-connection read; a transport failure leaves it false (the screen offers Connect). */
    private suspend fun readDriveConnected(): Boolean =
        when (val r = repository.isDriveConnected()) {
            is ApiResult.Success -> r.data.connected
            else -> false
        }

    /**
     * Begins the server-mediated Drive OAuth: POST start, store the state, emit LaunchAuth. Double-submit
     * guarded via the [ProjectDetailUiState.Content.connecting] flag (a no-op if already connecting or not yet
     * in Content). The start POST is NOT auto-retried.
     */
    fun connectGoogleDrive() {
        val current = _state.value as? ProjectDetailUiState.Content ?: return
        if (current.connecting) return
        _state.value = current.copy(connecting = true)
        viewModelScope.launch {
            when (val r = repository.startGoogleDrive()) {
                is ApiResult.Success -> {
                    savedState[KEY_OAUTH_STATE] = r.data.state
                    _effects.send(ProjectDetailEffect.LaunchAuth(r.data.authorizationUrl))
                }
                is ApiResult.Failure -> {
                    clearConnecting()
                    if (r.error.status == HTTP_UNAUTHORIZED) {
                        _effects.send(ProjectDetailEffect.NavigateToLogin)
                    } else {
                        _effects.send(ProjectDetailEffect.ShowMessage(r.error.message))
                    }
                }
                is ApiResult.NetworkError -> {
                    clearConnecting()
                    _effects.send(ProjectDetailEffect.ShowMessage(OFFLINE_MESSAGE))
                }
            }
        }
    }

    /**
     * Handles the OAuth return. A canceled/denied return shows a neutral message and leaves the project
     * unchanged. Otherwise the echoed [ProviderCallbackParams.state] MUST match the stored start state
     * (CSRF/replay); a mismatch/missing aborts WITHOUT calling the callback endpoint. On a match it POSTs the
     * callback and re-reads the connection state, flipping the screen to "Drive connected" on success.
     */
    fun onProviderCallback(params: ProviderCallbackParams) {
        viewModelScope.launch {
            if (params.error != null) {
                clearConnecting()
                clearStoredState()
                _effects.send(ProjectDetailEffect.ShowMessage(MESSAGE_CANCELED))
                return@launch
            }
            val code = params.code
            val state = params.state
            val stored = savedState.get<String>(KEY_OAUTH_STATE)
            if (code.isNullOrBlank() || state.isNullOrBlank() || stored == null || stored != state) {
                clearConnecting()
                clearStoredState()
                _effects.send(ProjectDetailEffect.ShowMessage(MESSAGE_UNVERIFIED))
                return@launch
            }
            markConnecting()
            when (val r = repository.completeGoogleDrive(params)) {
                is ApiResult.Success -> {
                    clearStoredState()
                    applyConnection(r.data)
                }
                is ApiResult.Failure -> {
                    clearConnecting()
                    if (r.error.status == HTTP_UNAUTHORIZED) {
                        _effects.send(ProjectDetailEffect.NavigateToLogin)
                    } else {
                        _effects.send(ProjectDetailEffect.ShowMessage(r.error.message))
                    }
                }
                is ApiResult.NetworkError -> {
                    clearConnecting()
                    _effects.send(ProjectDetailEffect.ShowMessage(OFFLINE_MESSAGE))
                }
            }
        }
    }

    /** The user returned from the Custom Tab without a callback (dismissed): drop the connecting spinner. */
    fun onConnectCanceled() {
        clearConnecting()
        clearStoredState()
    }

    /** Folds a fresh connection read into Content (connected reflects the credential read). */
    private suspend fun applyConnection(connection: DriveConnection) {
        val current = _state.value as? ProjectDetailUiState.Content
        // If the callback already confirmed connected, trust it; otherwise re-read for the authoritative state.
        val connected = if (connection.connected) true else readDriveConnected()
        if (current != null) {
            _state.value = current.copy(driveConnected = connected, connecting = false, isStale = false)
        } else {
            // No prior content (unlikely): reload the whole detail so the screen has a project to render.
            fetch()
        }
    }

    private fun markConnecting() {
        (_state.value as? ProjectDetailUiState.Content)?.let { _state.value = it.copy(connecting = true) }
    }

    private fun clearConnecting() {
        (_state.value as? ProjectDetailUiState.Content)?.let { _state.value = it.copy(connecting = false) }
    }

    private fun clearStoredState() {
        savedState.remove<String>(KEY_OAUTH_STATE)
    }

    private fun ProjectDriveReturn.toParams() =
        ProviderCallbackParams(code = code, state = state, error = error)

    companion object {
        const val ARG_PROJECT_ID = "projectId"

        private const val KEY_OAUTH_STATE = "projects_drive_oauth_state"
        private const val HTTP_UNAUTHORIZED = 401
        private const val OFFLINE_MESSAGE = "You're offline. Showing saved project."
        private const val MESSAGE_CANCELED = "Connection canceled."
        private const val MESSAGE_UNVERIFIED = "Connection couldn't be verified."
    }
}
