package com.testlogon.android.feature.files.drive

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.files.drive.data.GoogleDriveRepository
import com.testlogon.android.feature.files.drive.model.DriveFile
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/** AND-336 - a Drive folder on the navigation stack: its [id] (null = root) and display [name]. */
data class DriveCrumb(val id: String?, val name: String)

/**
 * AND-336 - UI state for the BACKEND-MEDIATED Drive picker.
 *
 * [Loading] is the initial status probe; [NotConnected] surfaces the consent button (the backend's
 * auth_url, opened externally); [Browsing] holds the current Drive folder + breadcrumbs + entries (plus
 * the id of an in-flight import for the per-row spinner and an optional inline error); [Error] is a
 * terminal status / list failure.
 */
sealed interface DrivePickerUiState {
    data object Loading : DrivePickerUiState

    data class NotConnected(val authUrl: String? = null) : DrivePickerUiState

    data class Browsing(
        val folderId: String? = null,
        val breadcrumbs: List<DriveCrumb> = emptyList(),
        val files: List<DriveFile> = emptyList(),
        val query: String = "",
        val loading: Boolean = false,
        val importing: String? = null,
        val error: String? = null,
    ) : DrivePickerUiState

    data class Error(val message: String) : DrivePickerUiState
}

/** AND-336 - one-shot effects consumed by the screen (a Channel, never a StateFlow). */
sealed interface DrivePickerEvent {
    /** Open the backend OAuth consent [url] externally (the screen uses the openExternalUrl idiom). */
    data class OpenUrl(val url: String) : DrivePickerEvent

    /** An import landed: [path] is the resulting TestLogon path when the backend reports one. */
    data class Imported(val path: String?) : DrivePickerEvent
}

/**
 * AND-336 - presentation logic for the BACKEND-MEDIATED Drive picker.
 *
 * FLOW: init probes status; connected -> list the root Drive folder; not connected -> [NotConnected]
 * exposing the consent button. onConnect fetches the auth_url and emits [DrivePickerEvent.OpenUrl] (the
 * screen opens it via the plain ACTION_VIEW openExternalUrl idiom - NO Custom Tabs, NO deep link). On
 * RETURN the screen calls [refreshStatus], a SINGLE status re-check (NOT a poll loop): the backend
 * completes OAuth via its own redirect server-side, so once connected the picker lists the root.
 *
 * Folder navigation is Drive folder_id based (onOpenFolder pushes a crumb, onBreadcrumb / onUp pop). The
 * non-idempotent import carries a DOUBLE-SEND guard (importing != null short-circuits) and, on success,
 * emits [DrivePickerEvent.Imported] (the repo has already signalled FolderRefreshBus for the target).
 */
@HiltViewModel
class DrivePickerViewModel @Inject constructor(
    private val repository: GoogleDriveRepository,
    private val savedState: SavedStateHandle,
) : ViewModel() {

    private val _uiState = MutableStateFlow<DrivePickerUiState>(DrivePickerUiState.Loading)
    val uiState: StateFlow<DrivePickerUiState> = _uiState.asStateFlow()

    private val _events = Channel<DrivePickerEvent>(Channel.BUFFERED)
    val events: Flow<DrivePickerEvent> = _events.receiveAsFlow()

    /**
     * The TestLogon target folder an import lands in (carried from the Files screen; may be null). The
     * nav layer passes a single-space placeholder when no target is supplied (an empty path segment is
     * not routable), so a blank value normalizes back to null here.
     */
    private val targetFolderPath: String? = savedState.get<String>(KEY_TARGET)?.takeIf { it.isNotBlank() }

    init {
        refreshStatus()
    }

    /**
     * SINGLE status re-check (the init probe AND the on-return re-check). Connected -> list the root
     * Drive folder; not connected -> [NotConnected]; failure -> [Error]. This is NOT a poll loop.
     */
    fun refreshStatus() {
        viewModelScope.launch {
            when (val result = repository.status()) {
                is ApiResult.Success ->
                    if (result.data.connected) {
                        openFolder(folderId = null, name = ROOT_NAME, resetStack = true)
                    } else {
                        _uiState.value = DrivePickerUiState.NotConnected(
                            authUrl = (_uiState.value as? DrivePickerUiState.NotConnected)?.authUrl,
                        )
                    }
                is ApiResult.Failure -> _uiState.value = DrivePickerUiState.Error(result.error.message)
                is ApiResult.NetworkError -> _uiState.value = DrivePickerUiState.Error(OFFLINE_MESSAGE)
            }
        }
    }

    /**
     * Fetches the consent URL and emits [DrivePickerEvent.OpenUrl] for the screen to open externally. On
     * failure the picker stays on [NotConnected] (the connect CTA remains so the user can retry).
     */
    fun onConnect() {
        viewModelScope.launch {
            when (val result = repository.connectUrl()) {
                is ApiResult.Success -> {
                    _uiState.value = DrivePickerUiState.NotConnected(authUrl = result.data)
                    _events.trySend(DrivePickerEvent.OpenUrl(result.data))
                }
                is ApiResult.Failure, is ApiResult.NetworkError ->
                    _uiState.value = DrivePickerUiState.NotConnected(authUrl = null)
            }
        }
    }

    /** Navigates into a Drive [folder], pushing a breadcrumb and listing its children. */
    fun onOpenFolder(folder: DriveFile) {
        if (!folder.isFolder) return
        openFolder(folderId = folder.id, name = folder.name, resetStack = false)
    }

    /** Jumps to the breadcrumb at [index], truncating the stack and re-listing that folder. */
    fun onBreadcrumb(index: Int) {
        val crumbs = currentCrumbs()
        if (index !in crumbs.indices) return
        val target = crumbs[index]
        val truncated = crumbs.subList(0, index + 1)
        listFolder(folderId = target.id, crumbs = truncated)
    }

    /** Pops one folder; at the Drive root this is a no-op (the screen's own close handles dismissal). */
    fun onUp() {
        val crumbs = currentCrumbs()
        if (crumbs.size <= 1) return
        onBreadcrumb(crumbs.size - 2)
    }

    /** Re-lists the current folder filtered by [query] (server-side search via the files endpoint). */
    fun onSearch(query: String) {
        val state = _uiState.value as? DrivePickerUiState.Browsing ?: return
        _uiState.value = state.copy(query = query)
        listFolder(folderId = state.folderId, crumbs = state.breadcrumbs, query = query)
    }

    /**
     * Imports [file] into the TestLogon [targetFolderPath]. DOUBLE-SEND guard: a second tap while an
     * import is in flight is ignored (the import is non-idempotent). On success emits
     * [DrivePickerEvent.Imported] (the repo has already signalled FolderRefreshBus).
     */
    fun onImport(file: DriveFile, targetFolderPath: String? = this.targetFolderPath) {
        val state = _uiState.value as? DrivePickerUiState.Browsing ?: return
        if (file.isFolder || state.importing != null) return
        _uiState.value = state.copy(importing = file.id, error = null)
        viewModelScope.launch {
            val result = repository.import(fileId = file.id, targetFolderPath = targetFolderPath)
            val current = _uiState.value as? DrivePickerUiState.Browsing ?: return@launch
            when (result) {
                is ApiResult.Success -> {
                    _uiState.value = current.copy(importing = null, error = null)
                    _events.trySend(DrivePickerEvent.Imported(result.data.path))
                }
                is ApiResult.Failure -> _uiState.value = current.copy(importing = null, error = result.error.message)
                is ApiResult.NetworkError -> _uiState.value = current.copy(importing = null, error = OFFLINE_MESSAGE)
            }
        }
    }

    /** Disconnects the Drive integration and returns to the [NotConnected] state. */
    fun onDisconnect() {
        viewModelScope.launch {
            when (val result = repository.disconnect()) {
                is ApiResult.Success -> _uiState.value = DrivePickerUiState.NotConnected()
                is ApiResult.Failure -> showError(result.error.message)
                is ApiResult.NetworkError -> showError(OFFLINE_MESSAGE)
            }
        }
    }

    private fun openFolder(folderId: String?, name: String, resetStack: Boolean) {
        val base = if (resetStack) emptyList() else currentCrumbs()
        listFolder(folderId = folderId, crumbs = base + DriveCrumb(id = folderId, name = name))
    }

    private fun listFolder(folderId: String?, crumbs: List<DriveCrumb>, query: String = "") {
        _uiState.value = DrivePickerUiState.Browsing(
            folderId = folderId,
            breadcrumbs = crumbs,
            files = (_uiState.value as? DrivePickerUiState.Browsing)?.files ?: emptyList(),
            query = query,
            loading = true,
            importing = null,
            error = null,
        )
        viewModelScope.launch {
            when (val result = repository.listFiles(folderId = folderId, query = query.ifBlank { null })) {
                is ApiResult.Success -> _uiState.value = DrivePickerUiState.Browsing(
                    folderId = folderId,
                    breadcrumbs = crumbs,
                    files = result.data.files,
                    query = query,
                    loading = false,
                    importing = null,
                    error = null,
                )
                is ApiResult.Failure -> _uiState.value = DrivePickerUiState.Browsing(
                    folderId = folderId,
                    breadcrumbs = crumbs,
                    files = emptyList(),
                    query = query,
                    loading = false,
                    importing = null,
                    error = result.error.message,
                )
                is ApiResult.NetworkError -> _uiState.value = DrivePickerUiState.Browsing(
                    folderId = folderId,
                    breadcrumbs = crumbs,
                    files = emptyList(),
                    query = query,
                    loading = false,
                    importing = null,
                    error = OFFLINE_MESSAGE,
                )
            }
        }
    }

    private fun currentCrumbs(): List<DriveCrumb> =
        (_uiState.value as? DrivePickerUiState.Browsing)?.breadcrumbs ?: emptyList()

    private fun showError(message: String) {
        val state = _uiState.value
        if (state is DrivePickerUiState.Browsing) {
            _uiState.value = state.copy(importing = null, error = message)
        } else {
            _uiState.value = DrivePickerUiState.Error(message)
        }
    }

    companion object {
        const val KEY_TARGET = "drive_target_folder"
        const val ROOT_NAME = "Drive"
        private const val OFFLINE_MESSAGE = "You appear to be offline."
    }
}
