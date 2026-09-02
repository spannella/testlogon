package com.testlogon.android.feature.files.mounts

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.files.FileMountUpdateRequest
import com.testlogon.android.feature.files.mounts.data.FileMount
import com.testlogon.android.feature.files.mounts.data.MountsRepository
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
 * FM-MOUNTS - list state for the file-manager Mounts screen. [available] = false means the surface is
 * not enabled in this environment (degrade-on-404/403) and the UI shows an honest "not available" state
 * instead of an error. [errorMessage] is only set for GENUINE list failures (422/5xx/network).
 */
data class MountsUiState(
    val mounts: List<FileMount> = emptyList(),
    val available: Boolean = true,
    val isLoading: Boolean = false,
    val isRefreshing: Boolean = false,
    val errorMessage: String? = null,
) {
    val isEmpty: Boolean get() = mounts.isEmpty()
}

/**
 * FM-MOUNTS - state of the add/edit mount editor sheet. [editingId] null = adding a new mount, non-null
 * = editing the mount with that id. [errors] holds inline per-field validation messages from [MountMath].
 */
data class MountEditorState(
    val visible: Boolean = false,
    val editingId: String? = null,
    val mountPath: String = "/",
    val bucket: String = "",
    val prefix: String = "",
    val mode: String = MOUNT_MODES.first(),
    val authRef: String = "",
    val status: String = MOUNT_STATUSES.first(),
    val saving: Boolean = false,
    val errors: MountValidation = MountValidation(emptyList()),
) {
    val isEditing: Boolean get() = editingId != null
}

/** FM-MOUNTS - one-shot user-facing effects (snackbar messages). */
sealed interface MountsEvent {
    data class Message(val text: String) : MountsEvent
}

/**
 * FM-MOUNTS - presentation logic for the Mounts management surface. Loads the mount list on
 * construction; [refresh] re-fetches. The editor is opened via [openAdd] / [openEdit], its fields update
 * through the on*Changed callbacks, and [save] validates CLIENT-SIDE (via [MountMath]) before the network
 * call — invalid drafts populate inline [MountEditorState.errors] and never hit the wire. [validate] runs
 * the server-side connectivity check; [delete] removes a mount. All mutations refresh the list on success.
 */
@HiltViewModel
class MountsViewModel @Inject constructor(
    private val repository: MountsRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(MountsUiState(isLoading = true))
    val uiState: StateFlow<MountsUiState> = _uiState.asStateFlow()

    private val _editor = MutableStateFlow(MountEditorState())
    val editor: StateFlow<MountEditorState> = _editor.asStateFlow()

    private val _events = Channel<MountsEvent>(Channel.BUFFERED)
    val events: Flow<MountsEvent> = _events.receiveAsFlow()

    init {
        load(isRefresh = false)
    }

    fun refresh() = load(isRefresh = true)

    private fun load(isRefresh: Boolean) {
        _uiState.update {
            it.copy(isLoading = !isRefresh, isRefreshing = isRefresh, errorMessage = null)
        }
        viewModelScope.launch {
            when (val result = repository.listMounts()) {
                is ApiResult.Success -> _uiState.update {
                    it.copy(
                        mounts = result.data.mounts,
                        available = result.data.available,
                        isLoading = false,
                        isRefreshing = false,
                        errorMessage = null,
                    )
                }
                is ApiResult.Failure -> _uiState.update {
                    it.copy(isLoading = false, isRefreshing = false, errorMessage = result.error.message)
                }
                is ApiResult.NetworkError -> _uiState.update {
                    it.copy(isLoading = false, isRefreshing = false, errorMessage = "Network error")
                }
            }
        }
    }

    // ---- editor lifecycle ----

    fun openAdd() {
        _editor.value = MountEditorState(visible = true)
    }

    fun openEdit(mount: FileMount) {
        _editor.value = MountEditorState(
            visible = true,
            editingId = mount.id,
            mountPath = mount.mountPath,
            bucket = mount.bucket,
            prefix = mount.prefix.orEmpty(),
            mode = mount.mode,
            authRef = mount.authRef,
            status = mount.status,
        )
    }

    fun closeEditor() {
        _editor.value = MountEditorState(visible = false)
    }

    fun onMountPathChanged(value: String) = _editor.update { it.copy(mountPath = value) }
    fun onBucketChanged(value: String) = _editor.update { it.copy(bucket = value) }
    fun onPrefixChanged(value: String) = _editor.update { it.copy(prefix = value) }
    fun onModeChanged(value: String) = _editor.update { it.copy(mode = value) }
    fun onAuthRefChanged(value: String) = _editor.update { it.copy(authRef = value) }
    fun onStatusChanged(value: String) = _editor.update { it.copy(status = value) }

    /**
     * Validate the draft CLIENT-SIDE, then create or update. Invalid drafts populate inline errors and
     * do NOT hit the network. On success the editor closes and the list refreshes.
     */
    fun save() {
        val draft = _editor.value
        val validation = validateMountDraft(
            mountPath = draft.mountPath,
            bucket = draft.bucket,
            prefix = draft.prefix,
            mode = draft.mode,
            authRef = draft.authRef,
            status = draft.status,
        )
        if (!validation.isValid) {
            _editor.update { it.copy(errors = validation) }
            return
        }
        _editor.update { it.copy(saving = true, errors = MountValidation(emptyList())) }
        viewModelScope.launch {
            val editingId = draft.editingId
            val result = if (editingId == null) {
                repository.createMount(
                    buildCreateRequest(
                        mountPath = draft.mountPath,
                        bucket = draft.bucket,
                        prefix = draft.prefix,
                        mode = draft.mode,
                        authRef = draft.authRef,
                        status = draft.status,
                    ),
                )
            } else {
                repository.updateMount(
                    editingId,
                    FileMountUpdateRequest(
                        mount_path = canonicalMountPath(draft.mountPath),
                        bucket = draft.bucket.trim().lowercase(),
                        prefix = canonicalPrefix(draft.prefix),
                        mode = draft.mode.lowercase(),
                        auth_ref = draft.authRef.trim(),
                        status = draft.status.lowercase(),
                    ),
                )
            }
            when (result) {
                is ApiResult.Success -> {
                    _editor.value = MountEditorState(visible = false)
                    emit(if (editingId == null) "Mount added" else "Mount updated")
                    load(isRefresh = true)
                }
                is ApiResult.Failure -> {
                    _editor.update { it.copy(saving = false) }
                    emit(result.error.message)
                }
                is ApiResult.NetworkError -> {
                    _editor.update { it.copy(saving = false) }
                    emit("Network error")
                }
            }
        }
    }

    /** Server-side connectivity check for [mount]; reports the returned status via a snackbar. */
    fun validate(mount: FileMount) {
        viewModelScope.launch {
            when (val result = repository.validateMount(mount.id)) {
                is ApiResult.Success -> {
                    val status = result.data.status ?: "unknown"
                    emit(if (result.data.ok) "Connection OK ($status)" else "Connection failed ($status)")
                }
                is ApiResult.Failure -> emit(result.error.message)
                is ApiResult.NetworkError -> emit("Network error")
            }
        }
    }

    /** Delete [mount]; refreshes the list on success. */
    fun delete(mount: FileMount) {
        viewModelScope.launch {
            when (val result = repository.deleteMount(mount.id)) {
                is ApiResult.Success -> {
                    emit("Mount removed")
                    load(isRefresh = true)
                }
                is ApiResult.Failure -> emit(result.error.message)
                is ApiResult.NetworkError -> emit("Network error")
            }
        }
    }

    private fun emit(text: String) {
        viewModelScope.launch { _events.send(MountsEvent.Message(text)) }
    }
}
