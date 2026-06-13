package com.testlogon.android.feature.share

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.R
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.share.data.ShareRepository
import com.testlogon.android.feature.share.model.ShareLink
import com.testlogon.android.feature.share.model.ShareLinkOptions
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
 * AND-335 - presentation logic for the OWNER ShareSheet.
 *
 * The file id comes from [SavedStateHandle]. On init the sheet lists the caller's links for that file
 * (the repo lists ALL links and filters by file_node_id). [create] builds a [ShareLinkOptions] from the
 * chosen expiry preset / password / max-downloads and POSTs it (DOUBLE-SEND GUARDED via isCreating).
 * [revoke] is OPTIMISTIC: the row id goes into `revoking` (so it disappears immediately) and is rolled
 * back on failure. [copy] emits a one-shot [ShareSheetEvent.CopyToClipboard] (the platform clipboard +
 * snackbar live in the screen). There is NO poll loop. Plain MutableStateFlow (no combine needed).
 */
@HiltViewModel
class ShareSheetViewModel @Inject constructor(
    private val repository: ShareRepository,
    savedState: SavedStateHandle,
) : ViewModel() {

    private val fileId: String = savedState.get<String>(ARG_FILE_ID).orEmpty()

    private val _uiState = MutableStateFlow(ShareSheetUiState(fileId = fileId))
    val uiState: StateFlow<ShareSheetUiState> = _uiState.asStateFlow()

    private val _events = Channel<ShareSheetEvent>(Channel.BUFFERED)
    val events: Flow<ShareSheetEvent> = _events.receiveAsFlow()

    init {
        if (fileId.isBlank()) {
            _uiState.update { it.copy(isLoading = false) }
        } else {
            refresh()
        }
    }

    /** (Re)load the caller's links for this file. */
    fun refresh() {
        if (fileId.isBlank()) return
        viewModelScope.launch {
            when (val result = repository.listLinks(fileId)) {
                is ApiResult.Success ->
                    _uiState.update {
                        it.copy(links = result.data, isLoading = false, isStale = false)
                    }
                is ApiResult.Failure ->
                    _uiState.update {
                        it.copy(isLoading = false, isStale = true, error = result.error.message)
                    }
                is ApiResult.NetworkError ->
                    _uiState.update { it.copy(isLoading = false, isStale = true, error = OFFLINE) }
            }
        }
    }

    // ---- Create form mutations ----

    fun onExpiryChange(preset: ExpiryPreset) = _uiState.update { it.copy(expiry = preset) }

    fun onPasswordEnabledChange(enabled: Boolean) =
        _uiState.update { it.copy(passwordEnabled = enabled, password = if (enabled) it.password else "") }

    fun onPasswordChange(value: String) = _uiState.update { it.copy(password = value, error = null) }

    fun onMaxDownloadsChange(value: Int) {
        val clamped = value.coerceIn(
            ShareSheetUiState.MIN_DOWNLOADS,
            ShareSheetUiState.MAX_DOWNLOADS_LIMIT,
        )
        _uiState.update { it.copy(maxDownloads = clamped) }
    }

    /**
     * Create a share link with the current form options. DOUBLE-SEND GUARDED (no-op while isCreating).
     * On success the new link is prepended and the result url is copied for convenience.
     */
    fun create() {
        val current = _uiState.value
        if (fileId.isBlank() || !current.canCreate) return
        val options = ShareLinkOptions(
            expiryHours = current.expiry.hours,
            maxDownloads = current.maxDownloads,
            password = if (current.passwordEnabled) current.password else null,
        )
        _uiState.update { it.copy(isCreating = true, error = null) }
        viewModelScope.launch {
            when (val result = repository.createLink(fileId, options)) {
                is ApiResult.Success -> {
                    val link = result.data
                    _uiState.update {
                        it.copy(
                            isCreating = false,
                            links = listOf(link) + it.links,
                            // Reset the password field after a successful create.
                            password = "",
                            passwordEnabled = false,
                        )
                    }
                    _events.trySend(ShareSheetEvent.CopyToClipboard(link.shareUrl))
                    _events.trySend(ShareSheetEvent.ShowMessage(R.string.share_link_created))
                }
                is ApiResult.Failure ->
                    _uiState.update { it.copy(isCreating = false, error = result.error.message) }
                is ApiResult.NetworkError ->
                    _uiState.update { it.copy(isCreating = false, error = OFFLINE) }
            }
        }
    }

    /**
     * Optimistically revoke [linkId]: hide the row immediately (add to `revoking`), POST, then on success
     * drop it from the list, or on failure roll back (remove from `revoking`) + surface an error.
     */
    fun revoke(linkId: String) {
        val current = _uiState.value
        if (linkId in current.revoking) return
        _uiState.update { it.copy(revoking = it.revoking + linkId, error = null) }
        viewModelScope.launch {
            when (val result = repository.revokeLink(linkId)) {
                is ApiResult.Success ->
                    _uiState.update {
                        it.copy(
                            links = it.links.filterNot { link -> link.linkId == linkId },
                            revoking = it.revoking - linkId,
                        )
                    }
                is ApiResult.Failure -> rollbackRevoke(linkId, result.error.message)
                is ApiResult.NetworkError -> rollbackRevoke(linkId, OFFLINE)
            }
        }
    }

    /** Copy [link]'s share url to the clipboard (one-shot event; the screen owns the platform manager). */
    fun copy(link: ShareLink) {
        _events.trySend(ShareSheetEvent.CopyToClipboard(link.shareUrl))
        _events.trySend(ShareSheetEvent.ShowMessage(R.string.share_link_copied))
    }

    /** Clear the one-shot error banner after the UI has shown it. */
    fun consumeError() = _uiState.update { it.copy(error = null) }

    private fun rollbackRevoke(linkId: String, message: String) {
        _uiState.update { it.copy(revoking = it.revoking - linkId, error = message) }
    }

    companion object {
        /** Nav arg carrying the file node id being shared. */
        const val ARG_FILE_ID = "fileId"

        // Non-resource fallback (the screen prefers stringResource where it has a Context).
        private const val OFFLINE = "Couldn't reach the server. Try again."
    }
}
