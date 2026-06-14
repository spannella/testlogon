package com.testlogon.android.feature.files.download

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.files.FileNode
import com.testlogon.android.data.files.download.CachedFile
import com.testlogon.android.data.files.download.DownloadRepository
import com.testlogon.android.data.files.download.DownloadStatus
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
 * AND-334 - UI state for the download / open-with affordance.
 *
 *  - [Idle] - nothing in flight.
 *  - [InProgress] - bytes streaming; [fraction] is null when the server omits Content-Length.
 *  - [Success] - the file is cached and ready to open / save.
 *  - [Cancelled] - the user cancelled an in-flight download.
 *  - [Error] - the download failed; [retryable] hints whether a retry is worthwhile.
 */
sealed interface FileDownloadUiState {
    data object Idle : FileDownloadUiState

    data class InProgress(
        val fraction: Float?,
        val bytesDownloaded: Long,
        val totalBytes: Long?,
    ) : FileDownloadUiState

    data class Success(val cached: CachedFile) : FileDownloadUiState

    data object Cancelled : FileDownloadUiState

    data class Error(val message: String, val retryable: Boolean) : FileDownloadUiState
}

/** AND-334 - one-shot effect: open the just-downloaded file via the system open-with. */
data class OpenFile(val cached: CachedFile)

/**
 * AND-334 - presentation logic for downloading a file then opening it with an external app.
 *
 * [onDownload] collects the bounded [DownloadRepository.download] flow (which finishes when the stream
 * ends - there is NO poll loop) and projects it into [uiState]. On success it ALSO emits a one-shot
 * [OpenFile] event so the screen can fire the open-with intent (which needs a Context the VM must not
 * hold). [onCancel] cancels the collecting job, which cancels the transfer and deletes the partial
 * file; the repository then yields no terminal status, so the VM marks [FileDownloadUiState.Cancelled]
 * itself. [onSaveToDownloads] re-emits the cached success for the screen to copy into Downloads.
 */
@HiltViewModel
class FileActionsViewModel @Inject constructor(
    private val repository: DownloadRepository,
    private val savedState: SavedStateHandle,
) : ViewModel() {

    private val _uiState = MutableStateFlow<FileDownloadUiState>(FileDownloadUiState.Idle)
    val uiState: StateFlow<FileDownloadUiState> = _uiState.asStateFlow()

    private val _events = Channel<OpenFile>(Channel.BUFFERED)
    val events: Flow<OpenFile> = _events.receiveAsFlow()

    /** The single in-flight download job; [onCancel] cancels exactly this one. */
    private var downloadJob: Job? = null

    /** Starts (or restarts) downloading [node], cancelling any in-flight download first. */
    fun onDownload(node: FileNode) {
        downloadJob?.cancel()
        _uiState.value = FileDownloadUiState.InProgress(fraction = null, bytesDownloaded = 0L, totalBytes = null)
        downloadJob = viewModelScope.launch {
            repository.download(node).collect { status ->
                when (status) {
                    is DownloadStatus.InProgress -> _uiState.value = FileDownloadUiState.InProgress(
                        fraction = status.fraction,
                        bytesDownloaded = status.bytesDownloaded,
                        totalBytes = status.totalBytes,
                    )

                    is DownloadStatus.Success -> {
                        _uiState.value = FileDownloadUiState.Success(status.cached)
                        _events.send(OpenFile(status.cached))
                    }

                    DownloadStatus.Cancelled -> _uiState.value = FileDownloadUiState.Cancelled

                    is DownloadStatus.Failed -> _uiState.value = FileDownloadUiState.Error(
                        message = status.error.message,
                        retryable = status.retryable,
                    )
                }
            }
        }
    }

    /** Cancels the in-flight download (deletes the partial file) and marks the state Cancelled. */
    fun onCancel() {
        if (downloadJob?.isActive != true) return
        downloadJob?.cancel()
        downloadJob = null
        _uiState.value = FileDownloadUiState.Cancelled
    }

    /** Re-emits the cached success so the screen can copy it into the public Downloads collection. */
    fun onSaveToDownloads(): CachedFile? =
        (_uiState.value as? FileDownloadUiState.Success)?.cached

    /** Resets to [FileDownloadUiState.Idle] (e.g. after the progress surface is dismissed). */
    fun onDismiss() {
        if (downloadJob?.isActive == true) return
        _uiState.value = FileDownloadUiState.Idle
    }
}
