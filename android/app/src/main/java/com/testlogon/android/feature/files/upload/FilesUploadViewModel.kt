package com.testlogon.android.feature.files.upload

import android.net.Uri
import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import com.testlogon.android.feature.files.presentation.FilePath
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.StateFlow
import javax.inject.Inject

/**
 * AND-333 - presentation seam for the upload sheet. Holds NO local copy of the job list - it simply
 * re-exposes the app-singleton [UploadCoordinator]'s [UploadCoordinator.jobs] StateFlow and delegates
 * enqueue / cancel / retry / dismiss to it, so uploads survive this VM (e.g. a config change) and the
 * single coordinator owns the bounded queue.
 *
 * The screen drives the OpenMultipleDocuments picker and hands the chosen Uris to [onFilesPicked] with
 * the folder currently on screen; placement is path-based (no folder_id).
 */
@HiltViewModel
class FilesUploadViewModel @Inject constructor(
    private val coordinator: UploadCoordinator,
    private val savedState: SavedStateHandle,
) : ViewModel() {

    /** All tracked uploads, owned by the coordinator (this VM does not duplicate the state). */
    val uploadJobs: StateFlow<List<UploadJob>> = coordinator.jobs

    /** Enqueues one job per picked [uris], all targeting [targetFolderPath]. */
    fun onFilesPicked(uris: List<Uri>, targetFolderPath: String) {
        val folder = FilePath.normalize(targetFolderPath)
        savedState[KEY_LAST_TARGET] = folder
        uris.forEach { coordinator.enqueue(it, folder) }
    }

    /** Cancels the in-flight job [id]. */
    fun onCancel(id: String) = coordinator.cancel(id)

    /** Retries the FAILED / CANCELLED job [id] from presign (same id; double-send guarded). */
    fun onRetry(id: String) = coordinator.retry(id)

    /** Removes a terminal job's row. */
    fun onDismiss(id: String) = coordinator.dismiss(id)

    private companion object {
        const val KEY_LAST_TARGET = "files_upload_last_target"
    }
}
