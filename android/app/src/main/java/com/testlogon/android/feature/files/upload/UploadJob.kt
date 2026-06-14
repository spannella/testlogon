package com.testlogon.android.feature.files.upload

import android.net.Uri

/**
 * AND-333 - lifecycle of a single in-process file upload (presign to PUT to confirm).
 *
 * Ordering reflects the leg sequence: QUEUED (waiting on the bounded-concurrency permit), PREPARING
 * (resolving content metadata + presign), UPLOADING (the bare storage PUT, with byte progress),
 * CONFIRMING (the complete-upload call), then a terminal DONE / FAILED / CANCELLED. Resumable /
 * background uploads (WorkManager) are intentionally DEFERRED; this wave keeps everything in-process.
 */
enum class UploadState { QUEUED, PREPARING, UPLOADING, CONFIRMING, DONE, FAILED, CANCELLED }

/**
 * AND-333 - one tracked upload. [id] is a stable UUID kept across retry so the UI row and the
 * double-send guard can identify the same logical upload. [sourceUri] is the picked content Uri;
 * [targetFolderPath] is the destination folder (the object path is targetFolderPath + displayName).
 * [resultPath] is the canonical path the server returned on confirm (its name is authoritative).
 */
data class UploadJob(
    val id: String,
    val sourceUri: Uri,
    val displayName: String,
    val mimeType: String,
    val sizeBytes: Long,
    val targetFolderPath: String,
    val state: UploadState = UploadState.QUEUED,
    val progress: Float = 0f,
    val error: String? = null,
    val resultPath: String? = null,
) {
    /** True while the job is still doing work (eligible for cancel, not eligible for retry). */
    val isActive: Boolean
        get() = state == UploadState.QUEUED ||
            state == UploadState.PREPARING ||
            state == UploadState.UPLOADING ||
            state == UploadState.CONFIRMING

    /** True for a job that ended unsuccessfully and may be retried. */
    val isFailed: Boolean
        get() = state == UploadState.FAILED
}
