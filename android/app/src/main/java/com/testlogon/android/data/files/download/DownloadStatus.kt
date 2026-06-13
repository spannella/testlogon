package com.testlogon.android.data.files.download

import com.testlogon.android.core.model.ApiError
import java.io.File

/**
 * AND-334 - a file that has been fully downloaded and committed to the on-disk download cache.
 *
 * [file] is a real file under the app cache (cacheDir/fs-downloads/), shareable to external viewers
 * through the existing FileProvider (authority "applicationId.fileprovider"). [path] is the server
 * file path it was downloaded from; [mimeType] / [displayName] come from the source [FileNode] (the
 * download endpoint advertises a misleading application/json content-type, so the node metadata is
 * authoritative for the open-with intent).
 */
data class CachedFile(
    val path: String,
    val file: File,
    val mimeType: String,
    val displayName: String,
)

/**
 * AND-334 - progress of one streamed download.
 *
 *  - [InProgress] - bytes are streaming to disk; [totalBytes] is null when the server omits
 *    Content-Length (the UI then shows an indeterminate bar via a null [fraction]).
 *  - [Success] - bytes are committed to the cache as [cached].
 *  - [Cancelled] - the collector cancelled; the partial .part file was deleted.
 *  - [Failed] - the transfer failed; [retryable] is true for transient transport / 429 / 5xx and
 *    false for client / auth errors (400/401/403/422) that a blind retry will not fix.
 */
sealed interface DownloadStatus {
    data class InProgress(val bytesDownloaded: Long, val totalBytes: Long?) : DownloadStatus {
        /** Fraction in 0..1, or null when the total is unknown (indeterminate progress). */
        val fraction: Float?
            get() = totalBytes?.takeIf { it > 0L }?.let { (bytesDownloaded.toFloat() / it).coerceIn(0f, 1f) }
    }

    data class Success(val cached: CachedFile) : DownloadStatus

    data object Cancelled : DownloadStatus

    data class Failed(val error: ApiError, val retryable: Boolean) : DownloadStatus
}
