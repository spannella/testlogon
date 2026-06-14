package com.testlogon.android.feature.files.upload

import android.content.ContentResolver
import android.net.Uri
import com.testlogon.android.data.upload.ProgressRequestBody
import com.testlogon.android.data.upload.StorageUploadClient
import com.testlogon.android.data.upload.UriMetadata
import okhttp3.RequestBody
import javax.inject.Inject

/** AND-333 - resolved metadata for a picked content [Uri] (display name, MIME, byte size). */
data class UploadMetadata(
    val displayName: String,
    val mimeType: String,
    val sizeBytes: Long,
)

/**
 * AND-333 - the Android-runtime seam the [UploadCoordinator] depends on, isolating ContentResolver +
 * the streaming [ProgressRequestBody] so the coordinator's leg sequencing is JVM-unit-testable with a
 * fake. The production impl reuses the AND-129 [UriMetadata] resolver and [ProgressRequestBody] (the
 * same 8 KB streaming body the attachment uploader uses) so uploads never buffer the whole file.
 */
interface UploadSource {

    /** Resolves display name / MIME / size for [uri] via the content resolver (OpenableColumns). */
    fun metadata(uri: Uri): UploadMetadata

    /**
     * A streaming [RequestBody] for [uri] that reports cumulative bytes via [onProgress]. [mimeType]
     * and [sizeBytes] come from the presign / resolved metadata so OkHttp emits a real Content-Length.
     */
    fun requestBody(
        uri: Uri,
        mimeType: String,
        sizeBytes: Long,
        onProgress: (bytesSent: Long) -> Unit,
    ): RequestBody
}

/** Production [UploadSource] over the AND-129 [UriMetadata] + [ProgressRequestBody]. */
class ContentResolverUploadSource @Inject constructor(
    private val contentResolver: ContentResolver,
    private val uriMetadata: UriMetadata,
) : UploadSource {

    override fun metadata(uri: Uri): UploadMetadata {
        val info = uriMetadata.resolve(uri)
        val name = info.displayName?.takeIf { it.isNotBlank() } ?: fallbackName(uri)
        return UploadMetadata(displayName = name, mimeType = info.mimeType, sizeBytes = info.sizeBytes)
    }

    override fun requestBody(
        uri: Uri,
        mimeType: String,
        sizeBytes: Long,
        onProgress: (bytesSent: Long) -> Unit,
    ): RequestBody = ProgressRequestBody(
        contentResolver = contentResolver,
        uri = uri,
        mimeType = mimeType,
        sizeBytes = sizeBytes,
        onProgress = onProgress,
    )

    private fun fallbackName(uri: Uri): String =
        uri.lastPathSegment?.substringAfterLast('/')?.takeIf { it.isNotBlank() } ?: "upload"
}

/**
 * AND-333 - narrow seam for the bare storage PUT, so the [UploadCoordinator] is JVM-unit-testable with
 * a fake (mockito-core cannot cleanly stub the concrete client's suspend `put`). The production impl
 * DELEGATES verbatim to the AND-129 [StorageUploadClient.put] (the @StorageOkHttp cookieless client),
 * so no PUT logic is duplicated or changed.
 */
interface StoragePut {
    suspend fun put(url: String, contentType: String, body: RequestBody): StorageUploadClient.PutResult
}

/** Production [StoragePut] delegating to the reused [StorageUploadClient]. */
class DelegatingStoragePut @Inject constructor(
    private val client: StorageUploadClient,
) : StoragePut {
    override suspend fun put(
        url: String,
        contentType: String,
        body: RequestBody,
    ): StorageUploadClient.PutResult = client.put(url, contentType, body)
}
