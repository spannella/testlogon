package com.testlogon.android.data.upload

import android.content.ContentResolver
import android.net.Uri
import android.provider.OpenableColumns
import javax.inject.Inject

/** Resolved metadata for a picked content [Uri]. */
data class UriInfo(
    val sizeBytes: Long,
    val mimeType: String,
    val displayName: String?,
)

/**
 * AND-129 — resolves size / MIME / display name for a picked content [Uri] via the
 * [ContentResolver] (OpenableColumns). Runtime-only; kept out of JVM unit tests.
 */
class UriMetadata @Inject constructor(
    private val contentResolver: ContentResolver,
) {
    fun resolve(uri: Uri, fallbackMime: String = "application/octet-stream"): UriInfo {
        var size = 0L
        var name: String? = null
        runCatching {
            contentResolver.query(uri, null, null, null, null)?.use { cursor ->
                val sizeIndex = cursor.getColumnIndex(OpenableColumns.SIZE)
                val nameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                if (cursor.moveToFirst()) {
                    if (sizeIndex >= 0 && !cursor.isNull(sizeIndex)) size = cursor.getLong(sizeIndex)
                    if (nameIndex >= 0) name = cursor.getString(nameIndex)
                }
            }
        }
        val mime = contentResolver.getType(uri) ?: fallbackMime
        return UriInfo(sizeBytes = size, mimeType = mime, displayName = name)
    }
}
