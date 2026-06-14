package com.testlogon.android.data.upload

import android.content.ContentResolver
import android.net.Uri
import okhttp3.MediaType
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.RequestBody
import okio.BufferedSink
import okio.source
import java.io.IOException

/**
 * AND-129 — streaming OkHttp [RequestBody] that copies a content [Uri] to the storage PUT in 8 KB
 * chunks, reporting cumulative bytes after each chunk WITHOUT buffering the whole file in memory.
 *
 * Runtime-only (uses [ContentResolver]); kept out of JVM unit tests. [contentLength] returns the
 * caller-resolved [sizeBytes] so OkHttp emits a real `Content-Length` (no chunked transfer).
 */
class ProgressRequestBody(
    private val contentResolver: ContentResolver,
    private val uri: Uri,
    private val mimeType: String,
    private val sizeBytes: Long,
    private val onProgress: (bytesSent: Long) -> Unit,
) : RequestBody() {

    override fun contentType(): MediaType? = mimeType.toMediaTypeOrNull()

    override fun contentLength(): Long = sizeBytes

    override fun writeTo(sink: BufferedSink) {
        val input = contentResolver.openInputStream(uri)
            ?: throw IOException("Unable to open input stream for $uri")
        input.source().use { source ->
            val buffer = okio.Buffer()
            var sent = 0L
            while (true) {
                val read = source.read(buffer, CHUNK_SIZE)
                if (read == -1L) break
                sink.write(buffer, read)
                sent += read
                onProgress(sent)
            }
        }
    }

    private companion object {
        const val CHUNK_SIZE = 8L * 1024L
    }
}
