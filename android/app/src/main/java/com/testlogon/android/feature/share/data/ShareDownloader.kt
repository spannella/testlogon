package com.testlogon.android.feature.share.data

import android.content.ContentValues
import android.content.Context
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.files.PublicDownloadRequest
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.network.share.PublicShareApi
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.FlowCollector
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn
import retrofit2.HttpException
import retrofit2.Response
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-335 - streamed PUBLIC download to the device Downloads collection (session-free).
 *
 * REUSE NOTE: the AND-334 DownloadRepository streams to an in-app CACHE (for open-with), and no
 * MediaStore "Save to Downloads" helper exists in the codebase (verified by grep), so this ticket adds a
 * small dedicated downloader. It mirrors AND-334's @Streaming + chunked-copy + cancellation idiom but
 * targets the public, COOKIELESS [PublicShareApi] and writes into MediaStore Downloads (the recipient is
 * keeping a copy, not previewing a cached file).
 *
 * The bytes stream through [PublicShareApi.downloadPublic] (no cookies / CSRF / Bearer). On Q+ the file
 * goes to MediaStore.Downloads via a pending insert; pre-Q it goes to the public Downloads directory.
 * Progress is emitted with a nullable total (Content-Length may be absent). A wrong/missing password
 * surfaces as a 401/403 [DownloadOutcome.Error] with a clear, non-leaking message.
 */
interface ShareDownloader {
    /**
     * A cold flow that downloads the public link [linkId] (with optional [password] and [fileName] /
     * [contentType] hints from the resolved info). Re-collecting restarts the download; cancelling the
     * collector cancels the transfer.
     */
    fun downloadPublic(
        linkId: String,
        password: String?,
        fileName: String?,
        contentType: String?,
    ): Flow<DownloadOutcome>
}

/** Progress / result of a public download. */
sealed interface DownloadOutcome {
    /** In flight: [bytesDownloaded] of [totalBytes] (null when Content-Length is absent). */
    data class InProgress(val bytesDownloaded: Long, val totalBytes: Long?) : DownloadOutcome

    /** Completed: the saved file's content [uri] and its [displayName]. */
    data class Success(val uri: Uri, val displayName: String) : DownloadOutcome

    /** Failed: a clear, non-leaking [error] plus a [retryable] hint for the UI. */
    data class Error(val error: ApiError, val retryable: Boolean) : DownloadOutcome
}

@Singleton
class ShareDownloaderImpl(
    private val context: Context,
    private val api: PublicShareApi,
    private val errorParser: ApiErrorParser,
    private val io: CoroutineDispatcher,
) : ShareDownloader {

    /** Production constructor: streaming runs on [Dispatchers.IO]. */
    @Inject
    constructor(
        @ApplicationContext context: Context,
        api: PublicShareApi,
        errorParser: ApiErrorParser,
    ) : this(context, api, errorParser, Dispatchers.IO)

    override fun downloadPublic(
        linkId: String,
        password: String?,
        fileName: String?,
        contentType: String?,
    ): Flow<DownloadOutcome> = flow {
        val displayName = fileName?.takeIf { it.isNotBlank() } ?: "download-$linkId"
        val mimeType = contentType?.takeIf { it.isNotBlank() } ?: DEFAULT_MIME

        val response: Response<okhttp3.ResponseBody> = try {
            api.downloadPublic(linkId, PublicDownloadRequest(password = password))
        } catch (e: CancellationException) {
            throw e
        } catch (e: HttpException) {
            emit(failure(errorParser.from(e), retryable = isRetryable(e.code())))
            return@flow
        } catch (e: IOException) {
            emit(failure(networkError(e), retryable = true))
            return@flow
        }

        if (!response.isSuccessful) {
            val http = HttpException(response)
            emit(failure(errorParser.from(http), retryable = isRetryable(response.code())))
            return@flow
        }

        val body = response.body()
        if (body == null) {
            emit(failure(networkError(IOException("Empty download body")), retryable = true))
            return@flow
        }

        val total: Long? = body.contentLength().takeIf { it >= 0L }
        try {
            emit(DownloadOutcome.InProgress(bytesDownloaded = 0L, totalBytes = total))
            val uri = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                streamToMediaStore(body, displayName, mimeType, total)
            } else {
                streamToLegacyDownloads(body, displayName, total)
            }
            emit(DownloadOutcome.Success(uri = uri, displayName = displayName))
        } catch (e: CancellationException) {
            throw e
        } catch (e: IOException) {
            emit(failure(networkError(e), retryable = true))
        }
    }.flowOn(io)

    /** Q+ : insert a PENDING MediaStore Downloads row, stream into it, then clear IS_PENDING. */
    private suspend fun FlowCollector<DownloadOutcome>.streamToMediaStore(
        body: okhttp3.ResponseBody,
        displayName: String,
        mimeType: String,
        total: Long?,
    ): Uri {
        val resolver = context.contentResolver
        val collection = MediaStore.Downloads.getContentUri(MediaStore.VOLUME_EXTERNAL_PRIMARY)
        val values = ContentValues().apply {
            put(MediaStore.Downloads.DISPLAY_NAME, displayName)
            put(MediaStore.Downloads.MIME_TYPE, mimeType)
            put(MediaStore.Downloads.IS_PENDING, 1)
        }
        val uri = resolver.insert(collection, values)
            ?: throw IOException("MediaStore insert returned null")
        try {
            val out = resolver.openOutputStream(uri)
                ?: throw IOException("Could not open MediaStore output stream")
            out.use { output ->
                body.byteStream().use { input -> copyWithProgress(input, output, total) }
            }
            values.clear()
            values.put(MediaStore.Downloads.IS_PENDING, 0)
            resolver.update(uri, values, null, null)
            return uri
        } catch (e: Throwable) {
            // Roll back the pending row on cancellation / failure so no half-written entry lingers.
            runCatching { resolver.delete(uri, null, null) }
            throw e
        }
    }

    /** pre-Q : write into the public Downloads directory and return a file Uri. */
    private suspend fun FlowCollector<DownloadOutcome>.streamToLegacyDownloads(
        body: okhttp3.ResponseBody,
        displayName: String,
        total: Long?,
    ): Uri {
        @Suppress("DEPRECATION")
        val dir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
        if (!dir.exists()) dir.mkdirs()
        val target = uniqueFile(dir, displayName)
        try {
            target.outputStream().use { output ->
                body.byteStream().use { input -> copyWithProgress(input, output, total) }
            }
            return Uri.fromFile(target)
        } catch (e: Throwable) {
            runCatching { target.delete() }
            throw e
        }
    }

    /** Copies [input] to [output] in chunks, honouring cancellation and emitting InProgress. */
    private suspend fun FlowCollector<DownloadOutcome>.copyWithProgress(
        input: InputStream,
        output: OutputStream,
        total: Long?,
    ) {
        val buffer = ByteArray(BUFFER_SIZE)
        var downloaded = 0L
        while (true) {
            currentCoroutineContext().ensureActive()
            val read = input.read(buffer)
            if (read == -1) break
            output.write(buffer, 0, read)
            downloaded += read
            emit(DownloadOutcome.InProgress(bytesDownloaded = downloaded, totalBytes = total))
        }
        output.flush()
    }

    private fun uniqueFile(dir: File, displayName: String): File {
        var candidate = File(dir, displayName)
        if (!candidate.exists()) return candidate
        val dot = displayName.lastIndexOf('.')
        val base = if (dot > 0) displayName.substring(0, dot) else displayName
        val ext = if (dot > 0) displayName.substring(dot) else ""
        var i = 1
        while (candidate.exists()) {
            candidate = File(dir, "$base ($i)$ext")
            i++
        }
        return candidate
    }

    private fun failure(error: ApiError, retryable: Boolean) =
        DownloadOutcome.Error(error = error, retryable = retryable)

    private fun networkError(e: IOException): ApiError =
        ApiError(status = ApiError.STATUS_NETWORK, message = e.message ?: NETWORK_MESSAGE)

    /** Transient classes worth a retry: 429 and 5xx (401/403/404 password/state errors are not). */
    private fun isRetryable(code: Int): Boolean = code == 429 || code >= 500

    private companion object {
        const val BUFFER_SIZE = 16 * 1024
        const val DEFAULT_MIME = "application/octet-stream"
        const val NETWORK_MESSAGE = "Network error"
    }
}
