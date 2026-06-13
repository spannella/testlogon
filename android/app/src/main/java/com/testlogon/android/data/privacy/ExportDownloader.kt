package com.testlogon.android.data.privacy

import android.content.ContentValues
import android.content.Context
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.network.error.ApiErrorParser
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import okhttp3.ResponseBody
import retrofit2.HttpException
import retrofit2.Response
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-385 - streams a COMPLETED export artifact to the device Downloads collection (FR-4 / AC-3).
 *
 * REUSE NOTE: mirrors the AND-335 ShareDownloader @Streaming + chunked-copy + cancellation + MediaStore idiom,
 * but targets the AUTHENTICATED [PrivacyApi.downloadExport] (cookies / CSRF / Bearer attached by the shared
 * interceptor) and returns a single outcome (the repository wraps it in ApiResult). The filename is
 * `testlogon-export-<requestId>-<yyyyMMdd>.<ext>`; the extension is derived defensively from the
 * Content-Type/Content-Disposition headers (NOT hard-coded .zip, per the unverified media-type assumption -
 * §16 claim 11). On any partial-write failure the half-written MediaStore row is rolled back so a truncated
 * file is never presented as complete (FR / §7). Export file bytes are NEVER logged.
 */
interface ExportDownloader {
    /** Downloads the export for [requestId] to Downloads; returns the saved content [Uri]. */
    suspend fun download(requestId: String): DownloadResult
}

/** AND-385 - the result of an export download. */
sealed interface DownloadResult {
    data class Success(val uri: Uri, val displayName: String) : DownloadResult
    data class Failure(val error: ApiError, val retryable: Boolean) : DownloadResult
}

@Singleton
class DefaultExportDownloader(
    private val context: Context,
    private val api: PrivacyApi,
    private val errorParser: ApiErrorParser,
    private val io: CoroutineDispatcher,
) : ExportDownloader {

    /** Production constructor: streaming runs on [Dispatchers.IO]. */
    @Inject
    constructor(
        @ApplicationContext context: Context,
        api: PrivacyApi,
        errorParser: ApiErrorParser,
    ) : this(context, api, errorParser, Dispatchers.IO)

    override suspend fun download(requestId: String): DownloadResult = withContext(io) {
        val response: Response<ResponseBody> = try {
            api.downloadExport(requestId)
        } catch (e: CancellationException) {
            throw e
        } catch (e: HttpException) {
            return@withContext DownloadResult.Failure(errorParser.from(e), retryable = isRetryable(e.code()))
        } catch (e: IOException) {
            return@withContext DownloadResult.Failure(networkError(e), retryable = true)
        }

        if (!response.isSuccessful) {
            val http = HttpException(response)
            return@withContext DownloadResult.Failure(
                errorParser.from(http),
                retryable = isRetryable(response.code()),
            )
        }

        val body = response.body()
            ?: return@withContext DownloadResult.Failure(
                networkError(IOException("Empty download body")),
                retryable = true,
            )

        val ext = extensionFor(
            contentType = response.headers()["Content-Type"],
            contentDisposition = response.headers()["Content-Disposition"],
        )
        val mime = response.headers()["Content-Type"]?.substringBefore(';')?.trim()
            ?.takeIf { it.isNotBlank() } ?: DEFAULT_MIME
        val displayName = "testlogon-export-$requestId-${today()}$ext"

        try {
            val uri = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                streamToMediaStore(body, displayName, mime)
            } else {
                streamToLegacyDownloads(body, displayName)
            }
            DownloadResult.Success(uri = uri, displayName = displayName)
        } catch (e: CancellationException) {
            throw e
        } catch (e: IOException) {
            DownloadResult.Failure(networkError(e), retryable = true)
        }
    }

    /** Q+ : insert a PENDING MediaStore Downloads row, stream into it, then clear IS_PENDING. */
    private suspend fun streamToMediaStore(
        body: ResponseBody,
        displayName: String,
        mimeType: String,
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
            out.use { output -> body.byteStream().use { input -> copy(input, output) } }
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
    private suspend fun streamToLegacyDownloads(body: ResponseBody, displayName: String): Uri {
        @Suppress("DEPRECATION")
        val dir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
        if (!dir.exists()) dir.mkdirs()
        val target = uniqueFile(dir, displayName)
        try {
            target.outputStream().use { output -> body.byteStream().use { input -> copy(input, output) } }
            return Uri.fromFile(target)
        } catch (e: Throwable) {
            runCatching { target.delete() }
            throw e
        }
    }

    /** Copies [input] to [output] in chunks, honouring cancellation. */
    private suspend fun copy(input: InputStream, output: OutputStream) {
        val buffer = ByteArray(BUFFER_SIZE)
        while (true) {
            currentCoroutineContext().ensureActive()
            val read = input.read(buffer)
            if (read == -1) break
            output.write(buffer, 0, read)
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

    private fun networkError(e: IOException): ApiError =
        ApiError(status = ApiError.STATUS_NETWORK, message = e.message ?: NETWORK_MESSAGE)

    /** Transient classes worth a retry: 429 and 5xx (401/403/404 state errors are not). */
    private fun isRetryable(code: Int): Boolean = code == 429 || code >= 500

    private fun today(): String = SimpleDateFormat("yyyyMMdd", Locale.US).format(Date())

    private companion object {
        const val BUFFER_SIZE = 16 * 1024
        const val DEFAULT_MIME = "application/octet-stream"
        const val NETWORK_MESSAGE = "Network error"

        /**
         * Derives a file extension defensively from headers (the media type is NOT declared in OpenAPI). A
         * `filename=...ext` in Content-Disposition wins; otherwise a known Content-Type maps to an extension;
         * otherwise default to `.zip` (the export artifact is an archive in practice).
         */
        fun extensionFor(contentType: String?, contentDisposition: String?): String {
            val fromDisposition = contentDisposition
                ?.substringAfter("filename=", "")
                ?.trim('"', ' ')
                ?.substringAfterLast('.', "")
                ?.takeIf { it.isNotBlank() }
            if (fromDisposition != null) return ".$fromDisposition"
            val mime = contentType?.substringBefore(';')?.trim()?.lowercase()
            return when (mime) {
                "application/zip", "application/x-zip-compressed" -> ".zip"
                "application/json" -> ".json"
                "application/gzip", "application/x-gzip" -> ".gz"
                "text/csv" -> ".csv"
                else -> ".zip"
            }
        }
    }
}
