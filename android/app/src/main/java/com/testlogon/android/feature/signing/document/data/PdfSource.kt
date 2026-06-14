package com.testlogon.android.feature.signing.document.data

import android.content.Context
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.network.signing.SigningApi
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
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-341 - the PDF byte source for the document viewer.
 *
 * REUSE: streams AND-339's SigningApi.downloadFinalPdf (the only streamed PDF endpoint -- @Streaming, so
 * Retrofit never buffers the whole body) to a per-packet cache file, mirroring AND-334's
 * DownloadRepository chunked-copy + between-chunk cancellation idiom. The endpoint serves the assembled
 * FINAL pdf; see the assumption note in [downloadPdf].
 *
 * The downloaded bytes are validated by the PDF magic header before the file is handed back, so a stray
 * HTML/JSON error page never reaches the renderer.
 */
interface PdfSource {

    /**
     * Downloads (or reuses a cached) PDF for [packetId] and returns the on-disk [File]. A non-empty
     * cache hit is returned without a network call; otherwise the bytes are streamed to disk, the magic
     * header is verified, and the committed file is returned. HTTP -> Failure, transport -> NetworkError.
     */
    suspend fun downloadPdf(packetId: String): ApiResult<File>
}

@Singleton
class PdfSourceImpl(
    private val api: SigningApi,
    private val errorParser: ApiErrorParser,
    private val cacheDir: File,
    private val io: CoroutineDispatcher,
) : PdfSource {

    /** Production constructor: targets the app cache dir, streaming on [Dispatchers.IO]. */
    @Inject
    constructor(
        api: SigningApi,
        errorParser: ApiErrorParser,
        @ApplicationContext context: Context,
    ) : this(api, errorParser, context.cacheDir, Dispatchers.IO)

    override suspend fun downloadPdf(packetId: String): ApiResult<File> = withContext(io) {
        val target = targetFile(packetId)

        // Cache-first: a present, non-empty file is reused (short-TTL re-download is intentionally not
        // implemented -- keep it simple; AND-342 re-opens the same file).
        if (target.isFile && target.length() > 0L) {
            return@withContext ApiResult.Success(target)
        }

        val response: Response<ResponseBody> = try {
            api.downloadFinalPdf(packetId)
        } catch (e: CancellationException) {
            throw e
        } catch (e: HttpException) {
            return@withContext ApiResult.Failure(errorParser.from(e))
        } catch (e: IOException) {
            return@withContext ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
        }

        if (!response.isSuccessful) {
            return@withContext ApiResult.Failure(errorParser.from(HttpException(response)))
        }
        val body = response.body()
            ?: return@withContext ApiResult.NetworkError(IOException("Empty PDF body"))

        val part = File(target.parentFile, target.name + PART_SUFFIX)
        try {
            body.byteStream().use { input ->
                part.outputStream().use { output ->
                    val buffer = ByteArray(BUFFER_SIZE)
                    while (true) {
                        // Honour viewer cancellation between chunks (the .part is cleaned up below).
                        currentCoroutineContext().ensureActive()
                        val read = input.read(buffer)
                        if (read == -1) break
                        output.write(buffer, 0, read)
                    }
                    output.flush()
                }
            }
        } catch (e: CancellationException) {
            part.delete()
            throw e
        } catch (e: IOException) {
            part.delete()
            return@withContext ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
        }

        if (!hasPdfMagic(part)) {
            part.delete()
            return@withContext ApiResult.Failure(
                ApiError(status = ApiError.STATUS_PARSE, message = CORRUPT_MESSAGE),
            )
        }

        // Commit: atomic-ish rename over any prior file.
        target.delete()
        if (!part.renameTo(target)) {
            // Fall back to a copy if rename across the same dir fails for any reason.
            part.copyTo(target, overwrite = true)
            part.delete()
        }
        ApiResult.Success(target)
    }

    private fun targetFile(packetId: String): File {
        val dir = File(cacheDir, DOCUMENTS_DIR).apply { mkdirs() }
        return File(dir, sanitize(packetId) + ".pdf")
    }

    private companion object {
        const val BUFFER_SIZE = 16 * 1024
        const val DOCUMENTS_DIR = "documents"
        const val PART_SUFFIX = ".part"
        const val CORRUPT_MESSAGE = "This document could not be opened."

        /** The 5-byte PDF file signature, as a byte array (kept out of comments to avoid a slash-star). */
        val PDF_MAGIC = byteArrayOf(0x25, 0x50, 0x44, 0x46, 0x2D)

        /** Verifies the file begins with the PDF signature; a short/garbage body fails fast. */
        fun hasPdfMagic(file: File): Boolean {
            if (file.length() < PDF_MAGIC.size) return false
            val head = ByteArray(PDF_MAGIC.size)
            file.inputStream().use { input ->
                var off = 0
                while (off < head.size) {
                    val n = input.read(head, off, head.size - off)
                    if (n == -1) return false
                    off += n
                }
            }
            return head.contentEquals(PDF_MAGIC)
        }

        /** Keeps the cache filename to a safe basename (packet ids are opaque, but be defensive). */
        fun sanitize(packetId: String): String =
            packetId.map { if (it.isLetterOrDigit() || it == '_' || it == '-') it else '_' }
                .joinToString("")
                .ifEmpty { "packet" }
    }
}
