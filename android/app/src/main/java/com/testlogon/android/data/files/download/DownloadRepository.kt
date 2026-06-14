package com.testlogon.android.data.files.download

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.files.FileNode
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.network.files.FilesApi
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn
import retrofit2.HttpException
import retrofit2.Response
import java.io.File
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-334 - authenticated file download for the Files feature: stream the bytes through the shared
 * authenticated FilesApi client (so Bearer + cookie + CSRF + the 401-refresh apply), copy them to a
 * .part file in the on-disk cache, then commit to a content-addressed entry and hand back a
 * [CachedFile] for the system open-with.
 *
 * CACHE-FIRST: a hit for this file's version emits [DownloadStatus.Success] immediately with no
 * network call. A miss streams api.download(path).body().byteStream() to disk in chunks, emitting
 * [DownloadStatus.InProgress] with bytesDownloaded plus the Content-Length total (nullable - the
 * endpoint may omit it). On completion the .part is committed; on collector cancellation the .part is
 * deleted. Errors map to [DownloadStatus.Failed] via the project's [ApiErrorParser]; retryable is true
 * only for transient classes (network / 429 / 5xx).
 *
 * RANGE / RESUME: not implemented. Every (re)download restarts from byte 0 into a fresh .part;
 * HTTP Range resume is a best-effort future enhancement and intentionally omitted here.
 *
 * Streaming runs on [Dispatchers.IO]; the body is never fully buffered (the FilesApi method is
 * @Streaming).
 */
interface DownloadRepository {
    /**
     * A cold flow that downloads [node] (a file). Re-collecting restarts the download. Cancelling the
     * collector cancels the transfer and deletes the partial file.
     */
    fun download(node: FileNode): Flow<DownloadStatus>
}

@Singleton
class DownloadRepositoryImpl(
    private val api: FilesApi,
    private val cache: FileCacheStore,
    private val errorParser: ApiErrorParser,
    private val io: CoroutineDispatcher,
) : DownloadRepository {

    /** Production constructor: streaming runs on [Dispatchers.IO]. */
    @Inject
    constructor(
        api: FilesApi,
        cache: FileCacheStore,
        errorParser: ApiErrorParser,
    ) : this(api, cache, errorParser, Dispatchers.IO)

    override fun download(node: FileNode): Flow<DownloadStatus> = flow {
        val version = node.updatedAt?.toEpochMilli() ?: 0L
        val key = cache.keyFor(node.path, version)
        val mimeType = node.contentType ?: DEFAULT_MIME
        val displayName = node.name

        // Cache-first: a hit for this version returns immediately, no network.
        cache.get(key, node.path)?.let { hit ->
            emit(DownloadStatus.Success(hit))
            return@flow
        }

        val response: Response<okhttp3.ResponseBody> = try {
            api.download(node.path)
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
        val part: File = cache.newPartFile(key)
        try {
            var downloaded = 0L
            emit(DownloadStatus.InProgress(bytesDownloaded = 0L, totalBytes = total))
            body.byteStream().use { input ->
                part.outputStream().use { output ->
                    val buffer = ByteArray(BUFFER_SIZE)
                    while (true) {
                        // Honour collector cancellation between chunks (deletes the .part in finally).
                        currentCoroutineContext().ensureActive()
                        val read = input.read(buffer)
                        if (read == -1) break
                        output.write(buffer, 0, read)
                        downloaded += read
                        emit(DownloadStatus.InProgress(bytesDownloaded = downloaded, totalBytes = total))
                    }
                    output.flush()
                }
            }
            val committed = cache.commit(key, part, displayName = displayName, mimeType = mimeType)
            emit(
                DownloadStatus.Success(
                    CachedFile(
                        path = node.path,
                        file = committed,
                        mimeType = mimeType,
                        displayName = displayName,
                    ),
                ),
            )
        } catch (e: CancellationException) {
            part.delete()
            throw e
        } catch (e: IOException) {
            part.delete()
            emit(failure(networkError(e), retryable = true))
        }
    }.flowOn(io)

    private fun failure(error: ApiError, retryable: Boolean) =
        DownloadStatus.Failed(error = error, retryable = retryable)

    private fun networkError(e: IOException): ApiError =
        ApiError(status = ApiError.STATUS_NETWORK, message = e.message ?: NETWORK_MESSAGE)

    /** Transient classes worth a retry: 429 and 5xx (documented client errors 400/401/403/422 are not). */
    private fun isRetryable(code: Int): Boolean = code == 429 || code >= 500

    private companion object {
        const val BUFFER_SIZE = 16 * 1024
        const val DEFAULT_MIME = "application/octet-stream"
        const val NETWORK_MESSAGE = "Network error"
    }
}
