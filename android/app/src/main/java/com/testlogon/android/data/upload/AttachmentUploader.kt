package com.testlogon.android.data.upload

import android.content.ContentResolver
import com.testlogon.android.core.network.error.ApiErrorParser
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.channelFlow
import kotlinx.coroutines.flow.flowOn
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-129 — reusable upload engine. Each [upload] returns its own cold [Flow]; collecting it starts
 * the work and cancelling the collector cancels the upload (structured concurrency to OkHttp
 * `Call.cancel()`). Multiple concurrent uploads are independent (stateless per call).
 *
 * Public surface is documented so AND-130 / AND-074 can consume without reading the impl.
 */
interface AttachmentUploader {
    /** Cold flow; collection drives presign to PUT to (optional) confirm. */
    fun upload(request: UploadRequest): Flow<UploadProgress>
}

@Singleton
class DefaultAttachmentUploader @Inject constructor(
    private val api: AttachmentApi,
    private val storageClient: StorageUploadClient,
    private val contentResolver: ContentResolver,
    private val errorParser: ApiErrorParser,
) : AttachmentUploader {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override fun upload(request: UploadRequest): Flow<UploadProgress> = channelFlow {
        var terminalSent = false

        suspend fun emitTerminal(progress: UploadProgress) {
            terminalSent = true
            send(progress)
        }

        try {
            // ---- PRESIGN ----
            send(UploadProgress.Preparing)
            val presign = try {
                api.presign(request.presignPath, request.toPresignBody())
            } catch (e: CancellationException) {
                throw e
            } catch (e: HttpException) {
                emitTerminal(UploadProgress.Failed(e.toUploadError(), UploadPhase.PRESIGN))
                return@channelFlow
            } catch (e: IOException) {
                emitTerminal(UploadProgress.Failed(e.toNetworkError(), UploadPhase.PRESIGN))
                return@channelFlow
            }

            // ---- STORAGE PUT (cookieless, streaming) ----
            val body = ProgressRequestBody(
                contentResolver = contentResolver,
                uri = request.uri,
                mimeType = presign.contentType,
                sizeBytes = request.sizeBytes,
            ) { sent -> trySend(UploadProgress.Uploading(sent, request.sizeBytes)) }

            val putResult = try {
                storageClient.put(presign.uploadUrl, presign.contentType, body)
            } catch (e: CancellationException) {
                throw e
            } catch (e: IOException) {
                emitTerminal(UploadProgress.Failed(e.toNetworkError(), UploadPhase.PUT))
                return@channelFlow
            }
            if (!putResult.success) {
                val kind = if (putResult.httpStatus == HTTP_FORBIDDEN) {
                    UploadError.Kind.EXPIRED
                } else {
                    UploadError.Kind.STORAGE
                }
                emitTerminal(
                    UploadProgress.Failed(
                        UploadError(kind = kind, httpStatus = putResult.httpStatus),
                        UploadPhase.PUT,
                    ),
                )
                return@channelFlow
            }
            // Ensure a final 100% emission even if the last chunk callback was conflated away.
            send(UploadProgress.Uploading(request.sizeBytes, request.sizeBytes))

            // ---- CONFIRM (optional; image flow has none) ----
            val confirmPath = request.confirmPath
            val confirm: ConfirmResponse? = if (confirmPath != null) {
                send(UploadProgress.Confirming)
                try {
                    api.confirm(
                        path = confirmPath,
                        body = ConfirmBody(
                            path = presign.path ?: request.remotePath.orEmpty(),
                            key = presign.key,
                            ticketId = presign.ticketId.orEmpty(),
                            contentType = presign.contentType,
                        ),
                    )
                } catch (e: CancellationException) {
                    throw e
                } catch (e: HttpException) {
                    emitTerminal(UploadProgress.Failed(e.toUploadError(), UploadPhase.CONFIRM))
                    return@channelFlow
                } catch (e: IOException) {
                    emitTerminal(UploadProgress.Failed(e.toNetworkError(), UploadPhase.CONFIRM))
                    return@channelFlow
                }
            } else {
                null
            }

            emitTerminal(UploadProgress.Succeeded(presign.toAttachmentRef(request, confirm)))
        } finally {
            // Cooperative-cancellation guard: if nothing terminal was sent, the collector was
            // cancelled mid-flight -> best-effort Cancelled (a no-op if the scope is already gone).
            if (!terminalSent) {
                runCatching { trySend(UploadProgress.Cancelled) }
            }
        }
    }.flowOn(io)

    // ---- error mapping ----

    private fun HttpException.toUploadError(): UploadError {
        val apiError = errorParser.from(this)
        val kind = if (code() == HTTP_UNPROCESSABLE) {
            UploadError.Kind.VALIDATION
        } else {
            UploadError.Kind.SERVER
        }
        return UploadError(kind = kind, httpStatus = code(), message = apiError.message)
    }

    private fun IOException.toNetworkError(): UploadError {
        val kind = if (this is SocketTimeoutException) UploadError.Kind.TIMEOUT else UploadError.Kind.NETWORK
        return UploadError(kind = kind, message = message)
    }

    private companion object {
        const val HTTP_FORBIDDEN = 403
        const val HTTP_UNPROCESSABLE = 422
    }
}

internal fun UploadRequest.toPresignBody(): PresignBody = PresignBody(
    contentType = mimeType,
    filename = displayName,
    path = remotePath,
)

/**
 * Synthesizes the app-side [AttachmentRef] from the presign key/bucket + (optional) confirm result.
 * The display URL follows the web client: use a server-provided url if present, else derive the S3
 * object URL `https://{bucket}.s3.amazonaws.com/{key}` (messagingAdapter.ts: buildS3ObjectUrl).
 */
internal fun PresignResponse.toAttachmentRef(
    request: UploadRequest,
    confirm: ConfirmResponse?,
): AttachmentRef = AttachmentRef(
    id = key,
    bucket = bucket,
    key = key,
    url = s3ObjectUrl(bucket, key),
    contentType = contentType,
    sizeBytes = confirm?.size ?: request.sizeBytes,
    ticketId = ticketId,
    remotePath = path ?: request.remotePath,
)

/**
 * Derives the public S3 object URL, mirroring messagingAdapter.ts: buildS3ObjectUrl. Pure (no
 * android.net.Uri) so it is JVM-unit-testable; percent-encodes per path segment, keeping slashes.
 */
internal fun s3ObjectUrl(bucket: String, key: String): String {
    val encoded = key.split("/").joinToString("/") { segment ->
        java.net.URLEncoder.encode(segment, Charsets.UTF_8.name()).replace("+", "%20")
    }
    return "https://$bucket.s3.amazonaws.com/$encoded"
}
