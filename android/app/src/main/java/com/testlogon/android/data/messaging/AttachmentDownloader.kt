package com.testlogon.android.data.messaging

import android.content.Context
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn
import retrofit2.HttpException
import java.io.File
import java.io.IOException
import java.util.UUID
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-132 — download progress for a file attachment. Terminal: [Done] (the local file) or [Failed].
 */
sealed interface DownloadProgress {
    data class Downloading(val fraction: Float) : DownloadProgress
    data class Done(val file: File) : DownloadProgress
    data class Failed(val reason: FileError) : DownloadProgress
}

/** AND-132 — structured file-download/open errors (pure; mapped to UI text in the @Composable). */
sealed interface FileError {
    data object GrantExpired : FileError
    data object DownloadFailed : FileError
    data object NoViewer : FileError
    data class Server(val message: String) : FileError
}

/**
 * AND-132 — orchestrates the grant -> (optional) consume -> GET-bytes flow, streaming to app-private
 * cache. Keyed by `message_id` (matches the API surface). A rejected grant on the bytes GET triggers
 * exactly ONE transparent re-grant; a second rejection surfaces [FileError.GrantExpired].
 *
 * The bytes are written to `<cacheDir>/attachments/<messageId>/<fileName>` via a `.part` temp that is
 * atomically renamed on success (no truncated files survive a mid-stream failure). Cache reuse is
 * gated to `consumption_policy:"none"` (once-policy messages are server-gated and re-download).
 */
interface AttachmentDownloader {
    fun download(
        conversationId: String,
        messageId: String,
        fileName: String,
        consumptionPolicy: String,
    ): Flow<DownloadProgress>
}

@Singleton
class DefaultAttachmentDownloader @Inject constructor(
    private val api: MessagingApi,
    @ApplicationContext private val context: Context,
) : AttachmentDownloader {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override fun download(
        conversationId: String,
        messageId: String,
        fileName: String,
        consumptionPolicy: String,
    ): Flow<DownloadProgress> = flow {
        val target = targetFile(messageId, fileName)

        // FR-6: cache reuse only for non-once-policy files.
        if (consumptionPolicy == POLICY_NONE && target.exists() && target.length() > 0L) {
            emit(DownloadProgress.Done(target))
            return@flow
        }

        var lastError: FileError = FileError.DownloadFailed
        // Attempt at most twice: a rejected grant/GET triggers exactly one fresh-grant retry.
        repeat(MAX_GRANT_ATTEMPTS) { attempt ->
            try {
                val grant = api.createAttachmentGrant(conversationId, messageId)

                if (consumptionPolicy == POLICY_VIEW_ONCE || consumptionPolicy == POLICY_LISTEN_ONCE) {
                    api.consumeAttachment(
                        id = conversationId,
                        messageId = messageId,
                        grantToken = grant.grantToken,
                        body = ConsumeAttachmentReq(
                            consumptionAttemptId = UUID.randomUUID().toString(),
                            trigger = if (consumptionPolicy == POLICY_LISTEN_ONCE) "play" else "open",
                        ),
                    )
                }

                val body = api.downloadAttachment(conversationId, messageId, grant.grantToken)
                val total = body.contentLength()
                val part = File(target.parentFile, target.name + ".part")
                part.parentFile?.mkdirs()
                part.delete()

                body.byteStream().use { input ->
                    part.outputStream().use { output ->
                        val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                        var written = 0L
                        while (true) {
                            val read = input.read(buffer)
                            if (read == -1) break
                            output.write(buffer, 0, read)
                            written += read
                            val fraction = if (total > 0L) (written.toFloat() / total).coerceIn(0f, 1f) else 0f
                            emit(DownloadProgress.Downloading(fraction))
                        }
                    }
                }
                if (!part.renameTo(target)) {
                    // Fall back to copy+delete if rename across the same dir somehow fails.
                    part.copyTo(target, overwrite = true)
                    part.delete()
                }
                emit(DownloadProgress.Downloading(1f))
                emit(DownloadProgress.Done(target))
                return@flow
            } catch (e: CancellationException) {
                throw e
            } catch (e: HttpException) {
                // 403/404/410 on grant or GET => expired/rejected; re-grant once then give up.
                lastError = if (e.code() in GRANT_REJECT_CODES) {
                    FileError.GrantExpired
                } else {
                    FileError.Server(e.message())
                }
                if (attempt == MAX_GRANT_ATTEMPTS - 1) {
                    emit(DownloadProgress.Failed(lastError))
                    return@flow
                }
            } catch (e: IOException) {
                lastError = FileError.DownloadFailed
                if (attempt == MAX_GRANT_ATTEMPTS - 1) {
                    emit(DownloadProgress.Failed(lastError))
                    return@flow
                }
            }
        }
        emit(DownloadProgress.Failed(lastError))
    }.flowOn(io)

    private fun targetFile(messageId: String, fileName: String): File {
        val dir = File(File(context.cacheDir, "attachments"), messageId)
        return File(dir, safeName(fileName))
    }

    private companion object {
        const val POLICY_NONE = "none"
        const val POLICY_VIEW_ONCE = "view_once"
        const val POLICY_LISTEN_ONCE = "listen_once"
        const val MAX_GRANT_ATTEMPTS = 2
        val GRANT_REJECT_CODES = setOf(403, 404, 410)

        /** Strip path separators so a malicious/odd file name cannot escape the message cache dir. */
        fun safeName(name: String): String =
            name.substringAfterLast('/').substringAfterLast('\\').ifBlank { "download" }
    }
}
