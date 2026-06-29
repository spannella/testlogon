package com.testlogon.android.feature.support.data

import android.content.ContentResolver
import android.net.Uri
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.files.CompleteUploadRequest
import com.testlogon.android.core.model.files.FileNode
import com.testlogon.android.core.model.files.FileNodeType
import com.testlogon.android.core.model.files.PresignRequest
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.network.files.FilesApi
import com.testlogon.android.core.network.files.toDomain
import com.testlogon.android.data.feed.CommentImageUploader
import com.testlogon.android.data.upload.StorageUploadClient
import com.testlogon.android.data.upload.UriMetadata
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.RequestBody.Companion.toRequestBody
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import java.util.UUID
import javax.inject.Inject
import javax.inject.Singleton

/**
 * B10 B-HELPMEDIA #5 - uploads picked media for the Support ticket composers and resolves file-manager
 * picks, producing the [SupportMediaItem]s the ticket create/reply attach as media[].
 *
 * Three paths, each reusing a PROVEN seam (no new backend endpoint):
 *  - IMAGE -> the shared [CommentImageUploader] (POST uploads/image, the same multipart upload the
 *    feed/comments use) -> a platform URL -> a {kind:"image", url} item.
 *  - VIDEO / FILE -> the file-manager VFS presign-PUT-complete flow ([FilesApi] + [StorageUploadClient],
 *    the same control plane the Files UploadCoordinator uses) into /tickets/<uuid>/<name>, then attached
 *    as a {kind:"file_ref", path} item so the server resolves name / content_type / size / thumbnail on
 *    read (the backend _resolve_ticket_media contract). NOTE the uploads/image endpoint REJECTS
 *    non-image content (HTTP 400), so video / file must NOT go through it - hence the VFS path.
 *  - FILE-MANAGER PICK -> an already-stored VFS file attached directly as {kind:"file_ref", path}.
 *
 * Every call folds into [ApiResult] and never throws (CancellationException is re-thrown).
 */
interface SupportMediaUploader {
    suspend fun uploadImage(uri: Uri): ApiResult<SupportMediaItem>
    suspend fun uploadVideo(uri: Uri): ApiResult<SupportMediaItem>
    suspend fun uploadFile(uri: Uri): ApiResult<SupportMediaItem>
    fun fileRefFor(node: FileNode): SupportMediaItem
    suspend fun listManagerFiles(query: String?): ApiResult<List<FileNode>>

    companion object {
        /** Hard cap matching the backend media list max_length. */
        const val MAX_MEDIA = 10
    }
}

@Singleton
class SupportMediaUploaderImpl @Inject constructor(
    private val imageUploader: CommentImageUploader,
    private val filesApi: FilesApi,
    private val storage: StorageUploadClient,
    private val uriMetadata: UriMetadata,
    private val contentResolver: ContentResolver,
    private val errorParser: ApiErrorParser,
) : SupportMediaUploader {

    override suspend fun uploadImage(uri: Uri): ApiResult<SupportMediaItem> =
        when (val r = imageUploader.uploadImage(uri)) {
            is ApiResult.Success ->
                ApiResult.Success(SupportMediaItem(kind = SupportMediaKind.IMAGE, url = r.data))
            is ApiResult.Failure -> ApiResult.Failure(r.error)
            is ApiResult.NetworkError -> ApiResult.NetworkError(r.cause, r.isTimeout)
        }

    override suspend fun uploadVideo(uri: Uri): ApiResult<SupportMediaItem> =
        uploadToVfs(uri, fallbackMime = "video/mp4", fallbackName = "video.mp4")

    override suspend fun uploadFile(uri: Uri): ApiResult<SupportMediaItem> =
        uploadToVfs(uri, fallbackMime = "application/octet-stream", fallbackName = "file.bin")

    override fun fileRefFor(node: FileNode): SupportMediaItem = SupportMediaItem(
        kind = SupportMediaKind.FILE_REF,
        path = node.path,
        name = node.name,
        contentType = node.contentType,
        sizeBytes = node.sizeBytes,
        thumbnail = node.posterUrl,
    )

    override suspend fun listManagerFiles(query: String?): ApiResult<List<FileNode>> =
        io {
            val q = query?.trim().orEmpty()
            val nodes = if (q.isNotBlank()) {
                filesApi.search(prefix = q, limit = 50).toDomain().results
            } else {
                filesApi.list(path = "/", limit = 100).toDomain().items
            }
            nodes.filter { it.type == FileNodeType.FILE }
        }

    /**
     * Presign -> bare PUT -> complete into /tickets/<uuid>/<name>, returning a FILE_REF item that carries
     * the stored VFS [FileNode.path] (the server resolves the rest on read).
     */
    private suspend fun uploadToVfs(
        uri: Uri,
        fallbackMime: String,
        fallbackName: String,
    ): ApiResult<SupportMediaItem> = io {
        val info = uriMetadata.resolve(uri, fallbackMime = fallbackMime)
        val mime = info.mimeType.ifBlank { fallbackMime }
        val safeName = (info.displayName ?: fallbackName)
            .map { c -> if (c == '/' || c == 92.toChar()) '_' else c }.joinToString("").ifBlank { fallbackName }
        val vfsPath = "/tickets/${UUID.randomUUID()}/$safeName"

        val presign = filesApi.presignUpload(PresignRequest(path = vfsPath, content_type = mime))
        val ctype = presign.content_type ?: mime

        val bytes = contentResolver.openInputStream(uri)?.use { it.readBytes() }
            ?: throw IOException("Could not read the selected file")
        val body = bytes.toRequestBody(ctype.toMediaTypeOrNull())
        val put = storage.put(presign.upload_url, ctype, body)
        if (!put.success) {
            throw IOException("Upload failed (HTTP ${put.httpStatus})")
        }
        val node = filesApi.completeUpload(
            CompleteUploadRequest(
                path = presign.path,
                key = presign.key,
                ticket_id = presign.ticket_id,
                content_type = ctype,
            ),
        ).toDomain()
        SupportMediaItem(
            kind = SupportMediaKind.FILE_REF,
            path = node.path.ifBlank { presign.path },
            name = node.name.ifBlank { safeName },
            contentType = node.contentType ?: ctype,
            sizeBytes = node.sizeBytes ?: info.sizeBytes.takeIf { it > 0 },
            thumbnail = node.posterUrl,
        )
    }

    private suspend fun <T> io(block: suspend () -> T): ApiResult<T> = withContext(Dispatchers.IO) {
        try {
            ApiResult.Success(block())
        } catch (e: CancellationException) {
            throw e
        } catch (e: HttpException) {
            ApiResult.Failure(errorParser.from(e))
        } catch (e: IOException) {
            ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
        }
    }
}
