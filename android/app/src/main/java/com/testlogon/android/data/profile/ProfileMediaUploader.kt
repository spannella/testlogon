package com.testlogon.android.data.profile

import com.testlogon.android.core.model.profile.MediaUploadResult
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.MultipartBody
import okhttp3.RequestBody.Companion.toRequestBody
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-074 — small reusable multipart uploader for profile photos.
 *
 * No backend presign/PUT/confirm flow exists; the verified contract is a single authenticated
 * multipart POST to /ui/profile/photos/{kind}/upload with one part named `file` (reference:
 * src/api/endpoints/profile.ts: uploadProfilePhoto). The bytes transit the app server over the
 * shared authenticated client (cookies + X-CSRF-Token applied by the core-network interceptors).
 *
 * [PreparedUpload] carries already-processed bytes so the uploader stays decoupled from Android
 * image decoding/cropping and is exercisable by JVM unit tests.
 */
interface ProfileMediaUploader {

    /** Already-encoded image bytes ready to POST (e.g. a downscaled, EXIF-stripped JPEG). */
    data class PreparedUpload(
        val bytes: ByteArray,
        val contentType: String = "image/jpeg",
        val fileName: String = "upload.jpg",
    ) {
        override fun equals(other: Any?): Boolean =
            this === other || (
                other is PreparedUpload &&
                    bytes.contentEquals(other.bytes) &&
                    contentType == other.contentType &&
                    fileName == other.fileName
                )

        override fun hashCode(): Int =
            (bytes.contentHashCode() * 31 + contentType.hashCode()) * 31 + fileName.hashCode()
    }

    suspend fun upload(kind: MediaKind, upload: PreparedUpload): MediaUploadResult
}

@Singleton
class ProfileMediaUploaderImpl @Inject constructor(
    private val api: ProfileApi,
) : ProfileMediaUploader {

    override suspend fun upload(
        kind: MediaKind,
        upload: ProfileMediaUploader.PreparedUpload,
    ): MediaUploadResult {
        val body = upload.bytes.toRequestBody(upload.contentType.toMediaType())
        val part = MultipartBody.Part.createFormData("file", upload.fileName, body)
        val resp = api.uploadPhoto(kind.wire, part)
        return MediaUploadResult(
            url = resp.url?.trim()?.takeIf { it.isNotBlank() },
            profile = resp.profile?.toDomain(),
        )
    }
}
