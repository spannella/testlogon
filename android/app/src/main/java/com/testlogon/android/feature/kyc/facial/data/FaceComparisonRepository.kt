package com.testlogon.android.feature.kyc.facial.data

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.kyc.KycFileAttachmentRequest
import com.testlogon.android.core.model.kyc.KycFileType
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.network.kyc.FaceComparisonApi
import com.testlogon.android.core.network.kyc.KycApi
import com.testlogon.android.data.upload.AttachmentApi
import com.testlogon.android.data.upload.PresignBody
import com.testlogon.android.data.upload.StorageUploadClient
import com.testlogon.android.feature.kyc.facial.model.FaceComparison
import com.testlogon.android.feature.kyc.facial.model.toDomain
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.asRequestBody
import retrofit2.HttpException
import java.io.File
import java.io.IOException
import java.net.SocketTimeoutException
import java.util.UUID
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-323 - data layer for the KYC facial-comparison flow.
 *
 * REUSE: the selfie upload reuses AND-129's [AttachmentApi.presign] (POST `v1/fs/presign-upload`,
 * body {path, content_type}) + [StorageUploadClient.put] (the COOKIELESS [@StorageOkHttp] PUT — the
 * presigned URL is an off-base origin and must NOT carry the session cookie / X-CSRF-Token). The
 * attach reuses AND-319's [KycApi.getCase] (to read the optimistic-concurrency `version` token) +
 * [KycApi.attachFile] (file_type "selfie", expected_version = case.version). The comparison itself is
 * AND-323's [FaceComparisonApi.compareFace] (server-side). DTOs are mapped to the domain BEFORE the
 * typed [ApiResult] (mirrors AND-320 / AND-321 / AND-322).
 *
 * submitSelfie runs the pipeline SEQUENTIALLY: presign -> bare PUT -> getCase (read version) ->
 * attachFile -> compareFace -> map. A 409 on attach (a stale version) surfaces as a typed
 * VersionConflict failure ([ApiError.status] == [HTTP_CONFLICT]); the VM re-submits (this method
 * re-reads the version each call, so a retry picks up the fresh token).
 *
 * DOUBLE-SEND GUARD: within a single in-flight submit, once the selfie has been presigned + PUT +
 * attached, a later FAILURE (e.g. compareFace 5xx) does NOT re-upload — the caller passes back the
 * SAME jpeg File and this method short-circuits the upload+attach when [attachedPath] is already
 * recorded for that file. The guard is per-File (keyed by absolute path) so a fresh selfie (retake)
 * starts a clean upload.
 */
interface FaceComparisonRepository {

    /**
     * Uploads [jpegFile] as the case selfie, attaches it, and runs the server-side comparison.
     * Returns the [FaceComparison] verdict, or a typed failure (VersionConflict carries
     * [ApiError.status] == 409). Idempotent re-upload guard: a re-call with the SAME File skips the
     * already-completed presign/PUT/attach and only re-runs compareFace.
     */
    suspend fun submitSelfie(caseId: String, jpegFile: File): ApiResult<FaceComparison>

    /** Reads the case's prior face-comparison attempts (most-recent-first ordering is server-defined). */
    suspend fun listHistory(caseId: String): ApiResult<List<FaceComparison>>
}

@Singleton
class FaceComparisonRepositoryImpl @Inject constructor(
    private val faceApi: FaceComparisonApi,
    private val kycApi: KycApi,
    private val attachmentApi: AttachmentApi,
    private val storageClient: StorageUploadClient,
    private val errorParser: ApiErrorParser,
) : FaceComparisonRepository {

    // DOUBLE-SEND GUARD state: absolute path of the file already presigned+PUT+attached -> the remote
    // presign path used for the attach. Confined to in-flight submits; a successful compare clears it.
    private var guardedFileKey: String? = null
    private var attachedPath: String? = null

    override suspend fun submitSelfie(
        caseId: String,
        jpegFile: File,
    ): ApiResult<FaceComparison> = withContext(Dispatchers.IO) {
        call {
            // DOUBLE-SEND GUARD: skip the upload+attach if this exact File was already uploaded+attached
            // in a prior (failed-at-compare) call of this submit; otherwise run the full pipeline.
            val alreadyAttached = guardedFileKey == jpegFile.absolutePath && attachedPath != null
            if (!alreadyAttached) {
                guardedFileKey = null
                attachedPath = null

                // ---- PRESIGN (authenticated control-plane POST) ----
                val remotePath = "/kyc/$caseId/selfie-${UUID.randomUUID()}.jpg"
                val presign = attachmentApi.presign(
                    path = PRESIGN_PATH,
                    body = PresignBody(contentType = CONTENT_TYPE_JPEG, path = remotePath),
                )

                // ---- BARE PUT (cookieless; off-base presigned origin) ----
                val body = jpegFile.asRequestBody(CONTENT_TYPE_JPEG.toMediaType())
                val put = storageClient.put(presign.uploadUrl, CONTENT_TYPE_JPEG, body)
                if (!put.success) throw IOException("Storage PUT failed (${put.httpStatus})")

                // ---- ATTACH (AND-319; read fresh version then attach as the selfie) ----
                val version = kycApi.getCase(caseId).case.version
                kycApi.attachFile(
                    caseId = caseId,
                    body = KycFileAttachmentRequest(
                        expected_version = version,
                        path = presign.path ?: remotePath,
                        file_type = KycFileType.SELFIE,
                    ),
                )

                // Record the guard only after a successful attach.
                guardedFileKey = jpegFile.absolutePath
                attachedPath = presign.path ?: remotePath
            }

            // ---- COMPARE (AND-323; server-side comparison) ----
            val comparison = faceApi.compareFace(caseId).toDomain()
            // The selfie has been consumed by a completed comparison; clear the guard so a retake
            // (new File) re-uploads cleanly.
            guardedFileKey = null
            attachedPath = null
            comparison
        }
    }

    override suspend fun listHistory(caseId: String): ApiResult<List<FaceComparison>> =
        withContext(Dispatchers.IO) {
            call {
                faceApi.listComparisons(caseId).comparisons.map { it.toDomain() }
            }
        }

    /**
     * Folds a block into [ApiResult]. HTTP errors -> Failure (via [ApiErrorParser], preserving the
     * status so the VM can detect 409 version conflicts); malformed JSON -> Failure(parse); transport
     * failures -> NetworkError. The JsonEncodingException catch precedes the IOException catch (it is an
     * IOException subtype). Cancellation is re-thrown. Mirrors AND-321 / AND-322.
     */
    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: JsonEncodingException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: JsonDataException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }

    private companion object {
        const val PRESIGN_PATH = "v1/fs/presign-upload"
        const val CONTENT_TYPE_JPEG = "image/jpeg"

        /** HTTP status for an optimistic-concurrency version conflict on attach. */
        const val HTTP_CONFLICT = 409
    }
}
