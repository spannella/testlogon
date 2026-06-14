package com.testlogon.android.feature.kyc.prooffunds.data

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.kyc.ProofOfFundsSubmitRequestDto
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.network.kyc.KycProofOfFundsApi
import com.testlogon.android.data.upload.AttachmentApi
import com.testlogon.android.data.upload.PresignBody
import com.testlogon.android.data.upload.StorageUploadClient
import com.testlogon.android.feature.kyc.prooffunds.model.PoFSummary
import com.testlogon.android.feature.kyc.prooffunds.model.ProofOfFunds
import com.testlogon.android.feature.kyc.prooffunds.model.toDomain
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
 * AND-327 - data layer for the KYC proof-of-funds flow.
 *
 * Wraps AND-327's [KycProofOfFundsApi] (the `ui/kyc/proof-of-funds` summary + submissions + submit control
 * plane, provided by core-network's KycNetworkModule). DTOs are mapped to the feature domain BEFORE the
 * typed [ApiResult] (mirrors AND-320 .. AND-326).
 *
 * REUSE: the optional supporting document upload reuses AND-129's [AttachmentApi.presign] (POST
 * `v1/fs/presign-upload`, body {path, content_type}) + [StorageUploadClient.put] (the COOKIELESS
 * [@StorageOkHttp] bare PUT — the presigned URL is an off-base origin and must NOT carry the session cookie
 * / X-CSRF-Token), exactly as AND-323 reused it. [uploadDocument] returns the presign `key`, which the
 * ViewModel passes back as document_s3_key on [submit]. The proof bytes are produced off-main by AND-321's
 * CaptureImageProcessor in the ViewModel; this layer PUTs the already-processed JPEG file.
 *
 * The submit POST is NON-IDEMPOTENT; the double-send guard lives in the ViewModel (this layer is a thin
 * per-call wrapper). There is NO @IoDispatcher qualifier in this project, so IO work runs under
 * Dispatchers.IO directly.
 */
interface ProofOfFundsRepository {

    /** Reads the proof-of-funds summary (idempotent GET). */
    suspend fun summary(): ApiResult<PoFSummary>

    /** Lists the user's proof-of-funds submissions (idempotent GET). */
    suspend fun submissions(): ApiResult<List<ProofOfFunds>>

    /** Reads a single submission by id (idempotent GET). */
    suspend fun getSubmission(submissionId: String): ApiResult<ProofOfFunds>

    /**
     * Uploads [jpegFile] as the supporting document via presign -> bare PUT and returns the storage `key`
     * to use as document_s3_key. NON-IDEMPOTENT (each call presigns a fresh key).
     */
    suspend fun uploadDocument(jpegFile: File): ApiResult<String>

    /** Submits a proof-of-funds entry (ALL fields optional). NON-IDEMPOTENT POST; success is 200. */
    suspend fun submit(
        sourceCategory: String?,
        declaredAmountCents: Long?,
        currency: String?,
        documentS3Key: String?,
        note: String?,
    ): ApiResult<ProofOfFunds>
}

@Singleton
class ProofOfFundsRepositoryImpl @Inject constructor(
    private val api: KycProofOfFundsApi,
    private val attachmentApi: AttachmentApi,
    private val storageClient: StorageUploadClient,
    private val errorParser: ApiErrorParser,
) : ProofOfFundsRepository {

    override suspend fun summary(): ApiResult<PoFSummary> = withContext(Dispatchers.IO) {
        call { api.summary().toDomain() }
    }

    override suspend fun submissions(): ApiResult<List<ProofOfFunds>> = withContext(Dispatchers.IO) {
        call { api.listSubmissions().submissions.map { it.toDomain() } }
    }

    override suspend fun getSubmission(submissionId: String): ApiResult<ProofOfFunds> =
        withContext(Dispatchers.IO) {
            call { api.getSubmission(submissionId).toDomain() }
        }

    override suspend fun uploadDocument(jpegFile: File): ApiResult<String> =
        withContext(Dispatchers.IO) {
            call {
                // ---- PRESIGN (authenticated control-plane POST) ----
                val remotePath = "/kyc/pof/${UUID.randomUUID()}.jpg"
                val presign = attachmentApi.presign(
                    path = PRESIGN_PATH,
                    body = PresignBody(contentType = CONTENT_TYPE_JPEG, path = remotePath),
                )

                // ---- BARE PUT (cookieless; off-base presigned origin) ----
                val body = jpegFile.asRequestBody(CONTENT_TYPE_JPEG.toMediaType())
                val put = storageClient.put(presign.uploadUrl, CONTENT_TYPE_JPEG, body)
                if (!put.success) throw IOException("Storage PUT failed (${put.httpStatus})")

                presign.key
            }
        }

    override suspend fun submit(
        sourceCategory: String?,
        declaredAmountCents: Long?,
        currency: String?,
        documentS3Key: String?,
        note: String?,
    ): ApiResult<ProofOfFunds> = withContext(Dispatchers.IO) {
        call {
            api.submit(
                ProofOfFundsSubmitRequestDto(
                    source_category = sourceCategory,
                    declared_amount_cents = declaredAmountCents,
                    currency = currency,
                    document_s3_key = documentS3Key,
                    note = note,
                ),
            ).toDomain()
        }
    }

    /**
     * Folds a block into [ApiResult]. HTTP errors -> Failure (via [ApiErrorParser], preserving the status,
     * covering the documented 422 + global 401); malformed JSON -> Failure(parse); transport failures ->
     * NetworkError. The JsonEncodingException catch precedes the IOException catch (it is an IOException
     * subtype). Cancellation is re-thrown. Mirrors AND-323 / AND-326.
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
    }
}
