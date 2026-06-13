package com.testlogon.android.feature.kyc.capture.data

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.kyc.KycDocumentUploadRequestDto
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.network.kyc.KycDocumentsApi
import com.testlogon.android.feature.kyc.capture.model.KycDocument
import com.testlogon.android.feature.kyc.capture.model.toDomain
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-321 - data layer for the KYC identity-document upload surface.
 *
 * Wraps AND-321's [KycDocumentsApi] (ui/kyc/documents). ONE [uploadDocument] call uploads ONE image
 * (a front+back ID is two calls, driven sequentially by the ViewModel). The DTO is mapped to the domain
 * [KycDocument] BEFORE the typed [ApiResult] (mirrors AND-320's KycTierRepositoryImpl). HTTP errors ->
 * Failure (via [ApiErrorParser], covering the 422 validation + 403 CSRF cases); transport failures ->
 * NetworkError; cancellation is re-thrown. There is NO @IoDispatcher qualifier in this project, so IO
 * work runs under Dispatchers.IO directly.
 *
 * The endpoint is NON-IDEMPOTENT; the double-send guard against re-uploading an already-succeeded image
 * on retry lives in the ViewModel (this layer is a thin per-call wrapper).
 */
interface KycDocumentsRepository {

    /**
     * Uploads ONE document image. [contentB64] is the base64 (NO_WRAP) JPEG body the caller produced
     * off the main thread. [documentType] is the fixed wire enum id (id_front | id_back).
     */
    suspend fun uploadDocument(
        documentType: String,
        fileName: String,
        contentB64: String,
        caseId: String? = null,
    ): ApiResult<KycDocument>
}

@Singleton
class KycDocumentsRepositoryImpl @Inject constructor(
    private val api: KycDocumentsApi,
    private val errorParser: ApiErrorParser,
) : KycDocumentsRepository {

    override suspend fun uploadDocument(
        documentType: String,
        fileName: String,
        contentB64: String,
        caseId: String?,
    ): ApiResult<KycDocument> = withContext(Dispatchers.IO) {
        call {
            api.uploadDocument(
                KycDocumentUploadRequestDto(
                    document_type = documentType,
                    file_name = fileName,
                    content_b64 = contentB64,
                    case_id = caseId,
                ),
            ).toDomain()
        }
    }

    /**
     * Folds a block into [ApiResult]. HTTP errors -> Failure (via [ApiErrorParser]); malformed JSON ->
     * Failure(parse); transport failures -> NetworkError. The JsonEncodingException catch precedes the
     * IOException catch (it is an IOException subtype). Cancellation is re-thrown. Mirrors AND-320's
     * KycTierRepositoryImpl.call.
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
}
