package com.testlogon.android.feature.kyc.idscanner.data

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.kyc.KycIdScannerScanRequestDto
import com.testlogon.android.core.model.kyc.KycIdScannerValidateRequestDto
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.network.kyc.KycIdScannerApi
import com.testlogon.android.feature.kyc.capture.data.KycDocumentsRepository
import com.testlogon.android.feature.kyc.idscanner.model.IdDocumentType
import com.testlogon.android.feature.kyc.idscanner.model.IdSide
import com.testlogon.android.feature.kyc.idscanner.model.ScanResult
import com.testlogon.android.feature.kyc.idscanner.model.ValidationInfo
import com.testlogon.android.feature.kyc.idscanner.model.toDomain
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-322 - data layer for the KYC ID-scanner flow.
 *
 * Wraps AND-322's [KycIdScannerApi] (validate-document + per-side scan-document) and REUSES AND-321's
 * [KycDocumentsRepository.uploadDocument] for the base64 image upload (no upload/processing logic is
 * reimplemented here). DTOs are mapped to the domain BEFORE the typed [ApiResult] (mirrors AND-320/AND-321).
 * HTTP errors -> Failure (via [ApiErrorParser], covering 422 validation); transport failures -> NetworkError;
 * cancellation is re-thrown.
 *
 * scan-document is NON-IDEMPOTENT; the double-send guard (don't re-upload an already-uploaded side, don't
 * re-scan an already-succeeded side on retry) lives in the ViewModel — this layer is a thin per-call wrapper.
 */
interface IdScannerRepository {

    /** Asks the server which sides are required and whether an MRZ is expected for [docType] in [caseId]. */
    suspend fun validate(caseId: String, docType: IdDocumentType): ApiResult<ValidationInfo>

    /**
     * Uploads ONE side's processed image (base64) by delegating to AND-321's KycDocumentsRepository.
     * Returns the server document id used as the scan call's image_ref.
     */
    suspend fun uploadSide(
        caseId: String,
        fileType: String,
        fileName: String,
        contentB64: String,
    ): ApiResult<String>

    /** Runs the per-side scan; [imageRef] is the uploaded document id, [mrzLines] the FLAGGED OCR output. */
    suspend fun scanSide(
        caseId: String,
        docType: IdDocumentType,
        side: IdSide,
        imageRef: String?,
        mrzLines: List<String>?,
    ): ApiResult<ScanResult>
}

@Singleton
class IdScannerRepositoryImpl @Inject constructor(
    private val api: KycIdScannerApi,
    private val documentsRepository: KycDocumentsRepository,
    private val errorParser: ApiErrorParser,
) : IdScannerRepository {

    override suspend fun validate(
        caseId: String,
        docType: IdDocumentType,
    ): ApiResult<ValidationInfo> = withContext(Dispatchers.IO) {
        call {
            api.validateDocument(
                caseId = caseId,
                body = KycIdScannerValidateRequestDto(document_type = docType.wireType),
            ).toDomain()
        }
    }

    override suspend fun uploadSide(
        caseId: String,
        fileType: String,
        fileName: String,
        contentB64: String,
    ): ApiResult<String> {
        // REUSE AND-321: the documents repo owns the upload call, error mapping and IO dispatch. The wire
        // document_type for an ID side is the side's file_type (id_front | id_back).
        return when (val result = documentsRepository.uploadDocument(
            documentType = fileType,
            fileName = fileName,
            contentB64 = contentB64,
            caseId = caseId,
        )) {
            is ApiResult.Success -> ApiResult.Success(result.data.documentId)
            is ApiResult.Failure -> result
            is ApiResult.NetworkError -> result
        }
    }

    override suspend fun scanSide(
        caseId: String,
        docType: IdDocumentType,
        side: IdSide,
        imageRef: String?,
        mrzLines: List<String>?,
    ): ApiResult<ScanResult> = withContext(Dispatchers.IO) {
        call {
            api.scanDocument(
                caseId = caseId,
                body = KycIdScannerScanRequestDto(
                    document_type = docType.wireType,
                    file_type = side.fileType,
                    mrz_lines = mrzLines?.takeIf { it.isNotEmpty() },
                    image_ref = imageRef,
                ),
            ).toDomain(side)
        }
    }

    /**
     * Folds a block into [ApiResult]. HTTP errors -> Failure (via [ApiErrorParser]); malformed JSON ->
     * Failure(parse); transport failures -> NetworkError. The JsonEncodingException catch precedes the
     * IOException catch (it is an IOException subtype). Cancellation is re-thrown. Mirrors AND-321.
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
