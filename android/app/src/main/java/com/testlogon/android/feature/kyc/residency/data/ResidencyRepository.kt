package com.testlogon.android.feature.kyc.residency.data

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.kyc.AddressInputDto
import com.testlogon.android.core.model.kyc.KycResidencyUploadRequestDto
import com.testlogon.android.core.model.kyc.PostalCodeValidationRequestDto
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.network.kyc.KycResidencyApi
import com.testlogon.android.feature.kyc.residency.model.AddressForm
import com.testlogon.android.feature.kyc.residency.model.AddressVerification
import com.testlogon.android.feature.kyc.residency.model.ResidencyDocType
import com.testlogon.android.feature.kyc.residency.model.ResidencyDocument
import com.testlogon.android.feature.kyc.residency.model.toDomain
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-326 - data layer for the two KYC residency / address-verification surfaces.
 *
 * Wraps AND-326's [KycResidencyApi] (both the `ui/kyc/residency` proof-of-residency document surface and the
 * `v1/kyc/address-verification` structured address surface, provided by core-network's KycNetworkModule).
 * DTOs are mapped to the feature domain BEFORE the typed [ApiResult] (mirrors AND-320 / AND-321 / AND-325).
 *
 * BOTH surfaces are REAL REST: the proof image/PDF is uploaded as inline base64 (the ViewModel produces the
 * base64 off-main via AND-321's CaptureImageProcessor); the address is verified server-side. NO vendor / ML
 * / CameraX SDK, NO flagged seam.
 *
 * The mutating POSTs are NON-IDEMPOTENT; the double-send guard against re-POSTing an already-succeeded
 * upload / verify on retry lives in the ViewModel (this layer is a thin per-call wrapper). There is NO
 * @IoDispatcher qualifier in this project, so IO work runs under Dispatchers.IO directly.
 */
interface ResidencyRepository {

    /** Lists the user's uploaded proof-of-residency documents (idempotent GET). */
    suspend fun residencyDocuments(): ApiResult<List<ResidencyDocument>>

    /**
     * Uploads ONE proof-of-residency document. [contentB64] is the base64 (NO_WRAP) body the caller produced
     * off the main thread. NON-IDEMPOTENT.
     */
    suspend fun uploadResidency(
        docType: ResidencyDocType,
        issuingEntity: String,
        documentDate: String,
        fileName: String,
        contentB64: String,
        caseId: String? = null,
    ): ApiResult<ResidencyDocument>

    /** Triggers server-side address extraction on an uploaded document (NON-IDEMPOTENT POST). */
    suspend fun extractResidency(documentId: String): ApiResult<ResidencyDocument>

    /** Verifies the structured [form] for [caseId] (NON-IDEMPOTENT POST). */
    suspend fun verifyAddress(caseId: String, form: AddressForm): ApiResult<AddressVerification>

    /** Reads the current address-verification result for [caseId] (idempotent GET). */
    suspend fun getAddressVerification(caseId: String): ApiResult<AddressVerification>

    /** Validates a [postal] code for [country] (optional convenience; NON-IDEMPOTENT POST). */
    suspend fun validatePostalCode(postal: String, country: String): ApiResult<Boolean>
}

@Singleton
class ResidencyRepositoryImpl @Inject constructor(
    private val api: KycResidencyApi,
    private val errorParser: ApiErrorParser,
) : ResidencyRepository {

    override suspend fun residencyDocuments(): ApiResult<List<ResidencyDocument>> =
        withContext(Dispatchers.IO) {
            call { api.listResidency().documents.map { it.toDomain() } }
        }

    override suspend fun uploadResidency(
        docType: ResidencyDocType,
        issuingEntity: String,
        documentDate: String,
        fileName: String,
        contentB64: String,
        caseId: String?,
    ): ApiResult<ResidencyDocument> = withContext(Dispatchers.IO) {
        call {
            api.uploadResidency(
                KycResidencyUploadRequestDto(
                    document_type = docType.wire,
                    issuing_entity = issuingEntity,
                    document_date = documentDate,
                    file_name = fileName,
                    content_b64 = contentB64,
                    case_id = caseId,
                ),
            ).toDomain()
        }
    }

    override suspend fun extractResidency(documentId: String): ApiResult<ResidencyDocument> =
        withContext(Dispatchers.IO) {
            call { api.extractResidency(documentId).toDomain() }
        }

    override suspend fun verifyAddress(caseId: String, form: AddressForm): ApiResult<AddressVerification> =
        withContext(Dispatchers.IO) {
            call {
                api.verifyAddress(
                    caseId,
                    AddressInputDto(
                        line_1 = form.line1,
                        line_2 = form.line2.ifBlank { null },
                        city = form.city,
                        state = form.state,
                        postal_code = form.postalCode,
                        country = form.country,
                    ),
                ).toDomain()
            }
        }

    override suspend fun getAddressVerification(caseId: String): ApiResult<AddressVerification> =
        withContext(Dispatchers.IO) {
            call { api.getAddressVerification(caseId).toDomain() }
        }

    override suspend fun validatePostalCode(postal: String, country: String): ApiResult<Boolean> =
        withContext(Dispatchers.IO) {
            call {
                api.validatePostalCode(
                    PostalCodeValidationRequestDto(postal_code = postal, country = country),
                ).valid
            }
        }

    /**
     * Folds a block into [ApiResult]. HTTP errors -> Failure (via [ApiErrorParser], preserving the status,
     * covering the documented 422 + global 401); malformed JSON -> Failure(parse); transport failures ->
     * NetworkError. The JsonEncodingException catch precedes the IOException catch (it is an IOException
     * subtype). Cancellation is re-thrown. Mirrors AND-321 / AND-325.
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
