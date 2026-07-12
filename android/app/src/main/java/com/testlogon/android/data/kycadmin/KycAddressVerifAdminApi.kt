package com.testlogon.android.data.kycadmin

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import retrofit2.Retrofit
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * B6 - KYC address-verification panel. Mirrors web /admin/kyc/address-verification
 * (KycAddressVerificationPanel.tsx + api/endpoints/kycAddressVerification.ts). Backend
 * kyc_address_verification.py, prefix /v1/kyc/address-verification, admin-gated. All operations are
 * case-scoped: the admin enters a case id, then GET the current verification + attempts, and can
 * validate a postal code / cross-reference a document address / override the decision. Epoch SECONDS.
 */
interface KycAddressVerifAdminApi {

    @GET("v1/kyc/address-verification/cases/{caseId}")
    suspend fun get(@Path("caseId") caseId: String): AddressVerificationEnvelopeDto

    @GET("v1/kyc/address-verification/cases/{caseId}/attempts")
    suspend fun attempts(@Path("caseId") caseId: String): AddressVerificationListDto

    @POST("v1/kyc/address-verification/validate-postal-code")
    suspend fun validatePostal(@Body body: PostalCodeReq): PostalCodeValidationDto

    @POST("v1/kyc/address-verification/cases/{caseId}/cross-reference")
    suspend fun crossReference(@Path("caseId") caseId: String, @Body body: CrossReferenceReq): CrossReferenceEnvelopeDto

    @POST("v1/kyc/address-verification/cases/{caseId}/override")
    suspend fun override(@Path("caseId") caseId: String, @Body body: AddressOverrideReq): AddressVerificationEnvelopeDto
}

@JsonClass(generateAdapter = true)
data class KycAddressInputDto(
    @Json(name = "line_1") val line1: String = "",
    @Json(name = "line_2") val line2: String? = null,
    @Json(name = "city") val city: String = "",
    @Json(name = "state") val state: String? = null,
    @Json(name = "postal_code") val postalCode: String = "",
    @Json(name = "country") val country: String = "",
)

@JsonClass(generateAdapter = true)
data class AddressVerificationOutDto(
    @Json(name = "verification_id") val verificationId: String? = null,
    @Json(name = "kyc_case_id") val kycCaseId: String? = null,
    @Json(name = "status") val status: String = "",
    @Json(name = "decision") val decision: String = "",
    @Json(name = "confidence_score") val confidenceScore: Double = 0.0,
    @Json(name = "country") val country: String? = null,
    @Json(name = "country_format_valid") val countryFormatValid: Boolean = false,
    @Json(name = "postal_format_hint") val postalFormatHint: String = "",
    @Json(name = "input_address") val inputAddress: KycAddressInputDto? = null,
    @Json(name = "standardized_address") val standardizedAddress: KycAddressInputDto? = null,
    @Json(name = "discrepancies") val discrepancies: List<String> = emptyList(),
    @Json(name = "provider") val provider: String? = null,
    @Json(name = "verified_at") val verifiedAt: Long? = null,
    @Json(name = "created_at") val createdAt: Long = 0L,
    @Json(name = "updated_at") val updatedAt: Long = 0L,
)

@JsonClass(generateAdapter = true)
data class AddressVerificationEnvelopeDto(
    @Json(name = "verification") val verification: AddressVerificationOutDto,
)

@JsonClass(generateAdapter = true)
data class AddressVerificationListDto(
    @Json(name = "attempts") val attempts: List<AddressVerificationOutDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class PostalCodeReq(
    @Json(name = "postal_code") val postalCode: String,
    @Json(name = "country") val country: String,
)

@JsonClass(generateAdapter = true)
data class PostalCodeValidationDto(
    @Json(name = "valid") val valid: Boolean = false,
    @Json(name = "format_hint") val formatHint: String = "",
    @Json(name = "normalized") val normalized: String = "",
)

@JsonClass(generateAdapter = true)
data class CrossReferenceReq(
    @Json(name = "document_address") val documentAddress: KycAddressInputDto,
)

@JsonClass(generateAdapter = true)
data class CrossReferenceOutDto(
    @Json(name = "match_score") val matchScore: Double = 0.0,
    @Json(name = "discrepancies") val discrepancies: List<String> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class CrossReferenceEnvelopeDto(
    @Json(name = "cross_reference") val crossReference: CrossReferenceOutDto,
)

@JsonClass(generateAdapter = true)
data class AddressOverrideReq(
    @Json(name = "decision") val decision: String,
    @Json(name = "note") val note: String? = null,
)

interface KycAddressVerifAdminRepository {
    suspend fun get(caseId: String): ApiResult<AddressVerificationOutDto>
    suspend fun attempts(caseId: String): ApiResult<List<AddressVerificationOutDto>>
    suspend fun validatePostal(postal: String, country: String): ApiResult<PostalCodeValidationDto>
    suspend fun override(caseId: String, decision: String, note: String): ApiResult<AddressVerificationOutDto>
}

@Singleton
class DefaultKycAddressVerifAdminRepository @Inject constructor(
    private val api: KycAddressVerifAdminApi,
    private val errorParser: ApiErrorParser,
) : KycAddressVerifAdminRepository {

    override suspend fun get(caseId: String): ApiResult<AddressVerificationOutDto> =
        io { api.get(caseId.trim()).verification }

    override suspend fun attempts(caseId: String): ApiResult<List<AddressVerificationOutDto>> =
        io { api.attempts(caseId.trim()).attempts }

    override suspend fun validatePostal(postal: String, country: String): ApiResult<PostalCodeValidationDto> =
        io { api.validatePostal(PostalCodeReq(postal.trim(), country.trim())) }

    override suspend fun override(caseId: String, decision: String, note: String): ApiResult<AddressVerificationOutDto> =
        io { api.override(caseId.trim(), AddressOverrideReq(decision, note.trim().ifEmpty { null })).verification }

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

@Module
@InstallIn(SingletonComponent::class)
object KycAddressVerifAdminApiModule {
    @Provides
    @Singleton
    fun provideKycAddressVerifAdminApi(retrofit: Retrofit): KycAddressVerifAdminApi =
        retrofit.create(KycAddressVerifAdminApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class KycAddressVerifAdminDataModule {
    @dagger.Binds
    @Singleton
    abstract fun bindKycAddressVerifAdminRepository(impl: DefaultKycAddressVerifAdminRepository): KycAddressVerifAdminRepository
}
