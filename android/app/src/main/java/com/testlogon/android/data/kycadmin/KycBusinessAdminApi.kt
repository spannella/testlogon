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
import retrofit2.http.Query
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * A8 — business (KYB) case review queue. Mirrors web /admin/kyc/business (kycBusiness.ts). Backend
 * /v1/kyc/business-cases/admin/{queue,{caseId},{caseId}/screen,{caseId}/approve,{caseId}/reject}.
 * approve/reject send an optimistic-lock expected_version + reason_codes + note. Epoch SECONDS.
 */
interface KycBusinessAdminApi {
    @GET("v1/kyc/business-cases/admin/queue")
    suspend fun queue(@Query("status") status: String? = null): KybQueueDto

    @GET("v1/kyc/business-cases/admin/{caseId}")
    suspend fun detail(@Path("caseId") caseId: String): KybCaseEnvelopeDto

    @POST("v1/kyc/business-cases/admin/{caseId}/screen")
    suspend fun screen(@Path("caseId") caseId: String, @Body body: Map<String, String> = emptyMap()): Unit

    @POST("v1/kyc/business-cases/admin/{caseId}/approve")
    suspend fun approve(@Path("caseId") caseId: String, @Body body: KybDecisionReq): KybCaseEnvelopeDto

    @POST("v1/kyc/business-cases/admin/{caseId}/reject")
    suspend fun reject(@Path("caseId") caseId: String, @Body body: KybDecisionReq): KybCaseEnvelopeDto
}

@JsonClass(generateAdapter = true)
data class KybCompanyDto(
    @Json(name = "legal_name") val legalName: String = "",
    @Json(name = "trading_name") val tradingName: String? = null,
    @Json(name = "registration_number") val registrationNumber: String = "",
    @Json(name = "jurisdiction") val jurisdiction: String = "",
    @Json(name = "company_type") val companyType: String = "",
    @Json(name = "industry") val industry: String? = null,
)

@JsonClass(generateAdapter = true)
data class KybUboSummaryDto(
    @Json(name = "total_ubos") val totalUbos: Int = 0,
    @Json(name = "all_kyc_approved") val allKycApproved: Boolean = false,
    @Json(name = "total_ownership_pct") val totalOwnershipPct: Double = 0.0,
)

@JsonClass(generateAdapter = true)
data class KybCaseDto(
    @Json(name = "kyb_case_id") val kybCaseId: String,
    @Json(name = "user_sub") val userSub: String = "",
    @Json(name = "status") val status: String = "",
    @Json(name = "company") val company: KybCompanyDto = KybCompanyDto(),
    @Json(name = "ubo_summary") val uboSummary: KybUboSummaryDto = KybUboSummaryDto(),
    @Json(name = "director_count") val directorCount: Int = 0,
    @Json(name = "document_count") val documentCount: Int = 0,
    @Json(name = "version") val version: Int = 0,
    @Json(name = "created_at") val createdAt: Long = 0L,
)

@JsonClass(generateAdapter = true)
data class KybQueueDto(
    @Json(name = "cases") val cases: List<KybCaseDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class KybCaseEnvelopeDto(
    @Json(name = "case") val case: KybCaseDto,
)

@JsonClass(generateAdapter = true)
data class KybDecisionReq(
    @Json(name = "expected_version") val expectedVersion: Int,
    @Json(name = "reason_codes") val reasonCodes: List<String> = emptyList(),
    @Json(name = "note") val note: String? = null,
)

interface KycBusinessAdminRepository {
    suspend fun queue(status: String?): ApiResult<List<KybCaseDto>>
    suspend fun detail(caseId: String): ApiResult<KybCaseDto>
    suspend fun screen(caseId: String): ApiResult<Unit>
    suspend fun approve(caseId: String, version: Int, reasonCodes: List<String>, note: String): ApiResult<KybCaseDto>
    suspend fun reject(caseId: String, version: Int, reasonCodes: List<String>, note: String): ApiResult<KybCaseDto>
}

@Singleton
class DefaultKycBusinessAdminRepository @Inject constructor(
    private val api: KycBusinessAdminApi,
    private val errorParser: ApiErrorParser,
) : KycBusinessAdminRepository {
    override suspend fun queue(status: String?) = io { api.queue(status).cases }
    override suspend fun detail(caseId: String) = io { api.detail(caseId).case }
    override suspend fun screen(caseId: String) = io { api.screen(caseId) }
    override suspend fun approve(caseId: String, version: Int, reasonCodes: List<String>, note: String) =
        io { api.approve(caseId, KybDecisionReq(version, reasonCodes, note.trim().ifBlank { null })).case }
    override suspend fun reject(caseId: String, version: Int, reasonCodes: List<String>, note: String) =
        io { api.reject(caseId, KybDecisionReq(version, reasonCodes, note.trim().ifBlank { null })).case }

    private suspend fun <T> io(block: suspend () -> T): ApiResult<T> = withContext(Dispatchers.IO) {
        try { ApiResult.Success(block()) }
        catch (e: CancellationException) { throw e }
        catch (e: HttpException) { ApiResult.Failure(errorParser.from(e)) }
        catch (e: IOException) { ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException) }
    }
}

@Module
@InstallIn(SingletonComponent::class)
object KycBusinessAdminApiModule {
    @Provides @Singleton
    fun provideKycBusinessAdminApi(retrofit: Retrofit): KycBusinessAdminApi = retrofit.create(KycBusinessAdminApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class KycBusinessAdminDataModule {
    @dagger.Binds @Singleton
    abstract fun bindKycBusinessAdminRepository(impl: DefaultKycBusinessAdminRepository): KycBusinessAdminRepository
}
