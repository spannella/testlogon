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
 * A1 + B1 (case detail) — the main KYC case review queue. Mirrors web /admin/kyc (KycQueuePage.tsx +
 * api/endpoints/kyc-admin.ts). Backend kyc_cases.py, prefix /v1/kyc/cases/admin, admin-gated (in-body
 * role check). queue -> detail -> approve/reject/request-info. Approve/reject send an optimistic-lock
 * expected_version + reason_codes + note; request-info sends requested_items. Epoch SECONDS.
 */
interface KycCaseAdminApi {

    @GET("v1/kyc/cases/admin/queue")
    suspend fun queue(
        @Query("status") status: String? = null,
        @Query("risk_tier") riskTier: String? = null,
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int? = null,
    ): KycQueueEnvelopeDto

    @GET("v1/kyc/cases/admin/cases/{caseId}")
    suspend fun detail(@Path("caseId") caseId: String): KycCaseDetailEnvelopeDto

    @POST("v1/kyc/cases/admin/cases/{caseId}/approve")
    suspend fun approve(@Path("caseId") caseId: String, @Body body: KycDecisionReq)

    @POST("v1/kyc/cases/admin/cases/{caseId}/reject")
    suspend fun reject(@Path("caseId") caseId: String, @Body body: KycDecisionReq)

    @POST("v1/kyc/cases/admin/cases/{caseId}/request-info")
    suspend fun requestInfo(@Path("caseId") caseId: String, @Body body: KycRequestInfoReq)
}

@JsonClass(generateAdapter = true)
data class KycQueueItemDto(
    @Json(name = "kyc_case_id") val kycCaseId: String,
    @Json(name = "user_sub") val userSub: String = "",
    @Json(name = "status") val status: String = "",
    @Json(name = "assigned_admin_sub") val assignedAdminSub: String? = null,
    @Json(name = "created_at") val createdAt: Long = 0L,
    @Json(name = "updated_at") val updatedAt: Long = 0L,
    @Json(name = "waiting_seconds") val waitingSeconds: Long? = null,
    @Json(name = "risk_tier") val riskTier: String? = null,
)

@JsonClass(generateAdapter = true)
data class KycQueueEnvelopeDto(
    @Json(name = "items") val items: List<KycQueueItemDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
)

@JsonClass(generateAdapter = true)
data class KycFileRefDto(
    @Json(name = "type") val type: String = "",
    @Json(name = "path") val path: String = "",
    @Json(name = "verification_state") val verificationState: String = "",
    @Json(name = "uploaded_at") val uploadedAt: Long? = null,
)

@JsonClass(generateAdapter = true)
data class KycDecisionStateDto(
    @Json(name = "decision") val decision: String? = null,
    @Json(name = "decided_at") val decidedAt: Long? = null,
    @Json(name = "reason_codes") val reasonCodes: List<String> = emptyList(),
    @Json(name = "assigned_admin_sub") val assignedAdminSub: String? = null,
)

@JsonClass(generateAdapter = true)
data class KycCaseDetailDto(
    @Json(name = "kyc_case_id") val kycCaseId: String,
    @Json(name = "user_sub") val userSub: String = "",
    @Json(name = "status") val status: String = "",
    @Json(name = "files_ref") val filesRef: List<KycFileRefDto> = emptyList(),
    @Json(name = "decision_state") val decisionState: KycDecisionStateDto? = null,
    @Json(name = "version") val version: Int = 0,
)

@JsonClass(generateAdapter = true)
data class KycCaseDetailEnvelopeDto(
    @Json(name = "case") val case: KycCaseDetailDto,
)

@JsonClass(generateAdapter = true)
data class KycDecisionReq(
    @Json(name = "decision") val decision: String,
    @Json(name = "expected_version") val expectedVersion: Int,
    @Json(name = "reason_codes") val reasonCodes: List<String>,
    @Json(name = "note") val note: String,
)

@JsonClass(generateAdapter = true)
data class KycRequestInfoReq(
    @Json(name = "expected_version") val expectedVersion: Int,
    @Json(name = "requested_items") val requestedItems: List<String>,
    @Json(name = "note") val note: String,
)

interface KycCaseAdminRepository {
    suspend fun queue(status: String?): ApiResult<KycQueueEnvelopeDto>
    suspend fun detail(caseId: String): ApiResult<KycCaseDetailDto>
    suspend fun approve(caseId: String, version: Int, reasonCodes: List<String>, note: String): ApiResult<Unit>
    suspend fun reject(caseId: String, version: Int, reasonCodes: List<String>, note: String): ApiResult<Unit>
    suspend fun requestInfo(caseId: String, version: Int, items: List<String>, note: String): ApiResult<Unit>
}

@Singleton
class DefaultKycCaseAdminRepository @Inject constructor(
    private val api: KycCaseAdminApi,
    private val errorParser: ApiErrorParser,
) : KycCaseAdminRepository {

    override suspend fun queue(status: String?): ApiResult<KycQueueEnvelopeDto> =
        io { api.queue(status = status) }

    override suspend fun detail(caseId: String): ApiResult<KycCaseDetailDto> =
        io { api.detail(caseId).case }

    override suspend fun approve(caseId: String, version: Int, reasonCodes: List<String>, note: String): ApiResult<Unit> =
        io { api.approve(caseId, KycDecisionReq("approve", version, reasonCodes, note.trim())) }

    override suspend fun reject(caseId: String, version: Int, reasonCodes: List<String>, note: String): ApiResult<Unit> =
        io { api.reject(caseId, KycDecisionReq("reject", version, reasonCodes, note.trim())) }

    override suspend fun requestInfo(caseId: String, version: Int, items: List<String>, note: String): ApiResult<Unit> =
        io { api.requestInfo(caseId, KycRequestInfoReq(version, items, note.trim())) }

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
object KycCaseAdminApiModule {
    @Provides
    @Singleton
    fun provideKycCaseAdminApi(retrofit: Retrofit): KycCaseAdminApi =
        retrofit.create(KycCaseAdminApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class KycCaseAdminDataModule {
    @dagger.Binds
    @Singleton
    abstract fun bindKycCaseAdminRepository(impl: DefaultKycCaseAdminRepository): KycCaseAdminRepository
}
