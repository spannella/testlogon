package com.testlogon.android.data.adminfraud

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
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
 * B5 admin fraud-review queue - mirrors the web /admin/fraud page (fraud/FraudReviewQueuePage.tsx +
 * api/endpoints/fraudDetection.ts). Backend: fraud_detection.py, prefix /v1/admin/fraud, gated by
 * require_admin_or_root. Surfaces the FLAGS queue (review: approve/block/investigate) and the CASES
 * list (resolve: false_positive/confirmed_fraud/inconclusive). The root-only PATCH /config and the
 * freeze/unfreeze/risk/chargebacks endpoints are deferred. Timestamps are epoch SECONDS.
 */
interface FraudAdminApi {

    @GET("v1/admin/fraud/queue")
    suspend fun queue(@Query("status") status: String): FraudFlagQueueDto

    @POST("v1/admin/fraud/flags/{id}/review")
    suspend fun reviewFlag(
        @Path("id") flagId: String,
        @Body body: FraudFlagReviewReq,
    ): FraudFlagDto

    @GET("v1/admin/fraud/cases")
    suspend fun cases(@Query("status") status: String? = null): List<FraudCaseDto>

    @POST("v1/admin/fraud/cases/{id}/resolve")
    suspend fun resolveCase(
        @Path("id") caseId: String,
        @Body body: FraudCaseResolveReq,
    ): FraudCaseResolveDto
}

@JsonClass(generateAdapter = true)
data class FraudFlagDto(
    @Json(name = "flag_id") val flagId: String,
    @Json(name = "user_id") val userId: String = "",
    @Json(name = "tx_id") val txId: String = "",
    @Json(name = "rule_triggered") val ruleTriggered: String = "",
    @Json(name = "risk_score") val riskScore: Int = 0,
    @Json(name = "amount_cents") val amountCents: Long = 0L,
    @Json(name = "status") val status: String = "",
    @Json(name = "reviewed_by") val reviewedBy: String? = null,
    @Json(name = "reviewed_at") val reviewedAt: Long? = null,
    @Json(name = "resolution") val resolution: String? = null,
    @Json(name = "notes") val notes: String? = null,
    @Json(name = "created_at") val createdAt: Long = 0L,
)

@JsonClass(generateAdapter = true)
data class FraudFlagQueueDto(
    @Json(name = "flags") val flags: List<FraudFlagDto> = emptyList(),
    @Json(name = "count") val count: Int = 0,
    @Json(name = "cursor") val cursor: String? = null,
)

@JsonClass(generateAdapter = true)
data class FraudFlagReviewReq(
    @Json(name = "action") val action: String,
    @Json(name = "notes") val notes: String = "",
)

@JsonClass(generateAdapter = true)
data class FraudCaseDto(
    @Json(name = "case_id") val caseId: String,
    @Json(name = "user_id") val userId: String = "",
    @Json(name = "status") val status: String = "",
    @Json(name = "assigned_to") val assignedTo: String? = null,
    @Json(name = "flags") val flags: List<String> = emptyList(),
    @Json(name = "resolution") val resolution: String? = null,
    @Json(name = "notes") val notes: String? = null,
    @Json(name = "created_at") val createdAt: Long = 0L,
    @Json(name = "resolved_at") val resolvedAt: Long? = null,
)

@JsonClass(generateAdapter = true)
data class FraudCaseResolveReq(
    @Json(name = "resolution") val resolution: String,
    @Json(name = "notes") val notes: String = "",
)

@JsonClass(generateAdapter = true)
data class FraudCaseResolveDto(
    @Json(name = "case_id") val caseId: String = "",
    @Json(name = "status") val status: String = "",
    @Json(name = "resolution") val resolution: String? = null,
)

interface FraudAdminRepository {
    suspend fun queue(status: String): ApiResult<FraudFlagQueueDto>
    suspend fun reviewFlag(flagId: String, action: String, notes: String): ApiResult<FraudFlagDto>
    suspend fun cases(status: String?): ApiResult<List<FraudCaseDto>>
    suspend fun resolveCase(caseId: String, resolution: String, notes: String): ApiResult<FraudCaseResolveDto>
}

@Singleton
class DefaultFraudAdminRepository @Inject constructor(
    private val api: FraudAdminApi,
    private val errorParser: ApiErrorParser,
) : FraudAdminRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun queue(status: String): ApiResult<FraudFlagQueueDto> =
        withContext(io) { call { api.queue(status) } }

    override suspend fun reviewFlag(flagId: String, action: String, notes: String): ApiResult<FraudFlagDto> =
        withContext(io) { call { api.reviewFlag(flagId, FraudFlagReviewReq(action, notes.trim())) } }

    override suspend fun cases(status: String?): ApiResult<List<FraudCaseDto>> =
        withContext(io) { call { api.cases(status) } }

    override suspend fun resolveCase(caseId: String, resolution: String, notes: String): ApiResult<FraudCaseResolveDto> =
        withContext(io) { call { api.resolveCase(caseId, FraudCaseResolveReq(resolution, notes.trim())) } }

    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }
}

@Module
@InstallIn(SingletonComponent::class)
object FraudAdminApiModule {
    @Provides
    @Singleton
    fun provideFraudAdminApi(retrofit: Retrofit): FraudAdminApi =
        retrofit.create(FraudAdminApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class FraudAdminDataModule {
    @dagger.Binds
    @Singleton
    abstract fun bindFraudAdminRepository(impl: DefaultFraudAdminRepository): FraudAdminRepository
}
