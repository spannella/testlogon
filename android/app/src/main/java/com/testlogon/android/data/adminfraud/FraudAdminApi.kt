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
 * B5 / FIN-015 admin fraud-detection console - mirrors the web /admin/fraud page
 * (api/endpoints/fraudDetection.ts). Backend: fraud_detection.py, prefix /v1/admin/fraud, gated by
 * require_admin_or_root. Surfaces the FLAGS queue (review: approve/block/investigate), the CASES list
 * (resolve: false_positive/confirmed_fraud/inconclusive), and per-user RISK lookup + freeze/unfreeze.
 * The root-only PATCH /config, /chargebacks, /stats, and case-create endpoints are deferred (no UI
 * surface). Timestamps are epoch SECONDS.
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

    @GET("v1/admin/fraud/users/{id}/risk")
    suspend fun userRisk(@Path("id") userId: String): UserRiskProfileDto

    @POST("v1/admin/fraud/users/{id}/freeze")
    suspend fun freezeUser(
        @Path("id") userId: String,
        @Body body: FreezeUserReq,
    ): FreezeResultDto

    @POST("v1/admin/fraud/users/{id}/unfreeze")
    suspend fun unfreezeUser(@Path("id") userId: String): FreezeResultDto
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

/** Mirrors UserRiskProfile (models.py). Composite score 0-100 + freeze state + 24h velocity. */
@JsonClass(generateAdapter = true)
data class UserRiskProfileDto(
    @Json(name = "user_id") val userId: String = "",
    @Json(name = "score") val score: Int = 0,
    @Json(name = "components") val components: Map<String, Int> = emptyMap(),
    @Json(name = "flagged") val flagged: Boolean = false,
    @Json(name = "frozen") val frozen: Boolean = false,
    @Json(name = "frozen_at") val frozenAt: Long? = null,
    @Json(name = "frozen_by") val frozenBy: String? = null,
    @Json(name = "tx_count_24h") val txCount24h: Int = 0,
    @Json(name = "tx_total_24h") val txTotal24h: Long = 0L,
    @Json(name = "chargeback_count") val chargebackCount: Int = 0,
    @Json(name = "last_scored_at") val lastScoredAt: Long = 0L,
    @Json(name = "recent_flags") val recentFlags: List<FraudFlagDto>? = null,
)

@JsonClass(generateAdapter = true)
data class FreezeUserReq(
    @Json(name = "reason") val reason: String,
)

/** freeze -> {user_id, frozen, frozen_at}; unfreeze -> {user_id, frozen}. */
@JsonClass(generateAdapter = true)
data class FreezeResultDto(
    @Json(name = "user_id") val userId: String = "",
    @Json(name = "frozen") val frozen: Boolean = false,
    @Json(name = "frozen_at") val frozenAt: Long? = null,
)

interface FraudAdminRepository {
    suspend fun queue(status: String): ApiResult<FraudFlagQueueDto>
    suspend fun reviewFlag(flagId: String, action: String, notes: String): ApiResult<FraudFlagDto>
    suspend fun cases(status: String?): ApiResult<List<FraudCaseDto>>
    suspend fun resolveCase(caseId: String, resolution: String, notes: String): ApiResult<FraudCaseResolveDto>
    suspend fun userRisk(userId: String): ApiResult<UserRiskProfileDto>
    suspend fun freezeUser(userId: String, reason: String): ApiResult<FreezeResultDto>
    suspend fun unfreezeUser(userId: String): ApiResult<FreezeResultDto>
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

    override suspend fun userRisk(userId: String): ApiResult<UserRiskProfileDto> =
        withContext(io) { call { api.userRisk(userId.trim()) } }

    override suspend fun freezeUser(userId: String, reason: String): ApiResult<FreezeResultDto> =
        withContext(io) { call { api.freezeUser(userId.trim(), FreezeUserReq(reason.trim())) } }

    override suspend fun unfreezeUser(userId: String): ApiResult<FreezeResultDto> =
        withContext(io) { call { api.unfreezeUser(userId.trim()) } }

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
