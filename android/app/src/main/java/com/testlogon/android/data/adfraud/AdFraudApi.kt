package com.testlogon.android.data.adfraud

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
 * Web-parity admin AD-FRAUD dashboard - mirrors the web /admin/ads/fraud page
 * (pages/admin/ads/AdFraudDashboard.tsx + api/endpoints/adFraud.ts). Backend: app/routers/ad_fraud.py,
 * prefix /ui/ads/fraud, all endpoints gated by require_admin_or_root (ADMIN-drivable on our admin account).
 *
 *  - GET  /ui/ads/fraud/summary                        -> AdFraudSummaryDto
 *  - GET  /ui/ads/fraud/events?date=&limit=            -> bare array of AdFraudEventDto
 *  - POST /ui/ads/fraud/events/{event_id}/review {decision:"confirm"|"dismiss"} -> event
 *  - GET  /ui/ads/fraud/accounts                       -> bare array of AdFraudAccountDto
 *  - POST /ui/ads/fraud/accounts/{account_id}/suspend {reason} -> {ok,status}
 *  - POST /ui/ads/fraud/accounts/{account_id}/unsuspend        -> {ok,status}
 *
 * All timestamps are epoch SECONDS. A backend 403 -> Failure(status=403) -> Forbidden.
 */
interface AdFraudApi {

    @GET("ui/ads/fraud/summary")
    suspend fun summary(): AdFraudSummaryDto

    @GET("ui/ads/fraud/events")
    suspend fun events(
        @Query("date") date: String? = null,
        @Query("limit") limit: Int? = null,
    ): List<AdFraudEventDto>

    @POST("ui/ads/fraud/events/{event_id}/review")
    suspend fun reviewEvent(
        @Path("event_id") eventId: String,
        @Body body: AdFraudReviewReq,
    ): AdFraudEventDto

    @GET("ui/ads/fraud/accounts")
    suspend fun accounts(): List<AdFraudAccountDto>

    @POST("ui/ads/fraud/accounts/{account_id}/suspend")
    suspend fun suspend(
        @Path("account_id") accountId: String,
        @Body body: AdFraudSuspendReq,
    ): AdFraudActionResultDto

    @POST("ui/ads/fraud/accounts/{account_id}/unsuspend")
    suspend fun unsuspend(@Path("account_id") accountId: String): AdFraudActionResultDto
}

// ---- DTOs (verified 1:1 against types.ts AdFraudEvent/AdFraudAccountRisk/AdFraudSummary) ----

@JsonClass(generateAdapter = true)
data class AdFraudSummaryDto(
    @Json(name = "flagged_events_today") val flaggedEventsToday: Int = 0,
    @Json(name = "total_events") val totalEvents: Int = 0,
    @Json(name = "flagged_events") val flaggedEvents: Int = 0,
    @Json(name = "fraud_rate_bps") val fraudRateBps: Int = 0,
    @Json(name = "suspended_accounts") val suspendedAccounts: Int = 0,
    @Json(name = "tracked_accounts") val trackedAccounts: Int = 0,
    @Json(name = "top_fraud_rules") val topFraudRules: Map<String, Int> = emptyMap(),
)

@JsonClass(generateAdapter = true)
data class AdFraudEventDto(
    @Json(name = "event_id") val eventId: String = "",
    @Json(name = "user_id") val userId: String = "",
    @Json(name = "ip_address") val ipAddress: String = "",
    @Json(name = "account_id") val accountId: String = "",
    @Json(name = "campaign_id") val campaignId: String = "",
    @Json(name = "creative_id") val creativeId: String = "",
    @Json(name = "event_type") val eventType: String = "",
    @Json(name = "fraud_score") val fraudScore: Double = 0.0,
    @Json(name = "status") val status: String = "",
    @Json(name = "created_at") val createdAt: Long = 0L,
    @Json(name = "reviewed_by") val reviewedBy: String? = null,
    @Json(name = "reviewed_at") val reviewedAt: Long? = null,
)

@JsonClass(generateAdapter = true)
data class AdFraudAccountDto(
    @Json(name = "account_id") val accountId: String = "",
    @Json(name = "fraud_rate_bps") val fraudRateBps: Int = 0,
    @Json(name = "total_events") val totalEvents: Int = 0,
    @Json(name = "flagged_events") val flaggedEvents: Int = 0,
    @Json(name = "status") val status: String = "",
    @Json(name = "last_fraud_event_at") val lastFraudEventAt: Long? = null,
    @Json(name = "last_event_at") val lastEventAt: Long? = null,
)

@JsonClass(generateAdapter = true)
data class AdFraudReviewReq(
    @Json(name = "decision") val decision: String,
)

@JsonClass(generateAdapter = true)
data class AdFraudSuspendReq(
    @Json(name = "reason") val reason: String = "",
)

@JsonClass(generateAdapter = true)
data class AdFraudActionResultDto(
    @Json(name = "ok") val ok: Boolean = false,
    @Json(name = "status") val status: String = "",
)

/** Combined dashboard snapshot (summary + events + accounts) fetched in one repository call. */
data class AdFraudDashboard(
    val summary: AdFraudSummaryDto,
    val events: List<AdFraudEventDto>,
    val accounts: List<AdFraudAccountDto>,
)

interface AdFraudRepository {
    suspend fun load(): ApiResult<AdFraudDashboard>
    suspend fun reviewEvent(eventId: String, decision: String): ApiResult<AdFraudEventDto>
    suspend fun suspend(accountId: String, reason: String): ApiResult<AdFraudActionResultDto>
    suspend fun unsuspend(accountId: String): ApiResult<AdFraudActionResultDto>
}

@Singleton
class DefaultAdFraudRepository @Inject constructor(
    private val api: AdFraudApi,
    private val errorParser: ApiErrorParser,
) : AdFraudRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun load(): ApiResult<AdFraudDashboard> = withContext(io) {
        call {
            AdFraudDashboard(
                summary = api.summary(),
                events = api.events(limit = 100),
                accounts = api.accounts(),
            )
        }
    }

    override suspend fun reviewEvent(eventId: String, decision: String): ApiResult<AdFraudEventDto> =
        withContext(io) { call { api.reviewEvent(eventId, AdFraudReviewReq(decision)) } }

    override suspend fun suspend(accountId: String, reason: String): ApiResult<AdFraudActionResultDto> =
        withContext(io) { call { api.suspend(accountId, AdFraudSuspendReq(reason)) } }

    override suspend fun unsuspend(accountId: String): ApiResult<AdFraudActionResultDto> =
        withContext(io) { call { api.unsuspend(accountId) } }

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
object AdFraudApiModule {
    @Provides
    @Singleton
    fun provideAdFraudApi(retrofit: Retrofit): AdFraudApi = retrofit.create(AdFraudApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class AdFraudDataModule {
    @dagger.Binds
    @Singleton
    abstract fun bindAdFraudRepository(impl: DefaultAdFraudRepository): AdFraudRepository
}
