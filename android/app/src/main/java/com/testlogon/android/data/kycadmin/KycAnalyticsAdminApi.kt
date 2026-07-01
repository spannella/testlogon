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
import retrofit2.http.GET
import retrofit2.http.Query
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * B4 - KYC analytics dashboard. Mirrors web /admin/kyc/analytics (KycAnalyticsDashboard.tsx +
 * api/endpoints/kyc-analytics.ts). Backend kyc_analytics.py, prefix /v1/kyc/analytics, admin-gated
 * (_require_admin). We surface the snapshot (over a default trailing-30d window) + trends + rejection
 * reasons + geographic + drop-off - the load-bearing views. Timestamps are epoch SECONDS.
 */
interface KycAnalyticsAdminApi {

    @GET("v1/kyc/analytics/snapshot")
    suspend fun snapshot(@Query("from") from: Long, @Query("to") to: Long): SnapshotEnvelopeDto

    @GET("v1/kyc/analytics/trends")
    suspend fun trends(@Query("granularity") granularity: String, @Query("periods") periods: Int): TrendsEnvelopeDto

    @GET("v1/kyc/analytics/rejection-reasons")
    suspend fun rejectionReasons(@Query("from") from: Long, @Query("to") to: Long): RejectionReasonsEnvelopeDto

    @GET("v1/kyc/analytics/geographic")
    suspend fun geographic(@Query("from") from: Long, @Query("to") to: Long): GeographicEnvelopeDto

    @GET("v1/kyc/analytics/drop-off")
    suspend fun dropOff(@Query("from") from: Long, @Query("to") to: Long): DropOffEnvelopeDto
}

@JsonClass(generateAdapter = true)
data class KycPercentilesDto(
    @Json(name = "p50") val p50: Double = 0.0,
    @Json(name = "p75") val p75: Double = 0.0,
    @Json(name = "p90") val p90: Double = 0.0,
    @Json(name = "p99") val p99: Double = 0.0,
)

@JsonClass(generateAdapter = true)
data class KycFunnelStepDto(
    @Json(name = "step") val step: String = "",
    @Json(name = "count") val count: Int = 0,
    @Json(name = "percentage") val percentage: Double = 0.0,
    @Json(name = "drop_off_count") val dropOffCount: Int = 0,
    @Json(name = "drop_off_pct") val dropOffPct: Double = 0.0,
)

@JsonClass(generateAdapter = true)
data class KycCountryStatsDto(
    @Json(name = "country") val country: String = "",
    @Json(name = "count") val count: Int = 0,
    @Json(name = "approved") val approved: Int = 0,
    @Json(name = "rejected") val rejected: Int = 0,
    @Json(name = "approval_rate") val approvalRate: Double = 0.0,
)

@JsonClass(generateAdapter = true)
data class KycAnalyticsSnapshotDto(
    @Json(name = "period_start") val periodStart: Long = 0L,
    @Json(name = "period_end") val periodEnd: Long = 0L,
    @Json(name = "total_applications") val totalApplications: Int = 0,
    @Json(name = "approved_count") val approvedCount: Int = 0,
    @Json(name = "rejected_count") val rejectedCount: Int = 0,
    @Json(name = "pending_count") val pendingCount: Int = 0,
    @Json(name = "conversion_rate") val conversionRate: Double = 0.0,
    @Json(name = "avg_processing_hours") val avgProcessingHours: Double = 0.0,
    @Json(name = "processing_time_distribution") val processingTimeDistribution: KycPercentilesDto = KycPercentilesDto(),
    @Json(name = "funnel") val funnel: List<KycFunnelStepDto> = emptyList(),
    @Json(name = "rejection_reasons") val rejectionReasons: Map<String, Int> = emptyMap(),
    @Json(name = "geographic_distribution") val geographicDistribution: List<KycCountryStatsDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class SnapshotEnvelopeDto(
    @Json(name = "snapshot") val snapshot: KycAnalyticsSnapshotDto,
)

@JsonClass(generateAdapter = true)
data class KycTrendPointDto(
    @Json(name = "period") val period: String = "",
    @Json(name = "started") val started: Int = 0,
    @Json(name = "submitted") val submitted: Int = 0,
    @Json(name = "approved") val approved: Int = 0,
    @Json(name = "rejected") val rejected: Int = 0,
)

@JsonClass(generateAdapter = true)
data class TrendsEnvelopeDto(
    @Json(name = "trends") val trends: List<KycTrendPointDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class RejectionReasonsEnvelopeDto(
    @Json(name = "reasons") val reasons: Map<String, Int> = emptyMap(),
)

@JsonClass(generateAdapter = true)
data class GeographicEnvelopeDto(
    @Json(name = "countries") val countries: List<KycCountryStatsDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class KycDropOffStepDto(
    @Json(name = "from_step") val fromStep: String = "",
    @Json(name = "to_step") val toStep: String = "",
    @Json(name = "continued") val continued: Int = 0,
    @Json(name = "dropped") val dropped: Int = 0,
    @Json(name = "drop_rate") val dropRate: Double = 0.0,
    @Json(name = "avg_time_in_step_hours") val avgTimeInStepHours: Double = 0.0,
)

@JsonClass(generateAdapter = true)
data class DropOffEnvelopeDto(
    @Json(name = "steps") val steps: List<KycDropOffStepDto> = emptyList(),
)

data class KycAnalyticsData(
    val snapshot: KycAnalyticsSnapshotDto,
    val trends: List<KycTrendPointDto>,
    val rejectionReasons: Map<String, Int>,
    val geographic: List<KycCountryStatsDto>,
    val dropOff: List<KycDropOffStepDto>,
)

interface KycAnalyticsAdminRepository {
    suspend fun load(): ApiResult<KycAnalyticsData>
}

@Singleton
class DefaultKycAnalyticsAdminRepository @Inject constructor(
    private val api: KycAnalyticsAdminApi,
    private val errorParser: ApiErrorParser,
) : KycAnalyticsAdminRepository {

    override suspend fun load(): ApiResult<KycAnalyticsData> = withContext(Dispatchers.IO) {
        try {
            val now = System.currentTimeMillis() / 1000L
            val from = now - 30L * 24 * 3600
            val snap = api.snapshot(from, now)
            val trends = api.trends("daily", 14)
            val rej = api.rejectionReasons(from, now)
            val geo = api.geographic(from, now)
            val drop = api.dropOff(from, now)
            ApiResult.Success(
                KycAnalyticsData(
                    snapshot = snap.snapshot,
                    trends = trends.trends,
                    rejectionReasons = rej.reasons,
                    geographic = geo.countries,
                    dropOff = drop.steps,
                ),
            )
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
object KycAnalyticsAdminApiModule {
    @Provides
    @Singleton
    fun provideKycAnalyticsAdminApi(retrofit: Retrofit): KycAnalyticsAdminApi =
        retrofit.create(KycAnalyticsAdminApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class KycAnalyticsAdminDataModule {
    @dagger.Binds
    @Singleton
    abstract fun bindKycAnalyticsAdminRepository(impl: DefaultKycAnalyticsAdminRepository): KycAnalyticsAdminRepository
}
