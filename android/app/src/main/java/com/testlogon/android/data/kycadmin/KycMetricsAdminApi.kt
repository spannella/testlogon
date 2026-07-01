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
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * B3 - KYC operational metrics dashboard. Mirrors web /admin/kyc/metrics (KycMetricsDashboard.tsx +
 * api/endpoints/kyc-admin.ts fetchKycMetrics). Backend kyc_cases.py GET /v1/kyc/cases/admin/metrics,
 * admin-gated (in-body role check). Response nests everything under `metrics`.
 */
interface KycMetricsAdminApi {
    @GET("v1/kyc/cases/admin/metrics")
    suspend fun metrics(): KycMetricsEnvelopeDto
}

@JsonClass(generateAdapter = true)
data class KycMetricsDto(
    @Json(name = "funnel_counts") val funnelCounts: Map<String, Int> = emptyMap(),
    @Json(name = "review_latency_seconds") val reviewLatencySeconds: Map<String, Double?> = emptyMap(),
    @Json(name = "stale_queue_count") val staleQueueCount: Int = 0,
    @Json(name = "submit_guard_failures_by_reason") val submitGuardFailures: Map<String, Int> = emptyMap(),
    @Json(name = "ticket_sync_counters") val ticketSyncCounters: Map<String, Int> = emptyMap(),
    @Json(name = "ticket_sync_deadletter_count") val ticketSyncDeadletterCount: Int = 0,
)

@JsonClass(generateAdapter = true)
data class KycMetricsEnvelopeDto(
    @Json(name = "metrics") val metrics: KycMetricsDto,
)

interface KycMetricsAdminRepository {
    suspend fun load(): ApiResult<KycMetricsDto>
}

@Singleton
class DefaultKycMetricsAdminRepository @Inject constructor(
    private val api: KycMetricsAdminApi,
    private val errorParser: ApiErrorParser,
) : KycMetricsAdminRepository {

    override suspend fun load(): ApiResult<KycMetricsDto> = withContext(Dispatchers.IO) {
        try {
            ApiResult.Success(api.metrics().metrics)
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
object KycMetricsAdminApiModule {
    @Provides
    @Singleton
    fun provideKycMetricsAdminApi(retrofit: Retrofit): KycMetricsAdminApi =
        retrofit.create(KycMetricsAdminApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class KycMetricsAdminDataModule {
    @dagger.Binds
    @Singleton
    abstract fun bindKycMetricsAdminRepository(impl: DefaultKycMetricsAdminRepository): KycMetricsAdminRepository
}
