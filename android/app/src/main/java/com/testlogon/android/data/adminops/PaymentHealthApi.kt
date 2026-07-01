package com.testlogon.android.data.adminops

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
 * B6 payment provider health dashboard - mirrors web /admin/payment-health
 * (PaymentHealthDashboard.tsx). Backend: payment_provider_health.py, prefix /ui/admin/payment-health.
 * Reads (status list + incidents) are require_admin_or_root (our admin CAN drive). Config PATCH/toggle
 * are require_root and are NOT surfaced. list_provider_status returns a bare JSON array.
 */
interface PaymentHealthApi {

    @GET("ui/admin/payment-health")
    suspend fun providers(@Query("hours") hours: Int = 24): List<PaymentHealthProviderDto>

    @GET("ui/admin/payment-health/incidents")
    suspend fun incidents(@Query("limit") limit: Int = 50): List<PaymentHealthIncidentDto>
}

@JsonClass(generateAdapter = true)
data class PaymentHealthProviderDto(
    @Json(name = "provider") val provider: String = "",
    @Json(name = "status") val status: String = "",
    @Json(name = "enabled") val enabled: Boolean = true,
    @Json(name = "success_rate") val successRate: Double = 100.0,
    @Json(name = "error_rate_bps") val errorRateBps: Int = 0,
    @Json(name = "avg_latency_ms") val avgLatencyMs: Int = 0,
    @Json(name = "p95_latency_ms") val p95LatencyMs: Int = 0,
    @Json(name = "p99_latency_ms") val p99LatencyMs: Int = 0,
    @Json(name = "total_success") val totalSuccess: Int = 0,
    @Json(name = "total_failure") val totalFailure: Int = 0,
    @Json(name = "last_check_at") val lastCheckAt: Long = 0,
)

@JsonClass(generateAdapter = true)
data class PaymentHealthIncidentDto(
    @Json(name = "incident_id") val incidentId: String = "",
    @Json(name = "provider") val provider: String = "",
    @Json(name = "started_at") val startedAt: Long = 0,
    @Json(name = "ended_at") val endedAt: Long? = null,
    @Json(name = "status") val status: String = "",
    @Json(name = "peak_error_rate") val peakErrorRate: Int = 0,
    @Json(name = "affected_webhooks") val affectedWebhooks: Int = 0,
)

data class PaymentHealthData(
    val providers: List<PaymentHealthProviderDto>,
    val incidents: List<PaymentHealthIncidentDto>,
)

interface PaymentHealthRepository {
    suspend fun load(): ApiResult<PaymentHealthData>
}

@Singleton
class DefaultPaymentHealthRepository @Inject constructor(
    private val api: PaymentHealthApi,
    private val errorParser: ApiErrorParser,
) : PaymentHealthRepository {

    override suspend fun load(): ApiResult<PaymentHealthData> = withContext(Dispatchers.IO) {
        try {
            val providers = api.providers()
            val incidents = api.incidents()
            ApiResult.Success(PaymentHealthData(providers, incidents))
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
object PaymentHealthApiModule {
    @Provides
    @Singleton
    fun providePaymentHealthApi(retrofit: Retrofit): PaymentHealthApi =
        retrofit.create(PaymentHealthApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class PaymentHealthDataModule {
    @dagger.Binds
    @Singleton
    abstract fun bindPaymentHealthRepository(impl: DefaultPaymentHealthRepository): PaymentHealthRepository
}
