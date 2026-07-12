package com.testlogon.android.data.inframonitoring

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import com.squareup.moshi.JsonDataException
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
import retrofit2.http.GET
import retrofit2.http.Path
import retrofit2.http.Query
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * B7 Cloud-Infra: Instance monitoring (metrics for an instance). Mirrors InstanceMonitoringPage.tsx +
 * api/endpoints/instanceMonitoring.ts. Backend: instance_monitoring.py, prefix /ui/compute/monitoring,
 * require_ui_session (ownership via the instance). Reads latest metric, a series, and a health summary.
 * The ingest/seed endpoints are test-only and NOT surfaced here. Self-contained per the B5 pattern.
 */
interface InstanceMonitoringApi {

    @GET("ui/compute/monitoring/instances/{id}/metrics/latest")
    suspend fun latest(@Path("id") instanceId: String): MetricLatestDto

    @GET("ui/compute/monitoring/instances/{id}/metrics")
    suspend fun series(
        @Path("id") instanceId: String,
        @Query("limit") limit: Int? = null,
    ): MetricSeriesDto

    @GET("ui/compute/monitoring/instances/{id}/health")
    suspend fun health(@Path("id") instanceId: String): InstanceHealthDto
}

@JsonClass(generateAdapter = true)
data class MetricPointDto(
    @Json(name = "instance_id") val instanceId: String = "",
    @Json(name = "ts") val ts: Long = 0L,
    @Json(name = "cpu_pct") val cpuPct: Int = 0,
    @Json(name = "mem_pct") val memPct: Int = 0,
    @Json(name = "disk_pct") val diskPct: Int = 0,
    @Json(name = "net_in_kbps") val netInKbps: Int = 0,
    @Json(name = "net_out_kbps") val netOutKbps: Int = 0,
    @Json(name = "status") val status: String = "",
)

@JsonClass(generateAdapter = true)
data class MetricLatestDto(
    @Json(name = "instance_id") val instanceId: String = "",
    @Json(name = "has_data") val hasData: Boolean = false,
    @Json(name = "point") val point: MetricPointDto? = null,
)

@JsonClass(generateAdapter = true)
data class MetricSeriesDto(
    @Json(name = "instance_id") val instanceId: String = "",
    @Json(name = "points") val points: List<MetricPointDto> = emptyList(),
    @Json(name = "count") val count: Int = 0,
)

@JsonClass(generateAdapter = true)
data class InstanceHealthDto(
    @Json(name = "instance_id") val instanceId: String = "",
    @Json(name = "instance_type") val instanceType: String = "",
    @Json(name = "instance_status") val instanceStatus: String = "",
    @Json(name = "health_status") val healthStatus: String = "unknown",
    @Json(name = "reasons") val reasons: List<String> = emptyList(),
    @Json(name = "cpu_pct") val cpuPct: Int = 0,
    @Json(name = "mem_pct") val memPct: Int = 0,
    @Json(name = "disk_pct") val diskPct: Int = 0,
    @Json(name = "datapoints") val datapoints: Int = 0,
    @Json(name = "last_metric_ts") val lastMetricTs: Long = 0L,
)

/** Aggregate for one instance's monitoring view. */
data class MonitoringSnapshot(
    val health: InstanceHealthDto,
    val series: List<MetricPointDto>,
    val latest: MetricPointDto?,
)

interface InstanceMonitoringRepository {
    suspend fun snapshot(instanceId: String): ApiResult<MonitoringSnapshot>
}

@Singleton
class DefaultInstanceMonitoringRepository @Inject constructor(
    private val api: InstanceMonitoringApi,
    private val errorParser: ApiErrorParser,
) : InstanceMonitoringRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun snapshot(instanceId: String): ApiResult<MonitoringSnapshot> =
        withContext(io) {
            call {
                val health = api.health(instanceId)
                val series = api.series(instanceId, limit = 60).points
                val latest = api.latest(instanceId).point
                MonitoringSnapshot(health = health, series = series, latest = latest)
            }
        }

    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: JsonDataException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }
}

@Module
@InstallIn(SingletonComponent::class)
object InstanceMonitoringApiModule {
    @Provides
    @Singleton
    fun provideInstanceMonitoringApi(retrofit: Retrofit): InstanceMonitoringApi =
        retrofit.create(InstanceMonitoringApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class InstanceMonitoringDataModule {
    @dagger.Binds
    @Singleton
    abstract fun bindInstanceMonitoringRepository(impl: DefaultInstanceMonitoringRepository): InstanceMonitoringRepository
}
