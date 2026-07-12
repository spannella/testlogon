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
 * B6 admin rate-limits dashboard - mirrors web /admin/rate-limits (RateLimitDashboard.tsx). Backend:
 * admin_rate_limits.py, prefix /ui/admin/rate-limits. ENTIRE surface is require_root -> our ADMIN account
 * gets 403 -> the screen renders the Forbidden state (ROOT-GATED). Config edits + allow/blocklist writes
 * are therefore not driveable by us and are not surfaced; this is the read dashboard that verifies gating.
 */
interface RateLimitsApi {

    @GET("ui/admin/rate-limits/config")
    suspend fun config(): RateLimitConfigDto

    @GET("ui/admin/rate-limits/live-summary")
    suspend fun liveSummary(@Query("hours") hours: Int = 1): RateLimitLiveSummaryDto

    @GET("ui/admin/rate-limits/top-offenders")
    suspend fun topOffenders(@Query("hours") hours: Int = 1, @Query("limit") limit: Int = 20): RateLimitOffendersDto
}

@JsonClass(generateAdapter = true)
data class RateLimitGlobalIpDto(
    @Json(name = "window_seconds") val windowSeconds: Int = 0,
    @Json(name = "max_requests") val maxRequests: Int = 0,
    @Json(name = "enabled") val enabled: Boolean = false,
)

@JsonClass(generateAdapter = true)
data class RateLimitGroupDto(
    @Json(name = "description") val description: String = "",
    @Json(name = "window_seconds") val windowSeconds: Int = 0,
    @Json(name = "max_requests_per_user") val maxRequestsPerUser: Int = 0,
    @Json(name = "max_requests_per_ip") val maxRequestsPerIp: Int = 0,
    @Json(name = "is_override") val isOverride: Boolean = false,
)

@JsonClass(generateAdapter = true)
data class RateLimitConfigDto(
    @Json(name = "global_ip") val globalIp: RateLimitGlobalIpDto = RateLimitGlobalIpDto(),
    @Json(name = "groups") val groups: Map<String, RateLimitGroupDto> = emptyMap(),
)

@JsonClass(generateAdapter = true)
data class RateLimitSourceDto(
    @Json(name = "source_ip") val sourceIp: String = "",
    @Json(name = "count") val count: Int = 0,
)

@JsonClass(generateAdapter = true)
data class RateLimitLiveSummaryDto(
    @Json(name = "by_group") val byGroup: Map<String, Int> = emptyMap(),
    @Json(name = "by_source") val bySource: List<RateLimitSourceDto> = emptyList(),
    @Json(name = "total_hits") val totalHits: Int = 0,
    @Json(name = "window_hours") val windowHours: Int = 0,
)

@JsonClass(generateAdapter = true)
data class RateLimitOffenderIpDto(
    @Json(name = "ip") val ip: String = "",
    @Json(name = "rejected_count") val rejectedCount: Int = 0,
    @Json(name = "last_seen") val lastSeen: Long = 0,
)

@JsonClass(generateAdapter = true)
data class RateLimitOffenderUserDto(
    @Json(name = "user_sub") val userSub: String = "",
    @Json(name = "rejected_count") val rejectedCount: Int = 0,
    @Json(name = "last_seen") val lastSeen: Long = 0,
)

@JsonClass(generateAdapter = true)
data class RateLimitOffendersDto(
    @Json(name = "top_ips") val topIps: List<RateLimitOffenderIpDto> = emptyList(),
    @Json(name = "top_users") val topUsers: List<RateLimitOffenderUserDto> = emptyList(),
)

data class RateLimitsDashboardData(
    val config: RateLimitConfigDto,
    val liveSummary: RateLimitLiveSummaryDto,
    val offenders: RateLimitOffendersDto,
)

interface RateLimitsRepository {
    suspend fun load(): ApiResult<RateLimitsDashboardData>
}

@Singleton
class DefaultRateLimitsRepository @Inject constructor(
    private val api: RateLimitsApi,
    private val errorParser: ApiErrorParser,
) : RateLimitsRepository {

    override suspend fun load(): ApiResult<RateLimitsDashboardData> = withContext(Dispatchers.IO) {
        try {
            val config = api.config()
            val summary = api.liveSummary()
            val offenders = api.topOffenders()
            ApiResult.Success(RateLimitsDashboardData(config, summary, offenders))
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
object RateLimitsApiModule {
    @Provides
    @Singleton
    fun provideRateLimitsApi(retrofit: Retrofit): RateLimitsApi = retrofit.create(RateLimitsApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class RateLimitsDataModule {
    @dagger.Binds
    @Singleton
    abstract fun bindRateLimitsRepository(impl: DefaultRateLimitsRepository): RateLimitsRepository
}
