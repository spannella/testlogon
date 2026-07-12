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
 * B6 admin compute dashboard - mirrors web /admin/compute (AdminComputeDashboard.tsx). Backend:
 * admin_compute.py, prefix /v1/admin/compute. Reads (spending / per-user / stats / instances / pods) are
 * require_admin_or_root (our admin CAN drive). Quota PUT/DELETE are require_root and are NOT surfaced.
 */
interface ComputeApi {

    @GET("v1/admin/compute/spending")
    suspend fun spending(): ComputeSpendingDto

    @GET("v1/admin/compute/spending/users")
    suspend fun perUserSpending(@Query("limit") limit: Int = 50): ComputePerUserSpendingDto

    @GET("v1/admin/compute/stats/instance-types")
    suspend fun instanceTypeStats(): ComputeInstanceTypeStatsDto

    @GET("v1/admin/compute/instances")
    suspend fun instances(@Query("limit") limit: Int = 100): ComputeInstanceListDto

    @GET("v1/admin/compute/pods")
    suspend fun pods(@Query("limit") limit: Int = 100): ComputePodListDto
}

@JsonClass(generateAdapter = true)
data class ComputeSpendingDto(
    @Json(name = "month") val month: String = "",
    @Json(name = "total_cents") val totalCents: Long = 0,
    @Json(name = "ec2_total_cents") val ec2TotalCents: Long = 0,
    @Json(name = "k8s_total_cents") val k8sTotalCents: Long = 0,
    @Json(name = "active_user_count") val activeUserCount: Int = 0,
    @Json(name = "active_instance_count") val activeInstanceCount: Int = 0,
    @Json(name = "active_pod_count") val activePodCount: Int = 0,
)

@JsonClass(generateAdapter = true)
data class ComputePerUserEntryDto(
    @Json(name = "user_sub") val userSub: String = "",
    @Json(name = "total_cents") val totalCents: Long = 0,
    @Json(name = "ec2_cents") val ec2Cents: Long = 0,
    @Json(name = "k8s_cents") val k8sCents: Long = 0,
    @Json(name = "instance_count") val instanceCount: Int = 0,
    @Json(name = "pod_count") val podCount: Int = 0,
)

@JsonClass(generateAdapter = true)
data class ComputePerUserSpendingDto(
    @Json(name = "users") val users: List<ComputePerUserEntryDto> = emptyList(),
    @Json(name = "month") val month: String = "",
)

@JsonClass(generateAdapter = true)
data class ComputeInstanceTypeStatDto(
    @Json(name = "instance_type") val instanceType: String = "",
    @Json(name = "running_count") val runningCount: Int = 0,
    @Json(name = "total_launched") val totalLaunched: Int = 0,
)

@JsonClass(generateAdapter = true)
data class ComputeInstanceTypeStatsDto(
    @Json(name = "stats") val stats: List<ComputeInstanceTypeStatDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class ComputeInstanceDto(
    @Json(name = "instance_id") val instanceId: String = "",
    @Json(name = "user_sub") val userSub: String = "",
    @Json(name = "label") val label: String = "",
    @Json(name = "instance_type") val instanceType: String = "",
    @Json(name = "status") val status: String = "",
    @Json(name = "public_ip") val publicIp: String = "",
    @Json(name = "created_at") val createdAt: Long = 0,
)

@JsonClass(generateAdapter = true)
data class ComputeInstanceListDto(
    @Json(name = "instances") val instances: List<ComputeInstanceDto> = emptyList(),
    @Json(name = "count") val count: Int = 0,
)

@JsonClass(generateAdapter = true)
data class ComputePodDto(
    @Json(name = "pod_id") val podId: String = "",
    @Json(name = "user_sub") val userSub: String = "",
    @Json(name = "label") val label: String = "",
    @Json(name = "preset") val preset: String = "",
    @Json(name = "status") val status: String = "",
    @Json(name = "created_at") val createdAt: Long = 0,
)

@JsonClass(generateAdapter = true)
data class ComputePodListDto(
    @Json(name = "pods") val pods: List<ComputePodDto> = emptyList(),
    @Json(name = "count") val count: Int = 0,
)

data class ComputeDashboardData(
    val spending: ComputeSpendingDto,
    val perUser: List<ComputePerUserEntryDto>,
    val instanceTypes: List<ComputeInstanceTypeStatDto>,
    val instances: List<ComputeInstanceDto>,
    val instanceCount: Int,
    val pods: List<ComputePodDto>,
    val podCount: Int,
)

interface ComputeRepository {
    suspend fun load(): ApiResult<ComputeDashboardData>
}

@Singleton
class DefaultComputeRepository @Inject constructor(
    private val api: ComputeApi,
    private val errorParser: ApiErrorParser,
) : ComputeRepository {

    override suspend fun load(): ApiResult<ComputeDashboardData> = withContext(Dispatchers.IO) {
        try {
            val spending = api.spending()
            val perUser = api.perUserSpending()
            val types = api.instanceTypeStats()
            val instances = api.instances()
            val pods = api.pods()
            ApiResult.Success(
                ComputeDashboardData(
                    spending = spending,
                    perUser = perUser.users,
                    instanceTypes = types.stats,
                    instances = instances.instances,
                    instanceCount = instances.count,
                    pods = pods.pods,
                    podCount = pods.count,
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
object ComputeApiModule {
    @Provides
    @Singleton
    fun provideComputeApi(retrofit: Retrofit): ComputeApi = retrofit.create(ComputeApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class ComputeDataModule {
    @dagger.Binds
    @Singleton
    abstract fun bindComputeRepository(impl: DefaultComputeRepository): ComputeRepository
}
