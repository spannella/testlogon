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
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * B6 admin background-jobs dashboard - mirrors web /admin/jobs (JobDashboardPage.tsx). Backend:
 * admin_jobs.py (require_ui_session + role check accepts admin+root). GET status/failed are admin-drivable;
 * POST retry/{action_id} (admin override) requires the action's user_sub. `tasks` is a name->task map.
 */
interface JobsApi {

    @GET("ui/admin/jobs/status")
    suspend fun status(): JobsStatusDto

    @GET("ui/admin/jobs/failed")
    suspend fun failed(@Query("limit") limit: Int = 50): JobsFailedListDto

    @POST("ui/admin/jobs/retry/{action_id}")
    suspend fun retry(
        @Path("action_id") actionId: String,
        @Query("user_sub") userSub: String,
    ): JobsRetryResultDto
}

@JsonClass(generateAdapter = true)
data class JobTaskDto(
    @Json(name = "name") val name: String = "",
    @Json(name = "description") val description: String = "",
    @Json(name = "status") val status: String = "",
    @Json(name = "enabled") val enabled: Boolean = false,
    @Json(name = "poll_interval_seconds") val pollIntervalSeconds: Int = 0,
    @Json(name = "last_poll_at") val lastPollAt: Long? = null,
    @Json(name = "last_poll_duration_ms") val lastPollDurationMs: Double? = null,
    @Json(name = "items_processed") val itemsProcessed: Int = 0,
    @Json(name = "items_failed") val itemsFailed: Int = 0,
    @Json(name = "total_polls") val totalPolls: Int = 0,
    @Json(name = "consecutive_errors") val consecutiveErrors: Int = 0,
    @Json(name = "last_error") val lastError: String? = null,
)

@JsonClass(generateAdapter = true)
data class JobQueueDto(
    @Json(name = "pending") val pending: Int = 0,
    @Json(name = "failed") val failed: Int = 0,
    @Json(name = "dead_letter") val deadLetter: Int = 0,
    @Json(name = "success_24h") val success24h: Int = 0,
    @Json(name = "total_endpoints") val totalEndpoints: Int = 0,
    @Json(name = "enabled_endpoints") val enabledEndpoints: Int = 0,
)

@JsonClass(generateAdapter = true)
data class JobsQueuesDto(
    @Json(name = "scheduled_actions") val scheduledActions: JobQueueDto = JobQueueDto(),
    @Json(name = "webhook_deliveries") val webhookDeliveries: JobQueueDto = JobQueueDto(),
)

@JsonClass(generateAdapter = true)
data class JobsStatusDto(
    @Json(name = "tasks") val tasks: Map<String, JobTaskDto> = emptyMap(),
    @Json(name = "queues") val queues: JobsQueuesDto = JobsQueuesDto(),
    @Json(name = "timestamp") val timestamp: Long = 0,
)

@JsonClass(generateAdapter = true)
data class JobFailedActionDto(
    @Json(name = "action_id") val actionId: String = "",
    @Json(name = "user_sub") val userSub: String = "",
    @Json(name = "action_type") val actionType: String = "",
    @Json(name = "retry_count") val retryCount: Int = 0,
    @Json(name = "last_error") val lastError: String = "",
    @Json(name = "due_at") val dueAt: Long = 0,
)

@JsonClass(generateAdapter = true)
data class JobsFailedListDto(
    @Json(name = "items") val items: List<JobFailedActionDto> = emptyList(),
    @Json(name = "count") val count: Int = 0,
)

@JsonClass(generateAdapter = true)
data class JobsRetryResultDto(
    @Json(name = "ok") val ok: Boolean = false,
    @Json(name = "action_id") val actionId: String = "",
    @Json(name = "status") val status: String = "",
)

data class JobsDashboardData(
    val status: JobsStatusDto,
    val failed: List<JobFailedActionDto>,
)

interface JobsRepository {
    suspend fun load(): ApiResult<JobsDashboardData>
    suspend fun retry(actionId: String, userSub: String): ApiResult<JobsRetryResultDto>
}

@Singleton
class DefaultJobsRepository @Inject constructor(
    private val api: JobsApi,
    private val errorParser: ApiErrorParser,
) : JobsRepository {

    override suspend fun load(): ApiResult<JobsDashboardData> = withContext(Dispatchers.IO) {
        call {
            val status = api.status()
            val failed = api.failed()
            JobsDashboardData(status, failed.items)
        }
    }

    override suspend fun retry(actionId: String, userSub: String): ApiResult<JobsRetryResultDto> =
        withContext(Dispatchers.IO) { call { api.retry(actionId, userSub) } }

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
object JobsApiModule {
    @Provides
    @Singleton
    fun provideJobsApi(retrofit: Retrofit): JobsApi = retrofit.create(JobsApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class JobsDataModule {
    @dagger.Binds
    @Singleton
    abstract fun bindJobsRepository(impl: DefaultJobsRepository): JobsRepository
}
