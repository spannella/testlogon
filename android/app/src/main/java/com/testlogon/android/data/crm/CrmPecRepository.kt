package com.testlogon.android.data.crm

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

// ── Aggregate results (each carries a module-disabled flag for degrade-on-404) ──

data class CrmProjectsPage(
    val projects: List<CrmProject>,
    val cursor: String?,
    val moduleDisabled: Boolean = false,
)

data class CrmProjectDetail(
    val project: CrmProject,
    val tasks: List<CrmProjectTask>,
)

data class CrmEventsPage(
    val events: List<CrmEvent>,
    val cursor: String?,
    val moduleDisabled: Boolean = false,
)

data class CrmCampaignsPage(
    val campaigns: List<CrmCampaign>,
    val cursor: String?,
    val moduleDisabled: Boolean = false,
)

data class CrmCampaignDetail(
    val campaign: CrmCampaign,
    val attribution: CrmCampaignAttribution?,
)

// ───────────────────────────  PROJECTS  ──────────────────────────────

interface CrmProjectsRepository {
    suspend fun list(status: String? = null): ApiResult<CrmProjectsPage>
    suspend fun detail(projectId: String): ApiResult<CrmProjectDetail>
    suspend fun create(body: CrmProjectCreateInDto): ApiResult<CrmProject>
}

@Singleton
class CrmProjectsRepositoryImpl @Inject constructor(
    private val api: CrmProjectsApi,
    private val errorParser: ApiErrorParser,
) : CrmProjectsRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun list(status: String?): ApiResult<CrmProjectsPage> = withContext(io) {
        when (val r = call { api.listProjects(status = status) }) {
            is ApiResult.Success -> ApiResult.Success(
                CrmProjectsPage(r.data.items.map { it.toDomain() }, r.data.cursor),
            )
            is ApiResult.Failure ->
                if (r.error.status == 404) ApiResult.Success(CrmProjectsPage(emptyList(), null, moduleDisabled = true))
                else r
            is ApiResult.NetworkError -> r
        }
    }

    override suspend fun detail(projectId: String): ApiResult<CrmProjectDetail> = withContext(io) {
        when (val proj = call { api.getProject(projectId).toDomain() }) {
            is ApiResult.Success -> {
                // Tasks are best-effort; a failure/degradation renders an empty task list.
                val tasks = (call { api.listTasks(projectId) } as? ApiResult.Success)
                    ?.data?.items?.map { it.toDomain() }?.sortedBy { it.taskOrder } ?: emptyList()
                ApiResult.Success(CrmProjectDetail(proj.data, tasks))
            }
            is ApiResult.Failure -> proj
            is ApiResult.NetworkError -> proj
        }
    }

    override suspend fun create(body: CrmProjectCreateInDto): ApiResult<CrmProject> = withContext(io) {
        call { api.createProject(body).toDomain() }
    }

    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = runCatchingApi(errorParser, block)
}

// ───────────────────────────  EVENTS  ────────────────────────────────

interface CrmEventsRepository {
    suspend fun list(): ApiResult<CrmEventsPage>
    suspend fun get(eventId: String): ApiResult<CrmEvent>
    suspend fun capacity(eventId: String): ApiResult<CrmEventCapacity?>
    suspend fun create(body: CrmEventCreateInDto): ApiResult<CrmEvent>
}

@Singleton
class CrmEventsRepositoryImpl @Inject constructor(
    private val api: CrmEventsApi,
    private val errorParser: ApiErrorParser,
) : CrmEventsRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun list(): ApiResult<CrmEventsPage> = withContext(io) {
        when (val r = call { api.listEvents() }) {
            is ApiResult.Success -> ApiResult.Success(
                CrmEventsPage(r.data.events.map { it.toDomain() }, r.data.cursor),
            )
            is ApiResult.Failure ->
                if (r.error.status == 404) ApiResult.Success(CrmEventsPage(emptyList(), null, moduleDisabled = true))
                else r
            is ApiResult.NetworkError -> r
        }
    }

    override suspend fun get(eventId: String): ApiResult<CrmEvent> = withContext(io) {
        call { api.getEvent(eventId).toDomain() }
    }

    override suspend fun capacity(eventId: String): ApiResult<CrmEventCapacity?> = withContext(io) {
        when (val r = call { api.getCapacity(eventId).toDomain() }) {
            is ApiResult.Success -> r
            is ApiResult.Failure -> if (r.error.status == 404) ApiResult.Success(null) else r
            is ApiResult.NetworkError -> r
        }
    }

    override suspend fun create(body: CrmEventCreateInDto): ApiResult<CrmEvent> = withContext(io) {
        call { api.createEvent(body).toDomain() }
    }

    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = runCatchingApi(errorParser, block)
}

// ──────────────────────────  CAMPAIGNS  ──────────────────────────────

interface CrmCampaignsRepository {
    suspend fun list(status: String? = null): ApiResult<CrmCampaignsPage>
    suspend fun detail(campaignId: String): ApiResult<CrmCampaignDetail>
}

@Singleton
class CrmCampaignsRepositoryImpl @Inject constructor(
    private val api: CrmCampaignsApi,
    private val errorParser: ApiErrorParser,
) : CrmCampaignsRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun list(status: String?): ApiResult<CrmCampaignsPage> = withContext(io) {
        when (val r = call { api.listCampaigns(status = status) }) {
            is ApiResult.Success -> ApiResult.Success(
                CrmCampaignsPage(r.data.campaigns.map { it.toDomain() }, r.data.cursor),
            )
            is ApiResult.Failure ->
                if (r.error.status == 404) ApiResult.Success(CrmCampaignsPage(emptyList(), null, moduleDisabled = true))
                else r
            is ApiResult.NetworkError -> r
        }
    }

    override suspend fun detail(campaignId: String): ApiResult<CrmCampaignDetail> = withContext(io) {
        when (val camp = call { api.getCampaign(campaignId).toDomain() }) {
            is ApiResult.Success -> {
                // Attribution is best-effort (analytics can be off even when the campaign exists).
                val attribution = (call { api.getAttribution(campaignId).toDomain() } as? ApiResult.Success)?.data
                ApiResult.Success(CrmCampaignDetail(camp.data, attribution))
            }
            is ApiResult.Failure -> camp
            is ApiResult.NetworkError -> camp
        }
    }

    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = runCatchingApi(errorParser, block)
}

// ── Shared error-mapping helper (mirrors the LeadsRepository `call` body). ──
private suspend fun <T> runCatchingApi(
    errorParser: ApiErrorParser,
    block: suspend () -> T,
): ApiResult<T> = try {
    ApiResult.Success(block())
} catch (e: CancellationException) {
    throw e
} catch (e: HttpException) {
    ApiResult.Failure(errorParser.from(e))
} catch (e: IOException) {
    ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
}
