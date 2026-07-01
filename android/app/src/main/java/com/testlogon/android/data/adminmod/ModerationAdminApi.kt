package com.testlogon.android.data.adminmod

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
 * B5 admin content-moderation board - mirrors the web /admin/moderation page (ModerationBoardPage.tsx +
 * api/endpoints/moderation.ts). Backend: admin_moderation.py, prefix /v1/admin/moderation, gated by
 * require_admin_scope(CONTENT_MODERATION). Content reports (#3) surface here: a ticket's linked_reports are the
 * user-filed reports aggregated into the ticket, so the board IS the admin content-reports queue.
 *
 * All timestamps are epoch SECONDS (moderation DTOs use numeric ts per the web ep). App feature DTOs use
 * codegen adapters (the established pattern). Actions: claim, decision, resolve.
 */
interface ModerationAdminApi {

    @GET("v1/admin/moderation/tickets")
    suspend fun listTickets(
        @Query("status") status: String? = null,
        @Query("queue") queue: String? = null,
        @Query("topic") topic: String? = null,
        @Query("assignee") assignee: String? = null,
        @Query("limit") limit: Int? = null,
        @Query("cursor") cursor: String? = null,
    ): ModerationTicketListDto

    @GET("v1/admin/moderation/tickets/{id}")
    suspend fun ticketDetail(@Path("id") ticketId: String): ModerationTicketDetailDto

    @POST("v1/admin/moderation/tickets/{id}/claim")
    suspend fun claim(@Path("id") ticketId: String): ModerationTicketDto

    @POST("v1/admin/moderation/tickets/{id}/decision")
    suspend fun decide(
        @Path("id") ticketId: String,
        @Body body: ModerationDecisionReq,
    ): ModerationTicketDto

    @POST("v1/admin/moderation/tickets/{id}/resolve")
    suspend fun resolve(
        @Path("id") ticketId: String,
        @Body body: ModerationResolveReq,
    ): ModerationTicketDto
}

// ---- DTOs (verified 1:1 against api/endpoints/moderation.ts) ----

@JsonClass(generateAdapter = true)
data class ModerationTicketDto(
    @Json(name = "ticket_id") val ticketId: String,
    @Json(name = "content_type") val contentType: String = "",
    @Json(name = "content_id") val contentId: String = "",
    @Json(name = "status") val status: String = "",
    @Json(name = "priority") val priority: String = "",
    @Json(name = "queue") val queue: String = "",
    @Json(name = "assigned_admin_user_id") val assignedAdminUserId: String? = null,
    @Json(name = "report_count") val reportCount: Int = 0,
    @Json(name = "aggregated_topics") val aggregatedTopics: List<String> = emptyList(),
    @Json(name = "latest_report_at") val latestReportAt: Long = 0L,
    @Json(name = "updated_at") val updatedAt: Long = 0L,
    @Json(name = "created_at") val createdAt: Long = 0L,
)

@JsonClass(generateAdapter = true)
data class ModerationTicketListDto(
    @Json(name = "items") val items: List<ModerationTicketDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
)

@JsonClass(generateAdapter = true)
data class ModerationLinkedReportDto(
    @Json(name = "report_id") val reportId: String = "",
    @Json(name = "reporter_user_id") val reporterUserId: String = "",
    @Json(name = "topics") val topics: List<String> = emptyList(),
    @Json(name = "reason_text") val reasonText: String = "",
    @Json(name = "created_at") val createdAt: Long = 0L,
)

@JsonClass(generateAdapter = true)
data class ModerationOffenderHistoryDto(
    @Json(name = "offender_user_id") val offenderUserId: String? = null,
    @Json(name = "total_tickets") val totalTickets: Int = 0,
    @Json(name = "open_tickets") val openTickets: Int = 0,
    @Json(name = "total_reports") val totalReports: Int = 0,
)

@JsonClass(generateAdapter = true)
data class ModerationTicketDetailDto(
    @Json(name = "ticket") val ticket: ModerationTicketDto,
    @Json(name = "linked_reports") val linkedReports: List<ModerationLinkedReportDto> = emptyList(),
    @Json(name = "offender_history_summary") val offenderHistory: ModerationOffenderHistoryDto? = null,
)

@JsonClass(generateAdapter = true)
data class ModerationDecisionReq(
    @Json(name = "decision") val decision: String,
    @Json(name = "note") val note: String? = null,
)

@JsonClass(generateAdapter = true)
data class ModerationResolveReq(
    @Json(name = "resolution") val resolution: String,
    @Json(name = "enforcement_action") val enforcementAction: String,
    @Json(name = "note") val note: String? = null,
)

/**
 * B5 - read + action data layer over [ModerationAdminApi]. Read-then-act queue; no cache (operational,
 * auth-scoped). A backend 403 surfaces as Failure(status=403) which the ViewModel maps to Forbidden.
 */
interface ModerationAdminRepository {
    suspend fun list(status: String?): ApiResult<ModerationTicketListDto>
    suspend fun detail(ticketId: String): ApiResult<ModerationTicketDetailDto>
    suspend fun claim(ticketId: String): ApiResult<ModerationTicketDto>
    suspend fun decide(ticketId: String, decision: String, note: String?): ApiResult<ModerationTicketDto>
    suspend fun resolve(
        ticketId: String,
        resolution: String,
        enforcementAction: String,
        note: String?,
    ): ApiResult<ModerationTicketDto>
}

@Singleton
class DefaultModerationAdminRepository @Inject constructor(
    private val api: ModerationAdminApi,
    private val errorParser: ApiErrorParser,
) : ModerationAdminRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun list(status: String?): ApiResult<ModerationTicketListDto> =
        withContext(io) { call { api.listTickets(status = status, limit = 50) } }

    override suspend fun detail(ticketId: String): ApiResult<ModerationTicketDetailDto> =
        withContext(io) { call { api.ticketDetail(ticketId) } }

    override suspend fun claim(ticketId: String): ApiResult<ModerationTicketDto> =
        withContext(io) { call { api.claim(ticketId) } }

    override suspend fun decide(
        ticketId: String,
        decision: String,
        note: String?,
    ): ApiResult<ModerationTicketDto> =
        withContext(io) { call { api.decide(ticketId, ModerationDecisionReq(decision, blankToNull(note))) } }

    override suspend fun resolve(
        ticketId: String,
        resolution: String,
        enforcementAction: String,
        note: String?,
    ): ApiResult<ModerationTicketDto> = withContext(io) {
        call { api.resolve(ticketId, ModerationResolveReq(resolution, enforcementAction, blankToNull(note))) }
    }

    private fun blankToNull(s: String?): String? = s?.trim()?.takeIf { it.isNotEmpty() }

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
object ModerationAdminApiModule {
    @Provides
    @Singleton
    fun provideModerationAdminApi(retrofit: Retrofit): ModerationAdminApi =
        retrofit.create(ModerationAdminApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class ModerationAdminDataModule {
    @dagger.Binds
    @Singleton
    abstract fun bindModerationAdminRepository(
        impl: DefaultModerationAdminRepository,
    ): ModerationAdminRepository
}
