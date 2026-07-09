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

    // MOD-E1: NEW state-machine case actions (admin_moderation.py:1041-1170).
    // dismiss = no violation -> un-hide (visible); confirm = violation -> 30d hold (hidden);
    // final-call {reinstate|delete} on a hold/awaiting_final case (delete supports +ban).
    @POST("v1/admin/moderation/tickets/{id}/dismiss")
    suspend fun dismiss(@Path("id") ticketId: String): ModerationCaseActionDto

    @POST("v1/admin/moderation/tickets/{id}/confirm")
    suspend fun confirm(@Path("id") ticketId: String): ModerationCaseActionDto

    @POST("v1/admin/moderation/tickets/{id}/final-call")
    suspend fun finalCall(
        @Path("id") ticketId: String,
        @Body body: ModerationFinalCallReq,
    ): ModerationCaseActionDto
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
data class ModerationContentSnapshotDto(
    @Json(name = "kind") val kind: String = "",
    @Json(name = "exists") val exists: Boolean = false,
    @Json(name = "text") val text: String = "",
    @Json(name = "author_user_id") val authorUserId: String? = null,
    @Json(name = "post_id") val postId: String? = null,
    @Json(name = "comment_id") val commentId: String? = null,
    @Json(name = "conversation_id") val conversationId: String? = null,
    @Json(name = "message_id") val messageId: String? = null,
    @Json(name = "syndicate_id") val syndicateId: String? = null,
    @Json(name = "profile_photo_url") val profilePhotoUrl: String? = null,
    @Json(name = "image_urls") val imageUrls: List<String> = emptyList(),
    @Json(name = "created_at") val createdAt: Long = 0L,
)

/** MOD-E2: one prior enforcement record on the offender (user_enforcement_history). */
@JsonClass(generateAdapter = true)
data class ModerationEnforcementHistoryDto(
    @Json(name = "enforcement_id") val enforcementId: String = "",
    @Json(name = "enforcement_type") val enforcementType: String = "",
    @Json(name = "status") val status: String = "",
    @Json(name = "duration_days") val durationDays: Int = 0,
    @Json(name = "source_ticket_id") val sourceTicketId: String = "",
    @Json(name = "note") val note: String = "",
    @Json(name = "created_at") val createdAt: Long = 0L,
)

@JsonClass(generateAdapter = true)
data class ModerationTicketDetailDto(
    @Json(name = "ticket") val ticket: ModerationTicketDto,
    @Json(name = "linked_reports") val linkedReports: List<ModerationLinkedReportDto> = emptyList(),
    @Json(name = "offender_history_summary") val offenderHistory: ModerationOffenderHistoryDto? = null,
    // MOD-E1: NEW state-machine fields (additive backend detail; admin_moderation.py detail endpoint).
    @Json(name = "content_snapshot") val contentSnapshot: ModerationContentSnapshotDto? = null,
    @Json(name = "case_state") val caseState: String = "",
    @Json(name = "hold_until") val holdUntil: Long? = null,
    @Json(name = "owner_user_id") val ownerUserId: String? = null,
    @Json(name = "prior_enforcement_history") val priorEnforcement: List<ModerationEnforcementHistoryDto> = emptyList(),
)

/** MOD-E1: response of dismiss/confirm/final-call (admin_moderation.py _CaseActionOut). */
@JsonClass(generateAdapter = true)
data class ModerationCaseActionDto(
    @Json(name = "ok") val ok: Boolean = false,
    @Json(name = "ticket_id") val ticketId: String = "",
    @Json(name = "case_id") val caseId: String = "",
    @Json(name = "state") val state: String = "",
    @Json(name = "hidden") val hidden: Boolean = false,
    @Json(name = "hold_until") val holdUntil: Long? = null,
    @Json(name = "owner_user_id") val ownerUserId: String? = null,
    @Json(name = "enforcement_id") val enforcementId: String? = null,
)

/** MOD-E2: final-call body. action=reinstate|delete; delete may ban (ban_duration_days=0 => permanent). */
@JsonClass(generateAdapter = true)
data class ModerationFinalCallReq(
    @Json(name = "action") val action: String,
    @Json(name = "note") val note: String? = null,
    @Json(name = "ban") val ban: Boolean = false,
    @Json(name = "ban_duration_days") val banDurationDays: Int? = null,
    @Json(name = "second_approver_admin_user_id") val secondApproverAdminUserId: String? = null,
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

    // MOD-E1/E2 state-machine actions.
    suspend fun dismiss(ticketId: String): ApiResult<ModerationCaseActionDto>
    suspend fun confirm(ticketId: String): ApiResult<ModerationCaseActionDto>
    suspend fun finalCall(
        ticketId: String,
        action: String,
        note: String?,
        ban: Boolean,
        banDurationDays: Int?,
    ): ApiResult<ModerationCaseActionDto>
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

    override suspend fun dismiss(ticketId: String): ApiResult<ModerationCaseActionDto> =
        withContext(io) { call { api.dismiss(ticketId) } }

    override suspend fun confirm(ticketId: String): ApiResult<ModerationCaseActionDto> =
        withContext(io) { call { api.confirm(ticketId) } }

    override suspend fun finalCall(
        ticketId: String,
        action: String,
        note: String?,
        ban: Boolean,
        banDurationDays: Int?,
    ): ApiResult<ModerationCaseActionDto> = withContext(io) {
        call {
            api.finalCall(
                ticketId,
                ModerationFinalCallReq(
                    action = action,
                    note = blankToNull(note),
                    ban = ban,
                    banDurationDays = banDurationDays,
                ),
            )
        }
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
