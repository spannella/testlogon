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

    // MODX-22: bulk triage over many tickets (per-item results).
    @POST("v1/admin/moderation/tickets/bulk")
    suspend fun bulk(@Body body: ModerationBulkReq): ModerationBulkResultDto

    // MODX-19: ban management roster + lift.
    @GET("v1/admin/moderation/bans")
    suspend fun listBans(
        @Query("user") user: String? = null,
        @Query("include_inactive") includeInactive: Boolean? = null,
    ): ModerationBanRosterDto

    @POST("v1/admin/moderation/bans/{userId}/lift")
    suspend fun liftBan(
        @Path("userId") userId: String,
        @Body body: ModerationBanLiftReq,
    ): ModerationBanLiftDto

    // MODX-20: decision audit trail for one ticket.
    @GET("v1/admin/moderation/tickets/{id}/audit")
    suspend fun ticketAudit(@Path("id") ticketId: String): ModerationAuditTrailDto

    // Queue-health KPIs for the board strip (parity with web ModerationBoardPage's getModerationKpis).
    @GET("v1/admin/moderation/kpis")
    suspend fun kpis(): ModerationKpisDto
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
    // MODX-14 (C3): the poster hold-response so the final call is not made blind.
    @Json(name = "poster_response") val posterResponse: String? = null,
    @Json(name = "responded_at") val respondedAt: Long? = null,
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

// ---- MODX-22: bulk actions ----
@JsonClass(generateAdapter = true)
data class ModerationBulkReq(
    @Json(name = "ticket_ids") val ticketIds: List<String>,
    @Json(name = "action") val action: String,
    @Json(name = "note") val note: String? = null,
    @Json(name = "steal") val steal: Boolean = false,
)

@JsonClass(generateAdapter = true)
data class ModerationBulkItemDto(
    @Json(name = "ticket_id") val ticketId: String = "",
    @Json(name = "ok") val ok: Boolean = false,
    @Json(name = "state") val state: String? = null,
    @Json(name = "error_code") val errorCode: String? = null,
    @Json(name = "error") val error: String? = null,
)

@JsonClass(generateAdapter = true)
data class ModerationBulkResultDto(
    @Json(name = "action") val action: String = "",
    @Json(name = "total") val total: Int = 0,
    @Json(name = "succeeded") val succeeded: Int = 0,
    @Json(name = "failed") val failed: Int = 0,
    @Json(name = "results") val results: List<ModerationBulkItemDto> = emptyList(),
)

// ---- MODX-19: ban management ----
@JsonClass(generateAdapter = true)
data class ModerationBanEntryDto(
    @Json(name = "user_id") val userId: String = "",
    @Json(name = "enforcement_id") val enforcementId: String = "",
    @Json(name = "source_ticket_id") val sourceTicketId: String = "",
    @Json(name = "created_at") val createdAt: Long = 0L,
    @Json(name = "created_by_admin_user_id") val createdBy: String? = null,
    @Json(name = "duration_days") val durationDays: Int = 0,
    @Json(name = "ban_until") val banUntil: Long = 0L,
    @Json(name = "permanent") val permanent: Boolean = false,
    @Json(name = "note") val note: String = "",
    @Json(name = "account_status") val accountStatus: String = "",
    @Json(name = "active") val active: Boolean = true,
)

@JsonClass(generateAdapter = true)
data class ModerationBanRosterDto(
    @Json(name = "items") val items: List<ModerationBanEntryDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
)

@JsonClass(generateAdapter = true)
data class ModerationBanLiftReq(
    @Json(name = "note") val note: String? = null,
    @Json(name = "enforcement_id") val enforcementId: String? = null,
)

@JsonClass(generateAdapter = true)
data class ModerationBanLiftDto(
    @Json(name = "ok") val ok: Boolean = false,
    @Json(name = "user_id") val userId: String = "",
    @Json(name = "account_status") val accountStatus: String = "",
    @Json(name = "lifted_enforcement_ids") val liftedEnforcementIds: List<String> = emptyList(),
)

// ---- Queue-health KPIs (board strip; parity with web ModerationKpis) ----
// Only the four fields the strip renders are modelled; Moshi ignores the rest of the payload.
@JsonClass(generateAdapter = true)
data class ModerationKpisDto(
    @Json(name = "open_ticket_count") val openTicketCount: Int = 0,
    @Json(name = "on_hold_count") val onHoldCount: Int = 0,
    @Json(name = "critical_backlog") val criticalBacklog: Int = 0,
    @Json(name = "oldest_open_age_minutes") val oldestOpenAgeMinutes: Int = 0,
)

// ---- MODX-20: audit trail ----
@JsonClass(generateAdapter = true)
data class ModerationAuditEventDto(
    @Json(name = "audit_id") val auditId: String = "",
    @Json(name = "action") val action: String = "",
    @Json(name = "actor_user_id") val actorUserId: String = "",
    @Json(name = "ticket_id") val ticketId: String = "",
    @Json(name = "target_user_id") val targetUserId: String = "",
    @Json(name = "created_at") val createdAt: Long = 0L,
)

@JsonClass(generateAdapter = true)
data class ModerationAuditTrailDto(
    @Json(name = "items") val items: List<ModerationAuditEventDto> = emptyList(),
)

/**
 * B5 - read + action data layer over [ModerationAdminApi]. Read-then-act queue; no cache (operational,
 * auth-scoped). A backend 403 surfaces as Failure(status=403) which the ViewModel maps to Forbidden.
 */
interface ModerationAdminRepository {
    suspend fun list(status: String?): ApiResult<ModerationTicketListDto>

    // MODX-21: real status + live-category filter + cursor pagination (infinite scroll).
    suspend fun listPage(
        status: String?,
        topic: String?,
        cursor: String?,
    ): ApiResult<ModerationTicketListDto>

    // MODX-22 / MODX-19 / MODX-20 admin-at-scale actions.
    suspend fun bulk(ticketIds: List<String>, action: String, note: String?): ApiResult<ModerationBulkResultDto>
    suspend fun listBans(includeInactive: Boolean = false): ApiResult<ModerationBanRosterDto>
    suspend fun liftBan(userId: String, note: String?): ApiResult<ModerationBanLiftDto>
    suspend fun ticketAudit(ticketId: String): ApiResult<ModerationAuditTrailDto>
    suspend fun kpis(): ApiResult<ModerationKpisDto>

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

    override suspend fun listPage(
        status: String?,
        topic: String?,
        cursor: String?,
    ): ApiResult<ModerationTicketListDto> = withContext(io) {
        call { api.listTickets(status = status, topic = topic, limit = 50, cursor = cursor) }
    }

    override suspend fun bulk(
        ticketIds: List<String>,
        action: String,
        note: String?,
    ): ApiResult<ModerationBulkResultDto> = withContext(io) {
        call { api.bulk(ModerationBulkReq(ticketIds = ticketIds, action = action, note = blankToNull(note))) }
    }

    override suspend fun listBans(includeInactive: Boolean): ApiResult<ModerationBanRosterDto> =
        withContext(io) { call { api.listBans(includeInactive = includeInactive) } }

    override suspend fun liftBan(userId: String, note: String?): ApiResult<ModerationBanLiftDto> =
        withContext(io) { call { api.liftBan(userId, ModerationBanLiftReq(note = blankToNull(note))) } }

    override suspend fun ticketAudit(ticketId: String): ApiResult<ModerationAuditTrailDto> =
        withContext(io) { call { api.ticketAudit(ticketId) } }

    override suspend fun kpis(): ApiResult<ModerationKpisDto> =
        withContext(io) { call { api.kpis() } }

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
