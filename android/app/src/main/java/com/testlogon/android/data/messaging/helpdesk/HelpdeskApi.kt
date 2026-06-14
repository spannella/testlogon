package com.testlogon.android.data.messaging.helpdesk

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import com.testlogon.android.data.messaging.ConversationDto
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * AND-161 / AND-162 — Retrofit interface for the agent-facing helpdesk surface.
 *
 * Kept SEPARATE from MessagingApi (per the gotchas) so the large MessagingApi + its test FakeApi stay
 * untouched. Paths are relative; cookies/Authorization/CSRF ride the shared interceptor chain.
 *
 * Endpoints verified against reference/openapi.index.txt (lines 393, 394) and
 * reference/openapi.pretty.json:
 *  - queue GET  messaging/helpdesk/queue?group_id=&state=&limit= -> 200 (bare ConversationOut[] array)
 *  - claim POST messaging/helpdesk/conversations/{conversation_id}/claim (no body) -> 200 HelpdeskClaimOut
 *
 * There is NO single-conversation helpdesk GET; refresh of assignment state is via the queue. The
 * queue is a single bounded fetch (no cursor/envelope) — only `limit` (default 50, max 200) controls
 * size, and `group_id` is REQUIRED. `last_message_at`/`active_agent_claimed_at` are epoch-SECONDS ints.
 */
interface HelpdeskApi {

    /**
     * Helpdesk queue: a BARE JSON array of ConversationOut. `group_id` is required. A 403 is the
     * not-an-agent signal (handled by the repository). Idempotent GET.
     */
    @GET("messaging/helpdesk/queue")
    suspend fun getQueue(
        @Query("group_id") groupId: String,
        @Query("state") state: String? = null,
        @Query("limit") limit: Int = DEFAULT_LIMIT,
    ): List<ConversationDto>

    /**
     * Claim a queued conversation for the current agent. EMPTY body. Returns HelpdeskClaimOut. The path
     * param is the messaging conversation id. Non-idempotent POST (never auto-retried); naturally
     * idempotent server-side (`idempotent: true` when re-claiming one's own conversation).
     */
    @Headers("Content-Type: application/json")
    @POST("messaging/helpdesk/conversations/{conversation_id}/claim")
    suspend fun claim(
        @Path("conversation_id") conversationId: String,
    ): HelpdeskClaimOutDto

    companion object {
        /** Queue page size; server default 50, max 200. */
        const val DEFAULT_LIMIT = 50
    }
}

/**
 * HelpdeskClaimOut. Required: ok, conversation_id, state, assigned_agent_user_id, assignment_version.
 * `idempotent` defaults false. No agent display name and no nested assignee — only the agent user id.
 * `state` ∈ {assigned, awaiting_agent, paused_no_agents_online, closed}.
 */
@JsonClass(generateAdapter = true)
data class HelpdeskClaimOutDto(
    val ok: Boolean = false,
    @Json(name = "conversation_id") val conversationId: String,
    val state: String,
    @Json(name = "assigned_agent_user_id") val assignedAgentUserId: String,
    @Json(name = "assignment_version") val assignmentVersion: Int = 0,
    val idempotent: Boolean = false,
)
