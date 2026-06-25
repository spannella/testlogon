package com.testlogon.android.core.network.support

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.POST
import retrofit2.http.Query

/**
 * B8 Android #13 — the CUSTOMER side of live-agent (helpdesk) chat.
 *
 * A normal user can (verified live against prod):
 *  1. CHECK availability — `GET messaging/helpdesk/availability?group_id=` is explicitly customer-callable
 *     (no helpdesk-group membership required) and returns COUNTS ONLY (never an agent identity).
 *  2. START a live chat — `POST messaging/conversations {type:"dm", routing_mode:"helpdesk_bridge",
 *     helpdesk_group_id:"<gid>"}` creates a real bridge conversation. The customer then talks via the normal
 *     messaging thread (`messaging/conversations/{id}/messages`). When an agent is online it is claimed and
 *     becomes a live DM; when no agent is online the conversation queues (routing_state
 *     awaiting_agent / paused_no_agents_online) and the customer's messages are delivered when an agent picks
 *     it up. This is the SAME conversation surface the existing ThreadScreen renders, so we just open it.
 *
 * Paths are relative to the shared authenticated Retrofit base URL; cookies + X-CSRF-Token ride the global
 * interceptor chain. Kept as a SEPARATE small interface so the large MessagingApi (+ its many test fakes) is
 * untouched.
 */
interface SupportLiveChatApi {

    /** Customer-callable agent availability for a helpdesk group. Counts only. Idempotent GET. */
    @GET("messaging/helpdesk/availability")
    suspend fun availability(
        @Query("group_id") groupId: String,
    ): HelpdeskAvailabilityDto

    /**
     * Start (or resume) a live-agent chat: creates a helpdesk_bridge DM conversation routed to [groupId].
     * Returns the conversation; the caller then opens the standard messaging thread by its id.
     */
    @Headers("Content-Type: application/json")
    @POST("messaging/conversations")
    suspend fun startLiveChat(
        @Body body: StartLiveChatReq,
    ): LiveChatConversationDto
}

@JsonClass(generateAdapter = true)
data class HelpdeskAvailabilityDto(
    @Json(name = "available_agent_count") val availableAgentCount: Int = 0,
    @Json(name = "any_available") val anyAvailable: Boolean = false,
)

@JsonClass(generateAdapter = true)
data class StartLiveChatReq(
    @Json(name = "type") val type: String = "dm",
    @Json(name = "routing_mode") val routingMode: String = "helpdesk_bridge",
    @Json(name = "helpdesk_group_id") val helpdeskGroupId: String,
)

/**
 * Only the fields we need from the ConversationOut envelope. The conversation id is the one required field;
 * routing_state is informational (awaiting_agent | assigned | paused_no_agents_online).
 */
@JsonClass(generateAdapter = true)
data class LiveChatConversationDto(
    @Json(name = "conversation_id") val conversationId: String,
    @Json(name = "type") val type: String? = null,
    @Json(name = "routing_mode") val routingMode: String? = null,
    @Json(name = "routing_state") val routingState: String? = null,
    @Json(name = "agent_connected") val agentConnected: Boolean? = null,
)
