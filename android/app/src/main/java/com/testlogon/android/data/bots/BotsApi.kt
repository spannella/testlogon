package com.testlogon.android.data.bots

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.PATCH
import retrofit2.http.POST
import retrofit2.http.PUT
import retrofit2.http.Path

/**
 * Retrofit interface + Moshi DTOs for the user-facing bots feature.
 *
 * Mirrors the web bots pages: list / create / status / delete a chat bot (ui/bots), manage a bot's
 * auto-reply rules (ui/bots/{botId}/auto-replies) and message templates (ui/bots/{botId}/templates).
 * Session cookies / Bearer / X-CSRF-Token are attached by interceptors. The base URL carries the
 * trailing slash, so every path here is relative and WITHOUT a leading slash.
 */
interface BotsApi {

    // ---- Chat bots ----

    /** The signed-in creator's chat bots. */
    @GET("ui/bots")
    suspend fun listBots(): BotListDto

    /** Creates a new chat bot. */
    @POST("ui/bots")
    suspend fun createBot(@Body body: BotCreateReqDto): BotDto

    /** Updates a bot's lifecycle status (active / paused / disabled). */
    @PATCH("ui/bots/{botId}/status")
    suspend fun updateBotStatus(
        @Path("botId") botId: String,
        @Body body: BotStatusReqDto,
    ): BotDto

    /** Permanently deletes a bot. */
    @DELETE("ui/bots/{botId}")
    suspend fun deleteBot(@Path("botId") botId: String): OkDto

    // ---- Auto-reply rules ----

    /** A bot's auto-reply rules. */
    @GET("ui/bots/{botId}/auto-replies")
    suspend fun listAutoReplyRules(@Path("botId") botId: String): AutoReplyListDto

    /** Creates a new auto-reply rule for a bot. */
    @POST("ui/bots/{botId}/auto-replies")
    suspend fun createAutoReplyRule(
        @Path("botId") botId: String,
        @Body body: AutoReplyReqDto,
    ): AutoReplyRuleDto

    /** Updates an existing auto-reply rule. */
    @PUT("ui/bots/{botId}/auto-replies/{ruleId}")
    suspend fun updateAutoReplyRule(
        @Path("botId") botId: String,
        @Path("ruleId") ruleId: String,
        @Body body: AutoReplyReqDto,
    ): AutoReplyRuleDto

    /** Deletes an auto-reply rule. */
    @DELETE("ui/bots/{botId}/auto-replies/{ruleId}")
    suspend fun deleteAutoReplyRule(
        @Path("botId") botId: String,
        @Path("ruleId") ruleId: String,
    ): OkDto

    // ---- Templates ----

    /** A bot's message templates. */
    @GET("ui/bots/{botId}/templates")
    suspend fun listTemplates(@Path("botId") botId: String): List<TemplateDto>

    /** Creates a new template for a bot. */
    @POST("ui/bots/{botId}/templates")
    suspend fun createTemplate(
        @Path("botId") botId: String,
        @Body body: TemplateReqDto,
    ): TemplateDto

    /** Deletes a template. */
    @DELETE("ui/bots/{botId}/templates/{templateId}")
    suspend fun deleteTemplate(
        @Path("botId") botId: String,
        @Path("templateId") templateId: String,
    ): OkDto
}

// ---- Shared DTOs ----

@JsonClass(generateAdapter = true)
data class OkDto(val ok: Boolean = false)

// ---- Chat bot DTOs ----

@JsonClass(generateAdapter = true)
data class BotListDto(
    val bots: List<BotDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class BotDto(
    @Json(name = "bot_id") val botId: String,
    @Json(name = "creator_id") val creatorId: String = "",
    val name: String = "",
    @Json(name = "avatar_url") val avatarUrl: String? = null,
    val description: String? = null,
    val personality: String? = null,
    @Json(name = "custom_personality") val customPersonality: String? = null,
    val status: String = "",
    @Json(name = "created_at") val createdAt: Long = 0,
    @Json(name = "updated_at") val updatedAt: Long = 0,
    @Json(name = "message_count") val messageCount: Int = 0,
)

@JsonClass(generateAdapter = true)
data class BotCreateReqDto(
    val name: String,
    val description: String? = null,
    val personality: String? = null,
)

@JsonClass(generateAdapter = true)
data class BotStatusReqDto(
    val status: String,
)

// ---- Auto-reply DTOs ----

@JsonClass(generateAdapter = true)
data class AutoReplyListDto(
    val rules: List<AutoReplyRuleDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class AutoReplyRuleDto(
    @Json(name = "rule_id") val ruleId: String,
    @Json(name = "bot_id") val botId: String = "",
    @Json(name = "trigger_pattern") val triggerPattern: String = "",
    @Json(name = "response_template") val responseTemplate: String = "",
    @Json(name = "match_type") val matchType: String = "",
    val priority: Int = 0,
    val enabled: Boolean = true,
    @Json(name = "created_at") val createdAt: Long = 0,
    @Json(name = "updated_at") val updatedAt: Long = 0,
    @Json(name = "match_count") val matchCount: Int = 0,
)

@JsonClass(generateAdapter = true)
data class AutoReplyReqDto(
    @Json(name = "trigger_pattern") val triggerPattern: String,
    @Json(name = "response_template") val responseTemplate: String,
    @Json(name = "match_type") val matchType: String,
    val priority: Int,
    val enabled: Boolean,
)

// ---- Template DTOs ----

@JsonClass(generateAdapter = true)
data class TemplateDto(
    @Json(name = "template_id") val templateId: String,
    @Json(name = "bot_id") val botId: String = "",
    val name: String = "",
    val text: String = "",
    val category: String = "",
    @Json(name = "body_format") val bodyFormat: String = "",
    @Json(name = "impression_count") val impressionCount: Int = 0,
    @Json(name = "response_count") val responseCount: Int = 0,
    @Json(name = "created_at") val createdAt: Long = 0,
    @Json(name = "updated_at") val updatedAt: Long = 0,
)

@JsonClass(generateAdapter = true)
data class TemplateReqDto(
    val name: String,
    val text: String,
    val category: String,
    @Json(name = "body_format") val bodyFormat: String,
)
