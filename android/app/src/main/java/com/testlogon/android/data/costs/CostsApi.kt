package com.testlogon.android.data.costs

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.PUT
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * Retrofit interface + Moshi DTOs for the Accountant / cost-tracking agent (web /agents/costs area).
 *
 * Mirrors frontend/src/api/endpoints/accountantAgent.ts (BASE /ui/agents/accountant): daily/period
 * summaries, trends, by-agent-type + by-ticket breakdowns, optimization recommendations, budget CRUD,
 * cost alerts + acknowledge, and a manual collect trigger. All endpoints are backend
 * `require_ui_session` (agent_accountant.py) -> usable by any authenticated user (no operator gate).
 * Money fields are integer CENTS; budget `created_at` / alert `created_at` are epoch-SECONDS (Long);
 * summary `date` / `week_start` are ISO date STRINGS. Session cookies / Bearer / X-CSRF-Token are
 * attached by interceptors; paths relative (the base URL carries the trailing slash).
 */
interface CostsApi {

    @GET("ui/agents/accountant/costs/summary/daily")
    suspend fun getDailySummary(@Query("date") date: String? = null): CostDailySummaryDto

    @GET("ui/agents/accountant/costs/trends")
    suspend fun getTrends(@Query("days") days: Int = 30): CostTrendsDto

    @GET("ui/agents/accountant/costs/by-ticket")
    suspend fun listTicketCosts(
        @Query("limit") limit: Int = 50,
        @Query("cursor") cursor: String? = null,
    ): TicketCostListDto

    @GET("ui/agents/accountant/costs/optimizations")
    suspend fun getOptimizations(): List<OptimizationRecommendationDto>

    @GET("ui/agents/accountant/costs/budgets")
    suspend fun listBudgets(): List<CostBudgetDto>

    @POST("ui/agents/accountant/costs/budgets")
    suspend fun createBudget(@Body body: CostBudgetInDto): CostBudgetDto

    @PUT("ui/agents/accountant/costs/budgets/{budgetId}")
    suspend fun updateBudget(
        @Path("budgetId") budgetId: String,
        @Body body: CostBudgetUpdateInDto,
    ): CostBudgetDto

    @DELETE("ui/agents/accountant/costs/budgets/{budgetId}")
    suspend fun deleteBudget(@Path("budgetId") budgetId: String): DeleteBudgetResultDto

    @GET("ui/agents/accountant/costs/alerts")
    suspend fun listAlerts(@Query("acknowledged") acknowledged: Boolean? = null): CostAlertListDto

    @POST("ui/agents/accountant/costs/alerts/{alertId}/acknowledge")
    suspend fun acknowledgeAlert(@Path("alertId") alertId: String): CostAlertDto
}

// ---- DTOs ----

@JsonClass(generateAdapter = true)
data class AgentCostEntryDto(
    @Json(name = "worker_id") val workerId: String = "",
    @Json(name = "agent_type") val agentType: String = "",
    @Json(name = "agent_id") val agentId: String = "",
    val date: String = "",
    @Json(name = "llm_cost_cents") val llmCostCents: Long = 0,
    @Json(name = "compute_cost_cents") val computeCostCents: Long = 0,
    @Json(name = "total_cost_cents") val totalCostCents: Long = 0,
)

@JsonClass(generateAdapter = true)
data class CostDailySummaryDto(
    val date: String = "",
    @Json(name = "total_cents") val totalCents: Long = 0,
    @Json(name = "llm_cents") val llmCents: Long = 0,
    @Json(name = "compute_cents") val computeCents: Long = 0,
    @Json(name = "by_agent_type") val byAgentType: Map<String, Long> = emptyMap(),
    @Json(name = "by_worker") val byWorker: List<AgentCostEntryDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class CostTrendWeekDto(
    @Json(name = "week_start") val weekStart: String = "",
    @Json(name = "total_cents") val totalCents: Long = 0,
    @Json(name = "llm_cents") val llmCents: Long = 0,
    @Json(name = "compute_cents") val computeCents: Long = 0,
)

@JsonClass(generateAdapter = true)
data class CostTrendsDto(
    val weeks: List<CostTrendWeekDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class TicketCostDto(
    @Json(name = "ticket_id") val ticketId: String = "",
    @Json(name = "agent_type") val agentType: String = "",
    @Json(name = "total_cost_cents") val totalCostCents: Long = 0,
    val status: String = "",
)

@JsonClass(generateAdapter = true)
data class TicketCostListDto(
    @Json(name = "ticket_costs") val ticketCosts: List<TicketCostDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
)

@JsonClass(generateAdapter = true)
data class OptimizationRecommendationDto(
    val type: String = "",
    val title: String = "",
    val description: String = "",
    @Json(name = "potential_savings_cents") val potentialSavingsCents: Long = 0,
    val action: String = "",
)

@JsonClass(generateAdapter = true)
data class CostBudgetDto(
    @Json(name = "budget_id") val budgetId: String = "",
    val name: String = "",
    val scope: String = "",
    @Json(name = "scope_ref") val scopeRef: String? = null,
    val period: String = "",
    @Json(name = "limit_cents") val limitCents: Long = 0,
    @Json(name = "alert_threshold_pct") val alertThresholdPct: Int = 0,
    @Json(name = "auto_pause_on_exceed") val autoPauseOnExceed: Boolean = false,
    val enabled: Boolean = true,
    @Json(name = "created_at") val createdAt: Long = 0,
)

@JsonClass(generateAdapter = true)
data class CostBudgetInDto(
    val name: String,
    val scope: String,
    @Json(name = "scope_ref") val scopeRef: String? = null,
    val period: String,
    @Json(name = "limit_cents") val limitCents: Long,
    @Json(name = "alert_threshold_pct") val alertThresholdPct: Int = 80,
    @Json(name = "auto_pause_on_exceed") val autoPauseOnExceed: Boolean = false,
)

@JsonClass(generateAdapter = true)
data class CostBudgetUpdateInDto(
    val name: String? = null,
    @Json(name = "limit_cents") val limitCents: Long? = null,
    @Json(name = "alert_threshold_pct") val alertThresholdPct: Int? = null,
    @Json(name = "auto_pause_on_exceed") val autoPauseOnExceed: Boolean? = null,
    val enabled: Boolean? = null,
)

@JsonClass(generateAdapter = true)
data class DeleteBudgetResultDto(
    val ok: Boolean = false,
    @Json(name = "budget_id") val budgetId: String = "",
)

@JsonClass(generateAdapter = true)
data class CostAlertDto(
    @Json(name = "alert_id") val alertId: String = "",
    @Json(name = "budget_id") val budgetId: String? = null,
    @Json(name = "alert_type") val alertType: String = "",
    val severity: String = "",
    val title: String = "",
    val message: String = "",
    @Json(name = "current_spend_cents") val currentSpendCents: Long = 0,
    @Json(name = "budget_limit_cents") val budgetLimitCents: Long? = null,
    val acknowledged: Boolean = false,
    @Json(name = "auto_action_taken") val autoActionTaken: String? = null,
    @Json(name = "created_at") val createdAt: Long = 0,
)

@JsonClass(generateAdapter = true)
data class CostAlertListDto(
    val alerts: List<CostAlertDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
)
