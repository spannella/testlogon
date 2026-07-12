package com.testlogon.android.data.costs

import java.util.Locale

/**
 * Framework-free cost-tracking domain models + total DTO -> domain mappers.
 *
 * Mirrors the web cost pages (overview, breakdown, budgets, alerts). Money is integer CENTS; [formatCents]
 * renders "$X.XX" (mirrors the web `formatCents`). Budget/alert timestamps are epoch-seconds. Enum folds
 * keep the UI resilient to unknown server values.
 */

/** "$12.34" from an integer-cents amount (mirrors the web formatCents). */
fun formatCents(cents: Long): String = "$" + String.format(Locale.US, "%,.2f", cents / 100.0)

enum class AlertSeverity {
    INFO, WARNING, CRITICAL, UNKNOWN;

    companion object {
        fun from(raw: String?): AlertSeverity = when (raw?.lowercase(Locale.US)) {
            "info" -> INFO
            "warning" -> WARNING
            "critical" -> CRITICAL
            else -> UNKNOWN
        }
    }
}

data class CostSummary(
    val date: String,
    val totalCents: Long,
    val llmCents: Long,
    val computeCents: Long,
    val byAgentType: List<Pair<String, Long>>,
    val byWorker: List<WorkerCost>,
)

data class WorkerCost(
    val workerId: String,
    val agentType: String,
    val date: String,
    val llmCents: Long,
    val computeCents: Long,
    val totalCents: Long,
)

data class TrendWeek(
    val weekStart: String,
    val totalCents: Long,
    val llmCents: Long,
    val computeCents: Long,
)

data class TicketCost(
    val ticketId: String,
    val agentType: String,
    val totalCents: Long,
    val status: String,
) {
    val isCompleted: Boolean get() = status.equals("completed", ignoreCase = true)
}

data class Optimization(
    val type: String,
    val title: String,
    val description: String,
    val potentialSavingsCents: Long,
    val action: String,
)

/** Aggregated overview surface (today + this-week + this-month + trend series + today's split). */
data class CostOverview(
    val today: CostSummary,
    val weekCents: Long,
    val monthCents: Long,
    val weeks: List<TrendWeek>,
    val unacknowledgedAlerts: Int,
    val optimizations: List<Optimization>,
) {
    val isEmpty: Boolean
        get() = today.totalCents == 0L && weeks.isEmpty() && today.byAgentType.isEmpty()
}

data class Budget(
    val id: String,
    val name: String,
    val scope: String,
    val scopeRef: String?,
    val period: String,
    val limitCents: Long,
    val alertThresholdPct: Int,
    val autoPauseOnExceed: Boolean,
    val enabled: Boolean,
)

data class CostAlert(
    val id: String,
    val severity: AlertSeverity,
    val title: String,
    val message: String,
    val currentSpendCents: Long,
    val budgetLimitCents: Long?,
    val acknowledged: Boolean,
    val autoActionTaken: String?,
)

// ---- Mappers (DTO -> domain) ----

internal fun AgentCostEntryDto.toDomain(): WorkerCost = WorkerCost(
    workerId = workerId,
    agentType = agentType,
    date = date,
    llmCents = llmCostCents,
    computeCents = computeCostCents,
    totalCents = totalCostCents,
)

internal fun CostDailySummaryDto.toDomain(): CostSummary = CostSummary(
    date = date,
    totalCents = totalCents,
    llmCents = llmCents,
    computeCents = computeCents,
    byAgentType = byAgentType.entries.map { it.key to it.value }.sortedByDescending { it.second },
    byWorker = byWorker.map { it.toDomain() },
)

internal fun CostTrendWeekDto.toDomain(): TrendWeek = TrendWeek(
    weekStart = weekStart,
    totalCents = totalCents,
    llmCents = llmCents,
    computeCents = computeCents,
)

internal fun TicketCostDto.toDomain(): TicketCost = TicketCost(
    ticketId = ticketId,
    agentType = agentType,
    totalCents = totalCostCents,
    status = status,
)

internal fun OptimizationRecommendationDto.toDomain(): Optimization = Optimization(
    type = type,
    title = title,
    description = description,
    potentialSavingsCents = potentialSavingsCents,
    action = action,
)

internal fun CostBudgetDto.toDomain(): Budget = Budget(
    id = budgetId,
    name = name,
    scope = scope,
    scopeRef = scopeRef?.takeIf { it.isNotBlank() },
    period = period,
    limitCents = limitCents,
    alertThresholdPct = alertThresholdPct,
    autoPauseOnExceed = autoPauseOnExceed,
    enabled = enabled,
)

internal fun CostAlertDto.toDomain(): CostAlert = CostAlert(
    id = alertId,
    severity = AlertSeverity.from(severity),
    title = title,
    message = message,
    currentSpendCents = currentSpendCents,
    budgetLimitCents = budgetLimitCents,
    acknowledged = acknowledged,
    autoActionTaken = autoActionTaken?.takeIf { it.isNotBlank() },
)
