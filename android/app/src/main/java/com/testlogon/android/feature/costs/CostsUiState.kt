package com.testlogon.android.feature.costs

import androidx.annotation.StringRes
import com.testlogon.android.data.costs.Budget
import com.testlogon.android.data.costs.CostAlert
import com.testlogon.android.data.costs.CostOverview
import com.testlogon.android.data.costs.CostSummary
import com.testlogon.android.data.costs.TicketCost

/** Shared render phase for the four cost screens. */
enum class CostsPhase { Loading, Content, Empty, SessionExpired, Error, Offline }

/** One-shot side effects (Channel-backed so they are not replayed on rotation). */
sealed interface CostsEffect {
    data class ShowMessage(@StringRes val resId: Int) : CostsEffect
}

/** Cost Overview: today/week/month totals + trend series + today's split + unacked-alert banner. */
data class CostOverviewUiState(
    val phase: CostsPhase = CostsPhase.Loading,
    val overview: CostOverview? = null,
    val isRefreshing: Boolean = false,
    val isStale: Boolean = false,
    val errorMessage: String? = null,
)

/** Cost Breakdown: a selected date's by-agent-type + by-worker split, plus the ticket-cost list. */
data class CostBreakdownUiState(
    val phase: CostsPhase = CostsPhase.Loading,
    val date: String = "",
    val summary: CostSummary? = null,
    val tickets: List<TicketCost> = emptyList(),
    val isRefreshing: Boolean = false,
    val errorMessage: String? = null,
)

/** Budget Manager: list of budgets + a create-budget dialog form. */
data class BudgetsUiState(
    val phase: CostsPhase = CostsPhase.Loading,
    val budgets: List<Budget> = emptyList(),
    val isRefreshing: Boolean = false,
    val errorMessage: String? = null,
    val form: BudgetFormState = BudgetFormState(),
)

/** Create-budget dialog form state. Mirrors the web CreateBudgetDialog fields + validation (name req'd). */
data class BudgetFormState(
    val isOpen: Boolean = false,
    val name: String = "",
    val scope: String = "overall",
    val scopeRef: String = "",
    val period: String = "daily",
    val limitDollars: String = "50",
    val thresholdPct: String = "80",
    val isSubmitting: Boolean = false,
) {
    val canSubmit: Boolean get() = !isSubmitting && name.trim().isNotEmpty()
}

/** Cost Alerts: list + unack/all filter. */
data class CostAlertsUiState(
    val phase: CostsPhase = CostsPhase.Loading,
    val alerts: List<CostAlert> = emptyList(),
    val unacknowledgedOnly: Boolean = true,
    val isRefreshing: Boolean = false,
    val errorMessage: String? = null,
)
