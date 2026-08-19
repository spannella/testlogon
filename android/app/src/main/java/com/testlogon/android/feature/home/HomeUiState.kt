package com.testlogon.android.feature.home

/**
 * Read-only Trading Home / Dashboard state. Composes several INDEPENDENT reads (portfolio summary,
 * watchlist snapshot, recent activity, onboarding progress) into one snapshot. Each card degrades on
 * its own: a 404/empty/undeployed source renders that card as empty/unavailable while the others still
 * show. Nothing here moves money - it is a consolidated launch surface for the trading app.
 */

/** Which navigation target a quick action / link points at (resolved by the route wiring). */
enum class HomeTarget {
    TRADE,
    DEPOSIT,
    PORTFOLIO,
    PNL,
    PRICE_ALERTS,
    TRADE_HISTORY,
}

/**
 * The portfolio summary card. [available] and [unrealizedPnl] are the headline numbers; [equityText]
 * is the pre-formatted total-equity snapshot. [priced] is true when a USD price map valued the
 * balances (so [equityText] is a USD figure); otherwise it is a coarse source-native sum. [unavailable]
 * degrades the card independently (all reads failed / undeployed).
 */
data class HomePortfolio(
    val loading: Boolean = true,
    val unavailable: Boolean = false,
    val equityText: String = "--",
    val priced: Boolean = false,
    val pricesStub: Boolean = false,
    /** Margin available balance (source-native), null when the margin read was not available. */
    val available: Long? = null,
    /** Open-position unrealized PnL (source-native), null when no open position / unavailable. */
    val unrealizedPnl: Long? = null,
)

/** One starred-symbol row in the watchlist snapshot. */
data class HomeWatchRow(
    val symbolId: Int,
    val symbol: String,
    /** Pre-formatted last price, or null (renders "--") when no quote could be read. */
    val lastPriceText: String?,
    /** Percent change over the sparkline window, null when unknown (renders "--"). */
    val changePct: Double?,
)

/** The watchlist snapshot card. Empty [rows] with [hasStarred]=false prompts the user to star symbols. */
data class HomeWatchlist(
    val loading: Boolean = true,
    val hasStarred: Boolean = false,
    val rows: List<HomeWatchRow> = emptyList(),
)

/** One recent-activity row (a recent fill), pre-formatted for display. */
data class HomeActivityRow(
    val symbol: String,
    val sideLabel: String,
    val isBuy: Boolean,
    val qtyText: String,
    val priceText: String,
)

/** The recent-activity card (last few fills). [unavailable] when the fills feed could not be read. */
data class HomeActivity(
    val loading: Boolean = true,
    val unavailable: Boolean = false,
    val rows: List<HomeActivityRow> = emptyList(),
) {
    val isEmpty: Boolean get() = !loading && !unavailable && rows.isEmpty()
}

/**
 * A single getting-started checklist step. [state] reflects REAL account state; UNKNOWN is neutral
 * (data unavailable) and never rendered as a false "incomplete". [target] is where tapping the step
 * navigates to satisfy it.
 */
data class OnboardingStep(
    val id: OnboardingStepId,
    val title: String,
    val state: StepState,
    val target: HomeTarget,
) {
    val isDone: Boolean get() = state == StepState.DONE
    /** Actionable = still worth prompting (not done, and we actually know it is incomplete). */
    val isActionable: Boolean get() = state == StepState.INCOMPLETE
}

enum class OnboardingStepId { FUND_CUSTODY, FUND_TRADING, FIRST_TRADE }

/** DONE = satisfied; INCOMPLETE = confirmed not-yet-done; UNKNOWN = data unavailable (neutral). */
enum class StepState { DONE, INCOMPLETE, UNKNOWN }

/**
 * The onboarding checklist card. [steps] is a stable, ordered list. The card is "all set" ONLY when
 * every step we could evaluate is DONE and none is still INCOMPLETE (UNKNOWN steps do not block "all
 * set", but they also never count as done). [dismissed] persists the user's dismissal of the all-set
 * banner.
 */
data class HomeOnboarding(
    val loading: Boolean = true,
    val steps: List<OnboardingStep> = emptyList(),
    val dismissed: Boolean = false,
) {
    /** Steps the user can still act on (confirmed incomplete). */
    val actionableSteps: List<OnboardingStep> get() = steps.filter { it.isActionable }
    /** True when nothing is confirmed-incomplete (every known step is done). */
    val allSet: Boolean get() = !loading && steps.isNotEmpty() && actionableSteps.isEmpty()
    /** Show the prominent checklist while there is at least one confirmed-incomplete step. */
    val showChecklist: Boolean get() = !loading && actionableSteps.isNotEmpty()
    /** Show the dismissible "all set" banner when everything known is done and not yet dismissed. */
    val showAllSet: Boolean get() = allSet && !dismissed
}

/** Inputs to the pure onboarding derivation (already extracted from the raw reads). */
data class OnboardingInputs(
    /** True/false when known (custody has any funded row); null when the custody read was unavailable. */
    val custodyFunded: Boolean?,
    /** True/false when known (spot OR margin available > 0); null when BOTH reads were unavailable. */
    val tradingFunded: Boolean?,
    /** True/false when known (any fill exists); null when the fills feed was unavailable. */
    val hasFirstTrade: Boolean?,
)

/**
 * Pure derivation of the getting-started checklist from real account signals. Kept free of Android /
 * coroutine deps so it is unit-testable in isolation (see HomeOnboardingDeriverTest). A `null` input
 * means "data unavailable" and maps to [StepState.UNKNOWN] (neutral) - never a false "incomplete".
 */
object HomeOnboardingDeriver {

    fun derive(inputs: OnboardingInputs): List<OnboardingStep> = listOf(
        OnboardingStep(
            id = OnboardingStepId.FUND_CUSTODY,
            title = "Fund your custody vault",
            state = stateOf(inputs.custodyFunded),
            target = HomeTarget.DEPOSIT,
        ),
        OnboardingStep(
            id = OnboardingStepId.FUND_TRADING,
            title = "Fund a trading account",
            state = stateOf(inputs.tradingFunded),
            target = HomeTarget.DEPOSIT,
        ),
        OnboardingStep(
            id = OnboardingStepId.FIRST_TRADE,
            title = "Place your first trade",
            state = stateOf(inputs.hasFirstTrade),
            target = HomeTarget.TRADE,
        ),
    )

    /** null -> UNKNOWN (neutral); true -> DONE; false -> INCOMPLETE. */
    private fun stateOf(signal: Boolean?): StepState = when (signal) {
        null -> StepState.UNKNOWN
        true -> StepState.DONE
        false -> StepState.INCOMPLETE
    }
}

/** The whole Home / Dashboard screen state. Each card is independent and degrades on its own. */
data class HomeUiState(
    val loading: Boolean = true,
    val portfolio: HomePortfolio = HomePortfolio(),
    val watchlist: HomeWatchlist = HomeWatchlist(),
    val activity: HomeActivity = HomeActivity(),
    val onboarding: HomeOnboarding = HomeOnboarding(),
)
