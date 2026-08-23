package com.testlogon.android.feature.onboarding

import com.testlogon.android.navigation.MoreRoutes

/**
 * PURE onboarding registry + helpers (no Android, no I/O) for the trading/investing guided tours.
 *
 * Two mechanisms share this model:
 *  - the first-run **Welcome tour** ([tourSteps]) — a stepper introducing the new surfaces, each step
 *    optionally carrying a [OnboardingStep.route] the "Go there" button navigates to;
 *  - per-surface **intro callouts** ([surfaceIntros]) shown once at the top of a key screen.
 *
 * Persistence is a monotonic set of already-seen [OnboardingStep.id]s (never un-set except by an
 * explicit reset). All helpers here are pure functions over that set so they are trivially unit-tested.
 */
object OnboardingModel {

    /** A single tour step or surface-intro descriptor. [route] (when non-null) is an in-app route. */
    data class OnboardingStep(
        val id: String,
        val title: String,
        val body: String,
        val route: String? = null,
    )

    // ---- stable ids (also the DataStore seen-set keys) ----

    /** The whole first-run welcome tour is gated behind ONE id (seen once, never re-nags). */
    const val WELCOME_TOUR_ID: String = "welcome_tour"

    const val INTRO_INVEST: String = "intro_invest"
    const val INTRO_STRATEGIES: String = "intro_strategies"
    const val INTRO_TOKENS: String = "intro_tokens"
    const val INTRO_BAILOUTS: String = "intro_bailouts"
    const val INTRO_PORTFOLIO_ANALYTICS: String = "intro_portfolio_analytics"
    const val INTRO_ACTIVITY_CENTER: String = "intro_activity_center"
    const val INTRO_ACTIVE_ALGOS: String = "intro_active_algos"

    /**
     * The ordered welcome-tour steps. First is an intro card (no route); the rest each spotlight one
     * shipped surface with a "Go there" into its existing [MoreRoutes] route.
     */
    fun tourSteps(): List<OnboardingStep> = listOf(
        OnboardingStep(
            id = "tour_welcome",
            title = "Welcome to Trading & Investing",
            body = "We just added a full trading and investing suite. Take a quick tour of what is new, or skip and explore on your own anytime.",
            route = null,
        ),
        OnboardingStep(
            id = "tour_invest",
            title = "Invest hub",
            body = "One front door for everything investable: live markets, creator tokens, strategy funds and open opportunities. Search filters them all at once.",
            route = MoreRoutes.INVEST,
        ),
        OnboardingStep(
            id = "tour_strategies",
            title = "Strategy funds",
            body = "Browse investable baskets built by other users, or create, backtest and publish your own strategy.",
            route = MoreRoutes.STRATEGIES,
        ),
        OnboardingStep(
            id = "tour_tokens",
            title = "Creator tokens",
            body = "Mint a revenue-share token or trade the ones already listed. Tap any token for its market and details.",
            route = MoreRoutes.TOKENS,
        ),
        OnboardingStep(
            id = "tour_bailouts",
            title = "Bailouts",
            body = "The rescuer opportunity board: step in on margin-distressed positions before liquidation via pre-emptive bailout auctions.",
            route = MoreRoutes.BAILOUTS,
        ),
        OnboardingStep(
            id = "tour_portfolio_analytics",
            title = "Portfolio analytics",
            body = "A cross-venue view of your holdings, performance and allocation across custody, spot, margin and staking.",
            route = MoreRoutes.PORTFOLIO_ANALYTICS,
        ),
        OnboardingStep(
            id = "tour_active_algos",
            title = "Active algos",
            body = "Monitor your running TWAP and Iceberg algo orders, with live progress and pause or cancel controls.",
            route = MoreRoutes.ACTIVE_ALGOS,
        ),
        OnboardingStep(
            id = "tour_activity_center",
            title = "Activity center",
            body = "A consolidated, filterable timeline of every account event across trading, custody and money movement.",
            route = MoreRoutes.ACTIVITY_CENTER,
        ),
        OnboardingStep(
            id = "tour_tax",
            title = "Tax & gains",
            body = "A read-only cost-basis report of your tax lots and realized gains, ready when you need it.",
            route = MoreRoutes.TAX_REPORT,
        ),
    )

    /** The per-surface intro callouts, keyed by their stable id. */
    fun surfaceIntros(): Map<String, OnboardingStep> = listOf(
        OnboardingStep(
            id = INTRO_INVEST,
            title = "This is your Invest hub",
            body = "Everything you can invest in lives here — markets, creator tokens, strategy funds and opportunities. Use search to filter across all of them, then tap See all to dive into a section.",
        ),
        OnboardingStep(
            id = INTRO_STRATEGIES,
            title = "Strategy funds",
            body = "Invest in baskets published by other users, or tap Create to define, backtest and publish your own strategy.",
        ),
        OnboardingStep(
            id = INTRO_TOKENS,
            title = "Creator tokens",
            body = "Trade listed revenue-share tokens or mint your own. Tap a token to open its market and details.",
        ),
        OnboardingStep(
            id = INTRO_BAILOUTS,
            title = "Bailout board",
            body = "Rescue margin-distressed positions before liquidation and earn the bailout premium. Tap an opportunity to review and bid.",
        ),
        OnboardingStep(
            id = INTRO_PORTFOLIO_ANALYTICS,
            title = "Portfolio analytics",
            body = "A read-only cross-venue snapshot of your holdings, performance and allocation. Pull to refresh for the latest.",
        ),
        OnboardingStep(
            id = INTRO_ACTIVITY_CENTER,
            title = "Activity center",
            body = "Your consolidated, day-grouped account timeline. Use the filters to narrow to the event types you care about.",
        ),
        OnboardingStep(
            id = INTRO_ACTIVE_ALGOS,
            title = "Active algos",
            body = "Watch your running TWAP and Iceberg orders here. Each card shows live progress and lets you pause or cancel.",
        ),
    ).associateBy { it.id }

    // ---- pure helpers over the seen-set ----

    /** True when [id] has NOT yet been recorded in [seen] (i.e. it should still be shown). */
    fun shouldShow(id: String, seen: Set<String>): Boolean = id !in seen

    /** Returns a new seen-set with [id] added (monotonic; never removes). Idempotent. */
    fun markSeen(id: String, seen: Set<String>): Set<String> =
        if (id in seen) seen else seen + id

    /** Look up a surface-intro descriptor by id, or null when unknown. */
    fun surfaceIntro(id: String): OnboardingStep? = surfaceIntros()[id]

    /** All ids this model can persist (welcome tour + every surface intro) — used by reset/debug. */
    fun allIds(): Set<String> = buildSet {
        add(WELCOME_TOUR_ID)
        addAll(surfaceIntros().keys)
    }
}
