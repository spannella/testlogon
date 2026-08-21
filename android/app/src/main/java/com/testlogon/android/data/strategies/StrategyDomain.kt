package com.testlogon.android.data.strategies

/**
 * USER-CREATED STRATEGIES / BASKETS domain models — render-ready shapes the feature layer consumes.
 *
 * A creator defines a STRATEGY: a basket of legs following a simple rule set. Others paper-trade it,
 * view its backtest, then invest real capital. It is a POOLED fund with NAV units (an ASSUMPTION
 * labelled in-UI and flippable): investors subscribe/redeem at NAV and own units — not copy/replication.
 * Amounts are integer CENTS; weights/fees are basis points (10_000 bps == 100%).
 */
enum class StrategyKind { BASKET, RULE, UNKNOWN }

enum class StrategyStatus { DRAFT, PAPER, PUBLISHED, CLOSED, UNKNOWN }

/** Rebalance cadence for the basket back to its target weights. */
enum class RebalanceRule { NONE, DAILY, WEEKLY, MONTHLY, THRESHOLD, UNKNOWN }

enum class RedemptionType { INSTANT, NOTICE, UNKNOWN }

/** Redemption / profit-taking policy. Notice + lockup only meaningful for a NOTICE policy. */
data class Redemption(
    val type: RedemptionType,
    val noticeDays: Int? = null,
    val lockupDays: Int? = null,
)

/** One basket leg: a [symbolId] with a target [weightBps] (all legs sum to 10_000). */
data class StrategyLeg(
    val symbolId: Int,
    val weightBps: Int,
)

data class Strategy(
    val strategyId: String,
    val creatorSub: String? = null,
    val name: String,
    val description: String = "",
    val kind: StrategyKind = StrategyKind.BASKET,
    val status: StrategyStatus = StrategyStatus.DRAFT,
    val legs: List<StrategyLeg> = emptyList(),
    val rebalance: RebalanceRule = RebalanceRule.NONE,
    val thresholdBps: Int? = null,
    val minInvestmentCents: Long = 0,
    val maxAumCents: Long = 0,
    val mgmtFeeBps: Int = 0,
    val perfFeeBps: Int = 0,
    val highWaterMark: Boolean = true,
    val redemption: Redemption = Redemption(RedemptionType.INSTANT),
    val createdTs: Long = 0,
    /** Current NAV per unit in cents (present once the strategy has a running fund). */
    val navPerUnit: Long? = null,
    val aumCents: Long? = null,
    val investorCount: Int? = null,
    /** Cumulative return since inception, in basis points (may be negative). */
    val inceptionReturnBps: Int? = null,
) {
    /** Remaining capacity = max AUM - current AUM (>= 0), or null when capacity/AUM is unknown. */
    val capacityRemainingCents: Long?
        get() = if (maxAumCents <= 0) null else (maxAumCents - (aumCents ?: 0L)).coerceAtLeast(0L)
}

/** Current NAV read for a strategy fund. */
data class StrategyNav(
    val strategyId: String,
    val navPerUnit: Long,
    val aumCents: Long,
    val unitsOutstanding: Long,
    val inceptionReturnBps: Int,
)

/** One holding row: target vs actual weight drift + current value. */
data class StrategyHolding(
    val symbolId: Int,
    val targetWeightBps: Int,
    val actualWeightBps: Int,
    val valueCents: Long,
)

/**
 * An investor's pooled position: [units] held at the current [navPerUnit], the cost basis
 * [investedCents], the mark-to-market [currentValueCents] + [unrealizedPnlCents], fees paid, and the
 * per-unit [highWaterMark] the performance fee is measured above.
 */
data class InvestorPosition(
    val strategyId: String,
    val units: Long,
    val navPerUnit: Long,
    val investedCents: Long,
    val currentValueCents: Long,
    val unrealizedPnlCents: Long,
    val feesPaidCents: Long,
    val highWaterMark: Long,
)

enum class FeeType { MANAGEMENT, PERFORMANCE, UNKNOWN }

/** One fee accrual line (management on AUM or performance above the high-water mark). */
data class FeeAccrual(
    val ts: Long,
    val type: FeeType,
    val amountCents: Long,
)

/** Creator-view fee schedule: accrued management + performance fees and the running high-water mark. */
data class StrategyFees(
    val strategyId: String,
    val mgmtFeesAccruedCents: Long,
    val perfFeesAccruedCents: Long,
    val highWaterMark: Long,
    val accruals: List<FeeAccrual>,
)

/** A simple mutation acknowledgement — [accepted] is false when the server didn't confirm. */
data class StrategyAck(
    val accepted: Boolean,
    val message: String? = null,
)
