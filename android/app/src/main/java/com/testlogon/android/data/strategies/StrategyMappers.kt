package com.testlogon.android.data.strategies

/**
 * DTO -> domain mappers for the USER-CREATED STRATEGIES / BASKETS surface. Every field is defensively
 * defaulted (the endpoints don't exist yet + the edge may drift), so a partial payload maps to a
 * sane, honest domain object rather than throwing.
 */

private fun String?.toStrategyKind(): StrategyKind = when (this?.trim()?.lowercase()) {
    "basket" -> StrategyKind.BASKET
    "rule" -> StrategyKind.RULE
    else -> StrategyKind.UNKNOWN
}

private fun String?.toStrategyStatus(): StrategyStatus = when (this?.trim()?.lowercase()) {
    "draft" -> StrategyStatus.DRAFT
    "paper" -> StrategyStatus.PAPER
    "published" -> StrategyStatus.PUBLISHED
    "closed" -> StrategyStatus.CLOSED
    else -> StrategyStatus.UNKNOWN
}

private fun String?.toRebalanceRule(): RebalanceRule = when (this?.trim()?.lowercase()) {
    "none" -> RebalanceRule.NONE
    "daily" -> RebalanceRule.DAILY
    "weekly" -> RebalanceRule.WEEKLY
    "monthly" -> RebalanceRule.MONTHLY
    "threshold" -> RebalanceRule.THRESHOLD
    else -> RebalanceRule.UNKNOWN
}

private fun String?.toRedemptionType(): RedemptionType = when (this?.trim()?.lowercase()) {
    "instant" -> RedemptionType.INSTANT
    "notice" -> RedemptionType.NOTICE
    else -> RedemptionType.UNKNOWN
}

private fun String?.toFeeType(): FeeType = when (this?.trim()?.lowercase()) {
    "management", "mgmt" -> FeeType.MANAGEMENT
    "performance", "perf" -> FeeType.PERFORMANCE
    else -> FeeType.UNKNOWN
}

fun StrategyLegDto.toDomain(): StrategyLeg = StrategyLeg(
    symbolId = symbolId ?: 0,
    weightBps = weightBps ?: 0,
)

fun RedemptionDto?.toDomain(): Redemption = Redemption(
    type = this?.type.toRedemptionType(),
    noticeDays = this?.noticeDays,
    lockupDays = this?.lockupDays,
)

fun StrategyDto.toDomain(): Strategy = Strategy(
    strategyId = strategyId.orEmpty(),
    creatorSub = creatorSub,
    name = name.orEmpty(),
    description = description.orEmpty(),
    kind = kind.toStrategyKind(),
    status = status.toStrategyStatus(),
    legs = legs.orEmpty().map { it.toDomain() }.filter { it.symbolId > 0 },
    rebalance = rebalance.toRebalanceRule(),
    thresholdBps = thresholdBps,
    minInvestmentCents = minInvestmentCents ?: 0L,
    maxAumCents = maxAumCents ?: 0L,
    mgmtFeeBps = mgmtFeeBps ?: 0,
    perfFeeBps = perfFeeBps ?: 0,
    highWaterMark = highWaterMark ?: true,
    redemption = redemption.toDomain(),
    createdTs = createdTs ?: 0L,
    navPerUnit = navPerUnit,
    aumCents = aumCents,
    investorCount = investorCount,
    inceptionReturnBps = inceptionReturnBps,
)

fun StrategyListDto.toDomain(): List<Strategy> =
    strategies.orEmpty().map { it.toDomain() }.filter { it.strategyId.isNotBlank() }

fun StrategyNavDto.toDomain(fallbackId: String): StrategyNav = StrategyNav(
    strategyId = strategyId ?: fallbackId,
    navPerUnit = navPerUnit ?: 0L,
    aumCents = aumCents ?: 0L,
    unitsOutstanding = unitsOutstanding ?: 0L,
    inceptionReturnBps = inceptionReturnBps ?: 0,
)

fun StrategyHoldingDto.toDomain(): StrategyHolding = StrategyHolding(
    symbolId = symbolId ?: 0,
    targetWeightBps = targetWeightBps ?: 0,
    actualWeightBps = actualWeightBps ?: 0,
    valueCents = valueCents ?: 0L,
)

fun StrategyHoldingsDto.toDomain(): List<StrategyHolding> =
    holdings.orEmpty().map { it.toDomain() }.filter { it.symbolId > 0 }

fun InvestorPositionDto.toDomain(fallbackId: String): InvestorPosition = InvestorPosition(
    strategyId = strategyId ?: fallbackId,
    units = units ?: 0L,
    navPerUnit = navPerUnit ?: 0L,
    investedCents = investedCents ?: 0L,
    currentValueCents = currentValueCents ?: 0L,
    unrealizedPnlCents = unrealizedPnlCents ?: 0L,
    feesPaidCents = feesPaidCents ?: 0L,
    highWaterMark = highWaterMark ?: 0L,
)

fun FeeAccrualDto.toDomain(): FeeAccrual = FeeAccrual(
    ts = ts ?: 0L,
    type = type.toFeeType(),
    amountCents = amountCents ?: 0L,
)

fun StrategyFeesDto.toDomain(fallbackId: String): StrategyFees = StrategyFees(
    strategyId = strategyId ?: fallbackId,
    mgmtFeesAccruedCents = mgmtFeesAccruedCents ?: 0L,
    perfFeesAccruedCents = perfFeesAccruedCents ?: 0L,
    highWaterMark = highWaterMark ?: 0L,
    accruals = accruals.orEmpty().map { it.toDomain() },
)

/** An ack is accepted when the server returns a positive status token. */
fun StrategyAckDto.toDomain(): StrategyAck {
    val accepted = when (status?.trim()?.lowercase()) {
        "ok", "ack", "accepted", "success", "queued", "published" -> true
        else -> false
    }
    return StrategyAck(accepted = accepted, message = message)
}
