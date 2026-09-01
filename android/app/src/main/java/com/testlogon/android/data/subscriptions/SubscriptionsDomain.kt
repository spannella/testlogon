package com.testlogon.android.data.subscriptions

/**
 * AND-234 — framework-free subscriptions domain models + total DTO -> domain mappers.
 *
 * Conventions (matching data/billing):
 *  - Money is integer cents + ISO-4217 currency (the backend's `*_cents`). No BigDecimal.
 *  - Timestamps are epoch-seconds Longs (NOT java.time) so this stays JVM-unit-testable.
 *  - Enums (BillingInterval, SubscriptionState) use an UNKNOWN fallback for forward compatibility.
 *
 * Mapping is TOTAL: unknown enum strings -> UNKNOWN, absent optionals -> null, absent lists -> empty.
 */

/** Recurring billing interval. Backend tokens are {month, year}; WEEK tolerated for forward-compat. */
enum class BillingInterval {
    MONTH,
    YEAR,
    WEEK,
    UNKNOWN,
    ;

    companion object {
        fun fromWire(value: String?): BillingInterval = when (value?.lowercase()) {
            "month", "monthly" -> MONTH
            "year", "yearly", "annual" -> YEAR
            "week", "weekly" -> WEEK
            else -> UNKNOWN
        }
    }
}

/**
 * Lifecycle state of a viewer's subscription. The backend `status` is a free string; this set is the
 * common taxonomy with an UNKNOWN fallback so a new value never crashes mapping.
 */
enum class SubscriptionState {
    ACTIVE,
    TRIALING,
    PAST_DUE,
    CANCELED,
    EXPIRED,
    UNKNOWN,
    ;

    companion object {
        fun fromWire(value: String?): SubscriptionState = when (value?.lowercase()) {
            "active" -> ACTIVE
            "trialing", "trial" -> TRIALING
            "past_due" -> PAST_DUE
            "canceled", "cancelled" -> CANCELED
            "expired" -> EXPIRED
            else -> UNKNOWN
        }
    }
}

/** SUB-E0 - a structured tier benefit/perk (label + optional detail), distinct from asset-name perks. */
data class TierBenefit(
    val label: String,
    val detail: String?,
)

/** Creator-offered subscription plan (the "tier"). */
data class SubscriptionTier(
    val planId: String,
    val creatorId: String,
    val name: String,
    val description: String?,
    val priceCents: Long,
    val currency: String,
    val interval: BillingInterval,
    val annualPriceCents: Long?,
    val status: String,
    /** SUBX-30 - explicit tier level (>=1); null on older/seeded plans (derived server-side). */
    val level: Int? = null,
    /** SUBX-43 (C10) - creator presentation order; null sorts after ordered plans. */
    val displayOrder: Int? = null,
    /** Feature/perk labels, mapped from `assets[].name` (legacy free-form perk bullets). */
    val perks: List<String>,
    /** SUB-E0 - structured benefits ({label, detail}); empty for older/seeded plans. */
    val benefits: List<TierBenefit> = emptyList(),
    val createdAtEpochSeconds: Long?,
    val updatedAtEpochSeconds: Long?,
) {
    /** Activeness is the backend `status` string == "active" (no is_active boolean exists). */
    val isActive: Boolean get() = status.equals("active", ignoreCase = true)
}

/** A viewer's subscription to a creator's plan. */
data class CreatorSubscription(
    val subscriptionId: String,
    val planId: String,
    val creatorId: String,
    val subscriberId: String?,
    val interval: BillingInterval,
    val provider: String?,
    val status: SubscriptionState,
    val startAtEpochSeconds: Long?,
    val currentPeriodEndEpochSeconds: Long?,
    val cancelAtPeriodEnd: Boolean,
    val priceCents: Long?,
    val currency: String?,
    val autoRenew: Boolean,
    /** SUBX-52 - the trial window end (epoch seconds), when the sub is/was on a trial; null otherwise. */
    val trialEndEpochSeconds: Long? = null,
)

/** Single-subscription summary read projection. */
data class CreatorSubscriptionSummary(
    val subscriptionId: String,
    val status: SubscriptionState,
    val cancelAtPeriodEnd: Boolean,
    val totalPaidCents: Long,
    val currency: String?,
    val nextAmountCents: Long,
    val nextRenewalAtEpochSeconds: Long?,
    val lastInvoiceAtEpochSeconds: Long?,
)

// ---- Mappers (DTO -> domain) ----

internal fun SubscriptionPlanDto.toDomain(): SubscriptionTier = SubscriptionTier(
    planId = planId,
    creatorId = creatorId,
    name = name,
    description = description,
    priceCents = priceCents,
    currency = currency,
    interval = BillingInterval.fromWire(interval),
    annualPriceCents = annualPriceCents,
    status = status,
    level = level,
    displayOrder = displayOrder,
    perks = assets.orEmpty().mapNotNull { it.name?.takeIf(String::isNotBlank) },
    benefits = benefits.orEmpty().mapNotNull { b ->
        b.label.takeIf(String::isNotBlank)?.let { TierBenefit(label = it, detail = b.detail?.takeIf(String::isNotBlank)) }
    },
    createdAtEpochSeconds = createdAt,
    updatedAtEpochSeconds = updatedAt,
)

internal fun SubscriptionOutDto.toDomain(): CreatorSubscription = CreatorSubscription(
    subscriptionId = subscriptionId,
    planId = planId,
    creatorId = creatorId,
    subscriberId = subscriberId,
    interval = BillingInterval.fromWire(interval),
    provider = provider,
    status = SubscriptionState.fromWire(status),
    startAtEpochSeconds = startAt,
    currentPeriodEndEpochSeconds = currentPeriodEnd,
    cancelAtPeriodEnd = cancelAtPeriodEnd,
    priceCents = priceCents,
    currency = currency,
    autoRenew = autoRenew,
    trialEndEpochSeconds = trialEnd,
)

internal fun SubscriptionSummaryDto.toDomain(): CreatorSubscriptionSummary = CreatorSubscriptionSummary(
    subscriptionId = subscriptionId,
    status = SubscriptionState.fromWire(status),
    cancelAtPeriodEnd = cancelAtPeriodEnd,
    totalPaidCents = totalPaidCents,
    currency = currency,
    nextAmountCents = nextAmountCents,
    nextRenewalAtEpochSeconds = nextRenewalAt,
    lastInvoiceAtEpochSeconds = lastInvoiceAt,
)

// ---- SUB-E4-3: creator subscriber management + MRR/analytics ----

/** SUB-E4-1 - a creator-facing subscriber row (from the CREATOR#SUB# index). */
data class CreatorSubscriberRow(
    val subscriptionId: String,
    val subscriberId: String,
    val subscriberName: String?,
    val planId: String?,
    val planName: String?,
    /** Mapped taxonomy state; use [rawStatus] for creator-only states (canceling/grace). */
    val status: SubscriptionState,
    val rawStatus: String,
    val interval: BillingInterval,
    val priceCents: Long,
    val currency: String?,
    val sinceEpochSeconds: Long?,
    val currentPeriodEndEpochSeconds: Long?,
    val nextBillingDateEpochSeconds: Long?,
    val cancelAtPeriodEnd: Boolean,
    val autoRenew: Boolean,
    val isGift: Boolean,
    val gifterId: String?,
    val isTrial: Boolean,
) {
    /** The subscriber's best display label (name -> id fallback). */
    val displayName: String get() = subscriberName?.takeIf { it.isNotBlank() } ?: subscriberId
}

/** SUB-E4-1 - a page of the creator subscriber list. */
data class CreatorSubscriberPage(
    val creatorId: String,
    val statusFilter: String?,
    val count: Int,
    val total: Int,
    val nextCursor: String?,
    val subscribers: List<CreatorSubscriberRow>,
)

/** SUB-E4-2 - creator subscription MRR/analytics, computed from real records + ledger. */
data class SubscriptionAnalytics(
    val creatorId: String,
    val currency: String?,
    val activeSubscribers: Int,
    val trialing: Int,
    val pastDue: Int,
    val canceledTotal: Int,
    val totalSubscribers: Int,
    val mrrCents: Long,
    val arpuCents: Long,
    /** SUBX-43 (C9) - recoverable book (past_due monthly-equiv), distinct from MRR. */
    val pastDueMrrCents: Long = 0,
    val periodDays: Int,
    val newSubs30d: Int,
    val churned30d: Int,
    /** SUBX-43 (C7) - cohort churn denominator (active-at-window-start). */
    val activeAtWindowStart: Int = 0,
    val churnRate: Double,
    val grossRevenueToDateCents: Long,
    val feeToDateCents: Long,
    val refundedToDateCents: Long,
    val netRevenueToDateCents: Long,
    /** SUBX-43 (C8) - per-tier breakdown (reconciles to the creator-wide aggregates). */
    val byTier: List<TierRevenue> = emptyList(),
)

/** SUBX-43 (C8) - per-tier (plan) revenue/subscriber slice of the analytics. */
data class TierRevenue(
    val planId: String?,
    val planName: String?,
    val level: Int?,
    val activeSubscribers: Int,
    val trialing: Int,
    val pastDue: Int,
    val totalSubscribers: Int,
    val mrrCents: Long,
    val grossRevenueToDateCents: Long,
    val refundedToDateCents: Long,
    val netRevenueToDateCents: Long,
)

/** SUBX-43 (C6) - the outcome of a creator refund (refund revokes access on the shared rail). */
data class SubscriptionRefundResult(
    val subscriptionId: String,
    val status: String?,
    val refundedCents: Long,
    val clawbackCents: Long,
    val idempotentReplay: Boolean,
)

internal fun CreatorSubscriberDto.toDomain(): CreatorSubscriberRow = CreatorSubscriberRow(
    subscriptionId = subscriptionId,
    subscriberId = subscriberId,
    subscriberName = subscriberName?.takeIf { it.isNotBlank() },
    planId = planId,
    planName = planName?.takeIf { it.isNotBlank() },
    status = SubscriptionState.fromWire(status),
    rawStatus = status,
    interval = BillingInterval.fromWire(interval),
    priceCents = priceCents,
    currency = currency,
    sinceEpochSeconds = since.takeIf { it > 0 },
    currentPeriodEndEpochSeconds = currentPeriodEnd,
    nextBillingDateEpochSeconds = nextBillingDate,
    cancelAtPeriodEnd = cancelAtPeriodEnd,
    autoRenew = autoRenew,
    isGift = isGift,
    gifterId = gifterId,
    isTrial = isTrial,
)

internal fun CreatorSubscriberListDto.toDomain(): CreatorSubscriberPage = CreatorSubscriberPage(
    creatorId = creatorId,
    statusFilter = statusFilter,
    count = count,
    total = total,
    nextCursor = nextCursor,
    subscribers = subscribers.map { it.toDomain() },
)

internal fun SubscriptionAnalyticsDto.toDomain(): SubscriptionAnalytics = SubscriptionAnalytics(
    creatorId = creatorId,
    currency = currency,
    activeSubscribers = activeSubscribers,
    trialing = trialing,
    pastDue = pastDue,
    canceledTotal = canceledTotal,
    totalSubscribers = totalSubscribers,
    mrrCents = mrrCents,
    arpuCents = arpuCents,
    pastDueMrrCents = pastDueMrrCents,
    periodDays = periodDays,
    newSubs30d = newSubs30d,
    churned30d = churned30d,
    activeAtWindowStart = activeAtWindowStart,
    churnRate = churnRate,
    grossRevenueToDateCents = grossRevenueToDateCents,
    feeToDateCents = feeToDateCents,
    refundedToDateCents = refundedToDateCents,
    netRevenueToDateCents = netRevenueToDateCents,
    byTier = byTier.orEmpty().map { it.toDomain() },
)

internal fun SubscriptionTierBreakdownDto.toDomain(): TierRevenue = TierRevenue(
    planId = planId,
    planName = planName?.takeIf { it.isNotBlank() },
    level = level,
    activeSubscribers = activeSubscribers,
    trialing = trialing,
    pastDue = pastDue,
    totalSubscribers = totalSubscribers,
    mrrCents = mrrCents,
    grossRevenueToDateCents = grossRevenueToDateCents,
    refundedToDateCents = refundedToDateCents,
    netRevenueToDateCents = netRevenueToDateCents,
)

internal fun SubscriptionRefundReceiptDto.toDomain(): SubscriptionRefundResult = SubscriptionRefundResult(
    subscriptionId = subscriptionId,
    status = status,
    refundedCents = refundedCents ?: 0,
    clawbackCents = clawbackCents ?: 0,
    idempotentReplay = idempotentReplay,
)
