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
