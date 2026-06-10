package com.testlogon.android.data.billing

/**
 * AND-223 — framework-free billing domain models + total DTO -> domain mappers.
 *
 * Conventions (matching this codebase + the spec gotchas):
 *  - Money is integer cents + ISO-4217 currency (the backend's `*_cents`). No BigDecimal here; the
 *    billing surface is uniformly cents.
 *  - Timestamps are epoch-seconds Longs (NOT java.time.Instant) so this stays JVM-unit-testable and
 *    free of the API-26 java.time dependency. ISO-8601 strings (next_billing_date) are parsed
 *    defensively into an epoch-seconds Long; unparseable values map to null (never throw).
 *  - Enums use an UNKNOWN fallback for forward compatibility; free-form strings stay String.
 *
 * Mapping is TOTAL: unknown enum strings -> UNKNOWN, absent optionals -> null, absent lists -> empty.
 */

/** Integer cents + ISO-4217 currency. */
data class BillingMoney(val cents: Long, val currency: String)

enum class SubscriptionStatus {
    ACTIVE,
    TRIALING,
    PAST_DUE,
    CANCELED,
    INCOMPLETE,
    UNKNOWN,
    ;

    companion object {
        fun fromWire(value: String?): SubscriptionStatus = when (value?.lowercase()) {
            "active" -> ACTIVE
            "trialing" -> TRIALING
            "past_due" -> PAST_DUE
            "canceled", "cancelled" -> CANCELED
            "incomplete" -> INCOMPLETE
            else -> UNKNOWN
        }
    }
}

data class Subscription(
    val subscriptionId: String,
    val planId: String,
    val status: SubscriptionStatus,
    val billingCycle: String?,
    val nextBillingDateEpochSeconds: Long?,
)

data class BillingConfig(val publishableKey: String?, val currency: String)

data class BillingSettings(
    val autopayEnabled: Boolean,
    val currency: String,
    val defaultPaymentMethodId: String?,
    val defaultPaymentTokenId: String?,
)

data class BillingBalance(
    val owedPending: BillingMoney,
    val owedSettled: BillingMoney,
    val paymentsPending: BillingMoney,
    val paymentsSettled: BillingMoney,
    val duePending: BillingMoney?,
    val dueSettled: BillingMoney?,
    val updatedAtEpochSeconds: Long?,
)

data class LedgerEntry(
    val sk: String,
    val type: String,
    val amount: BillingMoney,
    val state: String,
    val reason: String?,
    val timestampEpochSeconds: Long?,
)

data class LedgerPage(val items: List<LedgerEntry>)

/** Known card brands; UNKNOWN for anything else (incl. bank accounts, which carry no brand). */
enum class CardBrand {
    VISA,
    MASTERCARD,
    AMEX,
    DISCOVER,
    UNKNOWN,
    ;

    companion object {
        fun fromWire(value: String?): CardBrand = when (value?.lowercase()) {
            "visa" -> VISA
            "mastercard" -> MASTERCARD
            "amex", "american_express", "american express" -> AMEX
            "discover" -> DISCOVER
            else -> UNKNOWN
        }
    }
}

/**
 * AND-224 — a saved payment method. id maps DTO `payment_method_id`. brand/last4/exp are OPTIONAL
 * (absent for bank accounts). [rawBrand] preserves the original wire brand for display when known.
 */
data class PaymentMethod(
    val id: String,
    val methodType: String,
    val brand: CardBrand,
    val rawBrand: String?,
    val last4: String?,
    val expMonth: Int?,
    val expYear: Int?,
    val label: String?,
    val priority: Int,
    val provider: String?,
    val isDefault: Boolean,
)

data class WalletBalance(val balance: BillingMoney, val updatedAtEpochSeconds: Long?)

data class CheckoutSession(val sessionId: String, val url: String)

// ---- Mappers (DTO -> domain) ----

internal fun SubscriptionDto.toDomain(): Subscription = Subscription(
    subscriptionId = subscriptionId,
    planId = planId,
    status = SubscriptionStatus.fromWire(status),
    billingCycle = billingCycle,
    nextBillingDateEpochSeconds = nextBillingDate.toEpochSecondsOrNull(),
)

internal fun BillingConfigDto.toDomain(): BillingConfig =
    BillingConfig(publishableKey = publishableKey, currency = currency)

internal fun BillingSettingsDto.toDomain(): BillingSettings = BillingSettings(
    autopayEnabled = autopayEnabled,
    currency = currency,
    defaultPaymentMethodId = defaultPaymentMethodId,
    defaultPaymentTokenId = defaultPaymentTokenId,
)

internal fun BillingBalanceDto.toDomain(): BillingBalance = BillingBalance(
    owedPending = BillingMoney(owedPendingCents, currency),
    owedSettled = BillingMoney(owedSettledCents, currency),
    paymentsPending = BillingMoney(paymentsPendingCents, currency),
    paymentsSettled = BillingMoney(paymentsSettledCents, currency),
    duePending = duePendingCents?.let { BillingMoney(it, currency) },
    dueSettled = dueSettledCents?.let { BillingMoney(it, currency) },
    updatedAtEpochSeconds = updatedAt,
)

/** Ledger entries carry no per-row currency; the account/page currency is threaded in by the caller. */
internal fun LedgerEntryDto.toDomain(currency: String): LedgerEntry = LedgerEntry(
    sk = sk,
    type = type,
    amount = BillingMoney(amountCents, currency),
    state = state,
    reason = reason,
    timestampEpochSeconds = ts.takeIf { it > 0 },
)

internal fun LedgerPageDto.toDomain(currency: String): LedgerPage =
    LedgerPage(items = items.map { it.toDomain(currency) })

internal fun PaymentMethodDto.toDomain(): PaymentMethod = PaymentMethod(
    id = paymentMethodId,
    methodType = methodType,
    brand = CardBrand.fromWire(brand),
    rawBrand = brand,
    last4 = last4,
    expMonth = expMonth,
    expYear = expYear,
    label = label,
    priority = priority,
    provider = provider,
    isDefault = isDefault,
)

internal fun WalletBalanceDto.toDomain(): WalletBalance =
    WalletBalance(balance = BillingMoney(walletBalanceCents, currency), updatedAtEpochSeconds = updatedAt)

internal fun CheckoutSessionDto.toDomain(): CheckoutSession =
    CheckoutSession(sessionId = sessionId, url = url)

/**
 * Parses an ISO-8601 instant string (e.g. "2026-07-01T00:00:00Z") into epoch SECONDS, or null on any
 * failure. Uses a regex + manual day-count (NO java.time) so it is safe in JVM-unit-tested code and on
 * API < 26. Supports a trailing "Z" or "+HH:MM"/"-HH:MM" offset; fractional seconds are ignored.
 */
internal fun String?.toEpochSecondsOrNull(): Long? {
    if (this.isNullOrBlank()) return null
    val m = ISO_8601.matchEntire(trim()) ?: return null
    return try {
        val (yS, moS, dS, hS, miS, seS) = m.destructured
        val offset = m.groupValues.getOrNull(OFFSET_GROUP).orEmpty()
        val year = yS.toInt()
        val month = moS.toInt()
        val day = dS.toInt()
        if (month !in 1..12 || day !in 1..31) return null
        val days = daysFromEpoch(year, month, day)
        var secs = days * SECONDS_PER_DAY +
            hS.toInt() * 3600L + miS.toInt() * 60L + seS.toInt()
        secs -= offsetSeconds(offset)
        secs
    } catch (_: Exception) {
        null
    }
}

private const val SECONDS_PER_DAY = 86_400L
private const val OFFSET_GROUP = 7

// year-month-day T hour:min:sec [.frac] [Z | +HH:MM | -HH:MM]
private val ISO_8601 =
    Regex("""^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(Z|z|[+-]\d{2}:?\d{2})?$""")

/** Offset like "Z", "+05:30", "-0800" -> seconds to SUBTRACT to reach UTC. */
private fun offsetSeconds(offset: String): Long {
    if (offset.isBlank() || offset.equals("Z", ignoreCase = true)) return 0L
    val sign = if (offset[0] == '-') -1 else 1
    val digits = offset.drop(1).replace(":", "")
    val hh = digits.take(2).toInt()
    val mm = digits.drop(2).take(2).toIntOrNull() ?: 0
    return sign * (hh * 3600L + mm * 60L)
}

/** Days from 1970-01-01 to the given y/m/d (proleptic Gregorian), no java.time. */
private fun daysFromEpoch(year: Int, month: Int, day: Int): Long {
    var y = year.toLong()
    val m = month
    if (m <= 2) y -= 1
    val era = (if (y >= 0) y else y - 399) / 400
    val yoe = y - era * 400
    val mp = (m + 9) % 12
    val doy = (153 * mp + 2) / 5 + (day - 1)
    val doe = yoe * 365 + yoe / 4 - yoe / 100 + doy
    return era * 146_097 + doe - 719_468
}
