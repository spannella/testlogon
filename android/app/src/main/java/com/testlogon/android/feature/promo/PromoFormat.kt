package com.testlogon.android.feature.promo

import com.testlogon.android.data.promo.CreatePromoRequestDto
import com.testlogon.android.data.promo.DiscountType
import com.testlogon.android.data.promo.PromoCode
import com.testlogon.android.feature.earnings.formatEarningsMoney
import java.text.DateFormat
import java.util.Date
import java.util.Locale

/**
 * AND-266 — pure, JVM-testable promo-code formatting + create-form validation (no Android types).
 *
 * Discount labels mirror PromoCodesPage.tsx: `25% off` (percentage), `$7.50 off` (fixed cents/100 via the
 * reusable money formatter), `7-day trial` (free_trial). Money formatting reuses
 * [formatEarningsMoney]; currency defaults to USD (promo amounts carry no currency code).
 */

private const val USD = "USD"

/** A non-localized discount summary. Currency uses the reusable money formatter. */
fun PromoCode.discountSummary(locale: Locale = Locale.getDefault()): String = when (discountType) {
    DiscountType.PERCENTAGE -> "$discountValue% off"
    DiscountType.FIXED_AMOUNT -> "${formatEarningsMoney(discountValue.toLong(), USD, locale)} off"
    DiscountType.FREE_TRIAL -> "$freeTrialDays-day trial"
    DiscountType.OTHER -> rawDiscountType
}

/** Usage label: `12 / 100`, or `12 / ∞` when max_uses == 0 (unlimited). */
fun PromoCode.usageLabel(): String =
    if (isUnlimited) "$currentUses / ∞" else "$currentUses / $maxUses"

/** Expiry label: "Never" when expires_at == 0, else a locale medium date. */
fun PromoCode.expiryLabel(locale: Locale = Locale.getDefault()): String =
    if (expiresAtEpochSeconds <= 0L) {
        "Never"
    } else {
        DateFormat.getDateInstance(DateFormat.MEDIUM, locale)
            .format(Date(expiresAtEpochSeconds * 1000L))
    }

/** Hoisted create-form state (plain values; collected by the Compose sheet). */
data class CreatePromoForm(
    val code: String = "",
    val discountType: DiscountType = DiscountType.PERCENTAGE,
    val discountValue: Int = 0,
    val freeTrialDays: Int = 0,
    val appliesTo: List<String> = listOf("subscription"),
    val minPurchaseCents: Int = 0,
    val maxUses: Int = 0,
    val maxUsesPerUser: Int = 1,
    val expiresAtEpochSeconds: Long = 0,
)

/** Client-side validation outcome: a stable reason key, or null when the form is valid. */
enum class PromoFormError { CODE_REQUIRED, CODE_LENGTH, DISCOUNT_VALUE, PERCENT_RANGE, TRIAL_DAYS }

/**
 * Pure create-form validation (mirrors CreatePromoDialog): code required, 3..30 chars; percentage value
 * 1..100; fixed amount value > 0; free_trial days > 0. Returns the first error or null when valid.
 */
fun CreatePromoForm.validate(): PromoFormError? {
    val trimmed = code.trim()
    if (trimmed.isEmpty()) return PromoFormError.CODE_REQUIRED
    if (trimmed.length < 3 || trimmed.length > 30) return PromoFormError.CODE_LENGTH
    return when (discountType) {
        DiscountType.PERCENTAGE ->
            if (discountValue !in 1..100) PromoFormError.PERCENT_RANGE else null
        DiscountType.FIXED_AMOUNT ->
            if (discountValue <= 0) PromoFormError.DISCOUNT_VALUE else null
        DiscountType.FREE_TRIAL ->
            if (freeTrialDays <= 0) PromoFormError.TRIAL_DAYS else null
        DiscountType.OTHER -> null
    }
}

/** Builds the wire request from a validated form. The code is uppercased (web parity). */
fun CreatePromoForm.toRequest(): CreatePromoRequestDto = CreatePromoRequestDto(
    code = code.trim().uppercase(Locale.ROOT),
    discountType = when (discountType) {
        DiscountType.PERCENTAGE -> "percentage"
        DiscountType.FIXED_AMOUNT -> "fixed_amount"
        DiscountType.FREE_TRIAL -> "free_trial"
        DiscountType.OTHER -> "percentage"
    },
    discountValue = discountValue,
    freeTrialDays = freeTrialDays,
    appliesTo = appliesTo,
    minPurchaseCents = minPurchaseCents,
    maxUses = maxUses,
    maxUsesPerUser = maxUsesPerUser,
    expiresAt = expiresAtEpochSeconds,
)
