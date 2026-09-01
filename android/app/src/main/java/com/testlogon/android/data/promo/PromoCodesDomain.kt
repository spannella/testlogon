package com.testlogon.android.data.promo

/**
 * AND-266 — framework-free promo-code domain models + total DTO -> domain mappers.
 *
 * Timestamps are epoch SECONDS (expires_at/created_at; 0 = never/unknown) kept as Long — no java.time
 * (API-26) so this stays JVM-testable. discount_value is percent (PERCENTAGE) or cents (FIXED_AMOUNT).
 * isExpired is computed against an injected `nowEpochSeconds` (so tests are deterministic), mirroring the
 * web's `expires_at > 0 && expires_at < Date.now()/1000`. Mapping is TOTAL; unknown discount -> OTHER.
 */

enum class DiscountType {
    PERCENTAGE,
    FIXED_AMOUNT,
    FREE_TRIAL,
    OTHER,
    ;

    companion object {
        fun from(raw: String?): DiscountType = when (raw?.lowercase()) {
            "percentage" -> PERCENTAGE
            "fixed_amount" -> FIXED_AMOUNT
            "free_trial" -> FREE_TRIAL
            else -> OTHER
        }
    }
}

data class PromoCode(
    val codeId: String,
    val code: String,
    val discountType: DiscountType,
    val rawDiscountType: String,
    /** Percent for PERCENTAGE, cents for FIXED_AMOUNT, 0 for FREE_TRIAL. */
    val discountValue: Int,
    val freeTrialDays: Int,
    val appliesTo: List<String>,
    val minPurchaseCents: Int,
    val maxUses: Int,
    val maxUsesPerUser: Int,
    val currentUses: Int,
    val active: Boolean,
    /** Epoch seconds; 0 = never. */
    val expiresAtEpochSeconds: Long,
    val createdAtEpochSeconds: Long,
) {
    /** True only when an expiry is set and is in the past relative to [nowEpochSeconds]. */
    fun isExpired(nowEpochSeconds: Long): Boolean =
        expiresAtEpochSeconds > 0L && expiresAtEpochSeconds < nowEpochSeconds

    val isUnlimited: Boolean get() = maxUses == 0
}

// ---- Mappers (DTO -> domain) ----

internal fun PromoCodeDto.toDomain(): PromoCode = PromoCode(
    codeId = codeId,
    code = code,
    discountType = DiscountType.from(discountType),
    rawDiscountType = discountType,
    discountValue = discountValue,
    freeTrialDays = freeTrialDays,
    appliesTo = appliesTo,
    minPurchaseCents = minPurchaseCents,
    maxUses = maxUses,
    maxUsesPerUser = maxUsesPerUser,
    currentUses = currentUses,
    active = active,
    expiresAtEpochSeconds = expiresAt,
    createdAtEpochSeconds = createdAt,
)

internal fun PromoCodeListDto.toDomain(): List<PromoCode> = items.map { it.toDomain() }

/** Redemption outcome (internal/post-payment). */
data class RedeemResult(val ok: Boolean, val redeemedAtEpochSeconds: Long)

internal fun RedeemPromoResponseDto.toDomain(): RedeemResult = RedeemResult(ok = ok, redeemedAtEpochSeconds = redeemedAt)


/**
 * AND-266 (buyer surface) — the outcome of validating a code against a checkout context. Mirrors the
 * PromoValidateOut wire shape. When [valid] is false, [errorCode]/[message] carry the reason (the UI
 * shows [message]); [discountCents]/[finalPriceCents] are 0/original respectively. Money is Int cents.
 */
data class PromoValidation(
    val valid: Boolean,
    val codeId: String?,
    val discountType: DiscountType,
    val rawDiscountType: String?,
    val discountCents: Int,
    val discountPct: Int?,
    val originalPriceCents: Int,
    val finalPriceCents: Int,
    val freeTrialDays: Int,
    val errorCode: String?,
    val message: String?,
)

internal fun PromoValidateDto.toDomain(): PromoValidation = PromoValidation(
    valid = valid,
    codeId = codeId,
    discountType = DiscountType.from(discountType),
    rawDiscountType = discountType,
    discountCents = discountCents,
    discountPct = discountPct,
    originalPriceCents = originalPriceCents,
    finalPriceCents = finalPriceCents,
    freeTrialDays = freeTrialDays,
    errorCode = errorCode,
    message = message,
)
