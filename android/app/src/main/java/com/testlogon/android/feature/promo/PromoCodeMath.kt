package com.testlogon.android.feature.promo

import com.testlogon.android.data.promo.DiscountType
import com.testlogon.android.data.promo.PromoCode
import java.util.Locale

/**
 * AND-266 (buyer surface) — pure, framework-free promo-code math for the CHECKOUT redemption path.
 *
 * All functions are deterministic + side-effect free (no clock, no I/O, no Android types): the caller
 * passes `nowEpochSeconds` so expiry is fully testable. Money is integer cents (Int) throughout; nothing
 * here rounds for charging — the server is authoritative at /redeem. This only:
 *   1. validates the code string FORMAT locally before we bother the network (mirrors the backend's
 *      `^[A-Za-z0-9_-]{3,30}$`, so we can reject obviously-bad input with no round-trip),
 *   2. computes the discount cents + final price for a discount kind (mirrors the service
 *      _calculate_discount: percentage clamps, fixed clamps, free_trial zeroes the price), and
 *   3. runs the buyer-visible eligibility gates (active / expiry / usage-limit / per-user-limit /
 *      applies_to / min-purchase) so the UI can preview a reason WITHOUT trusting the client — the
 *      server re-checks every one of these at validate + redeem time.
 *
 * Mirrors backend app/services/promo_codes.py (CODE_PATTERN, validate_promo_code, _calculate_discount)
 * and the web PromoValidateOut contract (discount_cents / final_price_cents / free_trial_days).
 */
object PromoCodeMath {

    /** Backend code format: 3..30 of [A-Za-z0-9_-]. Kept in sync with services CODE_PATTERN. */
    private val CODE_PATTERN = Regex("^[A-Za-z0-9_-]{3,30}$")

    /** The buyer-facing rejection reason. A machine-stable key the UI maps to a message. */
    enum class Ineligibility {
        EMPTY,
        BAD_FORMAT,
        INACTIVE,
        EXPIRED,
        USAGE_LIMIT,
        ALREADY_USED,
        NOT_APPLICABLE,
        BELOW_MIN,
    }

    /**
     * The local preview of applying a code. [discountCents] is clamped to [0, originalPriceCents];
     * [finalPriceCents] never goes negative; [freeTrialDays] is non-zero only for FREE_TRIAL codes
     * (whose final price is 0). [reason] is null iff the code passed every local gate.
     */
    data class Preview(
        val eligible: Boolean,
        val discountCents: Int,
        val finalPriceCents: Int,
        val freeTrialDays: Int,
        val reason: Ineligibility?,
    )

    /** Normalizes user input the way the backend does before lookup: trim + uppercase (ROOT locale). */
    fun normalizeCode(raw: String): String = raw.trim().uppercase(Locale.ROOT)

    /** True when [raw] (after normalization) is a syntactically valid code. Blank -> false. */
    fun isValidFormat(raw: String): Boolean {
        val c = normalizeCode(raw)
        return c.isNotEmpty() && CODE_PATTERN.matches(c)
    }

    /**
     * Discount cents for a promo against [originalPriceCents], clamped to never exceed the price and
     * never go below 0. PERCENTAGE uses floor(price * pct / 100) (matches Python int() truncation);
     * FIXED_AMOUNT caps at the price; FREE_TRIAL / OTHER discount the full price (final becomes 0 for
     * free-trial). A non-positive price yields 0.
     */
    fun discountCents(discountType: DiscountType, discountValue: Int, originalPriceCents: Int): Int {
        if (originalPriceCents <= 0) return 0
        return when (discountType) {
            DiscountType.PERCENTAGE -> {
                val pct = discountValue.coerceIn(0, 100)
                val raw = originalPriceCents.toLong() * pct / 100L
                raw.toInt().coerceIn(0, originalPriceCents)
            }
            DiscountType.FIXED_AMOUNT -> discountValue.coerceIn(0, originalPriceCents)
            DiscountType.FREE_TRIAL -> originalPriceCents
            DiscountType.OTHER -> 0
        }
    }

    /** Final price after the discount, clamped at >= 0. */
    fun finalPriceCents(discountType: DiscountType, discountValue: Int, originalPriceCents: Int): Int {
        val d = discountCents(discountType, discountValue, originalPriceCents)
        return (originalPriceCents - d).coerceAtLeast(0)
    }

    /**
     * The first buyer-visible reason [promo] cannot be applied to a [checkoutType] purchase of
     * [itemPriceCents], or null when it passes every local gate. [userRedemptions] is how many times
     * THIS buyer has already redeemed it (0 when unknown). Order mirrors validate_promo_code:
     * inactive -> expired -> usage-limit -> per-user -> applies_to (+ free-trial-only-subscription)
     * -> min-purchase.
     */
    fun ineligibility(
        promo: PromoCode,
        checkoutType: String,
        itemPriceCents: Int,
        nowEpochSeconds: Long,
        userRedemptions: Int = 0,
    ): Ineligibility? {
        if (!promo.active) return Ineligibility.INACTIVE
        if (promo.isExpired(nowEpochSeconds)) return Ineligibility.EXPIRED
        if (promo.maxUses > 0 && promo.currentUses >= promo.maxUses) return Ineligibility.USAGE_LIMIT
        if (promo.maxUsesPerUser > 0 && userRedemptions >= promo.maxUsesPerUser) {
            return Ineligibility.ALREADY_USED
        }
        val applies = promo.appliesTo.map { it.lowercase(Locale.ROOT) }
        val type = checkoutType.lowercase(Locale.ROOT)
        if (applies.isNotEmpty() && type !in applies) return Ineligibility.NOT_APPLICABLE
        // Free-trial codes only make sense for subscription checkouts (backend enforces this too).
        if (promo.discountType == DiscountType.FREE_TRIAL && type != "subscription") {
            return Ineligibility.NOT_APPLICABLE
        }
        if (promo.minPurchaseCents > 0 && itemPriceCents < promo.minPurchaseCents) {
            return Ineligibility.BELOW_MIN
        }
        return null
    }

    /**
     * Full local preview: runs [ineligibility] and, when eligible, computes the discount/final/trial.
     * A rejected code returns discount 0 / final == original so the UI shows the untouched price.
     */
    fun preview(
        promo: PromoCode,
        checkoutType: String,
        itemPriceCents: Int,
        nowEpochSeconds: Long,
        userRedemptions: Int = 0,
    ): Preview {
        val reason = ineligibility(promo, checkoutType, itemPriceCents, nowEpochSeconds, userRedemptions)
        if (reason != null) {
            return Preview(
                eligible = false,
                discountCents = 0,
                finalPriceCents = itemPriceCents.coerceAtLeast(0),
                freeTrialDays = 0,
                reason = reason,
            )
        }
        val d = discountCents(promo.discountType, promo.discountValue, itemPriceCents)
        val trial = if (promo.discountType == DiscountType.FREE_TRIAL) promo.freeTrialDays else 0
        return Preview(
            eligible = true,
            discountCents = d,
            finalPriceCents = (itemPriceCents - d).coerceAtLeast(0),
            freeTrialDays = trial,
            reason = null,
        )
    }
}
