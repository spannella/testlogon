package com.testlogon.android.feature.settings.msgprivacy

import kotlin.math.roundToInt

/**
 * TIP-B4 (TIP-404) — pure, framework-free decision + formatting logic for the caller's
 * pay-to-message (message-privacy) settings. Kept as a tiny pure object so validation and the
 * dollars<->cents conversion are unit-testable without a network, Compose, or a ViewModel, and are
 * reused by [MessagePrivacyViewModel]. Mirrors the web contract's client-side rules.
 *
 * Money model: the UI edits the minimum tip as a DOLLARS string; the wire carries `min_tip_cents`
 * (an Int). All conversion + validation of that boundary lives here.
 */
object MessagePrivacyMath {

    /** Server ceiling on the minimum tip: \$1000 == 100_000 cents. */
    const val MAX_MIN_TIP_CENTS = 100_000

    /** Sentinel dollars string shown when the gate turns on but no min is on file yet. */
    const val DEFAULT_MIN_TIP_DOLLARS = "1.0"

    /** Outcome of validating the min-tip field for a Save. */
    sealed interface MinTipResult {
        /** Valid — [cents] is the wire value to PUT. */
        data class Valid(val cents: Int) : MinTipResult

        /** Invalid — [message] is the user-facing form error. */
        data class Invalid(val message: String) : MinTipResult
    }

    const val ERROR_TOO_LOW = "Set a minimum tip greater than \$0 to require a tip."
    const val ERROR_TOO_HIGH = "Minimum tip can't exceed \$1000."

    /**
     * Validate + convert the min-tip [dollarsInput] for a Save, given whether the gate is on.
     *
     * When [requireTip] is on the amount must be > \$0 and <= \$1000. When the gate is off the field
     * is advisory: any blank/invalid/negative value coalesces to 0 cents (nothing to enforce), so
     * Save always succeeds.
     */
    fun validateMinTip(requireTip: Boolean, dollarsInput: String): MinTipResult {
        val dollars = dollarsInput.trim().toDoubleOrNull()
        if (!requireTip) {
            val cents = dollarsToCents((dollars ?: 0.0).coerceAtLeast(0.0))
            return MinTipResult.Valid(cents)
        }
        return when {
            dollars == null || dollars <= 0.0 -> MinTipResult.Invalid(ERROR_TOO_LOW)
            dollarsToCents(dollars) > MAX_MIN_TIP_CENTS -> MinTipResult.Invalid(ERROR_TOO_HIGH)
            else -> MinTipResult.Valid(dollarsToCents(dollars))
        }
    }

    /** Round a non-negative dollars amount to whole cents (banker-free, half-up via roundToInt). */
    fun dollarsToCents(dollars: Double): Int = (dollars.coerceAtLeast(0.0) * 100).roundToInt()

    /**
     * Format [cents] as the editable dollars string for the field. Zero/negative shows the default
     * sentinel (so the user isn't asked to require "\$0"); otherwise a plain decimal of dollars.
     */
    fun centsToDollarsField(cents: Int): String =
        if (cents > 0) (cents / 100.0).toString() else DEFAULT_MIN_TIP_DOLLARS

    /**
     * True when [userId] is already present in [allowlist] (case-insensitive). Callers use this to
     * reject a duplicate add before hitting the network.
     */
    fun isDuplicateAllowlistEntry(allowlist: List<String>, userId: String): Boolean {
        val trimmed = userId.trim()
        return allowlist.any { it.equals(trimmed, ignoreCase = true) }
    }

    /** Normalize a raw allowlist input; blank -> null (nothing to add). */
    fun normalizeAllowlistInput(raw: String): String? = raw.trim().ifEmpty { null }

    /**
     * Degrade-on-404: a missing message-privacy config (the caller has never set a gate) is
     * equivalent to the default OFF gate, not an error. True when [status] should be coalesced to a
     * default [MessagePrivacy] instead of surfacing an error.
     */
    fun isBenignMissingConfig(status: Int?): Boolean = status == HTTP_NOT_FOUND

    const val HTTP_NOT_FOUND = 404
}
