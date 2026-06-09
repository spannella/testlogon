package com.testlogon.android.feature.auth.recovery

import com.testlogon.android.feature.auth.register.RegisterValidator

/**
 * Per-rule results for the new-password checklist (AND-059). Mirrors the registration password policy
 * ([RegisterValidator.validatePassword]) so the recovery meter and the register form never drift.
 */
data class PasswordRuleResults(
    val minLength: Boolean = false,
    val hasUpper: Boolean = false,
    val hasLower: Boolean = false,
    val hasDigit: Boolean = false,
    val hasSymbol: Boolean = false,
) {
    /** All policy rules satisfied — the submit gate uses this (server stays authoritative). */
    val allPass: Boolean get() = minLength && hasUpper && hasLower && hasDigit && hasSymbol
}

/**
 * Pure, JVM-testable new-password evaluation for the recovery confirm step (AND-059).
 *
 * The thresholds come from the shared [RegisterValidator] policy (12..128 chars + upper + lower +
 * digit + symbol) so the same rules drive the live checklist and the submit gate. The server remains
 * the source of truth; these client rules are a UX pre-filter.
 */
object RecoveryPasswordValidator {

    fun evaluate(password: String): PasswordRuleResults = PasswordRuleResults(
        minLength = password.length >= RegisterValidator.PASSWORD_MIN &&
            password.length <= RegisterValidator.PASSWORD_MAX,
        hasUpper = password.any(Char::isUpperCase),
        hasLower = password.any(Char::isLowerCase),
        hasDigit = password.any(Char::isDigit),
        hasSymbol = password.any { !it.isLetterOrDigit() },
    )
}
