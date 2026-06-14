package com.testlogon.android.feature.auth.login

/** Field-level validation error for the login form (AND-030). */
enum class FieldError { Required, InvalidEmail }

/**
 * Pure, JVM-testable login validation. Permissive by design (web parity): the identifier is
 * non-blank, and an email-format check applies only when it contains `@` (so bare usernames are
 * still accepted). Avoids `android.util.Patterns` so it runs without Robolectric.
 */
object LoginValidator {

    // Pragmatic email shape: local@domain.tld with no spaces. Only applied when '@' is present.
    private val EMAIL_REGEX =
        Regex("^[A-Za-z0-9._%+\\-]+@[A-Za-z0-9.\\-]+\\.[A-Za-z]{2,}$")

    fun validateEmail(raw: String): FieldError? = when {
        raw.isBlank() -> FieldError.Required
        '@' in raw && !EMAIL_REGEX.matches(raw.trim()) -> FieldError.InvalidEmail
        else -> null
    }

    fun validatePassword(raw: String): FieldError? =
        if (raw.isBlank()) FieldError.Required else null
}
