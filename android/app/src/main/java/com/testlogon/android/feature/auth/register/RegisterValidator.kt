package com.testlogon.android.feature.auth.register

/**
 * Field-level validation error for the registration form (AND-053).
 *
 * Password failures are split into [PolicyLength] vs [PolicyComplexity] to mirror the web copy.
 */
enum class RegisterFieldError {
    Required,
    InvalidEmail,
    PolicyLength,
    PolicyComplexity,
    PasswordMismatch,
    InvalidPhone,
}

/**
 * Pure, JVM-testable registration validation (AND-053). Avoids `android.util.Patterns` so it runs
 * without Robolectric, matching [com.testlogon.android.feature.auth.login.LoginValidator].
 *
 * Rules are the web-client policy verified in the spec:
 *  - full name: non-blank (trimmed).
 *  - email: non-blank + email-shape.
 *  - password: 12..128 chars + lower + upper + digit + special.
 *  - confirm: non-blank + equals password.
 *  - phone: required only when SMS-MFA is opted in; E.164-ish when required.
 */
object RegisterValidator {

    private val EMAIL_REGEX =
        Regex("^[A-Za-z0-9._%+\\-]+@[A-Za-z0-9.\\-]+\\.[A-Za-z]{2,}$")

    private val PHONE_REGEX = Regex("^\\+?[0-9]{7,15}$")

    const val PASSWORD_MIN = 12
    const val PASSWORD_MAX = 128

    fun validateFullName(raw: String): RegisterFieldError? =
        if (raw.isBlank()) RegisterFieldError.Required else null

    fun validateEmail(raw: String): RegisterFieldError? = when {
        raw.isBlank() -> RegisterFieldError.Required
        !EMAIL_REGEX.matches(raw.trim()) -> RegisterFieldError.InvalidEmail
        else -> null
    }

    /** Cheap syntactic plausibility gate for the debounced availability check (AND-055 FR-4). */
    fun isPlausibleEmail(raw: String): Boolean = EMAIL_REGEX.matches(raw.trim())

    fun validatePassword(raw: String): RegisterFieldError? = when {
        raw.isBlank() -> RegisterFieldError.Required
        raw.length < PASSWORD_MIN || raw.length > PASSWORD_MAX -> RegisterFieldError.PolicyLength
        !raw.any { it.isLowerCase() } -> RegisterFieldError.PolicyComplexity
        !raw.any { it.isUpperCase() } -> RegisterFieldError.PolicyComplexity
        !raw.any { it.isDigit() } -> RegisterFieldError.PolicyComplexity
        !raw.any { !it.isLetterOrDigit() } -> RegisterFieldError.PolicyComplexity
        else -> null
    }

    fun validateConfirm(password: String, confirm: String): RegisterFieldError? = when {
        confirm.isBlank() -> RegisterFieldError.Required
        confirm != password -> RegisterFieldError.PasswordMismatch
        else -> null
    }

    fun validatePhone(raw: String, required: Boolean): RegisterFieldError? = when {
        !required -> null
        raw.isBlank() -> RegisterFieldError.Required
        !PHONE_REGEX.matches(raw.trim()) -> RegisterFieldError.InvalidPhone
        else -> null
    }
}
