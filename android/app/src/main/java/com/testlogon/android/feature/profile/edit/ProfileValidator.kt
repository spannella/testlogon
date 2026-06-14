package com.testlogon.android.feature.profile.edit

import androidx.annotation.StringRes
import com.testlogon.android.R

/** Outcome of a single field validation: [Ok] or [Invalid] with a string-resource message. */
sealed interface ValidationResult {
    data object Ok : ValidationResult
    data class Invalid(@StringRes val msgRes: Int) : ValidationResult

    val errorRes: Int? get() = (this as? Invalid)?.msgRes
}

/**
 * AND-072 — pure client-side validator for the editable profile basics. No Android framework deps
 * beyond @StringRes, so it is exercisable by plain JVM unit tests.
 *
 * Server length limits are not declared in ProfilePatchReq (no maxLength), so these caps are
 * client-side UX guards (display name 1..50, description <=280, title/location <=100).
 */
class ProfileValidator {

    fun validateDisplayName(raw: String): ValidationResult {
        val trimmed = raw.trim()
        return when {
            trimmed.isEmpty() -> ValidationResult.Invalid(R.string.profile_edit_error_name_required)
            trimmed.any { it.isControlChar() } ->
                ValidationResult.Invalid(R.string.profile_edit_error_name_invalid)
            trimmed.length > MAX_DISPLAY_NAME ->
                ValidationResult.Invalid(R.string.profile_edit_error_name_too_long)
            else -> ValidationResult.Ok
        }
    }

    fun validateDescription(raw: String): ValidationResult =
        if (raw.length > MAX_DESCRIPTION) {
            ValidationResult.Invalid(R.string.profile_edit_error_description_too_long)
        } else {
            ValidationResult.Ok
        }

    fun validateTitle(raw: String): ValidationResult =
        if (raw.trim().length > MAX_SHORT_TEXT) {
            ValidationResult.Invalid(R.string.profile_edit_error_title_too_long)
        } else {
            ValidationResult.Ok
        }

    fun validateLocation(raw: String): ValidationResult =
        if (raw.trim().length > MAX_SHORT_TEXT) {
            ValidationResult.Invalid(R.string.profile_edit_error_location_too_long)
        } else {
            ValidationResult.Ok
        }

    private fun Char.isControlChar(): Boolean = this.code in 0..0x1F || this.code == 0x7F

    companion object {
        const val MAX_DISPLAY_NAME = 50
        const val MAX_DESCRIPTION = 280
        const val MAX_SHORT_TEXT = 100
    }
}
