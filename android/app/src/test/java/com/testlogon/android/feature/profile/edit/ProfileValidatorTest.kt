package com.testlogon.android.feature.profile.edit

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** AND-072 / AND-076 — pure validator boundary tests (no Android framework). */
class ProfileValidatorTest {

    private val validator = ProfileValidator()

    @Test
    fun displayName_emptyOrWhitespace_invalid() {
        assertTrue(validator.validateDisplayName("") is ValidationResult.Invalid)
        assertTrue(validator.validateDisplayName("   ") is ValidationResult.Invalid)
    }

    @Test
    fun displayName_oneAndMaxChars_ok() {
        assertEquals(ValidationResult.Ok, validator.validateDisplayName("a"))
        assertEquals(ValidationResult.Ok, validator.validateDisplayName("x".repeat(ProfileValidator.MAX_DISPLAY_NAME)))
    }

    @Test
    fun displayName_overMax_invalid() {
        assertTrue(
            validator.validateDisplayName("x".repeat(ProfileValidator.MAX_DISPLAY_NAME + 1)) is ValidationResult.Invalid,
        )
    }

    @Test
    fun displayName_controlChar_invalid() {
        val withControl = "Sean" + 1.toChar() // U+0001 control character
        assertTrue(validator.validateDisplayName(withControl) is ValidationResult.Invalid)
    }

    @Test
    fun description_atAndOverMax() {
        assertEquals(ValidationResult.Ok, validator.validateDescription("x".repeat(ProfileValidator.MAX_DESCRIPTION)))
        assertTrue(
            validator.validateDescription("x".repeat(ProfileValidator.MAX_DESCRIPTION + 1)) is ValidationResult.Invalid,
        )
    }

    @Test
    fun description_allowsNewlines() {
        assertEquals(ValidationResult.Ok, validator.validateDescription("line1\nline2"))
    }

    @Test
    fun titleAndLocation_overMax_invalid() {
        val long = "x".repeat(ProfileValidator.MAX_SHORT_TEXT + 1)
        assertTrue(validator.validateTitle(long) is ValidationResult.Invalid)
        assertTrue(validator.validateLocation(long) is ValidationResult.Invalid)
    }
}
