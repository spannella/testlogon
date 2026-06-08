package com.testlogon.android.feature.auth.register

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Truth-table coverage for [RegisterValidator] (AND-053 TC-01). */
class RegisterValidatorTest {

    @Test
    fun fullName_blank_isRequired_otherwiseValid() {
        assertEquals(RegisterFieldError.Required, RegisterValidator.validateFullName("  "))
        assertNull(RegisterValidator.validateFullName("A"))
        assertNull(RegisterValidator.validateFullName("Ada Lovelace"))
    }

    @Test
    fun email_blank_invalid_valid() {
        assertEquals(RegisterFieldError.Required, RegisterValidator.validateEmail(""))
        assertEquals(RegisterFieldError.InvalidEmail, RegisterValidator.validateEmail("a@"))
        assertEquals(RegisterFieldError.InvalidEmail, RegisterValidator.validateEmail("nope"))
        assertNull(RegisterValidator.validateEmail("ada@example.com"))
    }

    @Test
    fun password_lengthAndComplexity() {
        assertEquals(RegisterFieldError.Required, RegisterValidator.validatePassword(""))
        // 11 chars -> too short
        assertEquals(RegisterFieldError.PolicyLength, RegisterValidator.validatePassword("Ab1! Ab1!Ab".take(11)))
        assertEquals(RegisterFieldError.PolicyLength, RegisterValidator.validatePassword("Ab1!".repeat(33)))
        // 12+ chars but missing a class
        assertEquals(RegisterFieldError.PolicyComplexity, RegisterValidator.validatePassword("alllowercase1!"))
        assertEquals(RegisterFieldError.PolicyComplexity, RegisterValidator.validatePassword("ALLUPPERCASE1!"))
        assertEquals(RegisterFieldError.PolicyComplexity, RegisterValidator.validatePassword("NoDigitsHere!!"))
        assertEquals(RegisterFieldError.PolicyComplexity, RegisterValidator.validatePassword("NoSymbols1234"))
        assertNull(RegisterValidator.validatePassword("Ada!Lovelace2026"))
    }

    @Test
    fun confirm_blank_mismatch_match() {
        assertEquals(RegisterFieldError.Required, RegisterValidator.validateConfirm("pw", ""))
        assertEquals(RegisterFieldError.PasswordMismatch, RegisterValidator.validateConfirm("pw1", "pw2"))
        assertNull(RegisterValidator.validateConfirm("same", "same"))
    }

    @Test
    fun phone_requiredRules_andNotRequiredIgnored() {
        assertNull(RegisterValidator.validatePhone("", required = false))
        assertNull(RegisterValidator.validatePhone("garbage", required = false))
        assertEquals(RegisterFieldError.Required, RegisterValidator.validatePhone("", required = true))
        assertEquals(RegisterFieldError.InvalidPhone, RegisterValidator.validatePhone("abc", required = true))
        assertNull(RegisterValidator.validatePhone("+15551234567", required = true))
    }

    @Test
    fun isPlausibleEmail_gate() {
        assertFalse(RegisterValidator.isPlausibleEmail("foo"))
        assertFalse(RegisterValidator.isPlausibleEmail(""))
        assertTrue(RegisterValidator.isPlausibleEmail("a@b.com"))
    }
}
