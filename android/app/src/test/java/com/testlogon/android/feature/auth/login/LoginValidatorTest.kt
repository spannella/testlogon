package com.testlogon.android.feature.auth.login

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class LoginValidatorTest {

    @Test
    fun blankEmail_isRequired() {
        assertEquals(FieldError.Required, LoginValidator.validateEmail(""))
        assertEquals(FieldError.Required, LoginValidator.validateEmail("   "))
    }

    @Test
    fun usernameWithoutAt_isAccepted() {
        assertNull(LoginValidator.validateEmail("alice"))
    }

    @Test
    fun validEmail_isAccepted() {
        assertNull(LoginValidator.validateEmail("alice@example.com"))
    }

    @Test
    fun malformedEmail_isRejected() {
        assertEquals(FieldError.InvalidEmail, LoginValidator.validateEmail("a@b"))
        assertEquals(FieldError.InvalidEmail, LoginValidator.validateEmail("a@b@c.com"))
    }

    @Test
    fun blankPassword_isRequired() {
        assertEquals(FieldError.Required, LoginValidator.validatePassword(""))
        assertNull(LoginValidator.validatePassword("pw"))
    }
}
