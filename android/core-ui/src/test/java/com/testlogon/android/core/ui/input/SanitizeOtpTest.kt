package com.testlogon.android.core.ui.input

import org.junit.Assert.assertEquals
import org.junit.Test

class SanitizeOtpTest {

    @Test fun digitsOnly_passThrough() {
        assertEquals("123456", sanitizeOtp("123456", 6))
    }

    @Test fun stripsNonDigits() {
        assertEquals("123456", sanitizeOtp("12-34-56", 6))
        assertEquals("123456", sanitizeOtp(" 1 2 3\n4 5 6 ", 6))
    }

    @Test fun truncatesToLength() {
        assertEquals("123456", sanitizeOtp("123456789", 6))
        assertEquals("1234", sanitizeOtp("12-34-56", 4))
    }

    @Test fun emptyAndAllNonDigit_returnEmpty() {
        assertEquals("", sanitizeOtp("", 6))
        assertEquals("", sanitizeOtp("abc", 6))
    }
}
