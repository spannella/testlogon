package com.testlogon.android.feature.auth.recovery

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** AND-059 — new-password policy evaluation (shared with the registration password rules). */
class RecoveryPasswordValidatorTest {

    @Test
    fun allRulesPass_forAStrongPassword() {
        val r = RecoveryPasswordValidator.evaluate("Str0ng!Passw0rd")
        assertTrue(r.minLength)
        assertTrue(r.hasUpper)
        assertTrue(r.hasLower)
        assertTrue(r.hasDigit)
        assertTrue(r.hasSymbol)
        assertTrue(r.allPass)
    }

    @Test
    fun minLengthBoundary_at12() {
        // 11 chars (all classes present) -> fails length only.
        assertFalse(RecoveryPasswordValidator.evaluate("Aa1!Aa1!Aa1").minLength)
        // 12 chars -> passes length.
        assertTrue(RecoveryPasswordValidator.evaluate("Aa1!Aa1!Aa1!").minLength)
    }

    @Test
    fun missingClasses_failTheRelevantRuleOnly() {
        with(RecoveryPasswordValidator.evaluate("alllowercase1!")) {
            assertFalse(hasUpper)
            assertTrue(hasLower)
            assertFalse(allPass)
        }
        with(RecoveryPasswordValidator.evaluate("ALLUPPERCASE1!")) {
            assertFalse(hasLower)
            assertFalse(allPass)
        }
        with(RecoveryPasswordValidator.evaluate("NoDigitsHere!!")) {
            assertFalse(hasDigit)
        }
        with(RecoveryPasswordValidator.evaluate("NoSymbols12345")) {
            assertFalse(hasSymbol)
        }
    }

    @Test
    fun emptyPassword_failsEverything() {
        val r = RecoveryPasswordValidator.evaluate("")
        assertFalse(r.minLength)
        assertFalse(r.hasUpper)
        assertFalse(r.allPass)
    }
}
