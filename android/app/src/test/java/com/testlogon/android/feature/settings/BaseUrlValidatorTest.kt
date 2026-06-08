package com.testlogon.android.feature.settings

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** AND-041 §6 validation + normalization matrix (pure JVM). */
class BaseUrlValidatorTest {

    private fun invalid(raw: String) = BaseUrlValidator.validate(raw) as UrlValidation.Invalid
    private fun valid(raw: String) = BaseUrlValidator.validate(raw) as UrlValidation.Valid

    @Test fun blank() = assertEquals(UrlError.BLANK, invalid("").reason)
    @Test fun whitespaceOnly_isBlank() = assertEquals(UrlError.BLANK, invalid("   ").reason)
    @Test fun notAUrl_isMalformed() = assertEquals(UrlError.MALFORMED, invalid("not a url").reason)
    @Test fun ftpScheme_isBadScheme() = assertEquals(UrlError.BAD_SCHEME, invalid("ftp://h:21").reason)
    @Test fun noHost_isNoHost() = assertEquals(UrlError.NO_HOST, invalid("http://").reason)
    @Test fun portZero_isBadPort() = assertEquals(UrlError.BAD_PORT, invalid("http://h:0").reason)
    @Test fun portTooBig_isBadPort() = assertEquals(UrlError.BAD_PORT, invalid("http://h:70000").reason)

    @Test
    fun httpHostPort_isValidCleartext() {
        val v = valid("http://18.222.237.167:8000")
        assertEquals("http://18.222.237.167:8000", v.normalized)
        assertTrue(v.cleartext)
    }

    @Test
    fun https_isValidNotCleartext() {
        val v = valid("https://api.example.com")
        assertEquals("https://api.example.com", v.normalized)
        assertEquals(false, v.cleartext)
    }

    @Test
    fun normalize_trimsLowercasesScheme_stripsTrailingSlash() {
        assertEquals("http://18.222.237.167:8000", valid("  HTTP://18.222.237.167:8000/  ").normalized)
    }

    @Test
    fun normalize_preservesExplicitPort() {
        assertEquals("https://api.example.com:443", valid("https://api.example.com:443/").normalized)
    }

    @Test
    fun ipv6_roundTrips() {
        assertEquals("http://[::1]:8000", valid("http://[::1]:8000").normalized)
    }
}
