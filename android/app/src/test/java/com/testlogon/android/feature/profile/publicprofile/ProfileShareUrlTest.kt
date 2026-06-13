package com.testlogon.android.feature.profile.publicprofile

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * AND-390 — TC-AND-390-04. Pure JVM coverage of the canonical public-profile share URL builder. The
 * host is always the published App Link host (production), NEVER the plaintext dev base URL, so a
 * shared link round-trips back into the app via the verified `/u/` App Link path (FR-5/FR-6).
 */
class ProfileShareUrlTest {

    @Test
    fun build_usesProductionHost_andUPath() {
        assertEquals(
            "https://app.testlogon.example.com/u/ada",
            ProfileShareUrl.build("app.testlogon.example.com", "ada"),
        )
    }

    @Test
    fun build_isNeverTheDevHost_evenWhenDevHostPassedAsArgWouldDiffer() {
        // The builder takes the published host explicitly; the production caller supplies the App Link
        // host (applink_host), never http://18.222.237.167:8000. Asserting the https scheme + shape.
        val url = ProfileShareUrl.build("testlogon.com", "creator")
        assertEquals("https://testlogon.com/u/creator", url)
        assert(url.startsWith("https://")) { "share URL must be https, was: $url" }
    }

    @Test
    fun build_percentEncodesPathUnsafeIdentifier() {
        // encodeURIComponent-equivalent: spaces -> %20, slashes encoded, so the path segment is safe.
        assertEquals(
            "https://testlogon.com/u/a%20b%2Fc",
            ProfileShareUrl.build("testlogon.com", "a b/c"),
        )
    }

    @Test
    fun build_preservesCaseForOpaqueIdentifiers() {
        // OQ-1: Android does not aggressively lower-case; opaque/case-sensitive ids are preserved.
        assertEquals(
            "https://testlogon.com/u/Ada_Lovelace",
            ProfileShareUrl.build("testlogon.com", "Ada_Lovelace"),
        )
    }
}
