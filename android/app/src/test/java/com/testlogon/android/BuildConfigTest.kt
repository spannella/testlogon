package com.testlogon.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-006 — verifies the compile-time backend base URL constant.
 *
 * No product flavors are used; the single [BuildConfig.API_BASE_URL] MUST end with '/' so Retrofit
 * composes relative paths correctly. The app now ships against the managed HTTPS API host (the flaky
 * plaintext dev IP was retired), so the exact-host check tracks the current production endpoint.
 */
class BuildConfigTest {

    @Test
    fun apiBaseUrl_isPresent_andTrailingSlashed() {
        val url = BuildConfig.API_BASE_URL
        assertTrue("API_BASE_URL must not be blank", url.isNotBlank())
        assertTrue("API_BASE_URL must end with '/': $url", url.endsWith("/"))
    }

    @Test
    fun apiBaseUrl_pointsAtManagedHttpsHost() {
        assertEquals("https://tl-api.bitbazaar.cc/", BuildConfig.API_BASE_URL)
    }
}
