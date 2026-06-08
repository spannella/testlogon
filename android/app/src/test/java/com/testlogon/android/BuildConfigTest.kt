package com.testlogon.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-006 — verifies the compile-time backend base URL constant.
 *
 * No product flavors are used; the single [BuildConfig.API_BASE_URL] points at the dev host and
 * MUST end with '/' so Retrofit composes relative paths correctly.
 */
class BuildConfigTest {

    @Test
    fun apiBaseUrl_isPresent_andTrailingSlashed() {
        val url = BuildConfig.API_BASE_URL
        assertTrue("API_BASE_URL must not be blank", url.isNotBlank())
        assertTrue("API_BASE_URL must end with '/': $url", url.endsWith("/"))
    }

    @Test
    fun apiBaseUrl_pointsAtDevHost() {
        assertEquals("http://18.222.237.167:8000/", BuildConfig.API_BASE_URL)
    }
}
