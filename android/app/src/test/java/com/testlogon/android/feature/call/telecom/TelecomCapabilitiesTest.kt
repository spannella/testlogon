package com.testlogon.android.feature.call.telecom

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-304 — pure JVM tests for [TelecomCapabilities.supported] (the android-free gate decision). The
 * device-bound [TelecomCapabilities.isSupported] caching path is exercised here via the public companion
 * function; the real probe reads Build.VERSION.SDK_INT + TelecomManager nullability on a device.
 */
class TelecomCapabilitiesTest {

    @Test
    fun api25_unsupported() {
        assertFalse(TelecomCapabilities.supported(sdkInt = 25, telecomAvailable = true))
    }

    @Test
    fun api26_withTelecom_supported() {
        assertTrue(TelecomCapabilities.supported(sdkInt = 26, telecomAvailable = true))
    }

    @Test
    fun api26_withoutTelecom_unsupported() {
        assertFalse(TelecomCapabilities.supported(sdkInt = 26, telecomAvailable = false))
    }

    @Test
    fun api34_withTelecom_supported() {
        assertTrue(TelecomCapabilities.supported(sdkInt = 34, telecomAvailable = true))
    }

    @Test
    fun api24_unsupported_evenWithTelecom() {
        assertFalse(TelecomCapabilities.supported(sdkInt = 24, telecomAvailable = true))
    }
}
