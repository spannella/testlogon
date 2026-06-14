package com.testlogon.android.data.preferences

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.AccentColor
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.FontSizePref
import com.testlogon.android.core.model.PreferencesPatch
import com.testlogon.android.core.model.ThemeModePref
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/** AND-083 — preferences round-trip contract tests against MockWebServer (real Retrofit/Moshi). */
class PreferencesRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    // Codegen adapters resolve without the reflection factory (matches DashboardRepositoryContractTest).
    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): PreferencesRepositoryImpl {
        val api = backend.retrofit(moshi).create(PreferencesApi::class.java)
        return PreferencesRepositoryImpl(api = api, errorParser = ApiErrorParser(moshi))
    }

    @Test
    fun getPreferences_unwrapsEnvelope_andMapsFields() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"preferences":{"theme":"dark","accent_color":"teal","font_size":"large",""" +
                    """"density":"compact","high_contrast":true,"sidebar_collapsed":false,""" +
                    """"custom_accent_hex":"#1a2b3c"}}""",
            ),
        )
        val result = repo().getPreferences()
        assertTrue(result is ApiResult.Success)
        val prefs = (result as ApiResult.Success).data
        assertEquals(ThemeModePref.DARK, prefs.theme)
        assertEquals(AccentColor.TEAL, prefs.accentColor)
        assertEquals(FontSizePref.LARGE, prefs.fontSize)
        assertEquals("#1a2b3c", prefs.customAccentHex)
        assertTrue(prefs.highContrast)

        val recorded = backend.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/ui/settings/preferences", recorded.requestUrl?.encodedPath)
    }

    @Test
    fun getPreferences_emptyEnvelope_appliesDefaults() = runTest {
        backend.enqueue(Fixtures.okBody("""{"preferences":{}}"""))
        val result = repo().getPreferences()
        assertTrue(result is ApiResult.Success)
        val prefs = (result as ApiResult.Success).data
        assertEquals(ThemeModePref.SYSTEM, prefs.theme)
        assertEquals(AccentColor.BLUE, prefs.accentColor)
        assertEquals(FontSizePref.DEFAULT, prefs.fontSize)
        assertFalse(prefs.highContrast)
    }

    @Test
    fun updatePreferences_sendsOnlyChangedFields_thenReGets() = runTest {
        backend.enqueue(Fixtures.okBody("""{"ok":true}"""))
        backend.enqueue(Fixtures.okBody("""{"preferences":{"theme":"light","accent_color":"purple"}}"""))

        val result = repo().updatePreferences(
            PreferencesPatch(theme = ThemeModePref.LIGHT, accentColor = AccentColor.PURPLE),
        )
        assertTrue(result is ApiResult.Success)
        assertEquals(ThemeModePref.LIGHT, (result as ApiResult.Success).data.theme)
        assertEquals(AccentColor.PURPLE, result.data.accentColor)

        val patch = backend.takeRequest()
        assertEquals("PATCH", patch.method)
        assertEquals("/ui/settings/preferences", patch.requestUrl?.encodedPath)
        val body = patch.body.readUtf8()
        assertTrue(body.contains("\"theme\":\"light\""))
        assertTrue(body.contains("\"accent_color\":\"purple\""))
        // Null fields must be omitted, not sent as null.
        assertFalse(body.contains("font_size"))
        assertFalse(body.contains("density"))
        assertFalse(body.contains("high_contrast"))

        val reGet = backend.takeRequest()
        assertEquals("GET", reGet.method)
    }

    @Test
    fun getPreferences_httpError_mapsToFailure() = runTest {
        backend.enqueue(Fixtures.error("\"preferences temporarily unavailable\"", 503))
        val result = repo().getPreferences()
        assertTrue(result is ApiResult.Failure)
        assertEquals(503, (result as ApiResult.Failure).error.status)
    }

    @Test
    fun getPreferences_validationError_mapsDetailMessage() = runTest {
        backend.enqueue(
            Fixtures.error(
                """[{"loc":["body","theme"],"msg":"value is not a valid enumeration member","type":"value_error"}]""",
                422,
            ),
        )
        val result = repo().getPreferences()
        assertTrue(result is ApiResult.Failure)
        assertEquals(422, (result as ApiResult.Failure).error.status)
        assertTrue(result.error.message.contains("valid enumeration member"))
    }

    @Test
    fun getPreferences_transportFailure_mapsToNetworkError() = runTest {
        backend.enqueue(Fixtures.disconnect())
        val result = repo().getPreferences()
        assertTrue(result is ApiResult.NetworkError)
    }
}
