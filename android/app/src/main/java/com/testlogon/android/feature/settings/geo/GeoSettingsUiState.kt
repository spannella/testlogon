package com.testlogon.android.feature.settings.geo

/** Stable testTags for the geo-settings screen. */
object GeoSettingsTestTags {
    const val SCREEN = "geo_settings_screen"
    const val ERROR_RETRY = "geo_settings_error_retry"
    const val MODE_NONE = "geo_settings_mode_none"
    const val MODE_ALLOW = "geo_settings_mode_allow"
    const val MODE_BLOCK = "geo_settings_mode_block"
    const val COUNTRIES_INPUT = "geo_settings_countries_input"
    const val TEST_BUTTON = "geo_settings_test_button"
    const val RESULT = "geo_settings_result"
}

/**
 * Exhaustive UI state for the geo-blocking settings screen. [Loading] is the first-load spinner; [Content]
 * carries the detected country + the available country list + the dry-run test form/result; [Error] carries the
 * retry surface message. Mirrors the web GeoRulesPage (a read view + a dry-run tester).
 */
sealed interface GeoSettingsUiState {

    data object Loading : GeoSettingsUiState

    data class Content(
        val myCountry: MyCountry?,
        val countries: List<GeoCountry>,
        val testMode: String = "",
        val testCountries: String = "",
        val testing: Boolean = false,
        val result: GeoCheckOutcome? = null,
        val resultError: String? = null,
    ) : GeoSettingsUiState {
        /** Display name for [MyCountry.country], resolved against the country list. */
        val myCountryName: String?
            get() = myCountry?.country?.let { code -> countries.firstOrNull { it.code == code }?.name }
    }

    data class Error(val message: String) : GeoSettingsUiState
}
