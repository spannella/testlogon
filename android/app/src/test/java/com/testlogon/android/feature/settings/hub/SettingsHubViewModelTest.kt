package com.testlogon.android.feature.settings.hub

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** AND-083 — hub catalog order/size + availability (pure, no I/O). */
class SettingsHubViewModelTest {

    @Test
    fun catalog_hasSectionsInFixedOrder() {
        val keys = SettingsHubViewModel.buildCatalog().map { it.key }
        // Current shipped order. Sections beyond the original 8 were added by later
        // shipped programs: PUSH_EVENTS (push/realtime event prefs), EMOJIS (custom
        // reaction set), GEO (location/geo controls), CALL_RATE (pay-per-minute call
        // pricing). Kept in canonical hub order; update alongside buildCatalog().
        assertEquals(
            listOf(
                SettingsSectionKey.ACCOUNT,
                SettingsSectionKey.SECURITY,
                SettingsSectionKey.NOTIFICATIONS,
                SettingsSectionKey.PUSH_EVENTS,
                SettingsSectionKey.ALERTS, // AND-088 — email/SMS alert-target management
                SettingsSectionKey.TRADING, // trading prefs: theme + default market + alert-kind toggles
                SettingsSectionKey.MEDIA,
                SettingsSectionKey.APPEARANCE,
                SettingsSectionKey.LANGUAGE, // AND-114 — in-app locale picker
                SettingsSectionKey.PRIVACY,
                SettingsSectionKey.EMOJIS,
                SettingsSectionKey.GEO,
                SettingsSectionKey.CALL_RATE,
            ),
            keys,
        )
    }

    @Test
    fun catalog_allAvailable_haveRoutesAndTitles() {
        SettingsHubViewModel.buildCatalog().forEach { section ->
            assertTrue("route should be non-blank", section.route.isNotBlank())
            assertTrue("each shipped section is available", section.available)
        }
    }
}
