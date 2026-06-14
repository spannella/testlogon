package com.testlogon.android.feature.settings.hub

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** AND-083 — hub catalog order/size + availability (pure, no I/O). */
class SettingsHubViewModelTest {

    @Test
    fun catalog_hasSectionsInFixedOrder() {
        val keys = SettingsHubViewModel.buildCatalog().map { it.key }
        assertEquals(
            listOf(
                SettingsSectionKey.ACCOUNT,
                SettingsSectionKey.SECURITY,
                SettingsSectionKey.NOTIFICATIONS,
                SettingsSectionKey.ALERTS, // AND-088 — email/SMS alert-target management
                SettingsSectionKey.MEDIA,
                SettingsSectionKey.APPEARANCE,
                SettingsSectionKey.LANGUAGE, // AND-114 — in-app locale picker
                SettingsSectionKey.PRIVACY,
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
