package com.testlogon.android.feature.settings.hub

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Person
import androidx.compose.ui.test.assertHasClickAction
import androidx.compose.ui.test.assertHasNoClickAction
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.R
import com.testlogon.android.core.ui.theme.TestLogonTheme
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** AND-083 — Compose UI tests for the Settings hub: rows render, tap navigates, disabled is no-op. */
@RunWith(AndroidJUnit4::class)
class SettingsHubScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private fun section(
        key: SettingsSectionKey,
        route: String,
        available: Boolean,
    ) = SettingsSection(
        key = key,
        titleRes = R.string.settings_section_account_title,
        subtitleRes = R.string.settings_section_account_subtitle,
        icon = Icons.Outlined.Person,
        route = route,
        available = available,
    )

    @Test
    fun availableRow_tapNavigatesWithRoute() {
        var navigated: String? = null
        rule.setContent {
            TestLogonTheme(dynamicColor = false) {
                SettingsHubScreen(
                    state = SettingsHubUiState(
                        listOf(section(SettingsSectionKey.MEDIA, "settings/media", available = true)),
                    ),
                    onOpenSection = { navigated = it.route },
                    onBack = {},
                )
            }
        }
        rule.onNodeWithTag("settings_row_media").assertHasClickAction().performClick()
        assertEquals("settings/media", navigated)
    }

    @Test
    fun disabledRow_hasNoClickAction() {
        rule.setContent {
            TestLogonTheme(dynamicColor = false) {
                SettingsHubScreen(
                    state = SettingsHubUiState(
                        listOf(
                            section(SettingsSectionKey.PRIVACY, "settings/privacy", available = false),
                        ),
                    ),
                    onOpenSection = {},
                    onBack = {},
                )
            }
        }
        rule.onNodeWithTag("settings_row_privacy").assertIsDisplayed().assertHasNoClickAction()
    }
}
