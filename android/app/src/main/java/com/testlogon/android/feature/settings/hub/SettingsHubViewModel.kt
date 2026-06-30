package com.testlogon.android.feature.settings.hub

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.DarkMode
import androidx.compose.material.icons.outlined.Campaign
import androidx.compose.material.icons.outlined.Language
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.Notifications
import androidx.compose.material.icons.outlined.PermMedia
import androidx.compose.material.icons.outlined.Person
import androidx.compose.material.icons.outlined.EmojiEmotions
import androidx.compose.material.icons.outlined.Paid
import androidx.compose.material.icons.outlined.Public
import androidx.compose.material.icons.outlined.Security
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.R
import com.testlogon.android.navigation.MainDest
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import javax.inject.Inject

/**
 * AND-077 — resolves the static, ordered six-section Settings catalog into [SettingsHubUiState].
 * No I/O occurs; the hub is reachable even when the backend is down. Sections whose owning ticket
 * has landed are [SettingsSection.available]; others render Disabled.
 */
@HiltViewModel
class SettingsHubViewModel @Inject constructor() : ViewModel() {

    private val source = MutableStateFlow(Unit)

    val uiState: StateFlow<SettingsHubUiState> = source
        .map { SettingsHubUiState(sections = buildCatalog()) }
        .stateIn(
            scope = viewModelScope,
            started = SharingStarted.WhileSubscribed(5_000),
            initialValue = SettingsHubUiState(sections = buildCatalog()),
        )

    companion object {
        /** The fixed-order catalog. All six subsection screens ship in this change, so all available. */
        fun buildCatalog(): List<SettingsSection> = listOf(
            SettingsSection(
                key = SettingsSectionKey.ACCOUNT,
                titleRes = R.string.settings_section_account_title,
                subtitleRes = R.string.settings_section_account_subtitle,
                icon = Icons.Outlined.Person,
                route = MainDest.SettingsAccount.route,
                available = true,
            ),
            SettingsSection(
                key = SettingsSectionKey.SECURITY,
                titleRes = R.string.settings_section_security_title,
                subtitleRes = R.string.settings_section_security_subtitle,
                icon = Icons.Outlined.Security,
                route = MainDest.SettingsSecurity.route,
                available = true,
            ),
            SettingsSection(
                key = SettingsSectionKey.NOTIFICATIONS,
                titleRes = R.string.settings_section_notifications_title,
                subtitleRes = R.string.settings_section_notifications_subtitle,
                icon = Icons.Outlined.Notifications,
                route = MainDest.SettingsNotifications.route,
                available = true,
            ),
            SettingsSection(
                key = SettingsSectionKey.ALERTS,
                titleRes = R.string.settings_section_alerts_title,
                subtitleRes = R.string.settings_section_alerts_subtitle,
                icon = Icons.Outlined.Campaign,
                route = MainDest.SettingsAlerts.route,
                available = true,
            ),
            SettingsSection(
                key = SettingsSectionKey.MEDIA,
                titleRes = R.string.settings_section_media_title,
                subtitleRes = R.string.settings_section_media_subtitle,
                icon = Icons.Outlined.PermMedia,
                route = MainDest.SettingsMedia.route,
                available = true,
            ),
            SettingsSection(
                key = SettingsSectionKey.APPEARANCE,
                titleRes = R.string.settings_section_appearance_title,
                subtitleRes = R.string.settings_section_appearance_subtitle,
                icon = Icons.Outlined.DarkMode,
                route = MainDest.SettingsAppearance.route,
                available = true,
            ),
            SettingsSection(
                key = SettingsSectionKey.LANGUAGE,
                titleRes = R.string.settings_section_language_title,
                subtitleRes = R.string.settings_section_language_subtitle,
                icon = Icons.Outlined.Language,
                route = MainDest.SettingsLanguage.route,
                available = true,
            ),
            SettingsSection(
                key = SettingsSectionKey.PRIVACY,
                titleRes = R.string.settings_section_privacy_title,
                subtitleRes = R.string.settings_section_privacy_subtitle,
                icon = Icons.Outlined.Lock,
                route = MainDest.SettingsPrivacy.route,
                available = true,
            ),
            SettingsSection(
                key = SettingsSectionKey.EMOJIS,
                titleRes = R.string.settings_section_emojis_title,
                subtitleRes = R.string.settings_section_emojis_subtitle,
                icon = Icons.Outlined.EmojiEmotions,
                route = MainDest.SettingsEmojis.route,
                available = true,
            ),
            SettingsSection(
                key = SettingsSectionKey.GEO,
                titleRes = R.string.settings_section_geo_title,
                subtitleRes = R.string.settings_section_geo_subtitle,
                icon = Icons.Outlined.Public,
                route = MainDest.SettingsGeo.route,
                available = true,
            ),
            SettingsSection(
                key = SettingsSectionKey.CALL_RATE,
                titleRes = R.string.settings_section_call_rate_title,
                subtitleRes = R.string.settings_section_call_rate_subtitle,
                icon = Icons.Outlined.Paid,
                route = MainDest.SettingsCallRate.route,
                available = true,
            ),
        )
    }
}
