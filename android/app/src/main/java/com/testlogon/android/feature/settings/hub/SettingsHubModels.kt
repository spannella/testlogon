package com.testlogon.android.feature.settings.hub

import androidx.annotation.StringRes
import androidx.compose.ui.graphics.vector.ImageVector
import com.testlogon.android.R

/**
 * AND-077 — stable identity for each Settings section. The `key` drives test tags, analytics, and
 * the nav route so reordering/gating never touches navigation code.
 */
enum class SettingsSectionKey {
    ACCOUNT, SECURITY, NOTIFICATIONS, ALERTS, MEDIA, APPEARANCE, LANGUAGE, PRIVACY
}

/**
 * A single Settings hub row descriptor. [available] false renders the row Disabled (greyed,
 * non-clickable) so the hub never dead-links to an unbuilt destination.
 */
data class SettingsSection(
    val key: SettingsSectionKey,
    @StringRes val titleRes: Int,
    @StringRes val subtitleRes: Int?,
    val icon: ImageVector,
    val route: String,
    val available: Boolean,
)

/** Hub UI state — a synchronously-resolved catalog (no network). */
data class SettingsHubUiState(
    val sections: List<SettingsSection> = emptyList(),
)

/** Externalized "coming soon" subtitle for gated rows. */
@StringRes
internal val COMING_SOON_SUBTITLE: Int = R.string.settings_section_coming_soon
