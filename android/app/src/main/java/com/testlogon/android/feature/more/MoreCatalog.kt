package com.testlogon.android.feature.more

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Devices
import androidx.compose.material.icons.outlined.HelpOutline
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.outlined.Notifications
import androidx.compose.material.icons.outlined.Person
import androidx.compose.material.icons.outlined.Security
import androidx.compose.material.icons.outlined.Settings
import com.testlogon.android.R
import com.testlogon.android.navigation.MoreRoutes
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-067 — the single, ordered source of truth for the "More" directory entries.
 *
 * Routes point at destinations registered in the authenticated graph; entries for destinations not
 * yet built are flagged [MoreEntry.comingSoon] so they render Disabled rather than linking nowhere.
 */
@Singleton
class MoreCatalog @Inject constructor() {
    val entries: List<MoreEntry> = listOf(
        MoreEntry(
            id = "profile",
            labelRes = R.string.more_entry_profile,
            icon = Icons.Outlined.Person,
            route = MoreRoutes.PROFILE,
            section = MoreSection.ACCOUNT,
        ),
        MoreEntry(
            id = "sessions",
            labelRes = R.string.more_entry_sessions,
            icon = Icons.Outlined.Devices,
            route = MoreRoutes.SESSIONS,
            section = MoreSection.SECURITY,
        ),
        MoreEntry(
            id = "mfa_devices",
            labelRes = R.string.more_entry_mfa_devices,
            icon = Icons.Outlined.Security,
            route = MoreRoutes.MFA_DEVICES,
            section = MoreSection.SECURITY,
        ),
        MoreEntry(
            id = "notifications",
            labelRes = R.string.more_entry_notifications,
            icon = Icons.Outlined.Notifications,
            route = MoreRoutes.NOTIFICATIONS,
            section = MoreSection.APP,
            comingSoon = true,
        ),
        MoreEntry(
            id = "settings",
            labelRes = R.string.more_entry_settings,
            icon = Icons.Outlined.Settings,
            route = MoreRoutes.SETTINGS,
            section = MoreSection.APP,
            comingSoon = true,
        ),
        MoreEntry(
            id = "help",
            labelRes = R.string.more_entry_help,
            icon = Icons.Outlined.HelpOutline,
            route = MoreRoutes.HELP,
            section = MoreSection.SUPPORT,
            comingSoon = true,
        ),
        MoreEntry(
            id = "about",
            labelRes = R.string.more_entry_about,
            icon = Icons.Outlined.Info,
            route = MoreRoutes.ABOUT,
            section = MoreSection.SUPPORT,
            comingSoon = true,
        ),
    )
}
