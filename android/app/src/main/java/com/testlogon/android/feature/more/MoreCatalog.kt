package com.testlogon.android.feature.more

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Bookmark
import androidx.compose.material.icons.outlined.Devices
import androidx.compose.material.icons.outlined.EmojiEvents
import androidx.compose.material.icons.outlined.Campaign
import androidx.compose.material.icons.outlined.ChatBubbleOutline
import androidx.compose.material.icons.outlined.CreditCard
import androidx.compose.material.icons.outlined.HelpOutline
import androidx.compose.material.icons.outlined.SupportAgent
import androidx.compose.material.icons.outlined.History
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.outlined.NotificationsActive
import androidx.compose.material.icons.outlined.Notifications
import androidx.compose.material.icons.outlined.Movie
import androidx.compose.material.icons.outlined.Person
import androidx.compose.material.icons.outlined.PhotoLibrary
import androidx.compose.material.icons.outlined.Security
import androidx.compose.material.icons.outlined.Slideshow
import androidx.compose.material.icons.outlined.Storefront
import androidx.compose.material.icons.outlined.VideoLibrary
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material.icons.outlined.ShoppingCart
import androidx.compose.material.icons.outlined.ReceiptLong
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
            id = "messages",
            labelRes = R.string.more_entry_messages,
            icon = Icons.Outlined.ChatBubbleOutline,
            route = MoreRoutes.MESSAGES,
            section = MoreSection.ACCOUNT,
        ),
        MoreEntry(
            id = "mass_messages",
            labelRes = R.string.more_entry_mass_messages,
            icon = Icons.Outlined.Campaign,
            route = MoreRoutes.MASS_MESSAGES,
            section = MoreSection.ACCOUNT,
        ),
        MoreEntry(
            id = "helpdesk_queue",
            labelRes = R.string.more_entry_helpdesk_queue,
            icon = Icons.Outlined.SupportAgent,
            route = MoreRoutes.HELPDESK_QUEUE,
            section = MoreSection.SUPPORT,
        ),
        MoreEntry(
            id = "activity",
            labelRes = R.string.more_entry_activity,
            icon = Icons.Outlined.History,
            route = MoreRoutes.ACTIVITY,
            section = MoreSection.ACCOUNT,
        ),
        MoreEntry(
            id = "saved",
            labelRes = R.string.more_entry_saved,
            icon = Icons.Outlined.Bookmark,
            route = MoreRoutes.SAVED,
            section = MoreSection.ACCOUNT,
        ),
        MoreEntry(
            id = "achievements",
            labelRes = R.string.more_entry_achievements,
            icon = Icons.Outlined.EmojiEvents,
            route = MoreRoutes.ACHIEVEMENTS,
            section = MoreSection.APP,
        ),
        MoreEntry(
            id = "videos",
            labelRes = R.string.more_entry_videos,
            icon = Icons.Outlined.VideoLibrary,
            route = MoreRoutes.VIDEOS,
            section = MoreSection.APP,
        ),
        MoreEntry(
            id = "vod_catalog",
            labelRes = R.string.more_entry_vod_catalog,
            icon = Icons.Outlined.Movie,
            route = MoreRoutes.VOD_CATALOG,
            section = MoreSection.APP,
        ),
        MoreEntry(
            id = "clips",
            labelRes = R.string.more_entry_clips,
            icon = Icons.Outlined.Slideshow,
            route = MoreRoutes.CLIPS,
            section = MoreSection.APP,
        ),
        MoreEntry(
            id = "gallery",
            labelRes = R.string.more_entry_gallery,
            icon = Icons.Outlined.PhotoLibrary,
            route = MoreRoutes.GALLERY,
            section = MoreSection.APP,
        ),
        MoreEntry(
            id = "catalog",
            labelRes = R.string.more_entry_catalog,
            icon = Icons.Outlined.Storefront,
            route = MoreRoutes.CATALOG,
            section = MoreSection.APP,
        ),
        MoreEntry(
            id = "cart",
            labelRes = R.string.more_entry_cart,
            icon = Icons.Outlined.ShoppingCart,
            route = MoreRoutes.CART,
            section = MoreSection.APP,
        ),
        MoreEntry(
            id = "purchase_history",
            labelRes = R.string.more_entry_purchase_history,
            icon = Icons.Outlined.ReceiptLong,
            route = MoreRoutes.PURCHASE_HISTORY,
            section = MoreSection.APP,
        ),
        MoreEntry(
            id = "payment_methods",
            labelRes = R.string.more_entry_payment_methods,
            icon = Icons.Outlined.CreditCard,
            route = MoreRoutes.PAYMENT_METHODS,
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
            id = "notification_center",
            labelRes = R.string.more_entry_notification_center,
            icon = Icons.Outlined.NotificationsActive,
            route = MoreRoutes.NOTIFICATION_CENTER,
            section = MoreSection.APP,
        ),
        MoreEntry(
            id = "notifications",
            labelRes = R.string.more_entry_notifications,
            icon = Icons.Outlined.Notifications,
            route = MoreRoutes.NOTIFICATIONS,
            section = MoreSection.APP,
        ),
        MoreEntry(
            id = "settings",
            labelRes = R.string.more_entry_settings,
            icon = Icons.Outlined.Settings,
            route = MoreRoutes.SETTINGS,
            section = MoreSection.APP,
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
