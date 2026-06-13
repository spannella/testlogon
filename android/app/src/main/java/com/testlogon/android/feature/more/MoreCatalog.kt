package com.testlogon.android.feature.more

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.AccountBalanceWallet
import androidx.compose.material.icons.outlined.AccountBalance
import androidx.compose.material.icons.outlined.Bookmark
import androidx.compose.material.icons.outlined.Devices
import androidx.compose.material.icons.outlined.EmojiEvents
import androidx.compose.material.icons.outlined.FolderOpen
import androidx.compose.material.icons.outlined.CalendarMonth
import androidx.compose.material.icons.outlined.EditCalendar
import androidx.compose.material.icons.outlined.EventNote
import androidx.compose.material.icons.outlined.Schedule
import androidx.compose.material.icons.outlined.Campaign
import androidx.compose.material.icons.outlined.CardMembership
import androidx.compose.material.icons.outlined.ChatBubbleOutline
import androidx.compose.material.icons.outlined.CreditCard
import androidx.compose.material.icons.outlined.Description
import androidx.compose.material.icons.outlined.Diversity3
import androidx.compose.material.icons.outlined.Gavel
import androidx.compose.material.icons.outlined.Groups
import androidx.compose.material.icons.outlined.Handshake
import androidx.compose.material.icons.outlined.HelpOutline
import androidx.compose.material.icons.outlined.SupportAgent
import androidx.compose.material.icons.outlined.History
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.outlined.Insights
import androidx.compose.material.icons.outlined.Loyalty
import androidx.compose.material.icons.outlined.GroupAdd
import androidx.compose.material.icons.outlined.Hub
import androidx.compose.material.icons.outlined.LiveTv
import androidx.compose.material.icons.outlined.LocalOffer
import androidx.compose.material.icons.outlined.NotificationsActive
import androidx.compose.material.icons.outlined.Notifications
import androidx.compose.material.icons.outlined.Paid
import androidx.compose.material.icons.outlined.Movie
import androidx.compose.material.icons.outlined.Person
import androidx.compose.material.icons.outlined.PhotoLibrary
import androidx.compose.material.icons.outlined.Receipt
import androidx.compose.material.icons.outlined.Security
import androidx.compose.material.icons.outlined.Slideshow
import androidx.compose.material.icons.outlined.Storefront
import androidx.compose.material.icons.outlined.SupervisorAccount
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
            id = "call_history",
            labelRes = R.string.more_entry_call_history,
            icon = Icons.Outlined.History,
            route = MoreRoutes.CALL_HISTORY,
            section = MoreSection.ACCOUNT,
        ),
        MoreEntry(
            id = "broadcasts",
            labelRes = R.string.more_entry_broadcasts,
            icon = Icons.Outlined.LiveTv,
            route = MoreRoutes.BROADCASTS,
            section = MoreSection.APP,
        ),
        MoreEntry(
            id = "helpdesk_queue",
            labelRes = R.string.more_entry_helpdesk_queue,
            icon = Icons.Outlined.SupportAgent,
            route = MoreRoutes.HELPDESK_QUEUE,
            section = MoreSection.SUPPORT,
        ),
        MoreEntry(
            id = "helpdesk_dashboard",
            labelRes = R.string.more_entry_helpdesk_dashboard,
            icon = Icons.Outlined.Insights,
            route = MoreRoutes.HELPDESK_DASHBOARD,
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
            id = "calendar",
            labelRes = R.string.more_entry_calendar,
            icon = Icons.Outlined.CalendarMonth,
            route = MoreRoutes.CALENDAR,
            section = MoreSection.APP,
        ),
        MoreEntry(
            id = "content_calendar",
            labelRes = R.string.more_entry_content_calendar,
            icon = Icons.Outlined.EventNote,
            route = MoreRoutes.CONTENT_CALENDAR,
            section = MoreSection.APP,
        ),
        MoreEntry(
            id = "scheduler",
            labelRes = R.string.more_entry_scheduler,
            icon = Icons.Outlined.Schedule,
            route = MoreRoutes.SCHEDULER,
            section = MoreSection.APP,
        ),
        MoreEntry(
            id = "google_calendar",
            labelRes = R.string.more_entry_google_calendar,
            icon = Icons.Outlined.EditCalendar,
            route = MoreRoutes.GOOGLE_CALENDAR,
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
            id = "earnings",
            labelRes = R.string.more_entry_earnings,
            icon = Icons.Outlined.Paid,
            route = MoreRoutes.EARNINGS,
            section = MoreSection.ACCOUNT,
        ),
        MoreEntry(
            id = "per_content_revenue",
            labelRes = R.string.more_entry_per_content_revenue,
            icon = Icons.Outlined.ReceiptLong,
            route = MoreRoutes.PER_CONTENT_REVENUE,
            section = MoreSection.ACCOUNT,
        ),
        MoreEntry(
            id = "payout_setup",
            labelRes = R.string.more_entry_payout_setup,
            icon = Icons.Outlined.AccountBalance,
            route = MoreRoutes.PAYOUT_SETUP,
            section = MoreSection.ACCOUNT,
        ),
        MoreEntry(
            id = "payouts",
            labelRes = R.string.more_entry_payouts,
            icon = Icons.Outlined.AccountBalanceWallet,
            route = MoreRoutes.PAYOUTS,
            section = MoreSection.ACCOUNT,
        ),
        MoreEntry(
            id = "bulk_payouts",
            labelRes = R.string.more_entry_bulk_payouts,
            icon = Icons.Outlined.AccountBalance,
            route = MoreRoutes.BULK_PAYOUTS,
            section = MoreSection.ACCOUNT,
        ),
        MoreEntry(
            id = "engagement",
            labelRes = R.string.more_entry_engagement,
            icon = Icons.Outlined.Insights,
            route = MoreRoutes.ENGAGEMENT,
            section = MoreSection.ACCOUNT,
        ),
        MoreEntry(
            id = "referrals",
            labelRes = R.string.more_entry_referrals,
            icon = Icons.Outlined.GroupAdd,
            route = MoreRoutes.REFERRALS,
            section = MoreSection.ACCOUNT,
        ),
        MoreEntry(
            id = "affiliates",
            labelRes = R.string.more_entry_affiliates,
            icon = Icons.Outlined.Hub,
            route = MoreRoutes.AFFILIATES,
            section = MoreSection.ACCOUNT,
        ),
        MoreEntry(
            id = "promo_codes",
            labelRes = R.string.more_entry_promo_codes,
            icon = Icons.Outlined.LocalOffer,
            route = MoreRoutes.PROMO_CODES,
            section = MoreSection.ACCOUNT,
        ),
        MoreEntry(
            id = "discounts",
            labelRes = R.string.more_entry_discounts,
            icon = Icons.Outlined.Loyalty,
            route = MoreRoutes.DISCOUNTS,
            section = MoreSection.ACCOUNT,
        ),
        MoreEntry(
            id = "invoices",
            labelRes = R.string.more_entry_invoices,
            icon = Icons.Outlined.Receipt,
            route = MoreRoutes.INVOICES,
            section = MoreSection.ACCOUNT,
        ),
        MoreEntry(
            id = "refunds",
            labelRes = R.string.more_entry_refunds,
            icon = Icons.Outlined.Paid,
            route = MoreRoutes.REFUNDS,
            section = MoreSection.ACCOUNT,
        ),
        MoreEntry(
            id = "disputes",
            labelRes = R.string.more_entry_disputes,
            icon = Icons.Outlined.Gavel,
            route = MoreRoutes.DISPUTES,
            section = MoreSection.ACCOUNT,
        ),
        MoreEntry(
            id = "tax_documents",
            labelRes = R.string.more_entry_tax_documents,
            icon = Icons.Outlined.Description,
            route = MoreRoutes.TAX_DOCUMENTS,
            section = MoreSection.ACCOUNT,
        ),
        MoreEntry(
            id = "tax_forms_1099",
            labelRes = R.string.more_entry_tax_forms_1099,
            icon = Icons.Outlined.ReceiptLong,
            route = MoreRoutes.TAX_FORMS_1099,
            section = MoreSection.ACCOUNT,
        ),
        MoreEntry(
            id = "billing_config",
            labelRes = R.string.more_entry_billing_config,
            icon = Icons.Outlined.Paid,
            route = MoreRoutes.BILLING_CONFIG,
            section = MoreSection.ACCOUNT,
        ),
        MoreEntry(
            id = "subscription_tiers",
            labelRes = R.string.more_entry_subscription_tiers,
            icon = Icons.Outlined.Loyalty,
            route = MoreRoutes.SUBSCRIPTION_TIERS,
            section = MoreSection.ACCOUNT,
        ),
        MoreEntry(
            id = "manage_subscription",
            labelRes = R.string.more_entry_manage_subscription,
            icon = Icons.Outlined.CardMembership,
            route = MoreRoutes.MANAGE_SUBSCRIPTION,
            section = MoreSection.ACCOUNT,
        ),
        MoreEntry(
            id = "fan_club",
            labelRes = R.string.more_entry_fan_club,
            icon = Icons.Outlined.Groups,
            route = MoreRoutes.FAN_CLUB,
            section = MoreSection.ACCOUNT,
        ),
        MoreEntry(
            id = "organizations",
            labelRes = R.string.more_entry_organizations,
            icon = Icons.Outlined.Groups,
            route = MoreRoutes.ORGS_MEMBERS,
            section = MoreSection.ACCOUNT,
        ),
        MoreEntry(
            id = "groups",
            labelRes = R.string.more_entry_groups,
            icon = Icons.Outlined.Diversity3,
            route = MoreRoutes.GROUPS,
            section = MoreSection.ACCOUNT,
        ),
        MoreEntry(
            id = "syndicates",
            labelRes = R.string.more_entry_syndicates,
            icon = Icons.Outlined.AccountBalance,
            route = MoreRoutes.SYNDICATES,
            section = MoreSection.ACCOUNT,
        ),
        MoreEntry(
            id = "collaborations",
            labelRes = R.string.more_entry_collaborations,
            icon = Icons.Outlined.Diversity3,
            route = MoreRoutes.COLLABORATIONS,
            section = MoreSection.ACCOUNT,
        ),
        // AND-365: READ-ONLY sponsorship inbox (inbound brand deals + client-side status filter).
        MoreEntry(
            id = "sponsorships",
            labelRes = R.string.more_entry_sponsorships,
            icon = Icons.Outlined.Handshake,
            route = MoreRoutes.SPONSORSHIPS,
            section = MoreSection.ACCOUNT,
        ),
        // AND-367: ads-account billing (balance/lifetime-spend + ledger + invoice) + DEPOSIT add-funds.
        MoreEntry(
            id = "ads_billing",
            labelRes = R.string.more_entry_ads_billing,
            icon = Icons.Outlined.AccountBalanceWallet,
            route = MoreRoutes.ADS_BILLING,
            section = MoreSection.ACCOUNT,
        ),
        // AND-368: READ-ONLY ad-analytics dashboard (KPI summary + time-series charts + breakdown).
        MoreEntry(
            id = "ad_analytics",
            labelRes = R.string.more_entry_ad_analytics,
            icon = Icons.Outlined.Insights,
            route = MoreRoutes.AD_ANALYTICS,
            section = MoreSection.ACCOUNT,
        ),
        // AND-372: READ-ONLY ticket spaces + threads (support / helpdesk). Spaces -> tickets -> thread.
        MoreEntry(
            id = "tickets",
            labelRes = R.string.more_entry_tickets,
            icon = Icons.Outlined.SupportAgent,
            route = MoreRoutes.TICKETS,
            section = MoreSection.SUPPORT,
        ),
        // AND-374: projects (paged list -> detail + account-scoped Google Drive provider connect flow).
        MoreEntry(
            id = "projects",
            labelRes = R.string.more_entry_projects,
            icon = Icons.Outlined.FolderOpen,
            route = MoreRoutes.PROJECTS,
            section = MoreSection.ACCOUNT,
        ),
        // AND-360: the delegate console (focused manage-as-creator demonstration).
        MoreEntry(
            id = "delegate_console",
            labelRes = R.string.more_entry_delegate_console,
            icon = Icons.Outlined.SupervisorAccount,
            route = MoreRoutes.DELEGATE_CONSOLE,
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
        // AND-384: standalone DMCA copyright-takedown form entry (Privacy & Safety / Support).
        MoreEntry(
            id = "dmca",
            labelRes = R.string.more_entry_dmca,
            icon = Icons.Outlined.Gavel,
            route = MoreRoutes.DMCA,
            section = MoreSection.SUPPORT,
        ),
        // AND-385: Privacy & Data Export (request a machine-readable export -> status -> download).
        MoreEntry(
            id = "privacy_export",
            labelRes = R.string.more_entry_privacy_export,
            icon = Icons.Outlined.Security,
            route = MoreRoutes.PRIVACY_EXPORT,
            section = MoreSection.SECURITY,
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
