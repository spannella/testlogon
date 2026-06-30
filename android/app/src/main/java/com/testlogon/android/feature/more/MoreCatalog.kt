package com.testlogon.android.feature.more

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.AccountBalanceWallet
import androidx.compose.material.icons.outlined.AccountBalance
import androidx.compose.material.icons.outlined.Assessment
import androidx.compose.material.icons.outlined.Bookmark
import androidx.compose.material.icons.outlined.Devices
import androidx.compose.material.icons.outlined.EmojiEvents
import androidx.compose.material.icons.outlined.EmojiEmotions
import androidx.compose.material.icons.outlined.FolderOpen
import androidx.compose.material.icons.outlined.SmartToy
import androidx.compose.material.icons.outlined.Copyright
import androidx.compose.material.icons.outlined.Lightbulb
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
import androidx.compose.material.icons.outlined.Email
import androidx.compose.material.icons.outlined.Sms
import androidx.compose.material.icons.outlined.Gavel
import androidx.compose.material.icons.outlined.Groups
import androidx.compose.material.icons.outlined.Handshake
import androidx.compose.material.icons.outlined.HelpOutline
import androidx.compose.material.icons.outlined.SupportAgent
import androidx.compose.material.icons.outlined.History
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.outlined.Insights
import androidx.compose.material.icons.outlined.Tune
import androidx.compose.material.icons.outlined.TrendingUp
import androidx.compose.material.icons.outlined.Loyalty
import androidx.compose.material.icons.outlined.GroupAdd
import androidx.compose.material.icons.outlined.Hub
import androidx.compose.material.icons.outlined.LiveTv
import androidx.compose.material.icons.outlined.LocalOffer
import androidx.compose.material.icons.outlined.NotificationsActive
import androidx.compose.material.icons.outlined.Notifications
import androidx.compose.material.icons.outlined.Paid
import androidx.compose.material.icons.outlined.Movie
import androidx.compose.material.icons.outlined.Theaters
import androidx.compose.material.icons.outlined.Person
import androidx.compose.material.icons.outlined.PhotoLibrary
import androidx.compose.material.icons.outlined.Public
import androidx.compose.material.icons.outlined.Receipt
import androidx.compose.material.icons.outlined.Security
import androidx.compose.material.icons.outlined.Slideshow
import androidx.compose.material.icons.outlined.Storefront
import androidx.compose.material.icons.outlined.SupervisorAccount
import androidx.compose.material.icons.outlined.FactCheck
import androidx.compose.material.icons.outlined.VideoLibrary
import androidx.compose.material.icons.outlined.Verified
import androidx.compose.material.icons.outlined.VpnKey
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material.icons.outlined.ShoppingCart
import androidx.compose.material.icons.outlined.ReceiptLong
import androidx.compose.material.icons.outlined.Webhook
import com.testlogon.android.R
import com.testlogon.android.navigation.MoreRoutes
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-067 — the single, ordered source of truth for the "More" directory entries.
 *
 * Routes point at destinations registered in the authenticated graph; entries for destinations not
 * yet built are flagged [MoreEntry.comingSoon] so they render Disabled rather than linking nowhere.
 * Every entry declares a [MoreEntry.hub] — the top-level drill-down grouping for the More tab.
 */
@Singleton
class MoreCatalog @Inject constructor() {
    val entries: List<MoreEntry> = listOf(
        MoreEntry(
            id = "profile",
            labelRes = R.string.more_entry_profile,
            icon = Icons.Outlined.Person,
            route = MoreRoutes.PROFILE,
            hub = MoreHub.ACCOUNT,
            section = MoreSection.ACCOUNT,
        ),
        MoreEntry(
            id = "messages",
            labelRes = R.string.more_entry_messages,
            icon = Icons.Outlined.ChatBubbleOutline,
            route = MoreRoutes.MESSAGES,
            hub = MoreHub.INBOX,
            section = MoreSection.ACCOUNT,
        ),
        MoreEntry(
            id = "mass_messages",
            labelRes = R.string.more_entry_mass_messages,
            icon = Icons.Outlined.Campaign,
            route = MoreRoutes.MASS_MESSAGES,
            hub = MoreHub.INBOX,
            section = MoreSection.ACCOUNT,
        ),
        MoreEntry(
            id = "call_history",
            labelRes = R.string.more_entry_call_history,
            icon = Icons.Outlined.History,
            route = MoreRoutes.CALL_HISTORY,
            hub = MoreHub.INBOX,
            section = MoreSection.ACCOUNT,
        ),
        MoreEntry(
            id = "broadcasts",
            labelRes = R.string.more_entry_broadcasts,
            icon = Icons.Outlined.LiveTv,
            route = MoreRoutes.BROADCASTS,
            hub = MoreHub.STUDIO,
            section = MoreSection.APP,
        ),
        MoreEntry(
            id = "helpdesk_queue",
            labelRes = R.string.more_entry_helpdesk_queue,
            icon = Icons.Outlined.SupportAgent,
            route = MoreRoutes.HELPDESK_QUEUE,
            hub = MoreHub.SUPPORT,
            section = MoreSection.SUPPORT,
            operatorOnly = true,
        ),
        MoreEntry(
            id = "helpdesk_dashboard",
            labelRes = R.string.more_entry_helpdesk_dashboard,
            icon = Icons.Outlined.Insights,
            route = MoreRoutes.HELPDESK_DASHBOARD,
            hub = MoreHub.SUPPORT,
            section = MoreSection.SUPPORT,
            // B-SUP (batch 7): this is the AGENT/admin dashboard - it must not be advertised to normal users
            // (it self-gates server-side via 403, but it was previously visible in the member More hub).
            operatorOnly = true,
        ),
        MoreEntry(
            id = "activity",
            labelRes = R.string.more_entry_activity,
            icon = Icons.Outlined.History,
            route = MoreRoutes.ACTIVITY,
            hub = MoreHub.INBOX,
            section = MoreSection.ACCOUNT,
        ),
        MoreEntry(
            id = "saved",
            labelRes = R.string.more_entry_saved,
            icon = Icons.Outlined.Bookmark,
            route = MoreRoutes.SAVED,
            hub = MoreHub.SHOP,
            section = MoreSection.ACCOUNT,
        ),
        MoreEntry(
            id = "achievements",
            labelRes = R.string.more_entry_achievements,
            icon = Icons.Outlined.EmojiEvents,
            route = MoreRoutes.ACHIEVEMENTS,
            hub = MoreHub.GROWTH,
            section = MoreSection.APP,
        ),
        MoreEntry(
            id = "videos",
            labelRes = R.string.more_entry_videos,
            icon = Icons.Outlined.VideoLibrary,
            route = MoreRoutes.VIDEOS,
            hub = MoreHub.STUDIO,
            section = MoreSection.APP,
        ),
        // Web-parity: questionnaire BUILDER (creator authoring). Studio tool.
        MoreEntry(
            id = "questionnaire_builder",
            labelRes = R.string.more_entry_questionnaire_builder,
            icon = Icons.Outlined.FactCheck,
            route = MoreRoutes.QUESTIONNAIRE_BUILDER,
            hub = MoreHub.STUDIO,
            section = MoreSection.APP,
        ),
        MoreEntry(
            id = "vod_catalog",
            labelRes = R.string.more_entry_vod_catalog,
            icon = Icons.Outlined.Movie,
            route = MoreRoutes.VOD_CATALOG,
            hub = MoreHub.STUDIO,
            section = MoreSection.APP,
        ),
        // "My Rentals": the viewer's time-limited rentals + view-once purchases (web vod/rentals).
        MoreEntry(
            id = "vod_rentals",
            labelRes = R.string.more_entry_vod_rentals,
            icon = Icons.Outlined.Theaters,
            route = MoreRoutes.VOD_RENTALS,
            hub = MoreHub.STUDIO,
            section = MoreSection.APP,
        ),
        MoreEntry(
            id = "clips",
            labelRes = R.string.more_entry_clips,
            icon = Icons.Outlined.Slideshow,
            route = MoreRoutes.CLIPS,
            hub = MoreHub.STUDIO,
            section = MoreSection.APP,
        ),
        MoreEntry(
            id = "calendar",
            labelRes = R.string.more_entry_calendar,
            icon = Icons.Outlined.CalendarMonth,
            route = MoreRoutes.CALENDAR,
            hub = MoreHub.STUDIO,
            section = MoreSection.APP,
        ),
        MoreEntry(
            id = "content_calendar",
            labelRes = R.string.more_entry_content_calendar,
            icon = Icons.Outlined.EventNote,
            route = MoreRoutes.CONTENT_CALENDAR,
            hub = MoreHub.STUDIO,
            section = MoreSection.APP,
        ),
        MoreEntry(
            id = "scheduler",
            labelRes = R.string.more_entry_scheduler,
            icon = Icons.Outlined.Schedule,
            route = MoreRoutes.SCHEDULER,
            hub = MoreHub.STUDIO,
            section = MoreSection.APP,
        ),
        MoreEntry(
            id = "google_calendar",
            labelRes = R.string.more_entry_google_calendar,
            icon = Icons.Outlined.EditCalendar,
            route = MoreRoutes.GOOGLE_CALENDAR,
            hub = MoreHub.STUDIO,
            section = MoreSection.APP,
        ),
        MoreEntry(
            id = "gallery",
            labelRes = R.string.more_entry_gallery,
            icon = Icons.Outlined.PhotoLibrary,
            route = MoreRoutes.GALLERY,
            hub = MoreHub.STUDIO,
            section = MoreSection.APP,
        ),
        MoreEntry(
            id = "alerts",
            labelRes = R.string.more_entry_alerts,
            icon = Icons.Outlined.NotificationsActive,
            route = MoreRoutes.ALERTS,
            hub = MoreHub.INBOX,
            section = MoreSection.APP,
        ),
        MoreEntry(
            id = "appeals",
            labelRes = R.string.more_entry_appeals,
            icon = Icons.Outlined.Gavel,
            route = MoreRoutes.APPEALS,
            hub = MoreHub.SUPPORT,
            section = MoreSection.SUPPORT,
        ),
        MoreEntry(
            id = "ideas",
            labelRes = R.string.more_entry_ideas,
            icon = Icons.Outlined.Lightbulb,
            route = MoreRoutes.IDEAS,
            hub = MoreHub.SUPPORT,
            section = MoreSection.SUPPORT,
        ),
        MoreEntry(
            id = "licenses",
            labelRes = R.string.more_entry_licenses,
            icon = Icons.Outlined.Copyright,
            route = MoreRoutes.LICENSES,
            hub = MoreHub.GROWTH,
            section = MoreSection.ACCOUNT,
        ),
        MoreEntry(
            id = "watch_parties",
            labelRes = R.string.more_entry_watch_parties,
            icon = Icons.Outlined.LiveTv,
            route = MoreRoutes.WATCH_PARTIES,
            hub = MoreHub.STUDIO,
            section = MoreSection.APP,
        ),
        MoreEntry(
            id = "bots",
            labelRes = R.string.more_entry_bots,
            icon = Icons.Outlined.SmartToy,
            route = MoreRoutes.BOTS,
            hub = MoreHub.STUDIO,
            section = MoreSection.APP,
        ),
        MoreEntry(
            id = "files",
            labelRes = R.string.more_entry_files,
            icon = Icons.Outlined.FolderOpen,
            route = MoreRoutes.FILES,
            hub = MoreHub.STUDIO,
            section = MoreSection.APP,
        ),
        MoreEntry(
            id = "catalog",
            labelRes = R.string.more_entry_catalog,
            icon = Icons.Outlined.Storefront,
            route = MoreRoutes.CATALOG,
            hub = MoreHub.SHOP,
            section = MoreSection.APP,
        ),
        MoreEntry(
            id = "cart",
            labelRes = R.string.more_entry_cart,
            icon = Icons.Outlined.ShoppingCart,
            route = MoreRoutes.CART,
            hub = MoreHub.SHOP,
            section = MoreSection.APP,
        ),
        MoreEntry(
            id = "purchase_history",
            labelRes = R.string.more_entry_purchase_history,
            icon = Icons.Outlined.ReceiptLong,
            route = MoreRoutes.PURCHASE_HISTORY,
            hub = MoreHub.SHOP,
            section = MoreSection.APP,
        ),
        MoreEntry(
            id = "payment_methods",
            labelRes = R.string.more_entry_payment_methods,
            icon = Icons.Outlined.CreditCard,
            route = MoreRoutes.PAYMENT_METHODS,
            hub = MoreHub.WALLET,
            section = MoreSection.ACCOUNT,
        ),
        // PW18: wallet transactions (ledger) history.
        MoreEntry(
            id = "wallet_transactions",
            labelRes = R.string.more_entry_wallet_transactions,
            icon = Icons.Outlined.History,
            route = MoreRoutes.WALLET_TRANSACTIONS,
            hub = MoreHub.WALLET,
            section = MoreSection.ACCOUNT,
        ),
        MoreEntry(
            id = "earnings",
            labelRes = R.string.more_entry_earnings,
            icon = Icons.Outlined.Paid,
            route = MoreRoutes.EARNINGS,
            hub = MoreHub.WALLET,
            section = MoreSection.ACCOUNT,
        ),
        MoreEntry(
            id = "per_content_revenue",
            labelRes = R.string.more_entry_per_content_revenue,
            icon = Icons.Outlined.ReceiptLong,
            route = MoreRoutes.PER_CONTENT_REVENUE,
            hub = MoreHub.WALLET,
            section = MoreSection.ACCOUNT,
        ),
        MoreEntry(
            id = "payout_setup",
            labelRes = R.string.more_entry_payout_setup,
            icon = Icons.Outlined.AccountBalance,
            route = MoreRoutes.PAYOUT_SETUP,
            hub = MoreHub.WALLET,
            section = MoreSection.ACCOUNT,
        ),
        MoreEntry(
            id = "payouts",
            labelRes = R.string.more_entry_payouts,
            icon = Icons.Outlined.AccountBalanceWallet,
            route = MoreRoutes.PAYOUTS,
            hub = MoreHub.WALLET,
            section = MoreSection.ACCOUNT,
        ),
        MoreEntry(
            id = "bulk_payouts",
            labelRes = R.string.more_entry_bulk_payouts,
            icon = Icons.Outlined.AccountBalance,
            route = MoreRoutes.BULK_PAYOUTS,
            hub = MoreHub.WALLET,
            section = MoreSection.ACCOUNT,
            operatorOnly = true,
        ),
        MoreEntry(
            id = "engagement",
            labelRes = R.string.more_entry_engagement,
            icon = Icons.Outlined.Insights,
            route = MoreRoutes.ENGAGEMENT,
            hub = MoreHub.GROWTH,
            section = MoreSection.ACCOUNT,
        ),
        MoreEntry(
            id = "analytics_dashboard",
            labelRes = R.string.more_entry_analytics_dashboard,
            icon = Icons.Outlined.Assessment,
            route = MoreRoutes.ANALYTICS_DASHBOARD,
            hub = MoreHub.GROWTH,
            section = MoreSection.ACCOUNT,
        ),
        MoreEntry(
            id = "referrals",
            labelRes = R.string.more_entry_referrals,
            icon = Icons.Outlined.GroupAdd,
            route = MoreRoutes.REFERRALS,
            hub = MoreHub.GROWTH,
            section = MoreSection.ACCOUNT,
        ),
        MoreEntry(
            id = "affiliates",
            labelRes = R.string.more_entry_affiliates,
            icon = Icons.Outlined.Hub,
            route = MoreRoutes.AFFILIATES,
            hub = MoreHub.GROWTH,
            section = MoreSection.ACCOUNT,
        ),
        MoreEntry(
            id = "promo_codes",
            labelRes = R.string.more_entry_promo_codes,
            icon = Icons.Outlined.LocalOffer,
            route = MoreRoutes.PROMO_CODES,
            hub = MoreHub.GROWTH,
            section = MoreSection.ACCOUNT,
        ),
        MoreEntry(
            id = "discounts",
            labelRes = R.string.more_entry_discounts,
            icon = Icons.Outlined.Loyalty,
            route = MoreRoutes.DISCOUNTS,
            hub = MoreHub.GROWTH,
            section = MoreSection.ACCOUNT,
        ),
        MoreEntry(
            id = "invoices",
            labelRes = R.string.more_entry_invoices,
            icon = Icons.Outlined.Receipt,
            route = MoreRoutes.INVOICES,
            hub = MoreHub.WALLET,
            section = MoreSection.ACCOUNT,
        ),
        MoreEntry(
            id = "refunds",
            labelRes = R.string.more_entry_refunds,
            icon = Icons.Outlined.Paid,
            route = MoreRoutes.REFUNDS,
            hub = MoreHub.WALLET,
            section = MoreSection.ACCOUNT,
        ),
        MoreEntry(
            id = "disputes",
            labelRes = R.string.more_entry_disputes,
            icon = Icons.Outlined.Gavel,
            route = MoreRoutes.DISPUTES,
            hub = MoreHub.WALLET,
            section = MoreSection.ACCOUNT,
        ),
        MoreEntry(
            id = "tax_documents",
            labelRes = R.string.more_entry_tax_documents,
            icon = Icons.Outlined.Description,
            route = MoreRoutes.TAX_DOCUMENTS,
            hub = MoreHub.WALLET,
            section = MoreSection.ACCOUNT,
        ),
        MoreEntry(
            id = "tax_forms_1099",
            labelRes = R.string.more_entry_tax_forms_1099,
            icon = Icons.Outlined.ReceiptLong,
            route = MoreRoutes.TAX_FORMS_1099,
            hub = MoreHub.WALLET,
            section = MoreSection.ACCOUNT,
        ),
        MoreEntry(
            id = "billing_config",
            labelRes = R.string.more_entry_billing_config,
            icon = Icons.Outlined.Paid,
            route = MoreRoutes.BILLING_CONFIG,
            hub = MoreHub.WALLET,
            section = MoreSection.ACCOUNT,
            operatorOnly = true,
        ),
        MoreEntry(
            id = "subscription_tiers",
            labelRes = R.string.more_entry_subscription_tiers,
            icon = Icons.Outlined.Loyalty,
            route = MoreRoutes.SUBSCRIPTION_TIERS,
            hub = MoreHub.GROWTH,
            section = MoreSection.ACCOUNT,
        ),
        MoreEntry(
            id = "manage_subscription",
            labelRes = R.string.more_entry_manage_subscription,
            icon = Icons.Outlined.CardMembership,
            route = MoreRoutes.MANAGE_SUBSCRIPTION,
            hub = MoreHub.SHOP,
            section = MoreSection.ACCOUNT,
        ),
        MoreEntry(
            id = "fan_club",
            labelRes = R.string.more_entry_fan_club,
            icon = Icons.Outlined.Groups,
            route = MoreRoutes.FAN_CLUB,
            hub = MoreHub.GROWTH,
            section = MoreSection.ACCOUNT,
        ),
        MoreEntry(
            id = "organizations",
            labelRes = R.string.more_entry_organizations,
            icon = Icons.Outlined.Groups,
            route = MoreRoutes.ORGS_MEMBERS,
            hub = MoreHub.COMMUNITY,
            section = MoreSection.ACCOUNT,
        ),
        MoreEntry(
            id = "groups",
            labelRes = R.string.more_entry_groups,
            icon = Icons.Outlined.Diversity3,
            route = MoreRoutes.GROUPS,
            hub = MoreHub.COMMUNITY,
            section = MoreSection.ACCOUNT,
        ),
        MoreEntry(
            id = "syndicates",
            labelRes = R.string.more_entry_syndicates,
            icon = Icons.Outlined.AccountBalance,
            route = MoreRoutes.SYNDICATES,
            hub = MoreHub.COMMUNITY,
            section = MoreSection.ACCOUNT,
        ),
        // Web-parity: the caller's active syndicate bundle subscriptions (My Bundles).
        MoreEntry(
            id = "my_bundles",
            labelRes = R.string.more_entry_my_bundles,
            icon = Icons.Outlined.CardMembership,
            route = MoreRoutes.MY_BUNDLES,
            hub = MoreHub.COMMUNITY,
            section = MoreSection.ACCOUNT,
        ),
        // Web-parity: syndicate-advertising campaign detail (KPI / analytics / budget controls). Opens a
        // known sample syndicate+campaign id (no per-syndicate campaigns list this wave).
        MoreEntry(
            id = "syndicate_campaign",
            labelRes = R.string.more_entry_syndicate_campaign,
            icon = Icons.Outlined.Campaign,
            route = MoreRoutes.SYNDICATE_CAMPAIGN,
            hub = MoreHub.COMMUNITY,
            section = MoreSection.ACCOUNT,
        ),
        MoreEntry(
            id = "collaborations",
            labelRes = R.string.more_entry_collaborations,
            icon = Icons.Outlined.Diversity3,
            route = MoreRoutes.COLLABORATIONS,
            hub = MoreHub.COMMUNITY,
            section = MoreSection.ACCOUNT,
        ),
        // AND-365: READ-ONLY sponsorship inbox (inbound brand deals + client-side status filter).
        MoreEntry(
            id = "sponsorships",
            labelRes = R.string.more_entry_sponsorships,
            icon = Icons.Outlined.Handshake,
            route = MoreRoutes.SPONSORSHIPS,
            hub = MoreHub.GROWTH,
            section = MoreSection.ACCOUNT,
        ),
        // AND-367: ads-account billing (balance/lifetime-spend + ledger + invoice) + DEPOSIT add-funds.
        MoreEntry(
            id = "ads_billing",
            labelRes = R.string.more_entry_ads_billing,
            icon = Icons.Outlined.AccountBalanceWallet,
            route = MoreRoutes.ADS_BILLING,
            hub = MoreHub.GROWTH,
            section = MoreSection.ACCOUNT,
        ),
        // AND-368: READ-ONLY ad-analytics dashboard (KPI summary + time-series charts + breakdown).
        MoreEntry(
            id = "ad_analytics",
            labelRes = R.string.more_entry_ad_analytics,
            icon = Icons.Outlined.Insights,
            route = MoreRoutes.AD_ANALYTICS,
            hub = MoreHub.GROWTH,
            section = MoreSection.ACCOUNT,
        ),
        // AND-369: READ-ONLY ads-campaigns list (per-account campaigns: name/status/budget/spend).
        MoreEntry(
            id = "ads_campaigns",
            labelRes = R.string.more_entry_ads_campaigns,
            icon = Icons.Outlined.Campaign,
            route = MoreRoutes.ADS_CAMPAIGNS,
            hub = MoreHub.GROWTH,
            section = MoreSection.ACCOUNT,
        ),
        // Web-parity: ad TARGETING editor (audience / dayparting-hours / geo / device, live estimate).
        MoreEntry(
            id = "ads_targeting",
            labelRes = R.string.more_entry_ads_targeting,
            icon = Icons.Outlined.Tune,
            route = MoreRoutes.ADS_TARGETING,
            hub = MoreHub.GROWTH,
            section = MoreSection.ACCOUNT,
        ),
        // Web-parity: ad SCHEDULING (dayparting grid + flights + pacing/eligibility).
        MoreEntry(
            id = "ads_scheduling",
            labelRes = R.string.more_entry_ads_scheduling,
            icon = Icons.Outlined.Schedule,
            route = MoreRoutes.ADS_SCHEDULING,
            hub = MoreHub.GROWTH,
            section = MoreSection.ACCOUNT,
        ),
        // Web-parity: ad OPTIMIZATION (recommendations apply/dismiss + auto-optimize + bid/budget).
        MoreEntry(
            id = "ads_optimization",
            labelRes = R.string.more_entry_ads_optimization,
            icon = Icons.Outlined.TrendingUp,
            route = MoreRoutes.ADS_OPTIMIZATION,
            hub = MoreHub.GROWTH,
            section = MoreSection.ACCOUNT,
        ),
        // Web-parity: CONTENT AD-CONTROLS (per-content ad overrides + revenue share + ad-revenue breakdown).
        MoreEntry(
            id = "content_ad_controls",
            labelRes = R.string.more_entry_content_ad_controls,
            icon = Icons.Outlined.Settings,
            route = MoreRoutes.CONTENT_AD_CONTROLS,
            hub = MoreHub.GROWTH,
            section = MoreSection.ACCOUNT,
        ),
        // Web-parity: boost MANAGEMENT (your boosts list -> per-boost detail with cancel/refund).
        MoreEntry(
            id = "boosts",
            labelRes = R.string.more_entry_boosts,
            icon = Icons.Outlined.Campaign,
            route = MoreRoutes.BOOSTS,
            hub = MoreHub.GROWTH,
            section = MoreSection.ACCOUNT,
        ),
        // AND-400: READ-ONLY public SEO metadata inspector (preview of crawler/social-card metadata).
        MoreEntry(
            id = "seo",
            labelRes = R.string.more_entry_seo,
            icon = Icons.Outlined.Public,
            route = MoreRoutes.SEO,
            hub = MoreHub.STUDIO,
            section = MoreSection.ACCOUNT,
        ),
        // B-SUP (batch 7): the role-branched Support hub. Resolves /ui/me.is_admin at runtime: a normal user
        // sees a clean help/ticket experience; an admin sees the helpdesk/moderation queue.
        MoreEntry(
            id = "support",
            labelRes = R.string.more_entry_support,
            icon = Icons.Outlined.SupportAgent,
            route = MoreRoutes.SUPPORT,
            hub = MoreHub.SUPPORT,
            section = MoreSection.SUPPORT,
        ),
        // AND-372: READ-ONLY ticket spaces + threads (support / helpdesk). Spaces -> tickets -> thread.
        MoreEntry(
            id = "tickets",
            labelRes = R.string.more_entry_tickets,
            icon = Icons.Outlined.SupportAgent,
            route = MoreRoutes.TICKETS,
            hub = MoreHub.SUPPORT,
            section = MoreSection.SUPPORT,
        ),
        // AND-398: WEBHOOKS config (light) - list outbound webhook endpoints -> detail -> a LIGHT create.
        MoreEntry(
            id = "webhooks",
            labelRes = R.string.more_entry_webhooks,
            icon = Icons.Outlined.Webhook,
            route = MoreRoutes.WEBHOOKS,
            hub = MoreHub.ACCOUNT,
            section = MoreSection.ACCOUNT,
        ),
        // AND-403: READ-ONLY admin alerts/dashboards (client-aggregated job + webhook health). Self-gates via
        // the backend 403 -> the screen's Forbidden state; a non-admin sees no admin data (no client role flag
        // is available on the cookie-session client, so the entry is visible and the server 403 is authority).
        MoreEntry(
            id = "admin_dashboard",
            labelRes = R.string.more_entry_admin_dashboard,
            icon = Icons.Outlined.Security,
            route = MoreRoutes.ADMIN_DASHBOARD,
            hub = MoreHub.ACCOUNT,
            section = MoreSection.SECURITY,
            operatorOnly = true,
        ),
        // AND-404: READ-ONLY admin EMAIL delivery dashboard (per-channel stats + recent activity). Self-gates
        // via the backend 403 -> the screen's Forbidden state; a non-admin sees no admin data.
        MoreEntry(
            id = "admin_email_dashboard",
            labelRes = R.string.more_entry_admin_email_dashboard,
            icon = Icons.Outlined.Email,
            route = MoreRoutes.ADMIN_EMAIL_DASHBOARD,
            hub = MoreHub.ACCOUNT,
            section = MoreSection.SECURITY,
            operatorOnly = true,
        ),
        // AND-404: READ-ONLY admin SMS delivery dashboard (per-channel stats + recent activity). Self-gates via
        // the backend 403 -> the screen's Forbidden state; a non-admin sees no admin data.
        MoreEntry(
            id = "admin_sms_dashboard",
            labelRes = R.string.more_entry_admin_sms_dashboard,
            icon = Icons.Outlined.Sms,
            route = MoreRoutes.ADMIN_SMS_DASHBOARD,
            hub = MoreHub.ACCOUNT,
            section = MoreSection.SECURITY,
            operatorOnly = true,
        ),
        // AND-374: projects (paged list -> detail + account-scoped Google Drive provider connect flow).
        MoreEntry(
            id = "projects",
            labelRes = R.string.more_entry_projects,
            icon = Icons.Outlined.FolderOpen,
            route = MoreRoutes.PROJECTS,
            hub = MoreHub.STUDIO,
            section = MoreSection.ACCOUNT,
        ),
        // AND-360: the delegate console (focused manage-as-creator demonstration).
        MoreEntry(
            id = "delegate_console",
            labelRes = R.string.more_entry_delegate_console,
            icon = Icons.Outlined.SupervisorAccount,
            route = MoreRoutes.DELEGATE_CONSOLE,
            hub = MoreHub.STUDIO,
            section = MoreSection.ACCOUNT,
        ),
        // B-KYC (batch 7): identity verification status + steps (Account / Security). Discoverable entry.
        MoreEntry(
            id = "kyc",
            labelRes = R.string.more_entry_kyc,
            icon = Icons.Outlined.Verified,
            route = MoreRoutes.KYC,
            hub = MoreHub.ACCOUNT,
            section = MoreSection.SECURITY,
        ),
        // B-APIKEY (batch 7): developer API keys (Account / Security). Discoverable entry.
        MoreEntry(
            id = "api_keys",
            labelRes = R.string.more_entry_api_keys,
            icon = Icons.Outlined.VpnKey,
            route = MoreRoutes.API_KEYS,
            hub = MoreHub.ACCOUNT,
            section = MoreSection.SECURITY,
        ),
        // Web-parity: delegation-API keys (DELEGATED-access keys for tools acting on a creator's behalf;
        // distinct from the personal developer API keys above).
        MoreEntry(
            id = "delegation_keys",
            labelRes = R.string.more_entry_delegation_keys,
            icon = Icons.Outlined.SupervisorAccount,
            route = MoreRoutes.DELEGATION_KEYS,
            hub = MoreHub.ACCOUNT,
            section = MoreSection.SECURITY,
        ),
        // Settings: custom emojis (Account / App). Discoverable entry.
        MoreEntry(
            id = "custom_emojis",
            labelRes = R.string.more_entry_custom_emojis,
            icon = Icons.Outlined.EmojiEmotions,
            route = MoreRoutes.CUSTOM_EMOJIS,
            hub = MoreHub.ACCOUNT,
            section = MoreSection.APP,
        ),
        // Settings: geo-blocking rules (Account / App). Discoverable entry.
        MoreEntry(
            id = "geo_rules",
            labelRes = R.string.more_entry_geo_rules,
            icon = Icons.Outlined.Public,
            route = MoreRoutes.GEO_RULES,
            hub = MoreHub.ACCOUNT,
            section = MoreSection.APP,
        ),
        // Settings: paid-call rate (Wallet / Account). Discoverable entry.
        MoreEntry(
            id = "call_rate",
            labelRes = R.string.more_entry_call_rate,
            icon = Icons.Outlined.Paid,
            route = MoreRoutes.CALL_RATE,
            hub = MoreHub.WALLET,
            section = MoreSection.ACCOUNT,
        ),
        MoreEntry(
            id = "sessions",
            labelRes = R.string.more_entry_sessions,
            icon = Icons.Outlined.Devices,
            route = MoreRoutes.SESSIONS,
            hub = MoreHub.ACCOUNT,
            section = MoreSection.SECURITY,
        ),
        MoreEntry(
            id = "mfa_devices",
            labelRes = R.string.more_entry_mfa_devices,
            icon = Icons.Outlined.Security,
            route = MoreRoutes.MFA_DEVICES,
            hub = MoreHub.ACCOUNT,
            section = MoreSection.SECURITY,
        ),
        MoreEntry(
            id = "notification_center",
            labelRes = R.string.more_entry_notification_center,
            icon = Icons.Outlined.NotificationsActive,
            route = MoreRoutes.NOTIFICATION_CENTER,
            hub = MoreHub.INBOX,
            section = MoreSection.APP,
        ),
        MoreEntry(
            id = "notifications",
            labelRes = R.string.more_entry_notifications,
            icon = Icons.Outlined.Notifications,
            route = MoreRoutes.NOTIFICATIONS,
            hub = MoreHub.INBOX,
            section = MoreSection.APP,
        ),
        MoreEntry(
            id = "settings",
            labelRes = R.string.more_entry_settings,
            icon = Icons.Outlined.Settings,
            route = MoreRoutes.SETTINGS,
            hub = MoreHub.ACCOUNT,
            section = MoreSection.APP,
        ),
        // AND-384: standalone DMCA copyright-takedown form entry (Privacy & Safety / Support).
        MoreEntry(
            id = "dmca",
            labelRes = R.string.more_entry_dmca,
            icon = Icons.Outlined.Gavel,
            route = MoreRoutes.DMCA,
            hub = MoreHub.SUPPORT,
            section = MoreSection.SUPPORT,
        ),
        // AND-385: Privacy & Data Export (request a machine-readable export -> status -> download).
        MoreEntry(
            id = "privacy_export",
            labelRes = R.string.more_entry_privacy_export,
            icon = Icons.Outlined.Security,
            route = MoreRoutes.PRIVACY_EXPORT,
            hub = MoreHub.ACCOUNT,
            section = MoreSection.SECURITY,
        ),
        MoreEntry(
            id = "help",
            labelRes = R.string.more_entry_help,
            icon = Icons.Outlined.HelpOutline,
            route = MoreRoutes.HELP,
            hub = MoreHub.SUPPORT,
            section = MoreSection.SUPPORT,
            comingSoon = true,
        ),
        MoreEntry(
            id = "about",
            labelRes = R.string.more_entry_about,
            icon = Icons.Outlined.Info,
            route = MoreRoutes.ABOUT,
            hub = MoreHub.SUPPORT,
            section = MoreSection.SUPPORT,
            comingSoon = true,
        ),
    )
}
