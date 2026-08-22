package com.testlogon.android.feature.more

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.AccountBalanceWallet
import androidx.compose.material.icons.outlined.AccountBalance
import androidx.compose.material.icons.outlined.PieChart
import androidx.compose.material.icons.outlined.ShowChart
import androidx.compose.material.icons.outlined.Science
import androidx.compose.material.icons.outlined.Assessment
import androidx.compose.material.icons.outlined.Bookmark
import androidx.compose.material.icons.outlined.Devices
import androidx.compose.material.icons.outlined.EmojiEvents
import androidx.compose.material.icons.outlined.EmojiEmotions
import androidx.compose.material.icons.outlined.FolderOpen
import androidx.compose.material.icons.outlined.CandlestickChart
import androidx.compose.material.icons.outlined.SmartToy
import androidx.compose.material.icons.outlined.Copyright
import androidx.compose.material.icons.outlined.ReceiptLong
import androidx.compose.material.icons.outlined.ManageSearch
import androidx.compose.material.icons.outlined.Inventory2
import androidx.compose.material.icons.outlined.Sell
import androidx.compose.material.icons.outlined.Balance
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material.icons.outlined.CreditCardOff
import androidx.compose.material.icons.outlined.Lightbulb
import androidx.compose.material.icons.outlined.CalendarMonth
import androidx.compose.material.icons.outlined.EditCalendar
import androidx.compose.material.icons.outlined.EventNote
import androidx.compose.material.icons.outlined.Explore
import androidx.compose.material.icons.outlined.Schedule
import androidx.compose.material.icons.outlined.Campaign
import androidx.compose.material.icons.outlined.AddBusiness
import androidx.compose.material.icons.outlined.Image
import androidx.compose.material.icons.outlined.CardMembership
import androidx.compose.material.icons.outlined.ChatBubbleOutline
import androidx.compose.material.icons.outlined.Contacts
import androidx.compose.material.icons.outlined.CreditCard
import androidx.compose.material.icons.outlined.Description
import androidx.compose.material.icons.outlined.Memory
import androidx.compose.material.icons.outlined.Cloud
import androidx.compose.material.icons.outlined.Dns
import androidx.compose.material.icons.outlined.Monitor
import androidx.compose.material.icons.outlined.MergeType
import androidx.compose.material.icons.outlined.Diversity3
import androidx.compose.material.icons.outlined.Email
import androidx.compose.material.icons.outlined.Sms
import androidx.compose.material.icons.outlined.Gavel
import androidx.compose.material.icons.outlined.Groups
import androidx.compose.material.icons.outlined.Handshake
import androidx.compose.material.icons.outlined.HelpOutline
import androidx.compose.material.icons.outlined.SupportAgent
import androidx.compose.material.icons.outlined.FavoriteBorder
import androidx.compose.material.icons.outlined.History
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.outlined.Insights
import androidx.compose.material.icons.outlined.Tune
import androidx.compose.material.icons.outlined.TrendingUp
import androidx.compose.material.icons.outlined.Loyalty
import androidx.compose.material.icons.outlined.Apartment
import androidx.compose.material.icons.outlined.VpnKey
import androidx.compose.material.icons.outlined.AdminPanelSettings
import androidx.compose.material.icons.outlined.GroupAdd
import androidx.compose.material.icons.outlined.Hub
import androidx.compose.material.icons.outlined.Dashboard
import androidx.compose.material.icons.outlined.DesktopWindows
import androidx.compose.material.icons.outlined.SettingsEthernet
import androidx.compose.material.icons.outlined.Terminal
import androidx.compose.material.icons.outlined.LiveTv
import androidx.compose.material.icons.outlined.LocalOffer
import androidx.compose.material.icons.outlined.NotificationsActive
import androidx.compose.material.icons.outlined.Notifications
import androidx.compose.material.icons.outlined.Paid
import androidx.compose.material.icons.outlined.Palette
import androidx.compose.material.icons.outlined.Movie
import androidx.compose.material.icons.outlined.Theaters
import androidx.compose.material.icons.outlined.Person
import androidx.compose.material.icons.outlined.PhotoLibrary
import androidx.compose.material.icons.outlined.Block
import androidx.compose.material.icons.outlined.Public
import androidx.compose.material.icons.outlined.Receipt
import androidx.compose.material.icons.outlined.Security
import androidx.compose.material.icons.outlined.Slideshow
import androidx.compose.material.icons.outlined.Storefront
import androidx.compose.material.icons.outlined.SupervisorAccount
import androidx.compose.material.icons.outlined.FactCheck
import androidx.compose.material.icons.outlined.VideoLibrary
import androidx.compose.material.icons.outlined.Verified
import androidx.compose.material.icons.outlined.MonitorHeart
import androidx.compose.material.icons.outlined.LocationOn
import androidx.compose.material.icons.outlined.Policy
import androidx.compose.material.icons.outlined.Translate
import androidx.compose.material.icons.outlined.VerifiedUser
import androidx.compose.material.icons.outlined.Videocam
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
            id = "contacts",
            labelRes = R.string.more_entry_contacts,
            icon = Icons.Outlined.Contacts,
            route = MoreRoutes.CONTACTS_HUB,
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
        // B5 admin queues (Admin hub) - hidden from members; revealed only for a confirmed admin
        // (AdminVisibility from GET /ui/me.is_admin). The backend 403 stays authoritative.
        MoreEntry(
            id = "moderation_board",
            labelRes = R.string.more_entry_moderation_board,
            icon = Icons.Outlined.Gavel,
            route = MoreRoutes.ADMIN_MODERATION,
            hub = MoreHub.ADMIN,
            section = MoreSection.SUPPORT,
            operatorOnly = true,
        ),
        MoreEntry(
            id = "video_review",
            labelRes = R.string.more_entry_video_review,
            icon = Icons.Outlined.FactCheck,
            route = MoreRoutes.ADMIN_VIDEO_REVIEW,
            hub = MoreHub.ADMIN,
            section = MoreSection.SUPPORT,
            operatorOnly = true,
        ),
        MoreEntry(
            id = "dmca_admin",
            labelRes = R.string.more_entry_dmca_admin,
            icon = Icons.Outlined.Copyright,
            route = MoreRoutes.ADMIN_DMCA,
            hub = MoreHub.ADMIN,
            section = MoreSection.SUPPORT,
            operatorOnly = true,
        ),
        MoreEntry(
            id = "refund_admin",
            labelRes = R.string.more_entry_refund_admin,
            icon = Icons.Outlined.ReceiptLong,
            route = MoreRoutes.ADMIN_REFUNDS,
            hub = MoreHub.ADMIN,
            section = MoreSection.SUPPORT,
            operatorOnly = true,
        ),
        MoreEntry(
            id = "dispute_admin",
            labelRes = R.string.more_entry_dispute_admin,
            icon = Icons.Outlined.Gavel,
            route = MoreRoutes.ADMIN_DISPUTES,
            hub = MoreHub.ADMIN,
            section = MoreSection.SUPPORT,
            operatorOnly = true,
        ),
        MoreEntry(
            id = "appeal_admin",
            labelRes = R.string.more_entry_appeal_admin,
            icon = Icons.Outlined.Balance,
            route = MoreRoutes.ADMIN_APPEALS,
            hub = MoreHub.ADMIN,
            section = MoreSection.SUPPORT,
            operatorOnly = true,
        ),
        MoreEntry(
            id = "fraud_admin",
            labelRes = R.string.more_entry_fraud_admin,
            icon = Icons.Outlined.Shield,
            route = MoreRoutes.ADMIN_FRAUD,
            hub = MoreHub.ADMIN,
            section = MoreSection.SUPPORT,
            operatorOnly = true,
        ),
        MoreEntry(
            id = "incident_admin",
            labelRes = R.string.more_entry_incident_admin,
            icon = Icons.Outlined.CreditCardOff,
            route = MoreRoutes.ADMIN_PAYMENT_INCIDENTS,
            hub = MoreHub.ADMIN,
            section = MoreSection.SUPPORT,
            operatorOnly = true,
        ),
        // Web-parity KYC-admin review queues (A1..A8). All admin-gated (backend 403 -> Forbidden).
        MoreEntry(
            id = "kyc_admin_cases",
            labelRes = R.string.more_entry_kyc_admin_cases,
            icon = Icons.Outlined.VerifiedUser,
            route = MoreRoutes.ADMIN_KYC_CASES,
            hub = MoreHub.ADMIN,
            section = MoreSection.SUPPORT,
            operatorOnly = true,
        ),
        MoreEntry(
            id = "kyc_admin_documents",
            labelRes = R.string.more_entry_kyc_admin_documents,
            icon = Icons.Outlined.Description,
            route = MoreRoutes.ADMIN_KYC_DOCUMENTS,
            hub = MoreHub.ADMIN,
            section = MoreSection.SUPPORT,
            operatorOnly = true,
        ),
        MoreEntry(
            id = "kyc_admin_residency",
            labelRes = R.string.more_entry_kyc_admin_residency,
            icon = Icons.Outlined.Apartment,
            route = MoreRoutes.ADMIN_KYC_RESIDENCY,
            hub = MoreHub.ADMIN,
            section = MoreSection.SUPPORT,
            operatorOnly = true,
        ),
        MoreEntry(
            id = "kyc_admin_pof",
            labelRes = R.string.more_entry_kyc_admin_pof,
            icon = Icons.Outlined.Paid,
            route = MoreRoutes.ADMIN_KYC_PROOF_OF_FUNDS,
            hub = MoreHub.ADMIN,
            section = MoreSection.SUPPORT,
            operatorOnly = true,
        ),
        MoreEntry(
            id = "kyc_admin_liveness",
            labelRes = R.string.more_entry_kyc_admin_liveness,
            icon = Icons.Outlined.Videocam,
            route = MoreRoutes.ADMIN_KYC_LIVENESS,
            hub = MoreHub.ADMIN,
            section = MoreSection.SUPPORT,
            operatorOnly = true,
        ),
        MoreEntry(
            id = "kyc_admin_screening",
            labelRes = R.string.more_entry_kyc_admin_screening,
            icon = Icons.Outlined.Gavel,
            route = MoreRoutes.ADMIN_KYC_SCREENING,
            hub = MoreHub.ADMIN,
            section = MoreSection.SUPPORT,
            operatorOnly = true,
        ),
        MoreEntry(
            id = "kyc_admin_id_scanner",
            labelRes = R.string.more_entry_kyc_admin_id_scanner,
            icon = Icons.Outlined.FactCheck,
            route = MoreRoutes.ADMIN_KYC_ID_SCANNER,
            hub = MoreHub.ADMIN,
            section = MoreSection.SUPPORT,
            operatorOnly = true,
        ),
        MoreEntry(
            id = "kyc_admin_business",
            labelRes = R.string.more_entry_kyc_admin_business,
            icon = Icons.Outlined.Verified,
            route = MoreRoutes.ADMIN_KYC_BUSINESS,
            hub = MoreHub.ADMIN,
            section = MoreSection.SUPPORT,
            operatorOnly = true,
        ),
        // Web-parity KYC-admin dashboards + config (B2..B9). All admin-gated; each self-gates via 403.
        MoreEntry(
            id = "kyc_admin_workload",
            labelRes = R.string.more_entry_kyc_admin_workload,
            icon = Icons.Outlined.Groups,
            route = MoreRoutes.ADMIN_KYC_WORKLOAD,
            hub = MoreHub.ADMIN,
            section = MoreSection.SUPPORT,
            operatorOnly = true,
        ),
        MoreEntry(
            id = "kyc_admin_metrics",
            labelRes = R.string.more_entry_kyc_admin_metrics,
            icon = Icons.Outlined.Assessment,
            route = MoreRoutes.ADMIN_KYC_METRICS,
            hub = MoreHub.ADMIN,
            section = MoreSection.SUPPORT,
            operatorOnly = true,
        ),
        MoreEntry(
            id = "kyc_admin_analytics",
            labelRes = R.string.more_entry_kyc_admin_analytics,
            icon = Icons.Outlined.Insights,
            route = MoreRoutes.ADMIN_KYC_ANALYTICS,
            hub = MoreHub.ADMIN,
            section = MoreSection.SUPPORT,
            operatorOnly = true,
        ),
        MoreEntry(
            id = "kyc_admin_monitoring",
            labelRes = R.string.more_entry_kyc_admin_monitoring,
            icon = Icons.Outlined.MonitorHeart,
            route = MoreRoutes.ADMIN_KYC_MONITORING,
            hub = MoreHub.ADMIN,
            section = MoreSection.SUPPORT,
            operatorOnly = true,
        ),
        MoreEntry(
            id = "kyc_admin_address_verif",
            labelRes = R.string.more_entry_kyc_admin_address_verif,
            icon = Icons.Outlined.LocationOn,
            route = MoreRoutes.ADMIN_KYC_ADDRESS_VERIFICATION,
            hub = MoreHub.ADMIN,
            section = MoreSection.SUPPORT,
            operatorOnly = true,
        ),
        MoreEntry(
            id = "kyc_admin_compliance",
            labelRes = R.string.more_entry_kyc_admin_compliance,
            icon = Icons.Outlined.Policy,
            route = MoreRoutes.ADMIN_KYC_COMPLIANCE,
            hub = MoreHub.ADMIN,
            section = MoreSection.SUPPORT,
            operatorOnly = true,
        ),
        MoreEntry(
            id = "kyc_admin_templates",
            labelRes = R.string.more_entry_kyc_admin_templates,
            icon = Icons.Outlined.Description,
            route = MoreRoutes.ADMIN_KYC_TEMPLATES,
            hub = MoreHub.ADMIN,
            section = MoreSection.SUPPORT,
            operatorOnly = true,
        ),
        MoreEntry(
            id = "kyc_admin_translations",
            labelRes = R.string.more_entry_kyc_admin_translations,
            icon = Icons.Outlined.Translate,
            route = MoreRoutes.ADMIN_KYC_TRANSLATIONS,
            hub = MoreHub.ADMIN,
            section = MoreSection.SUPPORT,
            operatorOnly = true,
        ),
        // Web-parity admin ADS surfaces (Admin hub). Creative review + ad-fraud + ad-platform + 1099
        // manager + bulk-payout promote. All require_admin_or_root; each self-gates via the backend 403.
        MoreEntry(
            id = "ad_creative_review",
            labelRes = R.string.more_entry_ad_creative_review,
            icon = Icons.Outlined.Slideshow,
            route = MoreRoutes.ADMIN_AD_CREATIVE_REVIEW,
            hub = MoreHub.ADMIN,
            section = MoreSection.SUPPORT,
            operatorOnly = true,
        ),
        MoreEntry(
            id = "ad_fraud",
            labelRes = R.string.more_entry_ad_fraud,
            icon = Icons.Outlined.Security,
            route = MoreRoutes.ADMIN_AD_FRAUD,
            hub = MoreHub.ADMIN,
            section = MoreSection.SUPPORT,
            operatorOnly = true,
        ),
        MoreEntry(
            id = "ad_platform",
            labelRes = R.string.more_entry_ad_platform,
            icon = Icons.Outlined.Campaign,
            route = MoreRoutes.ADMIN_AD_PLATFORM,
            hub = MoreHub.ADMIN,
            section = MoreSection.SUPPORT,
            operatorOnly = true,
        ),
        MoreEntry(
            id = "admin_tax_forms_1099",
            labelRes = R.string.more_entry_admin_tax_forms_1099,
            icon = Icons.Outlined.ReceiptLong,
            route = MoreRoutes.ADMIN_TAX_FORMS_1099,
            hub = MoreHub.ADMIN,
            section = MoreSection.SUPPORT,
            operatorOnly = true,
        ),
        MoreEntry(
            id = "bulk_payouts_promote",
            labelRes = R.string.more_entry_bulk_payouts_promote,
            icon = Icons.Outlined.Paid,
            route = MoreRoutes.BULK_PAYOUTS_PROMOTE,
            hub = MoreHub.ADMIN,
            section = MoreSection.SUPPORT,
            operatorOnly = true,
        ),
        // B6 admin-ops read dashboards (Admin hub). ADMIN-drivable reads; rate-limits + audit-exports are
        // root-gated (render Forbidden). Each self-gates via the backend 403.
        MoreEntry(
            id = "admin_financials",
            labelRes = R.string.more_entry_admin_financials,
            icon = Icons.Outlined.Assessment,
            route = MoreRoutes.ADMIN_FINANCIALS,
            hub = MoreHub.ADMIN,
            section = MoreSection.SUPPORT,
            operatorOnly = true,
        ),
        MoreEntry(
            id = "admin_payment_health",
            labelRes = R.string.more_entry_admin_payment_health,
            icon = Icons.Outlined.CreditCard,
            route = MoreRoutes.ADMIN_PAYMENT_HEALTH,
            hub = MoreHub.ADMIN,
            section = MoreSection.SUPPORT,
            operatorOnly = true,
        ),
        MoreEntry(
            id = "admin_risk",
            labelRes = R.string.more_entry_admin_risk,
            icon = Icons.Outlined.Insights,
            route = MoreRoutes.ADMIN_RISK,
            hub = MoreHub.ADMIN,
            section = MoreSection.SUPPORT,
            operatorOnly = true,
        ),
        MoreEntry(
            id = "admin_compute",
            labelRes = R.string.more_entry_admin_compute,
            icon = Icons.Outlined.Memory,
            route = MoreRoutes.ADMIN_COMPUTE,
            hub = MoreHub.ADMIN,
            section = MoreSection.SUPPORT,
            operatorOnly = true,
        ),
        // B7 web-parity CLOUD-INFRA management surfaces (mirror the web /remote/* pages). Backends are
        // owner-scoped require_ui_session control planes; a 403 (defence-in-depth) renders Forbidden.
        // Surfaced operatorOnly in the ADMIN/Infra hub per the batch playbook.
        MoreEntry(
            id = "infra_ec2",
            labelRes = R.string.more_entry_infra_ec2,
            icon = Icons.Outlined.Cloud,
            route = MoreRoutes.INFRA_EC2,
            hub = MoreHub.ADMIN,
            section = MoreSection.SUPPORT,
            operatorOnly = true,
        ),
        MoreEntry(
            id = "infra_k8s",
            labelRes = R.string.more_entry_infra_k8s,
            icon = Icons.Outlined.Memory,
            route = MoreRoutes.INFRA_K8S,
            hub = MoreHub.ADMIN,
            section = MoreSection.SUPPORT,
            operatorOnly = true,
        ),
        MoreEntry(
            id = "infra_security_groups",
            labelRes = R.string.more_entry_infra_security_groups,
            icon = Icons.Outlined.Shield,
            route = MoreRoutes.INFRA_SECURITY_GROUPS,
            hub = MoreHub.ADMIN,
            section = MoreSection.SUPPORT,
            operatorOnly = true,
        ),
        MoreEntry(
            id = "infra_hosts",
            labelRes = R.string.more_entry_infra_hosts,
            icon = Icons.Outlined.Dns,
            route = MoreRoutes.INFRA_HOSTS,
            hub = MoreHub.ADMIN,
            section = MoreSection.SUPPORT,
            operatorOnly = true,
        ),
        MoreEntry(
            id = "infra_monitoring",
            labelRes = R.string.more_entry_infra_monitoring,
            icon = Icons.Outlined.Monitor,
            route = MoreRoutes.INFRA_MONITORING,
            hub = MoreHub.ADMIN,
            section = MoreSection.SUPPORT,
            operatorOnly = true,
        ),
        MoreEntry(
            id = "infra_billing",
            labelRes = R.string.more_entry_infra_billing,
            icon = Icons.Outlined.Paid,
            route = MoreRoutes.INFRA_BILLING,
            hub = MoreHub.ADMIN,
            section = MoreSection.SUPPORT,
            operatorOnly = true,
        ),
        // B7 web-parity REMOTE-ACCESS surfaces (mirror the web /remote/* + /remote-desktop pages).
        // Owner-scoped require_ui_session control planes; surfaced operatorOnly in the ADMIN/Infra hub.
        MoreEntry(
            id = "remote_ssh_keys",
            labelRes = R.string.more_entry_remote_ssh_keys,
            icon = Icons.Outlined.VpnKey,
            route = MoreRoutes.REMOTE_SSH_KEYS,
            hub = MoreHub.ADMIN,
            section = MoreSection.SUPPORT,
            operatorOnly = true,
        ),
        MoreEntry(
            id = "remote_ssh_recordings",
            labelRes = R.string.more_entry_remote_ssh_recordings,
            icon = Icons.Outlined.Terminal,
            route = MoreRoutes.REMOTE_SSH_RECORDINGS,
            hub = MoreHub.ADMIN,
            section = MoreSection.SUPPORT,
            operatorOnly = true,
        ),
        MoreEntry(
            id = "remote_bastion",
            labelRes = R.string.more_entry_remote_bastion,
            icon = Icons.Outlined.Hub,
            route = MoreRoutes.REMOTE_BASTION,
            hub = MoreHub.ADMIN,
            section = MoreSection.SUPPORT,
            operatorOnly = true,
        ),
        MoreEntry(
            id = "remote_connection_profiles",
            labelRes = R.string.more_entry_remote_connection_profiles,
            icon = Icons.Outlined.SettingsEthernet,
            route = MoreRoutes.REMOTE_CONNECTION_PROFILES,
            hub = MoreHub.ADMIN,
            section = MoreSection.SUPPORT,
            operatorOnly = true,
        ),
        MoreEntry(
            id = "remote_templates",
            labelRes = R.string.more_entry_remote_templates,
            icon = Icons.Outlined.Dashboard,
            route = MoreRoutes.REMOTE_TEMPLATES,
            hub = MoreHub.ADMIN,
            section = MoreSection.SUPPORT,
            operatorOnly = true,
        ),
        MoreEntry(
            id = "remote_desktop",
            labelRes = R.string.more_entry_remote_desktop,
            icon = Icons.Outlined.DesktopWindows,
            route = MoreRoutes.REMOTE_DESKTOP,
            hub = MoreHub.ADMIN,
            section = MoreSection.SUPPORT,
            operatorOnly = true,
        ),
        MoreEntry(
            id = "admin_jobs",
            labelRes = R.string.more_entry_admin_jobs,
            icon = Icons.Outlined.Schedule,
            route = MoreRoutes.ADMIN_JOBS,
            hub = MoreHub.ADMIN,
            section = MoreSection.SUPPORT,
            operatorOnly = true,
        ),
        MoreEntry(
            id = "admin_rate_limits",
            labelRes = R.string.more_entry_admin_rate_limits,
            icon = Icons.Outlined.Security,
            route = MoreRoutes.ADMIN_RATE_LIMITS,
            hub = MoreHub.ADMIN,
            section = MoreSection.SUPPORT,
            operatorOnly = true,
        ),
        MoreEntry(
            id = "admin_audit_exports",
            labelRes = R.string.more_entry_admin_audit_exports,
            icon = Icons.Outlined.Description,
            route = MoreRoutes.ADMIN_AUDIT_EXPORTS,
            hub = MoreHub.ADMIN,
            section = MoreSection.SUPPORT,
            operatorOnly = true,
        ),
        MoreEntry(
            id = "admin_tenants",
            labelRes = R.string.more_entry_admin_tenants,
            icon = Icons.Outlined.Apartment,
            route = MoreRoutes.ADMIN_TENANTS,
            hub = MoreHub.ADMIN,
            section = MoreSection.SUPPORT,
            operatorOnly = true,
        ),
        MoreEntry(
            id = "admin_sso",
            labelRes = R.string.more_entry_admin_sso,
            icon = Icons.Outlined.VpnKey,
            route = MoreRoutes.ADMIN_SSO,
            hub = MoreHub.ADMIN,
            section = MoreSection.SUPPORT,
            operatorOnly = true,
        ),
        MoreEntry(
            id = "admin_roles",
            labelRes = R.string.more_entry_admin_roles,
            icon = Icons.Outlined.AdminPanelSettings,
            route = MoreRoutes.ADMIN_ROLES,
            hub = MoreHub.ADMIN,
            section = MoreSection.SUPPORT,
            operatorOnly = true,
        ),
        MoreEntry(
            id = "admin_subscription_tiers",
            labelRes = R.string.more_entry_admin_subscription_tiers,
            icon = Icons.Outlined.Loyalty,
            route = MoreRoutes.ADMIN_SUBSCRIPTION_TIER_MANAGER,
            hub = MoreHub.ADMIN,
            section = MoreSection.SUPPORT,
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
            id = "my_content_review",
            labelRes = R.string.more_entry_my_content_review,
            icon = Icons.Outlined.Policy,
            route = MoreRoutes.MY_CONTENT_REVIEW,
            hub = MoreHub.SUPPORT,
            section = MoreSection.SUPPORT,
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
            id = "agent_configs",
            labelRes = R.string.more_entry_agent_configs,
            icon = Icons.Outlined.SmartToy,
            route = MoreRoutes.AGENT_CONFIGS,
            hub = MoreHub.SUPPORT,
            section = MoreSection.SUPPORT,
            operatorOnly = true,
        ),
        MoreEntry(
            id = "agent_types",
            labelRes = R.string.more_entry_agent_types,
            icon = Icons.Outlined.SmartToy,
            route = MoreRoutes.AGENT_TYPES,
            hub = MoreHub.SUPPORT,
            section = MoreSection.SUPPORT,
        ),
        MoreEntry(
            id = "workers",
            labelRes = R.string.more_entry_workers,
            icon = Icons.Outlined.Groups,
            route = MoreRoutes.WORKERS,
            hub = MoreHub.SUPPORT,
            section = MoreSection.SUPPORT,
        ),
        MoreEntry(
            id = "llm_keys",
            labelRes = R.string.more_entry_llm_keys,
            icon = Icons.Outlined.VpnKey,
            route = MoreRoutes.LLM_KEYS,
            hub = MoreHub.SUPPORT,
            section = MoreSection.SUPPORT,
        ),
        MoreEntry(
            id = "fleet",
            labelRes = R.string.more_entry_fleet,
            icon = Icons.Outlined.Hub,
            route = MoreRoutes.FLEET,
            hub = MoreHub.SUPPORT,
            section = MoreSection.SUPPORT,
        ),
        MoreEntry(
            id = "agent_feedback",
            labelRes = R.string.more_entry_agent_feedback,
            icon = Icons.Outlined.ChatBubbleOutline,
            route = MoreRoutes.AGENT_FEEDBACK,
            hub = MoreHub.SUPPORT,
            section = MoreSection.SUPPORT,
        ),
        MoreEntry(
            id = "agent_prs",
            labelRes = R.string.more_entry_agent_prs,
            icon = Icons.Outlined.MergeType,
            route = MoreRoutes.AGENT_PRS,
            hub = MoreHub.SUPPORT,
            section = MoreSection.SUPPORT,
        ),
        MoreEntry(
            id = "agent_memory",
            labelRes = R.string.more_entry_agent_memory,
            icon = Icons.Outlined.Memory,
            route = MoreRoutes.AGENT_MEMORY,
            hub = MoreHub.SUPPORT,
            section = MoreSection.SUPPORT,
        ),
        MoreEntry(
            id = "doc_coverage",
            labelRes = R.string.more_entry_doc_coverage,
            icon = Icons.Outlined.Description,
            route = MoreRoutes.DOC_COVERAGE,
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
            id = "stylist",
            labelRes = R.string.more_entry_stylist,
            icon = Icons.Outlined.Palette,
            route = MoreRoutes.STYLIST,
            hub = MoreHub.SUPPORT,
            section = MoreSection.SUPPORT,
        ),
        MoreEntry(
            id = "marketing",
            labelRes = R.string.more_entry_marketing,
            icon = Icons.Outlined.Campaign,
            route = MoreRoutes.MARKETING,
            hub = MoreHub.GROWTH,
            section = MoreSection.APP,
        ),
        MoreEntry(
            id = "costs",
            labelRes = R.string.more_entry_costs,
            icon = Icons.Outlined.AccountBalance,
            route = MoreRoutes.COSTS,
            hub = MoreHub.SUPPORT,
            section = MoreSection.SUPPORT,
        ),
        MoreEntry(
            id = "compliance",
            labelRes = R.string.more_entry_compliance,
            icon = Icons.Outlined.Security,
            route = MoreRoutes.COMPLIANCE,
            hub = MoreHub.SUPPORT,
            section = MoreSection.SUPPORT,
        ),
        MoreEntry(
            id = "security",
            labelRes = R.string.more_entry_security,
            icon = Icons.Outlined.Security,
            route = MoreRoutes.SECURITY,
            hub = MoreHub.SUPPORT,
            section = MoreSection.SECURITY,
        ),
        MoreEntry(
            id = "pm_ideas",
            labelRes = R.string.more_entry_pm_ideas,
            icon = Icons.Outlined.Lightbulb,
            route = MoreRoutes.PM_IDEAS,
            hub = MoreHub.SUPPORT,
            section = MoreSection.SUPPORT,
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
            id = "trading_blotter",
            labelRes = R.string.more_entry_trading_blotter,
            icon = Icons.Outlined.CandlestickChart,
            route = MoreRoutes.TRADING_BLOTTER,
            hub = MoreHub.STUDIO,
            section = MoreSection.APP,
        ),
        MoreEntry(
            id = "home",
            labelRes = R.string.more_entry_home,
            icon = Icons.Outlined.Dashboard,
            route = MoreRoutes.HOME,
            hub = MoreHub.WALLET,
            section = MoreSection.APP,
        ),
        MoreEntry(
            id = "custody",
            labelRes = R.string.more_entry_custody,
            icon = Icons.Outlined.AccountBalance,
            route = MoreRoutes.CUSTODY,
            hub = MoreHub.WALLET,
            section = MoreSection.APP,
        ),
        MoreEntry(
            id = "custody_providers",
            labelRes = R.string.more_entry_custody_providers,
            icon = Icons.Outlined.Shield,
            route = MoreRoutes.CUSTODY_PROVIDERS,
            hub = MoreHub.WALLET,
            section = MoreSection.APP,
        ),
        MoreEntry(
            id = "portfolio",
            labelRes = R.string.more_entry_portfolio,
            icon = Icons.Outlined.PieChart,
            route = MoreRoutes.PORTFOLIO,
            hub = MoreHub.WALLET,
            section = MoreSection.APP,
        ),
        MoreEntry(
            id = "pnl",
            labelRes = R.string.more_entry_pnl,
            icon = Icons.Outlined.ShowChart,
            route = MoreRoutes.PNL,
            hub = MoreHub.WALLET,
            section = MoreSection.APP,
        ),
        MoreEntry(
            id = "portfolio_analytics",
            labelRes = R.string.more_entry_portfolio_analytics,
            icon = Icons.Outlined.Assessment,
            route = MoreRoutes.PORTFOLIO_ANALYTICS,
            hub = MoreHub.WALLET,
            section = MoreSection.APP,
        ),
        MoreEntry(
            id = "paper_trading",
            labelRes = R.string.more_entry_paper_trading,
            icon = Icons.Outlined.Science,
            route = MoreRoutes.PAPER,
            hub = MoreHub.WALLET,
            section = MoreSection.APP,
        ),
        MoreEntry(
            id = "reports",
            labelRes = R.string.more_entry_reports,
            icon = Icons.Outlined.Description,
            route = MoreRoutes.REPORTS,
            hub = MoreHub.WALLET,
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
        // ECOM: wishlist / favourites — saved catalog items.
        MoreEntry(
            id = "wishlist",
            labelRes = R.string.more_entry_wishlist,
            icon = Icons.Outlined.FavoriteBorder,
            route = MoreRoutes.WISHLIST,
            hub = MoreHub.SHOP,
            section = MoreSection.APP,
        ),
        // ECOM-SELLER (D1): OWNER-SCOPED store management (SHOP hub). NOT operatorOnly - any
        // signed-in seller manages ONLY their own catalog (categories/items where creator_id ==
        // caller); the backend catalog create/edit/delete is require_ui_session + owner-checked.
        MoreEntry(
            id = "seller_store",
            labelRes = R.string.more_entry_seller_store,
            icon = Icons.Outlined.Storefront,
            route = MoreRoutes.SELLER_STORE,
            hub = MoreHub.SHOP,
            section = MoreSection.APP,
        ),
        MoreEntry(
            id = "seller_orders",
            labelRes = R.string.more_entry_seller_orders,
            icon = Icons.Outlined.Inventory2,
            route = MoreRoutes.SELLER_ORDERS,
            hub = MoreHub.SHOP,
            section = MoreSection.APP,
            operatorOnly = true,
        ),
        // ECOM-SELLER (G1-G4): the seller-scoped "My sales" (own ship groups + buyer address +
        // fulfilment). NON-admin: reachable for ANY seller (unlike the admin-only seller_orders above).
        MoreEntry(
            id = "seller_sales",
            labelRes = R.string.more_entry_seller_sales,
            icon = Icons.Outlined.Sell,
            route = MoreRoutes.SELLER_SALES,
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
        // TIPX-D3/D4: ledger-backed tip insights (top supporters + received/sent history).
        MoreEntry(
            id = "tip_insights",
            labelRes = R.string.more_entry_tip_insights,
            icon = Icons.Outlined.Insights,
            route = MoreRoutes.TIP_INSIGHTS,
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
        // PAY-52: the money-OUT Wallet home (available/held/pending/lifetime + Withdraw CTA + history).
        MoreEntry(
            id = "wallet",
            labelRes = R.string.more_entry_wallet,
            icon = Icons.Outlined.AccountBalanceWallet,
            route = MoreRoutes.WALLET,
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
            id = "creator_disputes",
            labelRes = R.string.more_entry_creator_disputes,
            icon = Icons.Outlined.Gavel,
            route = MoreRoutes.CREATOR_DISPUTES,
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
            id = "creator_subscribers",
            labelRes = R.string.more_entry_creator_subscribers,
            icon = Icons.Outlined.Insights,
            route = MoreRoutes.CREATOR_SUBSCRIBERS,
            hub = MoreHub.GROWTH,
            section = MoreSection.ACCOUNT,
        ),
        // SUBX-40: mobile tier authoring — create/price/benefit/level/archive/reorder tiers.
        MoreEntry(
            id = "creator_tiers",
            labelRes = R.string.more_entry_creator_tiers,
            icon = Icons.Outlined.Loyalty,
            route = MoreRoutes.CREATOR_TIERS,
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
        // SUBX-20: the subscriber's "My subscriptions" list (all active/past subs).
        MoreEntry(
            id = "my_subscriptions",
            labelRes = R.string.more_entry_my_subscriptions,
            icon = Icons.Outlined.CardMembership,
            route = MoreRoutes.MY_SUBSCRIPTIONS,
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
        // ADV2-709/710/711: SYNDICATE-ADS management (create/fund a syndicate ad account + campaign +
        // creative reusing the ads create flow, plus the per-syndicate placement split). Opens a known
        // sample syndicate id (no syndicate-admin picker this wave); real entry is the overview action.
        MoreEntry(
            id = "syndicate_ads",
            labelRes = R.string.more_entry_syndicate_ads,
            icon = Icons.Outlined.AccountBalance,
            route = MoreRoutes.SYNDICATE_ADS,
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
        // ADV2-407 (F4): advertiser "propose a sponsored post to a creator" composer.
        MoreEntry(
            id = "sponsored_post_compose",
            labelRes = R.string.more_entry_sponsored_post_compose,
            icon = Icons.Outlined.Campaign,
            route = MoreRoutes.SPONSORED_POST_COMPOSE,
            hub = MoreHub.GROWTH,
            section = MoreSection.ACCOUNT,
        ),
        // ADV2-408 (F4): creator APPROVAL QUEUE for advertiser-drafted sponsored posts.
        MoreEntry(
            id = "sponsored_post_queue",
            labelRes = R.string.more_entry_sponsored_post_queue,
            icon = Icons.Outlined.FactCheck,
            route = MoreRoutes.SPONSORED_POST_QUEUE,
            hub = MoreHub.GROWTH,
            section = MoreSection.ACCOUNT,
        ),
        // ADV2-E5 (F5): advertiser "propose a sponsored message to a creator" composer.
        MoreEntry(
            id = "ad_message_compose",
            labelRes = R.string.more_entry_ad_message_compose,
            icon = Icons.Outlined.Campaign,
            route = MoreRoutes.AD_MESSAGE_COMPOSE,
            hub = MoreHub.GROWTH,
            section = MoreSection.ACCOUNT,
        ),
        // ADV2-E5 (F5): creator APPROVAL QUEUE for advertiser-drafted sponsored MESSAGES.
        MoreEntry(
            id = "ad_message_queue",
            labelRes = R.string.more_entry_ad_message_queue,
            icon = Icons.Outlined.FactCheck,
            route = MoreRoutes.AD_MESSAGE_QUEUE,
            hub = MoreHub.GROWTH,
            section = MoreSection.ACCOUNT,
        ),
        // ADV2-E5 (F6): advertiser DIRECT mass-DM composer (eligible relationships only).
        MoreEntry(
            id = "ad_mass_dm",
            labelRes = R.string.more_entry_ad_mass_dm,
            icon = Icons.Outlined.Sms,
            route = MoreRoutes.AD_MASS_DM,
            hub = MoreHub.GROWTH,
            section = MoreSection.ACCOUNT,
        ),
        // ADV3-5 (B5): the single discoverable "Advertise" hub entry - launches the advertiser-accounts
        // list (create + manage ads), replacing the scattered flat rows as the primary entry point.
        MoreEntry(
            id = "advertise",
            labelRes = R.string.more_entry_advertise,
            icon = Icons.Outlined.Campaign,
            route = MoreRoutes.ADS_ACCOUNTS,
            hub = MoreHub.GROWTH,
            section = MoreSection.ADVERTISING,
        ),
        // AND-367: ads-account billing (balance/lifetime-spend + ledger + invoice) + DEPOSIT add-funds.
        MoreEntry(
            id = "ads_billing",
            labelRes = R.string.more_entry_ads_billing,
            icon = Icons.Outlined.AccountBalanceWallet,
            route = MoreRoutes.ADS_BILLING,
            hub = MoreHub.GROWTH,
            section = MoreSection.ADVERTISING,
        ),
        // AND-368: READ-ONLY ad-analytics dashboard (KPI summary + time-series charts + breakdown).
        MoreEntry(
            id = "ad_analytics",
            labelRes = R.string.more_entry_ad_analytics,
            icon = Icons.Outlined.Insights,
            route = MoreRoutes.AD_ANALYTICS,
            hub = MoreHub.GROWTH,
            section = MoreSection.ADVERTISING,
        ),
        // AND-369: READ-ONLY ads-campaigns list (per-account campaigns: name/status/budget/spend).
        MoreEntry(
            id = "ads_campaigns",
            labelRes = R.string.more_entry_ads_campaigns,
            icon = Icons.Outlined.Campaign,
            route = MoreRoutes.ADS_CAMPAIGNS,
            hub = MoreHub.GROWTH,
            section = MoreSection.ADVERTISING,
        ),
        // ADV-107: create an advertiser ACCOUNT (company + billing email) -> pending admin review.
        MoreEntry(
            id = "ads_create_account",
            labelRes = R.string.more_entry_ads_create_account,
            icon = Icons.Outlined.AddBusiness,
            route = MoreRoutes.ADS_CREATE_ACCOUNT,
            hub = MoreHub.GROWTH,
            section = MoreSection.ADVERTISING,
        ),
        // ADV-108: create a CAMPAIGN (objective/budget/bid) under a chosen account + submit for review.
        MoreEntry(
            id = "ads_create_campaign",
            labelRes = R.string.more_entry_ads_create_campaign,
            icon = Icons.Outlined.Campaign,
            route = MoreRoutes.ADS_CREATE_CAMPAIGN,
            hub = MoreHub.GROWTH,
            section = MoreSection.ADVERTISING,
        ),
        // ADV-109: create a CREATIVE (copy + CTA) + image upload under a chosen campaign + submit for review.
        MoreEntry(
            id = "ads_create_creative",
            labelRes = R.string.more_entry_ads_create_creative,
            icon = Icons.Outlined.Image,
            route = MoreRoutes.ADS_CREATE_CREATIVE,
            hub = MoreHub.GROWTH,
            section = MoreSection.ADVERTISING,
        ),
        // Web-parity: ad TARGETING editor (audience / dayparting-hours / geo / device, live estimate).
        MoreEntry(
            id = "ads_targeting",
            labelRes = R.string.more_entry_ads_targeting,
            icon = Icons.Outlined.Tune,
            route = MoreRoutes.ADS_TARGETING,
            hub = MoreHub.GROWTH,
            section = MoreSection.ADVERTISING,
        ),
        // Web-parity: ad SCHEDULING (dayparting grid + flights + pacing/eligibility).
        MoreEntry(
            id = "ads_scheduling",
            labelRes = R.string.more_entry_ads_scheduling,
            icon = Icons.Outlined.Schedule,
            route = MoreRoutes.ADS_SCHEDULING,
            hub = MoreHub.GROWTH,
            section = MoreSection.ADVERTISING,
        ),
        // Web-parity: ad OPTIMIZATION (recommendations apply/dismiss + auto-optimize + bid/budget).
        MoreEntry(
            id = "ads_optimization",
            labelRes = R.string.more_entry_ads_optimization,
            icon = Icons.Outlined.TrendingUp,
            route = MoreRoutes.ADS_OPTIMIZATION,
            hub = MoreHub.GROWTH,
            section = MoreSection.ADVERTISING,
        ),
        // Web-parity: CONTENT AD-CONTROLS (per-content ad overrides + revenue share + ad-revenue breakdown).
        MoreEntry(
            id = "content_ad_controls",
            labelRes = R.string.more_entry_content_ad_controls,
            icon = Icons.Outlined.Settings,
            route = MoreRoutes.CONTENT_AD_CONTROLS,
            hub = MoreHub.GROWTH,
            section = MoreSection.ADVERTISING,
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
        // Global search: quick-jump over exchange symbols + the app trading destinations + curated actions.
        MoreEntry(
            id = "global_search",
            labelRes = R.string.more_entry_global_search,
            icon = Icons.Outlined.ManageSearch,
            route = MoreRoutes.GLOBAL_SEARCH,
            hub = MoreHub.GROWTH,
            section = MoreSection.ACCOUNT,
        ),
        // Unified INVEST hub: one front door aggregating every investable/tradeable product (markets +
        // creator tokens + strategy funds + staking + open opportunities) client-side. A live search
        // filters all sections; each "see all" opens the existing screen. Degrades per-section on 404.
        MoreEntry(
            id = "invest",
            labelRes = R.string.more_entry_invest,
            icon = Icons.Outlined.Explore,
            route = MoreRoutes.INVEST,
            hub = MoreHub.GROWTH,
            section = MoreSection.ACCOUNT,
        ),
        // Markets (exchange market-data, VIEW-ONLY): tradable instruments -> per-symbol chart / order-book
        // ladder / recent-trades tape. Read-only; no order entry. Polls the md/ (market-data) endpoints on-screen.
        MoreEntry(
            id = "markets",
            labelRes = R.string.more_entry_markets,
            icon = Icons.Outlined.TrendingUp,
            route = MoreRoutes.MARKETS,
            hub = MoreHub.GROWTH,
            section = MoreSection.ACCOUNT,
        ),
        // Creator revenue-share TOKENS: mint a token (100% supply, $100 fee), browse the listed
        // market, and manage cap table / revenue / upkeep / IPO auction per token. All reads
        // degrade-on-404 (the me/tokens/* backend is pending).
        MoreEntry(
            id = "tokens",
            labelRes = R.string.more_entry_tokens,
            icon = Icons.Outlined.Paid,
            route = MoreRoutes.TOKENS,
            hub = MoreHub.GROWTH,
            section = MoreSection.ACCOUNT,
        ),
        // USER-CREATED STRATEGIES / BASKETS (investable funds): define a basket following a simple rule
        // set, paper-trade + backtest it, then invest real capital at NAV (pooled fund with NAV units).
        // Dual fee (mgmt on AUM + perf above a high-water mark). All reads degrade-on-404 (backend pending).
        MoreEntry(
            id = "strategies",
            labelRes = R.string.more_entry_strategies,
            icon = Icons.Outlined.PieChart,
            route = MoreRoutes.STRATEGIES,
            hub = MoreHub.GROWTH,
            section = MoreSection.ACCOUNT,
        ),
        // MARGIN DISTRESS / PRE-EMPTIVE BAILOUT AUCTION: the rescuer opportunity board (BROWSE open
        // bailouts to inject rescue capital for a position-share). The distress overview + per-position
        // auction + auto-bailout setting are reached from here / the margin position surface. All reads
        // degrade-on-404 (the me/margin/distress + me/bailouts backend is pending).
        MoreEntry(
            id = "bailouts",
            labelRes = R.string.more_entry_bailouts,
            icon = Icons.Outlined.Shield,
            route = MoreRoutes.BAILOUTS,
            hub = MoreHub.GROWTH,
            section = MoreSection.ACCOUNT,
        ),
        // Analysis workbench (VIEW-ONLY): historical market-data research — returns / volatility /
        // drawdown / correlation + a fast/slow MA-cross backtest over the md/ history (or recent window).
        MoreEntry(
            id = "analysis",
            labelRes = R.string.more_entry_analysis,
            icon = Icons.Outlined.Insights,
            route = MoreRoutes.ANALYSIS,
            hub = MoreHub.GROWTH,
            section = MoreSection.ACCOUNT,
        ),
        // Trading Alerts: derived notifications (fills / liquidations / funding / margin-distress / PM-resolved)
        // detected from the trader feed reads. Reachable here and from the Markets header bell.
        MoreEntry(
            id = "trading_alerts",
            labelRes = R.string.more_entry_trading_alerts,
            icon = Icons.Outlined.Notifications,
            route = MoreRoutes.TRADING_ALERTS,
            hub = MoreHub.GROWTH,
            section = MoreSection.ACCOUNT,
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
        // P0-BLOCK: Settings/Privacy — blocked-users management (list + unblock). Near geo-blocking.
        MoreEntry(
            id = "blocked_users",
            labelRes = R.string.more_entry_blocked_users,
            icon = Icons.Outlined.Block,
            route = MoreRoutes.BLOCKED_USERS,
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
        // TIP-B4: message privacy — pay-to-message gate + tip-free allowlist (Inbox / Account).
        MoreEntry(
            id = "message_privacy",
            labelRes = R.string.more_entry_message_privacy,
            icon = Icons.Outlined.Shield,
            route = MoreRoutes.MESSAGE_PRIVACY,
            hub = MoreHub.INBOX,
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
        // PAR-27: the unified Safety Center hub (Account / Security). Aggregation only - links to the
        // already-built blocked-users, data-export, DMCA + account-deletion screens.
        MoreEntry(
            id = "safety_center",
            labelRes = R.string.more_entry_safety_center,
            icon = Icons.Outlined.Shield,
            route = MoreRoutes.SAFETY_CENTER,
            hub = MoreHub.ACCOUNT,
            section = MoreSection.SECURITY,
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
        ),
        // PAR-29: static legal screens (Support hub). Terms + Community Guidelines + Contact.
        MoreEntry(
            id = "terms",
            labelRes = R.string.more_entry_terms,
            icon = Icons.Outlined.Gavel,
            route = MoreRoutes.TERMS,
            hub = MoreHub.SUPPORT,
            section = MoreSection.SUPPORT,
        ),
        MoreEntry(
            id = "community_guidelines",
            labelRes = R.string.more_entry_community_guidelines,
            icon = Icons.Outlined.Policy,
            route = MoreRoutes.GUIDELINES,
            hub = MoreHub.SUPPORT,
            section = MoreSection.SUPPORT,
        ),
        MoreEntry(
            id = "contact",
            labelRes = R.string.more_entry_contact,
            icon = Icons.Outlined.Email,
            route = MoreRoutes.CONTACT,
            hub = MoreHub.SUPPORT,
            section = MoreSection.SUPPORT,
        ),
    )
}
