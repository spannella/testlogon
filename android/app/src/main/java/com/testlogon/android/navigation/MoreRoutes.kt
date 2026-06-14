package com.testlogon.android.navigation

import com.testlogon.android.feature.call.nav.CallRoutes
import com.testlogon.android.feature.messaging.nav.MessagingRoutes
import com.testlogon.android.feature.shell.AuthedTab

/**
 * AND-067 — route constants the "More" hub links to, plus the set the authenticated graph registers.
 *
 * Tab routes (Profile) are handled inside the shell's inner NavController; full-screen destinations
 * (Sessions, MFA devices) are outer authenticated-graph routes. Coming-soon destinations are listed
 * so the hub can surface them Disabled; truly-absent routes are simply omitted (→ Hidden).
 */
object MoreRoutes {
    const val PROFILE = "more/profile"
    val SESSIONS: String get() = MainDest.ActiveSessions.route
    val MFA_DEVICES: String get() = MainDest.MfaDevices.route

    // AND-080: notification prefs now live under the Settings hub.
    val NOTIFICATIONS: String get() = MainDest.SettingsNotifications.route

    // AND-085: the notification center (inbox list).
    val NOTIFICATION_CENTER: String get() = MainDest.Notifications.route

    // AND-120..124: the messaging conversation list (inbox), first M3 two-user feature.
    val MESSAGES: String get() = MessagingRoutes.LIST

    // AND-160: mass messages (broadcast campaigns). Screen self-gates on the mass-send capability.
    val MASS_MESSAGES: String get() = MessagingRoutes.MASS_MESSAGES

    // AND-295/296: 1:1 call history (GET /ui/calls/history).
    const val CALL_HISTORY = CallRoutes.HISTORY

    // AND-279/AND-280/AND-281: browse live + scheduled broadcasts (-> viewer playback + live chat).
    const val BROADCASTS = BroadcastBrowseDest.ROUTE

    // AND-161/AND-162: agent-facing helpdesk queue. Screen self-gates via the 403 role signal.
    val HELPDESK_QUEUE: String get() = MessagingRoutes.HELPDESK_QUEUE

    // AND-377: agent helpdesk dashboard (metrics + queue preview). Self-gates via the 403 role signal.
    val HELPDESK_DASHBOARD: String get() = MessagingRoutes.HELPDESK_DASHBOARD

    // AND-088: alert preferences (email/SMS target management).
    val ALERT_PREFS: String get() = MainDest.SettingsAlerts.route

    // AND-091: account activity feed.
    val ACTIVITY: String get() = MainDest.Activity.route

    // AND-092: saved / bookmarks.
    val SAVED: String get() = MainDest.Saved.route

    // AND-093: achievements (earned/locked + progress).
    val ACHIEVEMENTS: String get() = MainDest.Achievements.route

    // AND-189: the caller's videos library grid.
    val VIDEOS: String get() = VideosLibraryDest.ROUTE

    // AND-191: the public VOD catalog (browse on-demand titles).
    val VOD_CATALOG: String get() = VodCatalogDest.ROUTE

    // AND-196: the clips vertical-pager feed.
    val CLIPS: String get() = ClipsFeedDest.ROUTE

    // AND-271: the calendar Month/Week/Agenda views.
    const val CALENDAR = CalendarDest.ROUTE

    // AND-273: Google Calendar integration (connect / link status; backend OAuth Custom-Tab handoff).
    const val GOOGLE_CALENDAR = GoogleCalendarDest.ROUTE

    // AND-274: the content calendar (read-only scheduled-content schedule view).
    const val CONTENT_CALENDAR = ContentCalendarDest.ROUTE

    // AND-275: the scheduler (scheduled-actions list + create/edit).
    const val SCHEDULER = SchedulerListDest.ROUTE

    // AND-201: the published video gallery browse grid.
    val GALLERY: String get() = GalleryDest.ROUTE

    // AND-205: the storefront catalog / category browse grid.
    val CATALOG: String get() = CatalogDest.ROUTE

    // AND-211: the shopping cart.
    val CART: String get() = CartDest.ROUTE

    // AND-219: the purchase history list + search.
    val PURCHASE_HISTORY: String get() = PurchaseHistoryDest.ROUTE

    // AND-224: saved payment-methods management (list / set-default / remove + add-card CTA).
    val PAYMENT_METHODS: String get() = PaymentMethodsDest.ROUTE

    // AND-243: the invoices list (paged number/date/amount/status + detail/email/PDF).
    const val INVOICES = InvoicesListDest.ROUTE

    // AND-244: the refund-requests list (submit from order detail; status tracking).
    const val REFUNDS = RefundsListDest.ROUTE

    // AND-245: the disputes list (file a dispute from order detail; status detail).
    const val DISPUTES = DisputesListDest.ROUTE

    // AND-246: the tax-documents list (year/type + view/download PDF via Custom Tabs).
    const val TAX_DOCUMENTS = TaxDocsDest.ROUTE

    // AND-247: the 1099-NEC tax-forms list (year/earnings/status + download PDF via Custom Tabs).
    const val TAX_FORMS_1099 = Form1099Dest.ROUTE

    // AND-248: the read-only billing-config view (root-gated server-side; 403 surfaces as an error).
    const val BILLING_CONFIG = BillingConfigDest.ROUTE

    // AND-252: the creator earnings dashboard (totals + chart + breakdown). Base route (no range arg);
    // the registered composable route carries an optional `?range=` deep-link arg.
    const val EARNINGS = EarningsDest.ROUTE_BASE

    // AND-253: the per-content revenue list (sortable, cursor-paged).
    const val PER_CONTENT_REVENUE = PerContentRevenueDest.ROUTE

    // AND-260: the creator payout history list (paged amount/status/date + detail).
    const val PAYOUTS = PayoutHistoryDest.ROUTE

    // AND-259: the payout setup + KYC gate (request a payout; FLAGGED identity-verification gate).
    const val PAYOUT_SETUP = PayoutSetupDest.ROUTE

    // AND-261: the READ-ONLY bulk/batch payout tools (admin batch list + detail; no execute action).
    const val BULK_PAYOUTS = BulkPayoutsDest.ROUTE

    // AND-254: the creator engagement-rate analytics (server rate + trend chart). Base route (no arg);
    // the registered composable route carries an optional `?period=` deep-link arg.
    const val ENGAGEMENT = EngagementDest.ROUTE_BASE

    // AND-399: account-wide analytics DASHBOARDS (read) - KPI tiles + views/subscriber charts +
    // top-content/audience breakdowns over a selectable range. Base route (no arg); the registered
    // composable route carries an optional `?range=` deep-link arg.
    const val ANALYTICS_DASHBOARD = AnalyticsDashboardDest.ROUTE_BASE

    // AND-264: referrals dashboard (referral code/link + stats + share/copy + create-code).
    const val REFERRALS = ReferralsDest.ROUTE

    // AND-265: affiliates dashboard (client-aggregated earnings + reusable chart + affiliate links).
    const val AFFILIATES = AffiliatesDest.ROUTE

    // AND-266: promo codes (list + create via plain CRUD; deactivate).
    const val PROMO_CODES = PromoDest.ROUTE

    // AND-267: affiliate discounts (read-only list of discounts attached to the caller's ad creatives).
    const val DISCOUNTS = DiscountsDest.ROUTE

    // AND-235: subscription tiers browse (self-browse from the hub via the SELF sentinel creator id).
    // Plain constant (no Uri.encode) so the JVM MoreCatalog integrity test stays Android-free.
    const val SUBSCRIPTION_TIERS = "subscriptions/tiers/${SubscriptionTiersDest.SELF}"

    // AND-237: manage / cancel the viewer's current subscription (arg-less route).
    const val MANAGE_SUBSCRIPTION = ManageSubscriptionDest.ROUTE

    // AND-238: "My fan clubs" — self-browse the viewer's fan-club channels (SELF sentinel creator id).
    // Plain constant (no Uri.encode) so the JVM MoreCatalog integrity test stays Android-free.
    const val FAN_CLUB = "fanclub/channels/${FanClubChannelsDest.SELF}"

    // AND-353: organizations members/roles (list members + pending invites + invite/change-role/remove).
    val ORGS_MEMBERS: String get() = OrgsGraphDest.ROUTE

    // AND-355: social groups (discover -> detail -> members; role-gated invite/change-role/remove + leave).
    val GROUPS: String get() = GroupsGraphDest.ROUTE

    // AND-356: READ-ONLY syndicate overview (Feed/Treasury/Revenue-split). No discovery list this wave, so
    // the hub opens a known sample syndicate id for manual testing (plain constant, no Uri.encode, so the
    // JVM MoreCatalog integrity test stays Android-free).
    const val SYNDICATES = SyndicateOverviewDest.STUB_ROUTE

    // AND-358: READ-ONLY collaborations (Paging-3 list -> detail; two parties + status + revenue split).
    const val COLLABORATIONS = CollaborationsListDest.ROUTE

    // AND-365: READ-ONLY sponsorship inbox (single GET list of inbound brand deals + client-side status
    // filter -> deal-detail placeholder; the real detail is AND-366).
    const val SPONSORSHIPS = SponsorshipInboxDest.ROUTE

    // AND-367: ads-account billing read view (balance/lifetime-spend + ledger + monthly invoice) + the
    // DEPOSIT add-funds sheet. No ads-accounts list yet, so the hub opens a known sample account id (plain
    // constant, no Uri.encode, so the JVM MoreCatalog integrity test stays Android-free).
    const val ADS_BILLING = AdsBillingDest.STUB_ROUTE

    // AND-368: READ-ONLY ad-analytics dashboard (KPI summary + time-series charts + breakdown over a
    // selectable date range). No ads-accounts list yet, so the hub opens a known sample account id (plain
    // constant, no Uri.encode, so the JVM MoreCatalog integrity test stays Android-free).
    const val AD_ANALYTICS = AdAnalyticsDest.STUB_ROUTE

    // AND-400: READ-ONLY public SEO metadata inspector (title / og / twitter / json-ld a crawler sees).
    // No per-resource detail surface wires it this wave, so the hub opens a known sample profile resource
    // (plain constant, no Uri.encode, so the JVM MoreCatalog integrity test stays Android-free).
    const val SEO = SeoDest.STUB_ROUTE

    // AND-372: READ-ONLY ticket spaces + threads (support / helpdesk). Spaces list -> ticket list -> thread.
    const val TICKETS = TicketSpacesListDest.ROUTE

    // AND-398: WEBHOOKS config (light) - list outbound webhook endpoints -> detail -> a LIGHT create.
    const val WEBHOOKS = WebhooksListDest.ROUTE

    // AND-403: READ-ONLY admin alerts/dashboards (client-aggregated job + webhook health). Self-gates via the
    // backend 403 role signal -> the screen's Forbidden state (cf. the helpdesk-dashboard / billing-config
    // pattern); a non-admin sees no admin data.
    const val ADMIN_DASHBOARD = AdminDashboardDest.ROUTE

    // AND-404: READ-ONLY admin email/SMS delivery dashboards (per-channel stats + recent activity). Self-gate
    // via the backend 403 -> the screen's Forbidden state (cf. the AND-403 admin-dashboard pattern); a non-admin
    // sees no admin data. Two concrete entry routes off the shared `{channel}` destination template.
    const val ADMIN_EMAIL_DASHBOARD = MessagingDashboardDest.EMAIL_ROUTE
    const val ADMIN_SMS_DASHBOARD = MessagingDashboardDest.SMS_ROUTE

    // AND-374: projects (paged list -> detail + the account-scoped Google Drive provider connect flow).
    const val PROJECTS = ProjectsListDest.ROUTE

    // AND-360: the delegate console (focused manage-as-creator demonstration). Self-gates on the managed-
    // creator state (shows an enter prompt when not in delegate mode); renders the persistent banner + the
    // permission-gated delegate feed / messaging affordances.
    const val DELEGATE_CONSOLE = DelegateConsoleDest.ROUTE

    // AND-384: file a DMCA copyright-takedown notice (standalone entry; the content-overflow entry uses
    // navigateToDmca with a pre-target). The composable is registered under DmcaDest.ROUTE; navigating to
    // the plain base route resolves to it (the optional query args default to null).
    val DMCA: String get() = DmcaDest.STANDALONE_ROUTE

    // AND-385: privacy & data export (request -> status -> download lifecycle; Room-cached offline history).
    const val PRIVACY_EXPORT = PrivacyExportDest.ROUTE

    // AND-077: the Settings hub landing.
    val SETTINGS: String get() = MainDest.Settings.route
    const val HELP = "more/help"
    const val ABOUT = "more/about"

    /** Routes the hub treats as registered (real destinations or intentionally-surfaced stubs). */
    val REGISTERED: Set<String>
        get() = setOf(
            PROFILE,
            MESSAGES,
            MASS_MESSAGES,
            CALL_HISTORY,
            BROADCASTS,
            HELPDESK_QUEUE,
            HELPDESK_DASHBOARD,
            SESSIONS,
            MFA_DEVICES,
            NOTIFICATION_CENTER,
            NOTIFICATIONS,
            ALERT_PREFS,
            ACTIVITY,
            SAVED,
            ACHIEVEMENTS,
            VIDEOS,
            VOD_CATALOG,
            CLIPS,
            CALENDAR,
            GOOGLE_CALENDAR,
            CONTENT_CALENDAR,
            SCHEDULER,
            GALLERY,
            CATALOG,
            CART,
            PURCHASE_HISTORY,
            PAYMENT_METHODS,
            EARNINGS,
            PER_CONTENT_REVENUE,
            ENGAGEMENT,
            ANALYTICS_DASHBOARD,
            REFERRALS,
            AFFILIATES,
            PROMO_CODES,
            DISCOUNTS,
            PAYOUTS,
            PAYOUT_SETUP,
            BULK_PAYOUTS,
            INVOICES,
            REFUNDS,
            DISPUTES,
            TAX_DOCUMENTS,
            TAX_FORMS_1099,
            BILLING_CONFIG,
            SUBSCRIPTION_TIERS,
            MANAGE_SUBSCRIPTION,
            FAN_CLUB,
            ORGS_MEMBERS,
            GROUPS,
            SYNDICATES,
            COLLABORATIONS,
            SPONSORSHIPS,
            ADS_BILLING,
            AD_ANALYTICS,
            SEO,
            TICKETS,
            WEBHOOKS,
            ADMIN_DASHBOARD,
            ADMIN_EMAIL_DASHBOARD,
            ADMIN_SMS_DASHBOARD,
            PROJECTS,
            DELEGATE_CONSOLE,
            DMCA,
            PRIVACY_EXPORT,
            SETTINGS,
            HELP,
            ABOUT,
        )
}

/** Resolves a [MoreRoutes] target to an in-shell tab where applicable. */
fun moreRouteToTab(route: String): AuthedTab? = when (route) {
    MoreRoutes.PROFILE -> AuthedTab.ME
    else -> null
}
