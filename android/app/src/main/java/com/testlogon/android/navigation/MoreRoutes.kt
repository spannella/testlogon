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

    // Feature 1 — the saved-contacts address book + "people you may know" hub.
    val CONTACTS_HUB: String get() = MessagingRoutes.CONTACTS_HUB

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

    // "My Rentals": the viewer's time-limited rentals + view-once purchases. Web parity: vod/rentals.
    val VOD_RENTALS: String get() = VodRentalsDest.ROUTE

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

    // ECOM: the wishlist / favourites (saved catalog items).
    val WISHLIST: String get() = WishlistDest.ROUTE
    val SELLER_STORE: String get() = SellerStoreDest.ROUTE
    val SELLER_ORDERS: String get() = SellerOrdersDest.ROUTE
    val SELLER_SALES: String get() = SellerSalesDest.BASE

    // AND-332: the server file manager (path-based browse + upload/download/share/Drive-import).
    const val FILES = FilesDest.ROUTE

    // Trading Blotter: native orders/fills/positions blotter (web parity). Sample data only.
    const val TRADING_BLOTTER = BlotterDest.ROUTE

    // Home / Dashboard: read-only trading launch surface (portfolio + watchlist + activity + onboarding).
    const val HOME = HomeDest.ROUTE

    // Custody: native crypto custody surface (balances / deposit / withdraw / activity / officer approvals), wired to /me/custody/*.
    const val CUSTODY = CustodyDest.ROUTE

    // External custody providers (Fireblocks / BitGo / internal gateway): connect + per-vault provider + withdrawal approval.
    const val CUSTODY_PROVIDERS = CustodyProvidersDest.ROUTE

    // Portfolio: read-only cross-venue account overview (custody / spot / margin / staking snapshot).
    const val PORTFOLIO = PortfolioDest.ROUTE

    // PnL & performance: read-only realized/unrealized analytics + equity curve (Wallet hub, near Portfolio).
    const val PNL = PnlDest.ROUTE

    // Paper Trading: a SELF-CONTAINED client-side trading simulation (isolated paper account; NO real
    // order calls). Reached from the More -> Wallet hub.
    const val PAPER = PaperDest.ROUTE

    // Export & reporting: read-only period-scoped CSV export (Wallet hub, near PnL).
    const val REPORTS = ReportsDest.ROUTE

    // AND-219: the purchase history list + search.
    val PURCHASE_HISTORY: String get() = PurchaseHistoryDest.ROUTE

    // AND-224: saved payment-methods management (list / set-default / remove + add-card CTA).
    val PAYMENT_METHODS: String get() = PaymentMethodsDest.ROUTE

    // PW18: Wallet transactions (ledger) history — date/amount/type/status from BK3.
    val WALLET_TRANSACTIONS: String get() = WalletTransactionsDest.ROUTE

    // AND-243: the invoices list (paged number/date/amount/status + detail/email/PDF).
    const val INVOICES = InvoicesListDest.ROUTE

    // AND-244: the refund-requests list (submit from order detail; status tracking).
    const val REFUNDS = RefundsListDest.ROUTE

    // AND-245: the disputes list (file a dispute from order detail; status detail).
    const val DISPUTES = DisputesListDest.ROUTE

    // DISP-024: the creator inbound queue — disputes filed against my sales, to respond to.
    const val CREATOR_DISPUTES = CreatorDisputesDest.ROUTE

    // AND-246: the tax-documents list (year/type + view/download PDF via Custom Tabs).
    const val TAX_DOCUMENTS = TaxDocsDest.ROUTE

    // AND-247: the 1099-NEC tax-forms list (year/earnings/status + download PDF via Custom Tabs).
    const val TAX_FORMS_1099 = Form1099Dest.ROUTE

    // AND-248: the read-only billing-config view (root-gated server-side; 403 surfaces as an error).
    const val BILLING_CONFIG = BillingConfigDest.ROUTE

    // AND-252: the creator earnings dashboard (totals + chart + breakdown). Base route (no range arg);
    // the registered composable route carries an optional `?range=` deep-link arg.
    const val EARNINGS = EarningsDest.ROUTE_BASE

    // TIPX-D3/D4: ledger-backed tip insights (top supporters + received/sent history).
    const val TIP_INSIGHTS = TipInsightsDest.ROUTE

    // AND-253: the per-content revenue list (sortable, cursor-paged).
    const val PER_CONTENT_REVENUE = PerContentRevenueDest.ROUTE

    // PAY-52: the money-OUT Wallet home (real available/held/pending/lifetime + Withdraw CTA + history).
    const val WALLET = WalletDest.ROUTE

    // AND-260: the creator payout history list (paged amount/status/date + detail).
    const val PAYOUTS = PayoutHistoryDest.ROUTE

    // AND-259 / PAY-52: the withdraw screen — payout methods + KYC/W-9 gate + amount flow (real request_payout).
    const val PAYOUT_SETUP = PayoutSetupDest.ROUTE

    // AND-261: the READ-ONLY bulk/batch payout tools (admin batch list + detail; no execute action).
    const val BULK_PAYOUTS = BulkPayoutsDest.ROUTE

    // Web-parity admin bulk-payout PROMOTE console (eligible -> preview -> EXECUTE; admin-gated; execute
    // moves real funds behind a confirm). The write half of /admin/bulk-payouts.
    const val BULK_PAYOUTS_PROMOTE = BulkPayoutPromoteDest.ROUTE

    // AND-254: the creator engagement-rate analytics (server rate + trend chart). Base route (no arg);
    // the registered composable route carries an optional `?period=` deep-link arg.
    const val ENGAGEMENT = EngagementDest.ROUTE_BASE

    // AND-399: account-wide analytics DASHBOARDS (read) - KPI tiles + views/subscriber charts +
    // top-content/audience breakdowns over a selectable range. Base route (no arg); the registered
    // composable route carries an optional `?range=` deep-link arg.
    const val ANALYTICS_DASHBOARD = AnalyticsDashboardDest.ROUTE_BASE

    // AND-264: referrals dashboard (referral code/link + stats + share/copy + create-code).
    const val REFERRALS = ReferralsDest.ROUTE

    // Alerts (system notifications) inbox — mirrors web /alerts.
    const val ALERTS = AlertsDest.ROUTE

    // MOD-D2: poster "My content under review" (moderation cases + respond/close).
    const val MY_CONTENT_REVIEW = ModerationReviewDest.ROUTE

    // Account-action appeals - mirrors web /appeals.
    const val APPEALS = AppealsDest.ROUTE

    // Web-route parity batch.
    const val IDEAS = IdeasDest.ROUTE
    const val LICENSES = LicensesDest.ROUTE
    const val AGENT_CONFIGS = AgentConfigsHubDest.ROUTE

    // AGENTS-BASICS web-parity: workers (list/detail/sessions + create). require_ui_session (usable).
    val WORKERS: String get() = WorkersListDest.ROUTE
    // AGENTS-BASICS web-parity: LLM provider keys (list/add/test/revoke). require_ui_session (usable).
    val LLM_KEYS: String get() = LlmKeysListDest.ROUTE
    // AGENTS-BASICS web-parity: fleet dashboard (status/capacity/bulk/templates). require_ui_session (usable).
    val FLEET: String get() = FleetDashboardDest.ROUTE
    // AGENTS-BASICS web-parity: agent-types dashboard/picker -> feeds the B4 type-config screens.
    val AGENT_TYPES: String get() = AgentTypesDashboardDest.ROUTE

    // AGENTS-BASICS web-parity: worker feedback queue (respond/skip). require_ui_session (usable).
    val AGENT_FEEDBACK: String get() = AgentFeedbackDest.ROUTE
    // AGENTS-BASICS web-parity: READ-ONLY agent pull-requests (list -> detail). require_ui_session (usable).
    val AGENT_PRS: String get() = AgentPrsListDest.ROUTE
    // AGENTS-BASICS web-parity: per-worker agent memory (worker picker -> identity/project/entries).
    val AGENT_MEMORY: String get() = AgentMemoryPickerDest.ROUTE
    // AGENTS-BASICS web-parity: doc-coverage dashboard (+ doc templates). require_ui_session (usable).
    val DOC_COVERAGE: String get() = DocCoverageDest.ROUTE

    // B4 web-parity: Stylist / UI-design agent (web /agents/stylist). require_ui_session (usable).
    const val STYLIST = StylistOverviewDest.ROUTE

    // B4 web-parity: Marketing content agent (web /agents/marketing). require_ui_session (usable).
    const val MARKETING = MarketingDashboardDest.ROUTE
    // B4 web-parity: Accountant/cost-tracking agent (web /agents/costs). require_ui_session (usable).
    const val COSTS = CostOverviewDest.ROUTE
    // B4 web-parity: Compliance agent (web /agents/compliance). require_ui_session (usable).
    const val COMPLIANCE = ComplianceDest.ROUTE
    // B4 web-parity: Security agent (web /agents/security == compliance page). require_ui_session (usable).
    const val SECURITY = SecurityDest.ROUTE
    // B4 web-parity: PM feature-idea triage (web /agents/pm/ideas). require_ui_session (usable).
    const val PM_IDEAS = PmIdeasDest.ROUTE
    const val WATCH_PARTIES = WatchPartiesDest.LIST
    const val BOTS = BotsDest.LIST

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

    // SUBX-20: the subscriber's "My subscriptions" list (all subs -> correct-target manage).
    const val MY_SUBSCRIPTIONS = MySubscriptionsDest.ROUTE

    // SUB-E4-3: creator subscribers + MRR/analytics dashboard (owner-scoped; Growth hub).
    const val CREATOR_SUBSCRIBERS = CreatorSubscribersDest.ROUTE

    // SUBX-40: creator tier authoring (create/price/benefits/level/archive/reorder; Growth hub).
    const val CREATOR_TIERS = CreatorTierManagerDest.ROUTE

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
    const val SYNDICATES = SyndicateListDest.ROUTE

    // Web-parity: My Bundles (the caller's active syndicate bundle subscriptions + per-bundle cancel).
    const val MY_BUNDLES = MyBundlesDest.ROUTE

    // Web-parity: syndicate-advertising campaign DETAIL. No per-syndicate campaigns list this wave, so the
    // hub opens a known sample syndicate+campaign id (plain constant, no Uri.encode, so the JVM MoreCatalog
    // integrity test stays Android-free).
    const val SYNDICATE_CAMPAIGN = CampaignDetailDest.STUB_ROUTE

    // ADV2-709/710/711 (F7): SYNDICATE-ADS management (create/fund a syndicate ad account + campaign
    // + creative + the placement split). No syndicate-admin picker this wave, so the hub opens a known
    // sample syndicate id (plain constant, no Uri.encode, so the JVM MoreCatalog integrity test stays
    // Android-free).
    const val SYNDICATE_ADS = SyndicateAdsDest.STUB_ROUTE

    // AND-358: READ-ONLY collaborations (Paging-3 list -> detail; two parties + status + revenue split).
    const val COLLABORATIONS = CollaborationsListDest.ROUTE

    // AND-365: READ-ONLY sponsorship inbox (single GET list of inbound brand deals + client-side status
    // filter -> deal-detail placeholder; the real detail is AND-366).
    const val SPONSORSHIPS = SponsorshipInboxDest.ROUTE

    // ADV2-407 (F4): advertiser "propose a sponsored post to a creator" composer (draft body + billing
    // linkage -> POST a proposal; nothing publishes until the creator approves).
    const val SPONSORED_POST_COMPOSE = SponsoredPostComposeDest.ROUTE

    // ADV2-408 (F4): creator APPROVAL QUEUE for advertiser-drafted sponsored posts (pending proposals ->
    // approve publishes a normal creator post carrying the DISTINCT paid_partnership flag / reject).
    const val SPONSORED_POST_QUEUE = SponsoredPostQueueDest.ROUTE

    // ADV2-E5 (F5): advertiser "propose a sponsored MESSAGE to a creator" composer (draft body + billing
    // linkage -> POST an offer; nothing sends until the creator approves — then it sends AS the creator).
    const val AD_MESSAGE_COMPOSE = AdMessageComposeDest.ROUTE

    // ADV2-E5 (F5): creator APPROVAL QUEUE for advertiser-drafted sponsored MESSAGES (pending offers ->
    // approve SENDS the message to the creator's audience as the creator / reject).
    const val AD_MESSAGE_QUEUE = AdMessageQueueDest.ROUTE

    // ADV2-E5 (F6): advertiser DIRECT mass-DM composer (compose + send AS the advertiser to eligible
    // relationships only — followers/subscribers minus ad opt-outs; platform-100%).
    const val AD_MASS_DM = AdMassDmComposeDest.ROUTE

    // AND-367: ads-account billing read view (balance/lifetime-spend + ledger + monthly invoice) + the
    // DEPOSIT add-funds sheet. No ads-accounts list yet, so the hub opens a known sample account id (plain
    // constant, no Uri.encode, so the JVM MoreCatalog integrity test stays Android-free).
    // ADV3-4 (B4) / ADV3-5 (B5): the "Advertise" hub landing = the advertiser-accounts LIST. Removes the
    // single-account ceiling (routes billing/campaigns/analytics with a real accountId) + launches the
    // create wizard. Plain route constant (no nav arg).
    const val ADS_ACCOUNTS = AdsAccountsDest.ROUTE

    const val ADS_BILLING = AdsBillingDest.STUB_ROUTE

    // AND-368: READ-ONLY ad-analytics dashboard (KPI summary + time-series charts + breakdown over a
    // selectable date range). No ads-accounts list yet, so the hub opens a known sample account id (plain
    // constant, no Uri.encode, so the JVM MoreCatalog integrity test stays Android-free).
    const val AD_ANALYTICS = AdAnalyticsDest.STUB_ROUTE

    // AND-369: READ-ONLY ads-campaigns list (per-account campaigns: name/status/budget/spend). No
    // ads-accounts list yet, so the hub opens a known sample account id (plain constant, no Uri.encode,
    // so the JVM MoreCatalog integrity test stays Android-free).
    const val ADS_CAMPAIGNS = AdsCampaignsDest.STUB_ROUTE

    // ADV-107/108/109: advertiser CREATE flow (create ad account -> campaign -> creative + upload +
    // submit-for-review). No nav arg: the pickers/steps carry the account/campaign via AdsStudioSelection.
    const val ADS_CREATE_ACCOUNT = CreateAdAccountDest.ROUTE
    const val ADS_CREATE_CAMPAIGN = CreateCampaignDest.ROUTE
    const val ADS_CREATE_CREATIVE = CreateCreativeDest.ROUTE

    // Web-parity ads STUDIO editors. Each VM self-resolves the caller's first account then campaign
    // (no campaign-picker nav yet), so the hub registers the plain route constants directly.
    const val ADS_TARGETING = AdTargetingDest.ROUTE
    const val ADS_SCHEDULING = AdSchedulingDest.ROUTE
    const val ADS_OPTIMIZATION = AdOptimizationDest.ROUTE

    // Web-parity CONTENT AD-CONTROLS (per-content overrides + revenue share + transparency). Caller-
    // scoped; no nav arg, so the hub registers the plain route constant directly.
    const val CONTENT_AD_CONTROLS = ContentAdControlsDest.ROUTE

    // Web-parity boost MANAGEMENT: the boosts LIST (/ads/boost). Rows open the detail-by-boostId screen.
    const val BOOSTS = BoostManageDest.LIST_ROUTE

    // AND-400: READ-ONLY public SEO metadata inspector (title / og / twitter / json-ld a crawler sees).
    // No per-resource detail surface wires it this wave, so the hub opens a known sample profile resource
    // (plain constant, no Uri.encode, so the JVM MoreCatalog integrity test stays Android-free).
    const val SEO = SeoDest.STUB_ROUTE

    // AND-372: READ-ONLY ticket spaces + threads (support / helpdesk). Spaces list -> ticket list -> thread.
    const val TICKETS = TicketSpacesListDest.ROUTE

    // B-SUP (batch 7): the role-branched Support landing (USER help / ADMIN helpdesk queue).
    const val SUPPORT = SupportDest.ROUTE

    // AND-398: WEBHOOKS config (light) - list outbound webhook endpoints -> detail -> a LIGHT create.
    const val WEBHOOKS = WebhooksListDest.ROUTE

    // AND-403: READ-ONLY admin alerts/dashboards (client-aggregated job + webhook health). Self-gates via the
    // backend 403 role signal -> the screen's Forbidden state (cf. the helpdesk-dashboard / billing-config
    // pattern); a non-admin sees no admin data.
    const val ADMIN_DASHBOARD = AdminDashboardDest.ROUTE

    // Markets (exchange market-data, VIEW-ONLY): instrument list -> per-symbol chart/book/tape.
    const val MARKETS = MarketsDest.ROUTE

    // Creator revenue-share TOKENS: mint a token, browse the listed market, per-token detail
    // (cap table / revenue / upkeep / IPO auction). Endpoints degrade-on-404 (backend pending).
    const val TOKENS = TokensMarketDest.ROUTE

    // USER-CREATED STRATEGIES / BASKETS (investable funds): the marketplace + "my strategies" list
    // (the navigable hub BROWSE entry). Builder / detail+invest/redeem / paper-run+backtest are
    // detail routes reached from there. All reads degrade-on-404 (the me/strategies backend is pending).
    const val STRATEGIES = StrategyMarketDest.ROUTE

    // MARGIN DISTRESS / PRE-EMPTIVE BAILOUT AUCTION: the rescuer opportunity board (the navigable hub
    // BROWSE entry) + the distress overview + auto-bailout account setting. Per-position auction is a
    // detail route reached from those. All reads degrade-on-404 (the margin-distress backend is pending).
    const val BAILOUTS = BailoutBoardDest.ROUTE
    const val MARGIN_DISTRESS = BailoutDistressDest.ROUTE
    const val BAILOUT_SETTINGS = BailoutSettingsDest.ROUTE

    // Analysis workbench: historical market-data research (stats / correlation / MA-cross backtest).
    const val ANALYSIS = AnalysisDest.ROUTE

    // Global search: quick-jump over exchange symbols + trading destinations + curated actions.
    const val GLOBAL_SEARCH = GlobalSearchDest.ROUTE

    // Trading Alerts (derived notifications: fills / liquidations / funding / margin-distress / PM-resolved).
    const val TRADING_ALERTS = TradingAlertsDest.ROUTE

    // AND-404: READ-ONLY admin email/SMS delivery dashboards (per-channel stats + recent activity). Self-gate
    // via the backend 403 -> the screen's Forbidden state (cf. the AND-403 admin-dashboard pattern); a non-admin
    // sees no admin data. Two concrete entry routes off the shared `{channel}` destination template.
    const val ADMIN_EMAIL_DASHBOARD = MessagingDashboardDest.EMAIL_ROUTE
    const val ADMIN_SMS_DASHBOARD = MessagingDashboardDest.SMS_ROUTE

    // B5: admin content-moderation board (queue + ticket detail + claim/decision/resolve).
    const val ADMIN_MODERATION = ModerationBoardDest.ROUTE

    // Web-parity admin ADS surfaces (all require_admin_or_root; ad-platform kill-switch toggle is
    // root-only -> surfaced read-only). Each self-gates via the backend 403.
    const val ADMIN_AD_CREATIVE_REVIEW = AdCreativeReviewDest.ROUTE
    const val ADMIN_AD_FRAUD = AdFraudDest.ROUTE
    const val ADMIN_AD_PLATFORM = AdPlatformDest.ROUTE

    // Web-parity admin 1099 MANAGER (year list + generate/correct/batch; require_admin_or_root). Distinct
    // from the user-facing own-1099 view (TAX_FORMS_1099).
    const val ADMIN_TAX_FORMS_1099 = AdminTaxFormDest.ROUTE

    // B6: admin-ops read dashboards. ADMIN-drivable reads (financials/payment-health/risk/compute/jobs)
    // + ROOT-gated (rate-limits/audit-exports -> Forbidden for admin). Each self-gates via the backend 403.
    const val ADMIN_FINANCIALS = AdminOpsFinancialsDest.ROUTE
    const val ADMIN_PAYMENT_HEALTH = AdminOpsPaymentHealthDest.ROUTE
    const val ADMIN_RISK = AdminOpsRiskDest.ROUTE
    const val ADMIN_COMPUTE = AdminOpsComputeDest.ROUTE
    const val ADMIN_JOBS = AdminOpsJobsDest.ROUTE
    const val ADMIN_RATE_LIMITS = AdminOpsRateLimitsDest.ROUTE
    const val ADMIN_AUDIT_EXPORTS = AdminOpsAuditExportsDest.ROUTE

    // Web-parity ROOT/ADMIN governance. tenants/SSO/role-mgmt are require_root_session/require_root ->
    // ROOT-GATED (render Forbidden for our admin account); the subscription-tier MANAGER is
    // require_admin_or_root -> ADMIN-drivable. Each self-gates via the backend 403.
    const val ADMIN_TENANTS = AdminTenantsDest.ROUTE
    const val ADMIN_SSO = AdminSsoDest.ROUTE
    const val ADMIN_ROLES = AdminRolesDest.ROUTE
    const val ADMIN_SUBSCRIPTION_TIER_MANAGER = AdminTierManagerDest.ROUTE

    // B5: admin video-review queue (approve/reject).
    const val ADMIN_VIDEO_REVIEW = VideoReviewDest.ROUTE

    // B5: admin DMCA claims dashboard (claims queue + resolve).
    const val ADMIN_DMCA = DmcaAdminDest.ROUTE

    // B5: admin refund-requests queue (status filter + approve/reject).
    const val ADMIN_REFUNDS = RefundAdminDest.ROUTE

    // B5: admin billing-disputes queue (status filter + respond/resolve).
    const val ADMIN_DISPUTES = DisputeAdminDest.ROUTE

    // B5: admin appeals review queue (claim + decide).
    const val ADMIN_APPEALS = AppealAdminDest.ROUTE

    // B5: admin fraud-review queue (flags review + cases resolve).
    const val ADMIN_FRAUD = FraudAdminDest.ROUTE

    // B5: admin payment-incidents queue (status filter + submit-response).
    const val ADMIN_PAYMENT_INCIDENTS = IncidentAdminDest.ROUTE

    // Web-parity KYC-admin review queues (A1..A8). Each admin-gated; self-gates via backend 403.
    const val ADMIN_KYC_CASES = KycCaseAdminDest.ROUTE
    const val ADMIN_KYC_DOCUMENTS = KycDocAdminDest.ROUTE
    const val ADMIN_KYC_RESIDENCY = KycResidencyAdminDest.ROUTE
    const val ADMIN_KYC_PROOF_OF_FUNDS = KycPofAdminDest.ROUTE
    const val ADMIN_KYC_LIVENESS = KycLivenessAdminDest.ROUTE
    const val ADMIN_KYC_SCREENING = KycScreeningAdminDest.ROUTE
    const val ADMIN_KYC_ID_SCANNER = KycIdScanAdminDest.ROUTE
    const val ADMIN_KYC_BUSINESS = KycBusinessAdminDest.ROUTE

    // Web-parity KYC-admin dashboards + config (B2..B9). Admin-gated; each self-gates via backend 403.
    const val ADMIN_KYC_WORKLOAD = KycWorkloadAdminDest.ROUTE
    const val ADMIN_KYC_METRICS = KycMetricsAdminDest.ROUTE
    const val ADMIN_KYC_ANALYTICS = KycAnalyticsAdminDest.ROUTE
    const val ADMIN_KYC_MONITORING = KycMonitoringAdminDest.ROUTE
    const val ADMIN_KYC_ADDRESS_VERIFICATION = KycAddressVerifAdminDest.ROUTE
    const val ADMIN_KYC_COMPLIANCE = KycComplianceAdminDest.ROUTE
    const val ADMIN_KYC_TEMPLATES = KycTemplatesAdminDest.ROUTE
    const val ADMIN_KYC_TRANSLATIONS = KycTranslationsAdminDest.ROUTE

    // B7 web-parity CLOUD-INFRA management surfaces. Owner-scoped require_ui_session (NOT admin); each
    // self-gates via the backend 403. Surfaced in the operator/Infra hub (operatorOnly in MoreCatalog).
    const val INFRA_EC2 = Ec2Dest.ROUTE
    const val INFRA_K8S = K8sDest.ROUTE
    const val INFRA_SECURITY_GROUPS = SecurityGroupsDest.ROUTE
    const val INFRA_HOSTS = HostInventoryDest.ROUTE
    const val INFRA_MONITORING = InstanceMonitoringDest.ROUTE
    const val INFRA_BILLING = ComputeBillingDest.ROUTE

    // B7 web-parity REMOTE-ACCESS surfaces (mirror the web /remote/* + /remote-desktop pages). Backends
    // are owner-scoped require_ui_session control planes; each self-gates via the backend 403. Surfaced in
    // the operator/Infra hub (operatorOnly in MoreCatalog). remote-desktop is FLAGGED on web (default ON);
    // the Android live viewer is an honest open-on-desktop state.
    const val REMOTE_SSH_KEYS = SshKeysDest.ROUTE
    const val REMOTE_SSH_RECORDINGS = SshRecordingsDest.ROUTE
    const val REMOTE_BASTION = SshBastionDest.ROUTE
    const val REMOTE_CONNECTION_PROFILES = ConnProfilesDest.ROUTE
    const val REMOTE_TEMPLATES = InstanceTemplatesDest.ROUTE
    const val REMOTE_DESKTOP = RemoteDesktopDest.ROUTE

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

    // B-KYC (batch 7): identity verification. Lands on the READ-ONLY KYC case list (current verification
    // status + the ongoing-monitoring banner); "Start verification" deep-links onward to the tier-status
    // requirements checklist + Evaluate, and the case steps (document capture, etc.). Already registered.
    const val KYC = KycCasesDest.ROUTE

    // B-APIKEY (batch 7): developer API-keys management (list / create-shown-once / revoke).
    const val API_KEYS = ApiKeysListDest.ROUTE

    // P0-BLOCK: Settings/Privacy — the blocked-users management screen (list + unblock).
    const val BLOCKED_USERS = BlockedUsersDest.ROUTE

    // PAR-27: the unified Safety Center hub (aggregates blocked users / data export / DMCA / account deletion).
    const val SAFETY_CENTER = SafetyCenterDest.ROUTE

    // Web-parity: questionnaire BUILDER (creator authoring: drafts list -> create -> sections +
    // questions of 9 types -> publish). Distinct from the respondent renderer.
    const val QUESTIONNAIRE_BUILDER = QuestionnaireBuilderListDest.ROUTE

    // Web-parity: delegation-API keys (/delegation-api) - DELEGATED-access keys (a tool acting on a
    // creator's behalf), distinct from API_KEYS (personal developer keys).
    const val DELEGATION_KEYS = DelegationKeysDest.ROUTE

    // Settings: custom emojis (personal emoji manager). Web parity: settings/emojis.
    val CUSTOM_EMOJIS: String get() = MainDest.SettingsEmojis.route

    // Settings: geo-blocking rules (detected country + dry-run check). Web parity: settings/geo.
    val GEO_RULES: String get() = MainDest.SettingsGeo.route

    // Settings: call rate (paid-calls per-minute rate). Web parity: settings/call-rate.
    val CALL_RATE: String get() = MainDest.SettingsCallRate.route

    // Settings: message privacy (TIP-B4 pay-to-message gate + tip-free allowlist).
    val MESSAGE_PRIVACY: String get() = MainDest.SettingsMessagePrivacy.route

    // AND-077: the Settings hub landing.
    val SETTINGS: String get() = MainDest.Settings.route
    const val HELP = "more/help"
    const val ABOUT = "more/about"

    // PAR-29: static legal screens reachable from the Support hub.
    val TERMS: String get() = LegalRoutes.TERMS
    val GUIDELINES: String get() = LegalRoutes.GUIDELINES
    val CONTACT: String get() = LegalRoutes.CONTACT

    /** Routes the hub treats as registered (real destinations or intentionally-surfaced stubs). */
    val REGISTERED: Set<String>
        get() = setOf(
            PROFILE,
            MESSAGES,
            CONTACTS_HUB,
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
            VOD_RENTALS,
            CLIPS,
            CALENDAR,
            GOOGLE_CALENDAR,
            CONTENT_CALENDAR,
            SCHEDULER,
            GALLERY,
            CATALOG,
            CART,
            WISHLIST,
            SELLER_STORE,
            SELLER_ORDERS,
            SELLER_SALES,
            FILES,
            TRADING_BLOTTER,
            HOME,
            CUSTODY,
            CUSTODY_PROVIDERS,
            PORTFOLIO,
            PNL,
            PAPER,
            REPORTS,
            PURCHASE_HISTORY,
            PAYMENT_METHODS,
            WALLET_TRANSACTIONS,
            WALLET,
            EARNINGS,
            TIP_INSIGHTS,
            PER_CONTENT_REVENUE,
            ENGAGEMENT,
            ANALYTICS_DASHBOARD,
            REFERRALS,
            ALERTS,
            MY_CONTENT_REVIEW,
            APPEALS,
            IDEAS,
            LICENSES,
            AGENT_CONFIGS,
            WORKERS,
            LLM_KEYS,
            FLEET,
            AGENT_TYPES,
            AGENT_FEEDBACK,
            AGENT_PRS,
            AGENT_MEMORY,
            DOC_COVERAGE,
            STYLIST,
            MARKETING,
            COSTS,
            COMPLIANCE,
            SECURITY,
            PM_IDEAS,
            WATCH_PARTIES,
            BOTS,
            AFFILIATES,
            PROMO_CODES,
            DISCOUNTS,
            PAYOUTS,
            PAYOUT_SETUP,
            BULK_PAYOUTS,
            BULK_PAYOUTS_PROMOTE,
            INVOICES,
            REFUNDS,
            DISPUTES,
            CREATOR_DISPUTES,
            TAX_DOCUMENTS,
            TAX_FORMS_1099,
            BILLING_CONFIG,
            SUBSCRIPTION_TIERS,
            CREATOR_SUBSCRIBERS,
            CREATOR_TIERS,
            MANAGE_SUBSCRIPTION,
            MY_SUBSCRIPTIONS,
            FAN_CLUB,
            ORGS_MEMBERS,
            GROUPS,
            SYNDICATES,
            MY_BUNDLES,
            SYNDICATE_CAMPAIGN,
            SYNDICATE_ADS,
            COLLABORATIONS,
            SPONSORSHIPS,
            SPONSORED_POST_COMPOSE,
            SPONSORED_POST_QUEUE,
            AD_MESSAGE_COMPOSE,
            AD_MESSAGE_QUEUE,
            AD_MASS_DM,
            ADS_ACCOUNTS,
            ADS_BILLING,
            AD_ANALYTICS,
            ADS_CAMPAIGNS,
            ADS_CREATE_ACCOUNT,
            ADS_CREATE_CAMPAIGN,
            ADS_CREATE_CREATIVE,
            ADS_TARGETING,
            ADS_SCHEDULING,
            ADS_OPTIMIZATION,
            CONTENT_AD_CONTROLS,
            BOOSTS,
            SEO,
            TICKETS,
            SUPPORT,
            WEBHOOKS,
            ADMIN_DASHBOARD,
            MARKETS,
            TOKENS,
            STRATEGIES,
            BAILOUTS,
            MARGIN_DISTRESS,
            BAILOUT_SETTINGS,
            ANALYSIS,
            GLOBAL_SEARCH,
            TRADING_ALERTS,
            ADMIN_EMAIL_DASHBOARD,
            ADMIN_SMS_DASHBOARD,
            ADMIN_MODERATION,
            ADMIN_AD_CREATIVE_REVIEW,
            ADMIN_AD_FRAUD,
            ADMIN_AD_PLATFORM,
            ADMIN_TAX_FORMS_1099,
            ADMIN_VIDEO_REVIEW,
            ADMIN_DMCA,
            ADMIN_REFUNDS,
            ADMIN_DISPUTES,
            ADMIN_APPEALS,
            ADMIN_FRAUD,
            ADMIN_PAYMENT_INCIDENTS,
            ADMIN_KYC_CASES,
            ADMIN_KYC_DOCUMENTS,
            ADMIN_KYC_RESIDENCY,
            ADMIN_KYC_PROOF_OF_FUNDS,
            ADMIN_KYC_LIVENESS,
            ADMIN_KYC_SCREENING,
            ADMIN_KYC_ID_SCANNER,
            ADMIN_KYC_BUSINESS,
            ADMIN_KYC_WORKLOAD,
            ADMIN_KYC_METRICS,
            ADMIN_KYC_ANALYTICS,
            ADMIN_KYC_MONITORING,
            ADMIN_KYC_ADDRESS_VERIFICATION,
            ADMIN_KYC_COMPLIANCE,
            ADMIN_KYC_TEMPLATES,
            ADMIN_KYC_TRANSLATIONS,
            ADMIN_FINANCIALS,
            ADMIN_PAYMENT_HEALTH,
            ADMIN_RISK,
            ADMIN_COMPUTE,
            ADMIN_JOBS,
            ADMIN_RATE_LIMITS,
            ADMIN_AUDIT_EXPORTS,
            ADMIN_TENANTS,
            ADMIN_SSO,
            ADMIN_ROLES,
            ADMIN_SUBSCRIPTION_TIER_MANAGER,
            INFRA_EC2,
            INFRA_K8S,
            INFRA_SECURITY_GROUPS,
            INFRA_HOSTS,
            INFRA_MONITORING,
            INFRA_BILLING,
            REMOTE_SSH_KEYS,
            REMOTE_SSH_RECORDINGS,
            REMOTE_BASTION,
            REMOTE_CONNECTION_PROFILES,
            REMOTE_TEMPLATES,
            REMOTE_DESKTOP,
            PROJECTS,
            DELEGATE_CONSOLE,
            DMCA,
            PRIVACY_EXPORT,
            KYC,
            API_KEYS,
            BLOCKED_USERS,
            SAFETY_CENTER,
            QUESTIONNAIRE_BUILDER,
            DELEGATION_KEYS,
            CUSTOM_EMOJIS,
            GEO_RULES,
            CALL_RATE,
            MESSAGE_PRIVACY,
            SETTINGS,
            HELP,
            ABOUT,
            TERMS,
            GUIDELINES,
            CONTACT,
        )
}

/** Resolves a [MoreRoutes] target to an in-shell tab where applicable. */
fun moreRouteToTab(route: String): AuthedTab? = when (route) {
    MoreRoutes.PROFILE -> AuthedTab.ME
    else -> null
}
