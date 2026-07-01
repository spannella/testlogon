package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import androidx.navigation.navigation
import com.testlogon.android.feature.account.MfaDevicesRoute
import com.testlogon.android.feature.achievements.AchievementsRoute
import com.testlogon.android.feature.achievements.LeaderboardRoute
import com.testlogon.android.feature.activity.ActivityFeedRoute
import com.testlogon.android.feature.alerts.AlertPrefsRoute
import com.testlogon.android.feature.call.nav.callGraph
import com.testlogon.android.feature.messaging.nav.messagingGraph
import com.testlogon.android.feature.notifications.NotificationCenterRoute
import com.testlogon.android.feature.notifications.NotificationTarget
import com.testlogon.android.feature.profile.edit.EditProfileRoute
import com.testlogon.android.feature.saved.SavedRoute
import com.testlogon.android.feature.sessions.ActiveSessionsRoute
import com.testlogon.android.feature.settings.account.AccountSettingsRoute
import com.testlogon.android.feature.settings.appearance.AppearanceSettingsRoute
import com.testlogon.android.feature.settings.hub.SettingsHubRoute
import com.testlogon.android.feature.settings.language.LanguagePickerRoute
import com.testlogon.android.feature.settings.media.MediaPreferencesRoute
import com.testlogon.android.feature.settings.callrate.CallRateRoute
import com.testlogon.android.feature.settings.emojis.CustomEmojiRoute
import com.testlogon.android.feature.settings.geo.GeoSettingsRoute
import com.testlogon.android.feature.settings.misc.PrivacySettingsScreen
import com.testlogon.android.feature.settings.misc.SecuritySettingsScreen
import com.testlogon.android.feature.settings.notifications.NotificationPreferencesRoute
import com.testlogon.android.feature.shell.AuthedShellScreen

/**
 * Registers the authenticated graph (AND-024). Its start destination is the bottom-nav shell.
 * Entry into this graph is reserved for the auth gate (AND-025); no unauthenticated screen links
 * here directly. The Active Sessions screen (AND-043) is a full-screen destination reached from
 * the Profile tab.
 */
fun NavGraphBuilder.authenticatedGraph(navController: NavHostController) {
    navigation(
        route = TlGraphs.AUTHENTICATED,
        startDestination = MainDest.Shell.route,
    ) {
        composable(MainDest.Shell.route) {
            AuthedShellScreen(
                onOpenSessions = {
                    navController.navigate(MainDest.ActiveSessions.route) { launchSingleTop = true }
                },
                onOpenMfaDevices = {
                    navController.navigate(MainDest.MfaDevices.route) { launchSingleTop = true }
                },
                onEditProfile = {
                    navController.navigate(MainDest.EditProfile.route) { launchSingleTop = true }
                },
                onOpenRoute = { route ->
                    // Guard: a few hub routes may not be registered as destinations yet; ignore those
                    // (no-op) rather than crashing the app on a missing navigation target.
                    runCatching { navController.navigate(route) { launchSingleTop = true } }
                },
            )
        }
        composable(MainDest.ActiveSessions.route) {
            ActiveSessionsRoute(onBack = { navController.popBackStack() })
        }
        composable(MainDest.MfaDevices.route) {
            MfaDevicesRoute(onBack = { navController.popBackStack() })
        }
        // AND-085: notification center (paged list + deep-link routing).
        composable(MainDest.Notifications.route) {
            NotificationCenterRoute(
                onNavigateTarget = { target -> navController.navigateToNotificationTarget(target) },
                onBack = { navController.popBackStack() },
            )
        }
        // AND-091: account activity feed (paged).
        composable(MainDest.Activity.route) {
            ActivityFeedRoute(onBack = { navController.popBackStack() })
        }
        // AND-120..124: messaging (conversation list + thread). First M3 two-user feature.
        messagingGraph(navController)
        // AND-295..297: 1:1 calling — outgoing-call screen + call history. The incoming full-screen UI
        // is a separate lock-screen Activity (IncomingCallActivity), launched by the call notification.
        callGraph(navController)
        // AND-092: saved / bookmarks (paged + unsave). Row-open is delegated to E14/E24 detail
        // screens that are not yet wired, so it is a safe no-op for now.
        composable(MainDest.Saved.route) {
            SavedRoute(onBack = { navController.popBackStack() })
        }
        // AND-093: achievements (earned/locked + progress); links to the leaderboard.
        composable(MainDest.Achievements.route) {
            AchievementsRoute(
                onBack = { navController.popBackStack() },
                onOpenLeaderboard = {
                    navController.navigate(MainDest.Leaderboard.route) { launchSingleTop = true }
                },
            )
        }
        // AND-094: achievements leaderboard.
        composable(MainDest.Leaderboard.route) {
            LeaderboardRoute(onBack = { navController.popBackStack() })
        }
        // AND-077..082: Settings hub + subsections.
        settingsDestinations(navController)
        // AND-072: edit own profile, reached from the Profile tab.
        composable(MainDest.EditProfile.route) {
            EditProfileRoute(onNavigateBack = { navController.popBackStack() })
        }
        // AND-073: public profile (also registered unauthenticated for shared links).
        publicProfileDestination(
            navController,
            onOpenFanClub = { creatorId, displayName ->
                navController.navigate(FanClubChannelsDest.build(creatorId, displayName)) {
                    launchSingleTop = true
                }
            },
        )
        // AND-100: read-only post detail (in-app nav + deep link).
        postDetailDestination(navController)
        // AND-364: content boost (paid post promotion) - budget/duration form -> create -> status watch
        // with cancel/refund while active. Route reachable via navigateToBoost(postId); deeper post-detail /
        // composer-success CTA wiring is FLAGGED (see BoostNavigation) to avoid regressing those screens.
        boostDestination(navController)
        // Web-parity boost MANAGEMENT: list (/ads/boost) + detail-by-boostId (/ads/boost/:boostId),
        // reusing the existing boost network client + repository (no new network code).
        boostManageDestinations(navController)
        // AND-367: ads-account billing read view (balance / lifetime-spend summary + billing-history ledger
        // + monthly invoice) + the DEPOSIT (add-funds) sheet. First MUTATING ads feature. Route reachable via
        // navigateToAdsBilling(accountId); the More-hub uses a sample account id (no ads-accounts list yet).
        adsBillingDestination(navController)
        // AND-368: READ-ONLY ad-analytics dashboard (KPI summary + time-series charts + breakdown over a
        // selectable date range). Route reachable via navigateToAdAnalytics(accountId); the More-hub uses a
        // sample account id (no ads-accounts list yet).
        adAnalyticsDestination(navController)
        // AND-369: READ-ONLY ads-campaigns list (ads-campaigns/{accountId}) - the account's campaigns
        // (name/status/budget/spend). Route reachable via navigateToAdsCampaigns(accountId); the More-hub
        // uses a sample account id (no ads-accounts list yet).
        adsCampaignsDestination(navController)
        // Web-parity ads STUDIO editors (targeting / scheduling / optimization). Each VM self-resolves
        // the caller's first ad account then first campaign (no campaign-picker nav yet); routes reachable
        // via navigateToAdTargeting / navigateToAdScheduling / navigateToAdOptimization.
        adTargetingDestination(navController)
        adSchedulingDestination(navController)
        adOptimizationDestination(navController)
        // Web-parity CONTENT AD-CONTROLS (per-content overrides + revenue share + ad-revenue
        // transparency/breakdown). Caller-scoped; no nav arg.
        contentAdControlsDestination(navController)
        // AND-400: READ-ONLY public SEO metadata inspector (seo/{resourceType}/{id}). Diagnostic preview
        // of the title / og / twitter / json-ld a crawler sees. Route reachable via navigateToSeo(type, id);
        // the More-hub uses a sample profile resource (no per-resource detail wiring this wave).
        seoDestination(navController)
        // AND-183: tag pages (in-app nav + App Link / dev-host deep links).
        tagPageDestination(navController)
        // AND-185: global multi-entity search (distinct from AND-152 message search).
        multiSearchDestination(navController)
        // AND-189: the caller's videos library grid.
        videosLibraryDestination(navController)
        // AND-191: the public VOD catalog (browse on-demand titles).
        vodCatalogDestination(navController)
        // AND-190: video detail + reusable player (shared by library, VOD, and discover recs).
        videoDetailDestination(navController)
        // AND-196: clips vertical pager (gallery feed) + public single-clip viewer (deep link).
        clipsFeedDestination(navController)
        publicClipDestination(navController)
        // AND-199/AND-200: full-screen story viewer (opened from the feed stories tray).
        storyViewerDestination(navController)
        // AND-201: published video gallery browse grid (tiles open the shared video detail route).
        galleryDestination(navController)
        // Newsfeed post compose (create a post).
        composePostDestination(navController)
        myPostsDestination(navController)
        // VOD upload (publish a video).
        videoUploadDestination(navController)
        // AND-332: read-only file-manager browse (path nav + breadcrumbs + search + sort + paged listing).
        filesDestination(navController)
        // AND-336: backend-mediated Google Drive import picker (authenticated-only).
        driveImportDestination(navController)
        // AND-335: owner share sheet (create/list/revoke share links) + the public share screen
        // (also registered unauthenticated, since a recipient may be signed out).
        shareSheetDestination(navController)
        publicShareDestination(navController)
        // AND-393: public fundraiser donation (App Link /donate/{fundraiserId}), anonymous-capable; also
        // registered unauthenticated since a donor may be signed out.
        donationDestination(navController)
        // AND-349: editable questionnaire respondent renderer (reached after the AND-395 entry resolves a
        // session); anonymous, also registered unauthenticated.
        questionnaireRespondDestination(navController)
        // AND-395: PUBLIC unauthenticated entry (App Link .../published/{slug}/respond) - resolves the
        // slug + an anonymous session, then forwards to the renderer above; also registered unauthenticated.
        publicQuestionnaireRespondDestination(navController)
        // AND-205: storefront catalog / category browse grid (cells open the product detail route).
        catalogDestination(navController)
        // AND-206: real product detail (item derived from the category-items list; add-to-cart).
        productDetailDestination(navController)
        // AND-207: catalog full-text search (rows open the product detail route).
        catalogSearchDestination(navController)
        // AND-211/AND-212: shopping cart (line items, qty edit, remove, in-cart search).
        cartDestination(navController)
        // AND-213: checkout session / order review (reached from the cart "Proceed to checkout").
        orderReviewDestination(navController)
        // AND-214: address step (saved-address list/add/select/set-primary; no shipping quote backend).
        addressShippingDestination(navController)
        // AND-215/AND-220: order (transaction) detail host that embeds the AND-215 tracking section.
        trackingDestination(navController)
        // AND-219: purchase history list + search (rows open the AND-220 order detail).
        purchaseHistoryDestination(navController)
        vodRentalsDestination(navController)
        // AND-224/AND-226: saved payment-methods management + add-card (FLAGGED stub card-entry seam).
        billingDestinations(navController)
        // PW18: Wallet transactions (ledger) history (BK3 GET /ui/billing/ledger + /ui/billing/wallet).
        walletTransactionsDestination(navController)
        // AND-227/228/229/230: redirect checkout (hosted/PayPal/CCBill via Custom Tabs, gated by the
        // BillingAuthorizer stub) + US-bank micro-deposit verification.
        paymentsDestinations(navController)
        // AND-235: subscription tiers browse (tier cards + current-plan badge + flag/stub-gated CTA).
        subscriptionTiersDestination(navController)
        // AND-236: subscribe confirmation flow (review tier -> BillingAuthorizer-gated pay -> subscribe).
        subscribeDestination(navController)
        // AND-237: manage / cancel subscription (status/renewal + cancel-at-period-end + resume/renew).
        manageSubscriptionDestination(navController)
        // AND-238/239/240: fan-club channels list (tier-grouped) + channel messages + tier members.
        fanClubDestinations(navController)
        // AND-243: invoices list (paged) + invoice detail (line items/totals + email + view-PDF).
        invoicesDestinations(navController)
        // AND-244: refund-requests list + submit (from order/txn detail) + detail (status tracking).
        refundsDestinations(navController)
        // AND-245: disputes list + file (open a dispute from order/txn detail) + detail (status).
        disputesDestinations(navController)
        // AND-246: tax-documents list + view/download PDF (Custom Tabs, reusing the AND-243 launcher).
        taxDocsDestination(navController)
        // AND-247: 1099-NEC tax-forms list + download PDF (resolves download_url, reuses the launcher).
        form1099Destination(navController)
        // AND-248: admin billing-config read-only view (effective config; root-gated server-side).
        billingConfigDestination(navController)
        // AND-403: read-only admin alerts/dashboards (client-aggregated job + webhook health; 403 self-gate).
        adminDashboardDestination(navController)
        // AND-404: read-only admin email/SMS delivery dashboards (per-channel stats + recent activity; 403
        // self-gate). One generic VM; channel via nav arg.
        messagingDashboardDestinations(navController)
        // AND-252/253: creator earnings dashboard (totals + Canvas chart + breakdown) and the
        // per-content revenue list (cursor-paged, sortable).
        earningsDestinations(navController)
        // AND-254: creator engagement-rate analytics (server rate + trend chart + breakdown).
        engagementDestinations(navController)
        // AND-399: account-wide analytics dashboards (read) — KPI tiles + views/subscriber charts +
        // top-content/audience breakdowns over a selectable range (fan-out across /ui/analytics/*).
        analyticsDashboardDestination(navController)
        // AND-258/259/260: creator payouts — setup (+ FLAGGED KYC gate) + paged history + detail.
        payoutsDestinations(navController)
        // AND-264: referrals dashboard (code/link + stats + share/copy + create-code CTA).
        referralsDestination(navController)
        // Alerts (system notifications) inbox.
        alertsDestination(navController)
        // Account-action appeals.
        appealsDestination(navController)
        ideasDestination(navController)
        licensesDestination(navController)
        agentConfigDestinations(navController)
        // B4 web-parity: Stylist / UI-design agent (overview + rules + review detail).
        stylistDestinations(navController)
        // B4 web-parity: Marketing content agent (dashboard + editor + calendar + engagement).
        marketingDestinations(navController)
        // B4 web-parity: Accountant/cost agent (overview + breakdown + budgets + alerts).
        costsDestinations(navController)
        // B4 web-parity: Compliance/Security agent (findings + audits + compliance + trends).
        complianceDestinations(navController)
        // B4 web-parity: PM feature-idea triage (pending/approved/rejected/archived).
        pmIdeasDestinations(navController)
        watchPartiesDestinations(navController)
        botsDestinations(navController)
        // AND-265: affiliates dashboard (client-aggregated earnings + reusable chart + links list).
        affiliatesDestination(navController)
        // AND-266: promo codes (list + create via plain CRUD; deactivate; usage/expiry/discount).
        promoDestination(navController)
        // AND-267: affiliate discounts (read-only list of discounts attached to the caller's ad creatives).
        discountsDestination(navController)
        // AND-271: calendar Month/Week/Agenda views (reached from the More hub).
        calendarDestination(navController)
        // AND-272: event detail + public event (also registered unauthenticated for shared links).
        eventDetailDestination(navController)
        // AND-273: Google Calendar integration (backend OAuth redirect; Custom-Tab connect/link status).
        googleCalendarDestination(navController)
        // AND-274: content calendar (read-only scheduled-content schedule/agenda view).
        contentCalendarDestination(navController)
        // AND-275: scheduler (list + create/edit sheet for scheduled actions).
        schedulerDestinations(navController)
        // AND-279/AND-280/AND-281: broadcast browse + viewer playback (HLS) + live chat panel.
        broadcastDestinations(navController)
        // AND-312: guest accept (testlogon://guest/accept) — also registered in the unauthenticated graph.
        guestAcceptDestination(navController)
        // AND-320: KYC tier status (current tier + target requirements checklist + Evaluate action).
        kycTierDestination(navController)
        // Batch-9 (#18): guided KYC verification wizard (email -> phone -> ID -> done) replacing the
        // confusing fragmented flow. Reached from the Tier-status "Begin verification" CTA.
        kycWizardDestination(navController)
        // AND-321: KYC identity-document capture+upload (system camera / photo picker + inline base64 POST).
        kycDocumentCaptureDestination(navController)
        // AND-322: KYC guided ID capture+scan (validate-document + per-side upload + scan-document).
        idScannerDestination(navController)
        // AND-323: KYC facial comparison (selfie capture + server-side face comparison + history).
        faceComparisonDestination(navController)
        // AND-324: KYC scheduled liveness (video-verification) call (real REST scheduling; join_url opens externally).
        livenessCallDestination(navController)
        // AND-325: KYC electronic ID verification (real REST redirect eIDV; redirect_url opens externally + poll).
        eidvDestination(navController)
        // AND-326: KYC residency (proof-of-residency document upload + structured address verification; real REST).
        residencyDestination(navController)
        // AND-327: KYC proof-of-funds (summary + submissions + submit with an optional document key; real REST).
        proofOfFundsDestination(navController)
        // AND-328: KYC screening status (READ-ONLY sanctions / PEP / adverse-media aggregated into one status).
        screeningDestination(navController)
        // AND-329: KYC case status + monitoring (READ-ONLY case list + synthesized timeline + monitoring banner).
        kycCasesDestinations(navController)
        // AND-340: e-signature Signing entry (load-by-id / create-draft) + packet DETAIL (status, signers,
        // field-manifest placeholder, events, status-driven action). No backend packet-list endpoint, so
        // the "list" half is deferred.
        signingDestinations(navController)
        // AND-353: organizations members/roles (list members + pending invites + invite/change-role/
        // remove with permission gating + self-protection). Nested graph so the members + invite screens
        // share one ViewModel.
        orgsDestinations(navController)
        // AND-355: social groups (discover -> detail -> members with role-gated invite/change-role/remove
        // + leave). Nested graph: GroupsList -> GroupDetail{groupId} -> GroupMembers{groupId}.
        groupsDestinations(navController)
        // AND-356: READ-ONLY syndicate overview (Feed / Treasury / Revenue-split tabs over /ui/syndicates/*).
        // Single screen keyed by {syndicateId}; write actions + open-licensing are downstream / OUT OF SCOPE.
        syndicateDestinations(navController)
        // Web-parity: My Bundles (the caller's active syndicate bundle subscriptions + per-bundle cancel)
        // over GET /ui/syndicates/my-bundles + the subscription cancel endpoint.
        myBundlesDestinations(navController)
        // Web-parity: syndicate-advertising campaign DETAIL (KPI + daily analytics + creative + budget; admin
        // pause/resume/cancel + add-budget) over /ui/syndicates/advertising/{sid}/campaigns/{cid}*.
        campaignDetailDestinations(navController)
        // AND-358: READ-ONLY collaborations (Paging-3 list -> detail with the two parties + status + the
        // revenue split over /ui/collaborations/*). Write actions are OUT OF SCOPE.
        collaborationsDestinations(navController)
        // AND-365: READ-ONLY sponsorship inbox (single GET list of inbound brand deals + client-side status
        // filter over /ui/ads/sponsorships) + a thin deal-detail placeholder. Accept / reject / negotiate
        // live in the detail (AND-366) and are OUT OF SCOPE.
        sponsorshipDestinations(navController)
        // AND-372: READ-ONLY ticket spaces + threads (support / helpdesk). Spaces list -> a space's ticket
        // list (Paging-3 over the AND-371 next_cursor) -> a ticket thread (embedded messages, mine-vs-other).
        // Composing / replying / member or status edits are AND-373 and OUT OF SCOPE.
        ticketsDestinations(navController)
        // B-SUP (batch 7): role-branched Support. The landing resolves /ui/me.is_admin and renders the
        // USER help experience (create + view my tickets) or the ADMIN helpdesk/moderation queue, then
        // drills into a shared ticket thread (isAdmin nav arg gates the admin status/assign controls).
        supportDestinations(navController)
        // AND-398: WEBHOOKS config (light). List of outbound webhook endpoints -> detail -> a LIGHT create
        // (url + event_types only). Update / delete / rotate / deliveries are FR-6 out-of-scope.
        webhooksDestinations(navController)
        // B-APIKEY (batch 7): developer API-keys management. List (label/prefix/created+expiry/scopes) with a
        // per-row revoke -> a create that shows the one-time secret exactly once. Backed by /ui/api_keys.
        apiKeysDestinations(navController)
        // Web-parity: questionnaire BUILDER (creator authoring). Drafts list -> create -> per-draft
        // editor (sections + 9 question types + publish) over /questionnaires/drafts*.
        questionnaireBuilderDestinations(navController)
        // Web-parity: delegation-API keys (/delegation-api) - the DELEGATED-access keys (a tool acting on a
        // creator's behalf), distinct from the personal developer keys above. Two tabs (My Keys / Keys For
        // My Account) + create-shown-once over /ui/delegation-api/*.
        delegationKeysDestinations(navController)
        // AND-374: projects (paged list -> detail with the account-scoped Google Drive provider connect flow,
        // server-mediated OAuth via a Custom Tab + a testlogon://projects/.../callback return deep link).
        projectsDestinations(navController)
        // AND-360: delegate console (the focused manage-as-creator demonstration) - lists the managed
        // creator's delegate feed posts + conversations and offers create-post / send-message gated by
        // feed_post / chat_respond, with the persistent banner. Overlay-only; the mature feed / broadcast /
        // messaging screens are untouched.
        delegateConsoleDestination(navController)
        // AND-384: DMCA copyright-takedown submit form. Reachable standalone (Settings -> Privacy & Safety)
        // and pre-targeted from a content / profile overflow (prefills + locks the content reference via
        // navigateToDmca). A single non-idempotent POST v1/dmca/claims; no auto-retry.
        dmcaDestination(navController)
        // AND-385: Privacy & Data Export. Authenticated request -> status -> download lifecycle over the
        // /ui/privacy/account-deletion/export + /ui/privacy/requests endpoints; Room-cached for offline.
        privacyExportDestination(navController)
        // AND-386: Account deletion request. Multi-step confirm -> request -> pending -> cancel over the
        // /ui/privacy/account-deletion/request + .../requests + .../requests/{id}/cancel endpoints.
        accountDeletionDestination(navController)
        // AND-387 (E50): account lifecycle - closure (start/finalize), suspend, reactivate over the
        // /ui/account/closure/* + /ui/account/suspend + /ui/account/reactivate endpoints.
        accountLifecycleDestinations(navController)
    }
}

/**
 * AND-077..082 — registers the Settings hub and its six subsections against the route constants in
 * [MainDest]. Destinations that belong to other tickets/epics (closure, data export) are handed off
 * via callbacks; until those land they resolve to existing surfaces or no-op safely.
 */
private fun NavGraphBuilder.settingsDestinations(navController: NavHostController) {
    composable(MainDest.Settings.route) {
        SettingsHubRoute(
            onOpenSection = { route -> navController.navigate(route) { launchSingleTop = true } },
            onBack = { navController.popBackStack() },
        )
    }
    composable(MainDest.SettingsAccount.route) {
        AccountSettingsRoute(
            onBack = { navController.popBackStack() },
            onOpenSessions = {
                navController.navigate(MainDest.ActiveSessions.route) { launchSingleTop = true }
            },
            onOpenMfaDevices = {
                navController.navigate(MainDest.MfaDevices.route) { launchSingleTop = true }
            },
            onOpenPrivacy = {
                navController.navigate(MainDest.SettingsPrivacy.route) { launchSingleTop = true }
            },
            // AND-387 (E50): the lifecycle flows now own their destinations. onCloseAccount fires only
            // after the AND-082 confirm gate, then deep-links into the closure flow (which adds its own
            // re-auth + typed-CLOSE guard before the irreversible finalize).
            onReactivate = { navController.navigateToAccountReactivate() },
            onSuspend = { navController.navigateToAccountSuspend() },
            onCloseAccount = { navController.navigateToAccountClosure() },
        )
    }
    composable(MainDest.SettingsSecurity.route) {
        SecuritySettingsScreen(
            onBack = { navController.popBackStack() },
            onOpenSessions = {
                navController.navigate(MainDest.ActiveSessions.route) { launchSingleTop = true }
            },
            onOpenMfaDevices = {
                navController.navigate(MainDest.MfaDevices.route) { launchSingleTop = true }
            },
        )
    }
    composable(MainDest.SettingsNotifications.route) {
        NotificationPreferencesRoute(onBack = { navController.popBackStack() })
    }
    // AND-088: alert preferences — email/SMS alert target management. Links to the AND-080
    // type-preferences screen rather than duplicating the alert event-type matrix.
    composable(MainDest.SettingsAlerts.route) {
        AlertPrefsRoute(
            onBack = { navController.popBackStack() },
            onOpenTypePreferences = {
                navController.navigate(MainDest.SettingsNotifications.route) { launchSingleTop = true }
            },
        )
    }
    composable(MainDest.SettingsMedia.route) {
        MediaPreferencesRoute(onBack = { navController.popBackStack() })
    }
    composable(MainDest.SettingsEmojis.route) {
        CustomEmojiRoute(onBack = { navController.popBackStack() })
    }
    composable(MainDest.SettingsGeo.route) {
        GeoSettingsRoute(onBack = { navController.popBackStack() })
    }
    composable(MainDest.SettingsCallRate.route) {
        CallRateRoute(onBack = { navController.popBackStack() })
    }
    composable(MainDest.SettingsAppearance.route) {
        AppearanceSettingsRoute(onBack = { navController.popBackStack() })
    }
    composable(MainDest.SettingsLanguage.route) {
        LanguagePickerRoute(onBack = { navController.popBackStack() })
    }
    composable(MainDest.SettingsPrivacy.route) {
        PrivacySettingsScreen(
            onBack = { navController.popBackStack() },
            // AND-385 owns the export surface; AND-386 wires the account-deletion request flow.
            onRequestExport = { navController.navigateToPrivacyExport() },
            onDeleteData = { navController.navigateToAccountDeletion() },
        )
    }
}

/**
 * AND-085 — routes a tapped notification's resolved [NotificationTarget] to an in-app destination.
 * Targets whose backing route is not yet wired (or that are [NotificationTarget.Unknown]) are
 * no-oped safely rather than crashing.
 *
 * AND-108 reuses this same routing (and the [NotificationTargetResolver]) for FCM push-notification
 * taps, so in-app and push notifications resolve to identical destinations.
 */
internal fun NavHostController.navigateToNotificationTarget(target: NotificationTarget) {
    when (target) {
        is NotificationTarget.Profile ->
            navigate(PublicProfileDest.build(target.identifier)) { launchSingleTop = true }
        NotificationTarget.Sessions ->
            navigate(MainDest.ActiveSessions.route) { launchSingleTop = true }
        NotificationTarget.Settings ->
            navigate(MainDest.Settings.route) { launchSingleTop = true }
        NotificationTarget.Unknown ->
            // No first-party detail route yet for this kind — land on the Notification Center so a
            // push tap is never a dead end (AND-108 §13 R1; swap to a per-entity route on merge).
            navigate(MainDest.Notifications.route) { launchSingleTop = true }
    }
}
