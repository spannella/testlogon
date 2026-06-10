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
                    navController.navigate(route) { launchSingleTop = true }
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
        publicProfileDestination(navController)
        // AND-100: read-only post detail (in-app nav + deep link).
        postDetailDestination(navController)
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
        // AND-224/AND-226: saved payment-methods management + add-card (FLAGGED stub card-entry seam).
        billingDestinations(navController)
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
            // E50 reactivation/closure flows are out of scope; route to the privacy/lifecycle
            // surface as a safe handoff until those tickets register their own destinations.
            onReactivate = {
                navController.navigate(MainDest.SettingsPrivacy.route) { launchSingleTop = true }
            },
            onCloseAccount = {
                navController.navigate(MainDest.SettingsPrivacy.route) { launchSingleTop = true }
            },
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
    composable(MainDest.SettingsAppearance.route) {
        AppearanceSettingsRoute(onBack = { navController.popBackStack() })
    }
    composable(MainDest.SettingsLanguage.route) {
        LanguagePickerRoute(onBack = { navController.popBackStack() })
    }
    composable(MainDest.SettingsPrivacy.route) {
        PrivacySettingsScreen(
            onBack = { navController.popBackStack() },
            // Data export / deletion execution is owned by E50; handoff is a no-op for now.
            onRequestExport = {},
            onDeleteData = {},
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
