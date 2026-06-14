package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.feature.admin.ARG_DASHBOARD_CHANNEL
import com.testlogon.android.feature.admin.EmailDashboardRoute
import com.testlogon.android.feature.admin.SmsDashboardRoute

/**
 * AND-404 - the READ-ONLY admin email/SMS delivery dashboard destinations, registered in the AUTHENTICATED nav
 * graph (one shared graph; NOT forked), building on the AND-403 admin surface. Each route carries a `{channel}`
 * path arg consumed by the generic [com.testlogon.android.feature.admin.MessagingDashboardViewModel] via
 * SavedStateHandle, so a single VM serves both screens (AND-404 §4). Role gating matches AND-403: the VM's
 * client-side pre-check (a verified non-admin -> Forbidden, no fetch) + the backend `403` (the final authority),
 * rendered as the non-destructive Forbidden state with Back - a non-admin who deep-links here issues no admin
 * data render (AND-404 FR6 / AC5 / TC-14). There is NO mutation affordance anywhere (read-only - AC2).
 */
data object MessagingDashboardDest {
    /** Route template with the channel path arg; the two concrete entry routes live in [MoreRoutes]. */
    const val ROUTE = "admin/messaging-dashboard/{$ARG_DASHBOARD_CHANNEL}"

    const val CHANNEL_EMAIL = "email"
    const val CHANNEL_SMS = "sms"

    const val EMAIL_ROUTE = "admin/messaging-dashboard/$CHANNEL_EMAIL"
    const val SMS_ROUTE = "admin/messaging-dashboard/$CHANNEL_SMS"
}

/** AND-404 - registers the email + sms delivery dashboard destinations (Back pops the back stack). */
fun NavGraphBuilder.messagingDashboardDestinations(navController: NavHostController) {
    composable(
        route = MessagingDashboardDest.ROUTE,
        arguments = listOf(navArgument(ARG_DASHBOARD_CHANNEL) { type = NavType.StringType }),
    ) { entry ->
        val channel = entry.arguments?.getString(ARG_DASHBOARD_CHANNEL)
        if (channel == MessagingDashboardDest.CHANNEL_SMS) {
            SmsDashboardRoute(onBack = { navController.popBackStack() })
        } else {
            EmailDashboardRoute(onBack = { navController.popBackStack() })
        }
    }
}
