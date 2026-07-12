package com.testlogon.android.navigation

import android.net.Uri
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.feature.watchparties.WatchPartiesListRoute
import com.testlogon.android.feature.watchparties.WatchPartyDetailRoute
import com.testlogon.android.feature.watchparties.WatchPartyInviteRoute

/**
 * Watch-parties destinations (web parity: /watch-parties, /watch-parties/:partyId, /party/:inviteCode).
 *
 * The list opens a party's detail via [WatchPartiesDest.detail]; the invite route resolves a code to a
 * party id (GET ui/watch-parties/join/{code}) then *replaces itself* with the detail destination so
 * Back from detail returns to wherever the invite was opened from, not the transient resolver.
 */
data object WatchPartiesDest {
    const val ROUTE = "watch-parties"
    const val LIST = "watch-parties"
    const val DETAIL = "watch-parties/{partyId}"
    const val ARG_PARTY_ID = "partyId"

    const val INVITE = "party/{inviteCode}"
    const val ARG_INVITE_CODE = "inviteCode"

    fun detail(id: String): String = "watch-parties/${Uri.encode(id)}"

    fun invite(code: String): String = "party/${Uri.encode(code)}"
}

/** Registers the watch-parties list + detail + invite destinations in the authenticated graph. */
fun NavGraphBuilder.watchPartiesDestinations(navController: NavHostController) {
    composable(WatchPartiesDest.LIST) {
        WatchPartiesListRoute(
            onBack = { navController.popBackStack() },
            onOpenParty = { partyId ->
                navController.navigate(WatchPartiesDest.detail(partyId)) { launchSingleTop = true }
            },
            onSessionExpired = { navController.popBackStack() },
        )
    }

    composable(
        route = WatchPartiesDest.DETAIL,
        arguments = listOf(
            navArgument(WatchPartiesDest.ARG_PARTY_ID) { type = NavType.StringType },
        ),
    ) {
        WatchPartyDetailRoute(
            onBack = { navController.popBackStack() },
            onSessionExpired = { navController.popBackStack() },
        )
    }

    composable(
        route = WatchPartiesDest.INVITE,
        arguments = listOf(
            navArgument(WatchPartiesDest.ARG_INVITE_CODE) { type = NavType.StringType },
        ),
    ) {
        WatchPartyInviteRoute(
            onResolved = { partyId ->
                navController.navigate(WatchPartiesDest.detail(partyId)) {
                    popUpTo(WatchPartiesDest.INVITE) { inclusive = true }
                    launchSingleTop = true
                }
            },
            onBack = { navController.popBackStack() },
        )
    }
}
