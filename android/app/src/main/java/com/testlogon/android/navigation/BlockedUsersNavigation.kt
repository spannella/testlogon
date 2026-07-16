package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.blocking.BlockedUsersRoute

/**
 * P0-BLOCK — the Blocked Users management destination (Settings / Privacy). A single LIST screen
 * showing the users the caller has blocked (avatar + name) with a per-row, confirm-gated Unblock.
 * Registered in the authenticated graph and surfaced from the More hub (Privacy section) next to the
 * geo-blocking entry. Mirrors the API-keys list nav playbook (a leaf destination, no args).
 */
data object BlockedUsersDest {
    const val ROUTE = "blocked_users"
}

/** P0-BLOCK — registers the Blocked Users destination in the authenticated graph. */
fun NavGraphBuilder.blockedUsersDestinations(navController: NavHostController) {
    composable(route = BlockedUsersDest.ROUTE) {
        BlockedUsersRoute(onBack = { navController.popBackStack() })
    }
}
