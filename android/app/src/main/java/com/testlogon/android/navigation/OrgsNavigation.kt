package com.testlogon.android.navigation

import androidx.hilt.navigation.compose.hiltViewModel
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import androidx.navigation.navigation
import com.testlogon.android.feature.orgs.InviteMemberRoute
import com.testlogon.android.feature.orgs.OrgMembersRoute
import com.testlogon.android.feature.orgs.OrgMembersViewModel

/** AND-353 - the nested orgs graph (its route is the More-hub entry point). */
data object OrgsGraphDest {
    const val ROUTE = "orgs"
}

/** AND-353 - the org members/roles route + the invite-member route (reached from the More hub). */
data object OrgMembersDest {
    const val ROUTE = "orgs/members"
}

/** AND-353 - the invite-member form route (opened from the members screen invite affordance). */
data object InviteMemberDest {
    const val ROUTE = "orgs/members/invite"
}

/**
 * AND-353 - registers the org members + invite destinations as a NESTED graph so both screens share ONE
 * graph-scoped [OrgMembersViewModel] (the invite's new pending invite then lands in the shared roster
 * state). The graph route ([OrgsGraphDest.ROUTE]) is the More-hub entry point.
 */
fun NavGraphBuilder.orgsDestinations(navController: NavHostController) {
    navigation(route = OrgsGraphDest.ROUTE, startDestination = OrgMembersDest.ROUTE) {
        composable(OrgMembersDest.ROUTE) { backStackEntry ->
            val parentEntry = rememberOrgsGraphEntry(navController, backStackEntry)
            OrgMembersRoute(
                onBack = { navController.popBackStack() },
                onOpenInvite = {
                    navController.navigate(InviteMemberDest.ROUTE) { launchSingleTop = true }
                },
                viewModel = hiltViewModel<OrgMembersViewModel>(parentEntry),
            )
        }
        composable(InviteMemberDest.ROUTE) { backStackEntry ->
            val parentEntry = rememberOrgsGraphEntry(navController, backStackEntry)
            InviteMemberRoute(
                onBack = { navController.popBackStack() },
                viewModel = hiltViewModel<OrgMembersViewModel>(parentEntry),
            )
        }
    }
}

/** Resolves (and remembers) the nested-orgs-graph back stack entry that scopes the shared ViewModel. */
@androidx.compose.runtime.Composable
private fun rememberOrgsGraphEntry(
    navController: NavHostController,
    backStackEntry: androidx.navigation.NavBackStackEntry,
): androidx.navigation.NavBackStackEntry =
    androidx.compose.runtime.remember(backStackEntry) {
        navController.getBackStackEntry(OrgsGraphDest.ROUTE)
    }
