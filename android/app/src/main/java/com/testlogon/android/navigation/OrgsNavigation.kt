package com.testlogon.android.navigation

import androidx.compose.runtime.collectAsState
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import androidx.navigation.navigation
import com.testlogon.android.feature.orgs.InviteMemberRoute
import com.testlogon.android.feature.orgs.MyInvitesRoute
import com.testlogon.android.feature.orgs.OrgMembersRoute
import com.testlogon.android.feature.orgs.OrgMembersViewModel
import com.testlogon.android.feature.orgs.OrgOverviewRoute
import com.testlogon.android.feature.orgs.OrgOverviewViewModel
import com.testlogon.android.feature.orgs.TransferOwnershipRoute

/** AND-353 - the nested orgs graph (its route is the More-hub entry point). */
data object OrgsGraphDest {
    const val ROUTE = "orgs"
}

/**
 * AND-354 - the org OVERVIEW hub route (the graph's start destination). The More-hub "Organizations" entry
 * lands here, and Overview routes onward to the Members + My-Invites screens.
 */
data object OrgOverviewDest {
    const val ROUTE = "orgs/overview"
}

/** AND-353 - the org members/roles route + the invite-member route (reached from the More hub). */
data object OrgMembersDest {
    const val ROUTE = "orgs/members"
}

/** AND-353 - the invite-member form route (opened from the members screen invite affordance). */
data object InviteMemberDest {
    const val ROUTE = "orgs/members/invite"
}

/** AND-354 - the my-invites route (the caller's own pending invites; reached from Overview). */
data object MyInvitesDest {
    const val ROUTE = "orgs/my-invites"
}

/** PAR-35(c) - the transfer-ownership member-picker route (owner-only; reached from Overview). */
data object TransferOwnershipDest {
    const val ROUTE = "orgs/transfer-ownership"
}

/**
 * AND-353 / AND-354 - registers the orgs destinations as a NESTED graph. The members + invite screens
 * share ONE graph-scoped [OrgMembersViewModel] (the invite's new pending invite lands in the shared roster
 * state). AND-354 makes the Overview hub the start destination (the More-hub entry point) and adds the
 * My-Invites screen; Overview navigates to the existing Members route + the new My-Invites route.
 */
fun NavGraphBuilder.orgsDestinations(navController: NavHostController) {
    navigation(route = OrgsGraphDest.ROUTE, startDestination = OrgOverviewDest.ROUTE) {
        composable(OrgOverviewDest.ROUTE) { backStackEntry ->
            val overviewVm = hiltViewModel<OrgOverviewViewModel>()
            // PAR-35(c): when the transfer picker pops back with a success flag, reload the roles.
            val transferred = backStackEntry.savedStateHandle
                .getStateFlow(TRANSFER_RESULT_KEY, false)
                .collectAsState()
            androidx.compose.runtime.LaunchedEffect(transferred.value) {
                if (transferred.value) {
                    overviewVm.reloadAfterTransfer()
                    backStackEntry.savedStateHandle[TRANSFER_RESULT_KEY] = false
                }
            }
            OrgOverviewRoute(
                onBack = { navController.popBackStack() },
                onOpenMembers = {
                    navController.navigate(OrgMembersDest.ROUTE) { launchSingleTop = true }
                },
                onOpenInvites = {
                    navController.navigate(MyInvitesDest.ROUTE) { launchSingleTop = true }
                },
                onOpenTransfer = {
                    navController.navigate(TransferOwnershipDest.ROUTE) { launchSingleTop = true }
                },
                viewModel = overviewVm,
            )
        }
        composable(TransferOwnershipDest.ROUTE) {
            TransferOwnershipRoute(
                onBack = { navController.popBackStack() },
                onTransferred = {
                    navController.previousBackStackEntry
                        ?.savedStateHandle?.set(TRANSFER_RESULT_KEY, true)
                    navController.popBackStack()
                },
            )
        }
        composable(MyInvitesDest.ROUTE) {
            MyInvitesRoute(onBack = { navController.popBackStack() })
        }
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

/** PAR-35(c) - savedStateHandle key set by the transfer picker so Overview reloads its roles on return. */
private const val TRANSFER_RESULT_KEY = "orgs.transfer.result"
