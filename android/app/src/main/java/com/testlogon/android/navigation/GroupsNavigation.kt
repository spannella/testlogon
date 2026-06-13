package com.testlogon.android.navigation

import android.net.Uri
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import androidx.navigation.navigation
import com.testlogon.android.feature.groups.GroupDetailRoute
import com.testlogon.android.feature.groups.GroupMembersRoute
import com.testlogon.android.feature.groups.GroupsListRoute

/** AND-355 - the nested social-groups graph (its route is the More-hub entry point). */
data object GroupsGraphDest {
    const val ROUTE = "groups"
}

/** AND-355 - the groups discovery list route (the graph's start destination, the More-hub landing). */
data object GroupsListDest {
    const val ROUTE = "groups/list"
}

/** AND-355 - the group detail route (carries the {groupId} nav arg). */
data object GroupDetailDest {
    const val ARG_GROUP_ID = "groupId"
    const val ROUTE = "groups/detail/{$ARG_GROUP_ID}"

    fun build(groupId: String): String = "groups/detail/${Uri.encode(groupId)}"
}

/** AND-355 - the group members route (carries the {groupId} nav arg). */
data object GroupMembersDest {
    const val ARG_GROUP_ID = "groupId"
    const val ROUTE = "groups/members/{$ARG_GROUP_ID}"

    fun build(groupId: String): String = "groups/members/${Uri.encode(groupId)}"
}

/**
 * AND-355 - registers the social-groups destinations as a NESTED graph: GroupsList -> GroupDetail{groupId}
 * -> GroupMembers{groupId}. The detail + members ViewModels read groupId from SavedStateHandle (the nav
 * arg). A successful Leave pops the detail back to the list (the cache is dropped on the next list load).
 * Dissolve / discover / requests are OUT OF SCOPE.
 */
fun NavGraphBuilder.groupsDestinations(navController: NavHostController) {
    navigation(route = GroupsGraphDest.ROUTE, startDestination = GroupsListDest.ROUTE) {
        composable(GroupsListDest.ROUTE) {
            GroupsListRoute(
                onBack = { navController.popBackStack() },
                onOpenGroup = { groupId ->
                    navController.navigate(GroupDetailDest.build(groupId)) { launchSingleTop = true }
                },
            )
        }
        composable(
            route = GroupDetailDest.ROUTE,
            arguments = listOf(navArgument(GroupDetailDest.ARG_GROUP_ID) { type = NavType.StringType }),
        ) {
            GroupDetailRoute(
                onBack = { navController.popBackStack() },
                onLeft = { navController.popBackStack() },
                onOpenMembers = { groupId ->
                    navController.navigate(GroupMembersDest.build(groupId)) { launchSingleTop = true }
                },
            )
        }
        composable(
            route = GroupMembersDest.ROUTE,
            arguments = listOf(navArgument(GroupMembersDest.ARG_GROUP_ID) { type = NavType.StringType }),
        ) {
            GroupMembersRoute(onBack = { navController.popBackStack() })
        }
    }
}
