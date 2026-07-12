package com.testlogon.android.navigation

import android.net.Uri
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import androidx.navigation.navigation
import com.testlogon.android.feature.groups.GroupAdsRoute
import com.testlogon.android.feature.groups.GroupDetailRoute
import com.testlogon.android.feature.groups.GroupFeedRoute
import com.testlogon.android.feature.groups.GroupFundraisingRoute
import com.testlogon.android.feature.groups.GroupMembersRoute
import com.testlogon.android.feature.groups.GroupSettingsRoute
import com.testlogon.android.feature.groups.GroupTreasuryRoute
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

/** Batch-8 (#11) - the group feed route (carries the {groupId} nav arg). */
data object GroupFeedDest {
    const val ARG_GROUP_ID = "groupId"
    const val ROUTE = "groups/{$ARG_GROUP_ID}/feed"

    fun build(groupId: String): String = "groups/${Uri.encode(groupId)}/feed"
}

/** AND-355 (sub-pages) - the group treasury route (carries the {groupId} nav arg). */
data object GroupTreasuryDest {
    const val ARG_GROUP_ID = "groupId"
    const val ROUTE = "groups/{$ARG_GROUP_ID}/treasury"

    fun build(groupId: String): String = "groups/${Uri.encode(groupId)}/treasury"
}

/** AND-355 (sub-pages) - the group fundraising route (carries the {groupId} nav arg). */
data object GroupFundraisingDest {
    const val ARG_GROUP_ID = "groupId"
    const val ROUTE = "groups/{$ARG_GROUP_ID}/fundraising"

    fun build(groupId: String): String = "groups/${Uri.encode(groupId)}/fundraising"
}

/** AND-355 (sub-pages) - the group advertising route (carries the {groupId} nav arg). */
data object GroupAdsDest {
    const val ARG_GROUP_ID = "groupId"
    const val ROUTE = "groups/{$ARG_GROUP_ID}/ads"

    fun build(groupId: String): String = "groups/${Uri.encode(groupId)}/ads"
}

/** AND-355 (sub-pages) - the group settings route (carries the {groupId} nav arg). */
data object GroupSettingsDest {
    const val ARG_GROUP_ID = "groupId"
    const val ROUTE = "groups/{$ARG_GROUP_ID}/settings"

    fun build(groupId: String): String = "groups/${Uri.encode(groupId)}/settings"
}

/**
 * AND-355 - registers the social-groups destinations as a NESTED graph: GroupsList -> GroupDetail{groupId}
 * -> {GroupMembers / GroupTreasury / GroupFundraising / GroupAds / GroupSettings}{groupId}. Every
 * sub-screen ViewModel reads groupId from SavedStateHandle (the nav arg). A successful Leave pops the
 * detail back to the list (the cache is dropped on the next list load).
 */
fun NavGraphBuilder.groupsDestinations(navController: NavHostController) {
    navigation(route = GroupsGraphDest.ROUTE, startDestination = GroupsListDest.ROUTE) {
        composable(GroupsListDest.ROUTE) {
            GroupsListRoute(
                onBack = { navController.popBackStack() },
                onOpenGroup = { groupId ->
                    // Batch-9 (#10): opening a group lands on the GROUP FEED first; the feed's gear
                    // icon reaches the group hub (members / settings / treasury / etc.).
                    navController.navigate(GroupFeedDest.build(groupId)) { launchSingleTop = true }
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
                onOpenFeed = { groupId ->
                    navController.navigate(GroupFeedDest.build(groupId)) { launchSingleTop = true }
                },
                onOpenMembers = { groupId ->
                    navController.navigate(GroupMembersDest.build(groupId)) { launchSingleTop = true }
                },
                onOpenTreasury = { groupId ->
                    navController.navigate(GroupTreasuryDest.build(groupId)) { launchSingleTop = true }
                },
                onOpenFundraising = { groupId ->
                    navController.navigate(GroupFundraisingDest.build(groupId)) { launchSingleTop = true }
                },
                onOpenAds = { groupId ->
                    navController.navigate(GroupAdsDest.build(groupId)) { launchSingleTop = true }
                },
                onOpenSettings = { groupId ->
                    navController.navigate(GroupSettingsDest.build(groupId)) { launchSingleTop = true }
                },
            )
        }
        composable(
            route = GroupMembersDest.ROUTE,
            arguments = listOf(navArgument(GroupMembersDest.ARG_GROUP_ID) { type = NavType.StringType }),
        ) {
            GroupMembersRoute(onBack = { navController.popBackStack() })
        }
        composable(
            route = GroupFeedDest.ROUTE,
            arguments = listOf(navArgument(GroupFeedDest.ARG_GROUP_ID) { type = NavType.StringType }),
        ) { entry ->
            val groupId = entry.arguments?.getString(GroupFeedDest.ARG_GROUP_ID).orEmpty()
            GroupFeedRoute(
                onBack = { navController.popBackStack() },
                onOpenHub = {
                    navController.navigate(GroupDetailDest.build(groupId)) { launchSingleTop = true }
                },
                // #4 (B-GROUPUNIFY) — compose a group post with the SHARED newsfeed composer, audience
                // locked to this group (the composer is registered in the outer authenticated graph).
                onComposePost = {
                    runCatching {
                        navController.navigate(ComposePostDest.buildForGroup(groupId)) { launchSingleTop = true }
                    }
                },
            )
        }
        composable(
            route = GroupTreasuryDest.ROUTE,
            arguments = listOf(navArgument(GroupTreasuryDest.ARG_GROUP_ID) { type = NavType.StringType }),
        ) {
            GroupTreasuryRoute(onBack = { navController.popBackStack() })
        }
        composable(
            route = GroupFundraisingDest.ROUTE,
            arguments = listOf(navArgument(GroupFundraisingDest.ARG_GROUP_ID) { type = NavType.StringType }),
        ) {
            GroupFundraisingRoute(onBack = { navController.popBackStack() })
        }
        composable(
            route = GroupAdsDest.ROUTE,
            arguments = listOf(navArgument(GroupAdsDest.ARG_GROUP_ID) { type = NavType.StringType }),
        ) {
            GroupAdsRoute(onBack = { navController.popBackStack() })
        }
        composable(
            route = GroupSettingsDest.ROUTE,
            arguments = listOf(navArgument(GroupSettingsDest.ARG_GROUP_ID) { type = NavType.StringType }),
        ) {
            GroupSettingsRoute(onBack = { navController.popBackStack() })
        }
    }
}
