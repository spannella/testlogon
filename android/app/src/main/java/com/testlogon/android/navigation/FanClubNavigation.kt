package com.testlogon.android.navigation

import android.net.Uri
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.feature.fanclub.ChannelMessagesRoute
import com.testlogon.android.feature.fanclub.ChannelMessagesViewModel
import com.testlogon.android.feature.fanclub.ChannelsViewModel
import com.testlogon.android.feature.fanclub.FanClubChannelsRoute
import com.testlogon.android.feature.fanclub.TierMembersRoute
import com.testlogon.android.feature.fanclub.TierMembersViewModel

/**
 * AND-238 — fan-club channels list route `fanclub/channels/{creatorId}` (+ optional `creatorDisplayName`
 * query arg). The More-hub self-browse passes the [ChannelsViewModel.SELF] sentinel creator id; a creator
 * profile passes the real creator id. Locked-channel taps route to the AND-236 subscribe browse; accessible
 * channels open AND-239; a tier's members affordance opens AND-240.
 */
data object FanClubChannelsDest {
    const val ARG_CREATOR_ID = ChannelsViewModel.ARG_CREATOR_ID
    const val ARG_DISPLAY_NAME = ChannelsViewModel.ARG_DISPLAY_NAME

    /** Sentinel creator id for the More-hub self-browse. */
    const val SELF = ChannelsViewModel.SELF
    const val ROUTE = "fanclub/channels/{$ARG_CREATOR_ID}"
    const val ROUTE_WITH_ARGS = "$ROUTE?$ARG_DISPLAY_NAME={$ARG_DISPLAY_NAME}"

    fun build(creatorId: String, displayName: String? = null): String {
        val base = "fanclub/channels/${Uri.encode(creatorId)}"
        return if (displayName.isNullOrBlank()) base else "$base?$ARG_DISPLAY_NAME=${Uri.encode(displayName)}"
    }
}

/** AND-239 — fan-club channel messages route `fanclub/channels/{channelId}/messages` (+ optional name). */
data object FanClubMessagesDest {
    const val ARG_CHANNEL_ID = ChannelMessagesViewModel.ARG_CHANNEL_ID
    const val ARG_CHANNEL_NAME = ChannelMessagesViewModel.ARG_CHANNEL_NAME
    const val ROUTE = "fanclub/channels/{$ARG_CHANNEL_ID}/messages"
    const val ROUTE_WITH_ARGS = "$ROUTE?$ARG_CHANNEL_NAME={$ARG_CHANNEL_NAME}"

    fun build(channelId: String, channelName: String? = null): String {
        val base = "fanclub/channels/${Uri.encode(channelId)}/messages"
        return if (channelName.isNullOrBlank()) base else "$base?$ARG_CHANNEL_NAME=${Uri.encode(channelName)}"
    }
}

/** AND-240 — tier members route `fanclub/tiers/{tierId}/members` (+ optional name + member count). */
data object FanClubMembersDest {
    const val ARG_TIER_ID = TierMembersViewModel.ARG_TIER_ID
    const val ARG_TIER_NAME = TierMembersViewModel.ARG_TIER_NAME
    const val ARG_MEMBER_COUNT = TierMembersViewModel.ARG_MEMBER_COUNT
    const val ROUTE = "fanclub/tiers/{$ARG_TIER_ID}/members"
    const val ROUTE_WITH_ARGS = "$ROUTE?$ARG_TIER_NAME={$ARG_TIER_NAME}&$ARG_MEMBER_COUNT={$ARG_MEMBER_COUNT}"

    fun build(tierId: String, tierName: String? = null, memberCount: Int = -1): String {
        val base = "fanclub/tiers/${Uri.encode(tierId)}/members"
        return "$base?$ARG_TIER_NAME=${Uri.encode(tierName.orEmpty())}&$ARG_MEMBER_COUNT=$memberCount"
    }
}

/** AND-238/239/240 — registers the fan-club destinations in the authenticated graph. */
fun NavGraphBuilder.fanClubDestinations(navController: NavHostController) {
    // AND-238: channels list.
    composable(
        route = FanClubChannelsDest.ROUTE_WITH_ARGS,
        arguments = listOf(
            navArgument(FanClubChannelsDest.ARG_CREATOR_ID) { type = NavType.StringType },
            navArgument(FanClubChannelsDest.ARG_DISPLAY_NAME) {
                type = NavType.StringType
                nullable = true
                defaultValue = null
            },
        ),
    ) {
        FanClubChannelsRoute(
            onChannelClick = { channelId, channelName ->
                navController.navigate(FanClubMessagesDest.build(channelId, channelName)) {
                    launchSingleTop = true
                }
            },
            // A locked channel routes to the AND-236 subscribe browse (self-context tiers).
            onUpgrade = {
                navController.navigate(MoreRoutes.SUBSCRIPTION_TIERS) { launchSingleTop = true }
            },
            onMembers = { tierId, tierName ->
                navController.navigate(FanClubMembersDest.build(tierId, tierName)) { launchSingleTop = true }
            },
            onBack = { navController.popBackStack() },
        )
    }

    // AND-239: channel messages.
    composable(
        route = FanClubMessagesDest.ROUTE_WITH_ARGS,
        arguments = listOf(
            navArgument(FanClubMessagesDest.ARG_CHANNEL_ID) { type = NavType.StringType },
            navArgument(FanClubMessagesDest.ARG_CHANNEL_NAME) {
                type = NavType.StringType
                nullable = true
                defaultValue = null
            },
        ),
    ) {
        ChannelMessagesRoute(onBack = { navController.popBackStack() })
    }

    // AND-240: tier members.
    composable(
        route = FanClubMembersDest.ROUTE_WITH_ARGS,
        arguments = listOf(
            navArgument(FanClubMembersDest.ARG_TIER_ID) { type = NavType.StringType },
            navArgument(FanClubMembersDest.ARG_TIER_NAME) {
                type = NavType.StringType
                nullable = true
                defaultValue = null
            },
            navArgument(FanClubMembersDest.ARG_MEMBER_COUNT) {
                type = NavType.IntType
                defaultValue = -1
            },
        ),
    ) {
        TierMembersRoute(
            onMemberClick = { /* TODO: member-profile detail route does not exist yet (AND-240 FR-9). */ },
            onBack = { navController.popBackStack() },
        )
    }
}
