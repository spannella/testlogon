package com.testlogon.android.navigation

import android.net.Uri
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.feature.subscriptions.SubscriptionTiersRoute
import com.testlogon.android.feature.subscriptions.SubscriptionTiersViewModel

/**
 * AND-235 — subscription tiers browse route `subscriptions/tiers/{creatorId}` (+ optional
 * `creatorDisplayName` query arg). Reached from a creator profile and from the More hub
 * ([MoreRoutes.SUBSCRIPTION_TIERS], which self-browses the current user's plans).
 */
data object SubscriptionTiersDest {
    const val ARG_CREATOR_ID = SubscriptionTiersViewModel.ARG_CREATOR_ID
    const val ARG_DISPLAY_NAME = SubscriptionTiersViewModel.ARG_DISPLAY_NAME

    /** Sentinel creator id for the More-hub self-browse (resolved to the current user in the VM). */
    const val SELF = SubscriptionTiersViewModel.SELF
    const val ROUTE = "subscriptions/tiers/{$ARG_CREATOR_ID}"

    /** Full route pattern with the optional display-name query arg, used at registration. */
    const val ROUTE_WITH_ARGS = "$ROUTE?$ARG_DISPLAY_NAME={$ARG_DISPLAY_NAME}"

    fun build(creatorId: String, displayName: String? = null): String {
        val base = "subscriptions/tiers/${Uri.encode(creatorId)}"
        return if (displayName.isNullOrBlank()) {
            base
        } else {
            "$base?$ARG_DISPLAY_NAME=${Uri.encode(displayName)}"
        }
    }
}

/** AND-235 — registers the subscription tiers browse destination. */
fun NavGraphBuilder.subscriptionTiersDestination(navController: NavHostController) {
    composable(
        route = SubscriptionTiersDest.ROUTE_WITH_ARGS,
        arguments = listOf(
            navArgument(SubscriptionTiersDest.ARG_CREATOR_ID) { type = NavType.StringType },
            navArgument(SubscriptionTiersDest.ARG_DISPLAY_NAME) {
                type = NavType.StringType
                nullable = true
                defaultValue = null
            },
        ),
    ) {
        SubscriptionTiersRoute(
            // Checkout route is not built this milestone; the CTA is flag-gated + stub-gated so this
            // is only reached once checkout lands. Pop back as a safe no-op until then.
            onNavigateToCheckout = { navController.popBackStack() },
            onBack = { navController.popBackStack() },
        )
    }
}
