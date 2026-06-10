package com.testlogon.android.navigation

import android.net.Uri
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.feature.subscriptions.ManageSubscriptionRoute
import com.testlogon.android.feature.subscriptions.ManageSubscriptionViewModel
import com.testlogon.android.feature.subscriptions.SubscribeRoute
import com.testlogon.android.feature.subscriptions.SubscribeViewModel
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
            // AND-236: the (flag-gated, BillingAuthorizer-gated) Subscribe CTA opens the subscribe
            // confirmation flow for the chosen tier.
            onNavigateToCheckout = { e ->
                navController.navigate(
                    SubscribeDest.build(
                        planId = e.tierId,
                        creatorId = e.creatorId,
                        name = e.name,
                        priceCents = e.priceCents,
                        currency = e.currency,
                        interval = e.interval.name,
                        description = e.description,
                    ),
                ) { launchSingleTop = true }
            },
            // AND-237: the current-plan "Manage" action opens the manage / cancel screen.
            onNavigateToManage = {
                navController.navigate(ManageSubscriptionDest.ROUTE) { launchSingleTop = true }
            },
            onBack = { navController.popBackStack() },
        )
    }
}

/**
 * AND-236 — subscribe confirmation flow route. Args carry the chosen tier's display fields + the
 * plan id (the subscribe PATH param) and the price (the BillingAuthorizer amount).
 */
data object SubscribeDest {
    const val ARG_PLAN_ID = SubscribeViewModel.ARG_PLAN_ID
    const val ARG_CREATOR_ID = SubscribeViewModel.ARG_CREATOR_ID
    const val ARG_TIER_NAME = SubscribeViewModel.ARG_TIER_NAME
    const val ARG_PRICE_CENTS = SubscribeViewModel.ARG_PRICE_CENTS
    const val ARG_CURRENCY = SubscribeViewModel.ARG_CURRENCY
    const val ARG_INTERVAL = SubscribeViewModel.ARG_INTERVAL
    const val ARG_DESCRIPTION = SubscribeViewModel.ARG_DESCRIPTION

    const val ROUTE_WITH_ARGS =
        "subscriptions/subscribe/{$ARG_PLAN_ID}/{$ARG_CREATOR_ID}" +
            "?$ARG_TIER_NAME={$ARG_TIER_NAME}" +
            "&$ARG_PRICE_CENTS={$ARG_PRICE_CENTS}" +
            "&$ARG_CURRENCY={$ARG_CURRENCY}" +
            "&$ARG_INTERVAL={$ARG_INTERVAL}" +
            "&$ARG_DESCRIPTION={$ARG_DESCRIPTION}"

    fun build(
        planId: String,
        creatorId: String,
        name: String,
        priceCents: Long,
        currency: String,
        interval: String,
        description: String?,
    ): String {
        val base = "subscriptions/subscribe/${Uri.encode(planId)}/${Uri.encode(creatorId)}"
        return base +
            "?$ARG_TIER_NAME=${Uri.encode(name)}" +
            "&$ARG_PRICE_CENTS=$priceCents" +
            "&$ARG_CURRENCY=${Uri.encode(currency)}" +
            "&$ARG_INTERVAL=${Uri.encode(interval)}" +
            "&$ARG_DESCRIPTION=${Uri.encode(description.orEmpty())}"
    }
}

/** AND-236 — registers the subscribe confirmation flow destination. */
fun NavGraphBuilder.subscribeDestination(navController: NavHostController) {
    composable(
        route = SubscribeDest.ROUTE_WITH_ARGS,
        arguments = listOf(
            navArgument(SubscribeDest.ARG_PLAN_ID) { type = NavType.StringType },
            navArgument(SubscribeDest.ARG_CREATOR_ID) { type = NavType.StringType },
            navArgument(SubscribeDest.ARG_TIER_NAME) { type = NavType.StringType; defaultValue = "" },
            navArgument(SubscribeDest.ARG_PRICE_CENTS) { type = NavType.LongType; defaultValue = 0L },
            navArgument(SubscribeDest.ARG_CURRENCY) { type = NavType.StringType; defaultValue = "USD" },
            navArgument(SubscribeDest.ARG_INTERVAL) { type = NavType.StringType; defaultValue = "MONTH" },
            navArgument(SubscribeDest.ARG_DESCRIPTION) {
                type = NavType.StringType
                nullable = true
                defaultValue = null
            },
        ),
    ) {
        SubscribeRoute(
            // On activation, pop back to the originating browse screen so it reflects entitlement.
            onSubscribed = { _, _ -> navController.popBackStack() },
            onBack = { navController.popBackStack() },
        )
    }
}

/** AND-237 — manage / cancel subscription route (arg-less; the VM resolves the current sub). */
data object ManageSubscriptionDest {
    const val ROUTE = ManageSubscriptionViewModel.ROUTE
}

/** AND-237 — registers the manage / cancel subscription destination. */
fun NavGraphBuilder.manageSubscriptionDestination(navController: NavHostController) {
    composable(ManageSubscriptionDest.ROUTE) {
        ManageSubscriptionRoute(
            onNavigateToSubscribe = { planId, creatorId ->
                navController.navigate(
                    SubscribeDest.build(
                        planId = planId,
                        creatorId = creatorId,
                        name = "",
                        priceCents = 0L,
                        currency = "USD",
                        interval = "MONTH",
                        description = null,
                    ),
                ) { launchSingleTop = true }
            },
            onBack = { navController.popBackStack() },
        )
    }
}
