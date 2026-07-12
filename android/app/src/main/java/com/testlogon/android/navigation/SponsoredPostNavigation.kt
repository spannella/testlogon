package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.sponsoredpost.ui.SponsoredPostComposeRoute
import com.testlogon.android.feature.sponsoredpost.ui.SponsoredPostQueueRoute

/**
 * ADV2-E4 (F4) / ADV2-407..409 - the sponsored-as-creator (paid partnership) destinations:
 *  - the advertiser COMPOSER (draft a post + propose it to a creator), and
 *  - the creator APPROVAL QUEUE (pending proposals -> approve publishes a normal creator post / reject).
 *
 * Distinct from the ADS-013 brand-deal sponsorship inbox (sponsorshipDestinations). Both pop back; the
 * composer also pops on the post-send "Done".
 */
data object SponsoredPostComposeDest {
    const val ROUTE = "sponsored_post/compose"
}

data object SponsoredPostQueueDest {
    const val ROUTE = "sponsored_post/queue"
}

fun NavGraphBuilder.sponsoredPostDestinations(navController: NavHostController) {
    composable(route = SponsoredPostComposeDest.ROUTE) {
        SponsoredPostComposeRoute(
            onBack = { navController.popBackStack() },
            onDone = { navController.popBackStack() },
        )
    }
    composable(route = SponsoredPostQueueDest.ROUTE) {
        SponsoredPostQueueRoute(onBack = { navController.popBackStack() })
    }
}
