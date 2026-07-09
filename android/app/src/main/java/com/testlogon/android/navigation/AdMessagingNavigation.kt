package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.admessaging.ui.AdMassDmComposeRoute
import com.testlogon.android.feature.admessaging.ui.AdMessageComposeRoute
import com.testlogon.android.feature.admessaging.ui.AdMessageQueueRoute

/**
 * ADV2-E5 (F5+F6) — the ad-messaging destinations:
 *  - F5 advertiser COMPOSER (draft a sponsored message + offer it to a creator),
 *  - F5 creator APPROVAL QUEUE (pending offers -> approve SENDS as the creator / reject), and
 *  - F6 advertiser mass-DM COMPOSER (compose + send AS the advertiser to eligible relationships only).
 *
 * Distinct from the E4 sponsored-POST destinations and the ADS-013 brand-deal inbox. All pop back; the
 * composers also pop on the post-send "Done".
 */
data object AdMessageComposeDest {
    const val ROUTE = "ad_message/compose"
}

data object AdMessageQueueDest {
    const val ROUTE = "ad_message/queue"
}

data object AdMassDmComposeDest {
    const val ROUTE = "ad_message/mass_dm"
}

fun NavGraphBuilder.adMessagingDestinations(navController: NavHostController) {
    composable(route = AdMessageComposeDest.ROUTE) {
        AdMessageComposeRoute(
            onBack = { navController.popBackStack() },
            onDone = { navController.popBackStack() },
        )
    }
    composable(route = AdMessageQueueDest.ROUTE) {
        AdMessageQueueRoute(onBack = { navController.popBackStack() })
    }
    composable(route = AdMassDmComposeDest.ROUTE) {
        AdMassDmComposeRoute(
            onBack = { navController.popBackStack() },
            onDone = { navController.popBackStack() },
        )
    }
}
