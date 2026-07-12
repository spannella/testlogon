package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.ads.create.account.CreateAdAccountRoute
import com.testlogon.android.feature.ads.create.campaign.CreateCampaignRoute
import com.testlogon.android.feature.ads.create.creative.CreateCreativeRoute

/**
 * ADV-107/108/109 - the advertiser CREATE flow destinations (create ad account -> create campaign -> create
 * creative + asset upload -> submit-for-review). No nav args: the account/campaign selection is carried by the
 * process-scoped AdsStudioSelection (set by the pickers/create steps), so each step self-resolves the chosen
 * context and can be reached standalone from the More hub. The steps chain forward on success.
 */
data object CreateAdAccountDest {
    const val ROUTE = "ads-create-account"
}

data object CreateCampaignDest {
    const val ROUTE = "ads-create-campaign"
}

data object CreateCreativeDest {
    const val ROUTE = "ads-create-creative"
}

fun NavHostController.navigateToCreateAdAccount() {
    navigate(CreateAdAccountDest.ROUTE) { launchSingleTop = true }
}

fun NavHostController.navigateToCreateCampaign() {
    navigate(CreateCampaignDest.ROUTE) { launchSingleTop = true }
}

fun NavHostController.navigateToCreateCreative() {
    navigate(CreateCreativeDest.ROUTE) { launchSingleTop = true }
}

/** ADV-107/108/109 - registers the three advertiser-create destinations. */
fun NavGraphBuilder.adsCreateDestinations(navController: NavHostController) {
    composable(route = CreateAdAccountDest.ROUTE) {
        CreateAdAccountRoute(
            onBack = { navController.popBackStack() },
            onCreated = { navController.navigateToCreateCampaign() },
        )
    }
    composable(route = CreateCampaignDest.ROUTE) {
        CreateCampaignRoute(
            onBack = { navController.popBackStack() },
            onCreated = { navController.navigateToCreateCreative() },
        )
    }
    composable(route = CreateCreativeDest.ROUTE) {
        CreateCreativeRoute(
            onBack = { navController.popBackStack() },
            onDone = { navController.popBackStack() },
        )
    }
}
