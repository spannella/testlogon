package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.feature.bailout.BailoutAuctionRoute
import com.testlogon.android.feature.bailout.BailoutBoardRoute
import com.testlogon.android.feature.bailout.BailoutSettingsRoute
import com.testlogon.android.feature.bailout.DistressRoute

/**
 * MARGIN DISTRESS / PRE-EMPTIVE BAILOUT AUCTION destinations, registered in the AUTHENTICATED nav graph.
 *
 * [BailoutDistressDest] is the distress overview (the caller's distressed-but-solvent positions + a
 * "browse open bailouts" jump); [BailoutBoardDest] is the rescuer opportunity board (the navigable hub
 * entry); [BailoutAuctionDest] is one auction addressed by the position's symbolId; [BailoutSettingsDest]
 * is the auto-bailout protection account setting. All reads degrade to honest empty/pending states when
 * the (not-yet-built) margin-distress / bailouts backend 404s — distress is never fabricated.
 */
data object BailoutDistressDest {
    const val ROUTE = "bailout/distress"
}

data object BailoutBoardDest {
    const val ROUTE = "bailout/board"
}

data object BailoutAuctionDest {
    const val ROUTE = "bailout/auction/{symbolId}"
    const val ARG_SYMBOL_ID = "symbolId"

    fun build(symbolId: Int): String = "bailout/auction/$symbolId"
}

data object BailoutSettingsDest {
    const val ROUTE = "bailout/settings"
}

/** Registers the distress overview + auction + discovery board + settings destinations. */
fun NavGraphBuilder.bailoutDestinations(navController: NavHostController) {
    composable(BailoutDistressDest.ROUTE) {
        DistressRoute(
            onBack = { navController.popBackStack() },
            onOpenAuction = { symbolId ->
                navController.navigate(BailoutAuctionDest.build(symbolId)) { launchSingleTop = true }
            },
            onBrowseBailouts = {
                navController.navigate(BailoutBoardDest.ROUTE) { launchSingleTop = true }
            },
            // Add margin / reduce position reuse the existing trade surface (Markets).
            onAddMargin = { navController.navigate(MarketsDest.ROUTE) { launchSingleTop = true } },
            onReducePosition = { navController.navigate(MarketsDest.ROUTE) { launchSingleTop = true } },
        )
    }
    composable(BailoutBoardDest.ROUTE) {
        BailoutBoardRoute(
            onBack = { navController.popBackStack() },
            onOpenAuction = { symbolId ->
                navController.navigate(BailoutAuctionDest.build(symbolId)) { launchSingleTop = true }
            },
        )
    }
    composable(
        route = BailoutAuctionDest.ROUTE,
        arguments = listOf(navArgument(BailoutAuctionDest.ARG_SYMBOL_ID) { type = NavType.StringType }),
    ) {
        BailoutAuctionRoute(onBack = { navController.popBackStack() })
    }
    composable(BailoutSettingsDest.ROUTE) {
        BailoutSettingsRoute(onBack = { navController.popBackStack() })
    }
}
