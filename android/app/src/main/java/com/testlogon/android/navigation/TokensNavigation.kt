package com.testlogon.android.navigation

import android.net.Uri
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.feature.tokens.TokenDetailRoute
import com.testlogon.android.feature.tokens.TokenMintRoute
import com.testlogon.android.feature.tokens.TokensMarketRoute

/**
 * CREATOR REVENUE-SHARE TOKEN destinations, registered in the AUTHENTICATED nav graph.
 *
 * [TokensMarketDest] is the browse/market list (the navigable hub entry); [TokenMintDest] is the mint
 * form; [TokenDetailDest] is the per-token detail addressed by the token id. All read surfaces degrade
 * to honest empty/pending states when the (not-yet-built) `me/tokens/(all)` backend 404s.
 */
data object TokensMarketDest {
    const val ROUTE = "tokens"
}

data object TokenMintDest {
    const val ROUTE = "tokens/mint"
}

data object TokenDetailDest {
    const val ROUTE = "tokens/detail/{tokenId}"
    const val ARG_TOKEN_ID = "tokenId"

    fun build(tokenId: String): String = "tokens/detail/${Uri.encode(tokenId)}"
}

/** Registers the token market + mint + detail destinations (Back pops the back stack). */
fun NavGraphBuilder.tokensDestinations(navController: NavHostController) {
    composable(TokensMarketDest.ROUTE) {
        TokensMarketRoute(
            onBack = { navController.popBackStack() },
            onOpenToken = { tokenId ->
                navController.navigate(TokenDetailDest.build(tokenId)) { launchSingleTop = true }
            },
            onMint = { navController.navigate(TokenMintDest.ROUTE) { launchSingleTop = true } },
        )
    }
    composable(TokenMintDest.ROUTE) {
        TokenMintRoute(
            onBack = { navController.popBackStack() },
            onMinted = { tokenId ->
                // Replace Mint with the new token's detail so Back returns to the market list.
                navController.navigate(TokenDetailDest.build(tokenId)) {
                    launchSingleTop = true
                    popUpTo(TokenMintDest.ROUTE) { inclusive = true }
                }
            },
        )
    }
    composable(
        route = TokenDetailDest.ROUTE,
        arguments = listOf(navArgument(TokenDetailDest.ARG_TOKEN_ID) { type = NavType.StringType }),
    ) {
        TokenDetailRoute(onBack = { navController.popBackStack() })
    }
}
