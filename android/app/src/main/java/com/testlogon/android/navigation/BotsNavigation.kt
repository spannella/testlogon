package com.testlogon.android.navigation

import android.net.Uri
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.feature.bots.BotAutoReplyRoute
import com.testlogon.android.feature.bots.BotTemplatesRoute
import com.testlogon.android.feature.bots.BotsListRoute

/**
 * Bots destinations (reached from the More hub). Mirrors the web bots / bots/{botId}/auto-reply /
 * bots/{botId}/templates routes. The list opens a bot's auto-reply rules or message templates; both
 * detail routes carry the bot id as a nav arg (consumed via SavedStateHandle in their ViewModels).
 */
data object BotsDest {
    const val ROUTE = "bots"
    const val LIST = "bots"
    const val AUTO_REPLY = "bots/{botId}/auto-reply"
    const val TEMPLATES = "bots/{botId}/templates"
    const val ARG_BOT_ID = "botId"

    fun autoReply(id: String): String = "bots/${Uri.encode(id)}/auto-reply"

    fun templates(id: String): String = "bots/${Uri.encode(id)}/templates"
}

/** Registers the bots list + per-bot auto-reply and templates destinations. */
fun NavGraphBuilder.botsDestinations(navController: NavHostController) {
    composable(BotsDest.LIST) {
        BotsListRoute(
            onBack = { navController.popBackStack() },
            onOpenAutoReply = { id ->
                navController.navigate(BotsDest.autoReply(id)) { launchSingleTop = true }
            },
            onOpenTemplates = { id ->
                navController.navigate(BotsDest.templates(id)) { launchSingleTop = true }
            },
            onSessionExpired = { navController.popBackStack() },
        )
    }

    composable(
        route = BotsDest.AUTO_REPLY,
        arguments = listOf(navArgument(BotsDest.ARG_BOT_ID) { type = NavType.StringType }),
    ) {
        BotAutoReplyRoute(
            onBack = { navController.popBackStack() },
            onSessionExpired = { navController.popBackStack() },
        )
    }

    composable(
        route = BotsDest.TEMPLATES,
        arguments = listOf(navArgument(BotsDest.ARG_BOT_ID) { type = NavType.StringType }),
    ) {
        BotTemplatesRoute(
            onBack = { navController.popBackStack() },
            onSessionExpired = { navController.popBackStack() },
        )
    }
}
