package com.testlogon.android.navigation

import android.net.Uri
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.core.model.LogoutReason
import com.testlogon.android.feature.knowledgebase.ui.KbDetailRoute
import com.testlogon.android.feature.knowledgebase.ui.KbListRoute

/**
 * KB-AND-1 - the READ-ONLY Knowledge Base (help centre) destinations: an article LIST / SEARCH -> an article
 * DETAIL. The detail ViewModel reads its {articleId} nav arg from SavedStateHandle. There are NO mutations
 * (create / edit / rate are OUT OF SCOPE this wave). Degrade-on-404: when the KB flag is off the list resolves
 * to a clean empty state and detail resolves to "not found".
 */
data object KbListDest {
    const val ROUTE = "kb/articles"
}

data object KbArticleDetailDest {
    const val ARG_ARTICLE_ID = "articleId"
    const val ROUTE = "kb/articles/{$ARG_ARTICLE_ID}"

    fun build(articleId: String): String = "kb/articles/${Uri.encode(articleId)}"
}

/**
 * KB-AND-1 - registers the KB list -> detail destinations in the authenticated graph (one shared nav graph;
 * NOT forked). Each screen's one-shot NavigateToLogin effect (a TERMINAL 401) routes to the login /
 * unauthenticated graph carrying [LogoutReason.SESSION_EXPIRED] (mirrors the AND-372 tickets handoff).
 */
fun NavGraphBuilder.knowledgeBaseDestinations(navController: NavHostController) {
    composable(route = KbListDest.ROUTE) {
        KbListRoute(
            onBack = { navController.popBackStack() },
            onOpenArticle = { articleId ->
                navController.navigate(KbArticleDetailDest.build(articleId)) { launchSingleTop = true }
            },
            onNavigateToLogin = { navController.navigateToKbReauth() },
        )
    }
    composable(
        route = KbArticleDetailDest.ROUTE,
        arguments = listOf(
            navArgument(KbArticleDetailDest.ARG_ARTICLE_ID) { type = NavType.StringType },
        ),
    ) {
        KbDetailRoute(
            onBack = { navController.popBackStack() },
            onNavigateToLogin = { navController.navigateToKbReauth() },
        )
    }
}

/** KB-AND-1 - the terminal-401 re-auth handoff (mirrors the AND-372 tickets handoff). */
private fun NavHostController.navigateToKbReauth() {
    navigate(AuthDest.Login.build(LogoutReason.SESSION_EXPIRED.name)) { launchSingleTop = true }
}
