package com.testlogon.android.navigation

import android.net.Uri
import androidx.navigation.NavDeepLink
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import androidx.navigation.navDeepLink
import com.testlogon.android.data.discover.SearchEntityType
import com.testlogon.android.data.discover.SearchResult
import com.testlogon.android.feature.discover.MultiSearchRoute
import com.testlogon.android.feature.discover.TagPageRoute
import com.testlogon.android.feature.discover.TagPageViewModel

/**
 * AND-183 — tag page destination `discover/tags/{tag}` (in-app + App Link / dev-host deep links).
 * The `{tag}` segment is URL-encoded when building the route and decoded once by the ViewModel.
 */
data object TagPageDest {
    const val ROUTE = "discover/tags/{${TagPageViewModel.ARG_TAG}}"
    const val DEEP_LINK_PATH = "/discover/tags"

    fun build(tag: String): String = "discover/tags/${Uri.encode(tag)}"
}

/** AND-185 — global multi-entity search route. */
data object MultiSearchDest {
    const val ROUTE = "search/global"
}

/** AND-183 — registers the tag page with its `discover/tags/{tag}` route + deep links. */
fun NavGraphBuilder.tagPageDestination(navController: NavHostController) {
    composable(
        route = TagPageDest.ROUTE,
        arguments = listOf(
            navArgument(TagPageViewModel.ARG_TAG) { type = NavType.StringType },
        ),
        deepLinks = tagPageDeepLinks(),
    ) {
        TagPageRoute(
            onPostClick = { postId ->
                navController.navigate(PostDetailDest.build(postId)) { launchSingleTop = true }
            },
            onAuthorClick = { authorId ->
                navController.navigate(PublicProfileDest.build(authorId)) { launchSingleTop = true }
            },
            onBack = {
                if (!navController.popBackStack()) {
                    navController.navigate(navController.graph.startDestinationRoute ?: TlGraphs.AUTHENTICATED) {
                        launchSingleTop = true
                    }
                }
            },
        )
    }
}

private fun tagPageDeepLinks(): List<NavDeepLink> {
    val path = TagPageDest.DEEP_LINK_PATH
    return listOf(
        navDeepLink { uriPattern = "https://{host}$path/{tag}" },
        navDeepLink { uriPattern = "http://18.222.237.167$path/{tag}" },
        navDeepLink { uriPattern = "testlogon://discover/tags/{tag}" },
    )
}

/** AND-185 — registers the global multi-entity search destination. */
fun NavGraphBuilder.multiSearchDestination(navController: NavHostController) {
    composable(MultiSearchDest.ROUTE) {
        MultiSearchRoute(
            onOpenResult = { result -> navController.openSearchResult(result) },
            onBack = { navController.popBackStack() },
        )
    }
}

/**
 * AND-185 — resolves a search result's server-provided `url` to an in-app destination, falling back to
 * a type+id route when the url can't be parsed. The web client navigates straight to `item.url`; the
 * Android port maps the known path prefixes onto its feature routes.
 */
internal fun NavHostController.openSearchResult(result: SearchResult) {
    val route = result.toInAppRoute() ?: return
    navigate(route) { launchSingleTop = true }
}

/** Maps a [SearchResult] to an in-app route, or null when no destination is known (no-op). */
internal fun SearchResult.toInAppRoute(): String? {
    // Prefer parsing the server url path (e.g. "/users/u_1", "/posts/c_9").
    val segments = url.takeIf { it.isNotBlank() }
        ?.let { runCatching { Uri.parse(it) }.getOrNull()?.pathSegments }
        .orEmpty()
    if (segments.size >= 2) {
        val (head, id) = segments[0] to segments[1]
        when (head) {
            "users", "u", "profile" -> return PublicProfileDest.build(id)
            "posts", "post" -> return PostDetailDest.build(id)
            "discover" -> if (segments.size >= 3 && segments[1] == "tags") return TagPageDest.build(segments[2])
        }
    }
    // Fallback: route by entity type + id.
    return when (type) {
        SearchEntityType.USER, SearchEntityType.CONTACT -> PublicProfileDest.build(id)
        SearchEntityType.POST -> PostDetailDest.build(id)
        else -> null // no first-party detail route for this kind yet — safe no-op
    }
}
