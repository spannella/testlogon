package com.testlogon.android.navigation

import android.net.Uri
import androidx.navigation.NavDeepLink
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import androidx.navigation.navDeepLink
import com.testlogon.android.feature.questionnaire.respond.RespondRoute
import com.testlogon.android.feature.questionnaire.respond.RespondentSessionViewModel

/**
 * AND-349 - the PUBLIC respondent destination for the published-questionnaire response flow (epic E45),
 * reached from the App Link https://HOST/questionnaires/published/{slug}/respond. The respond flow is
 * ANONYMOUS, so it is registered in BOTH top-level graphs (mirroring AND-335 publicShareDestination /
 * AND-073 publicProfileDestination) - a respondent need not be signed in.
 *
 * Deep-link wiring MIRRORS the existing public App Links: the destination declares a [navDeepLink] for
 * the verified HTTPS host plus a plaintext dev-host tap-through; MainActivity already forwards warm VIEW
 * intents via navController.handleDeepLink and the NavHost resolves the cold-start launch intent. No
 * navDeepLink-only behaviour is added beyond the existing pattern.
 *
 * NOTE: KDoc here deliberately avoids the comment-terminator character pair.
 */
data object QuestionnaireRespondDest {
    /** The published-questionnaire respond path prefix; the slug is the segment before `/respond`. */
    const val PATH_PREFIX = "/questionnaires/published"
    const val PATH_SUFFIX = "respond"

    const val ROUTE = "questionnaire_respond/{${RespondentSessionViewModel.ARG_SLUG}}"

    fun build(slug: String): String = "questionnaire_respond/${Uri.encode(slug)}"

    /**
     * Deep links for https://HOST/questionnaires/published/{slug}/respond: a verified HTTPS App Link on
     * the production host plus a plaintext HTTP tap-through on the dev host (cannot serve assetlinks).
     * The `{slug}` placeholder is the single path segment between the prefix and `/respond`.
     */
    fun deepLinks(): List<NavDeepLink> = listOf(
        navDeepLink {
            uriPattern = "https://{host}$PATH_PREFIX/{${RespondentSessionViewModel.ARG_SLUG}}/$PATH_SUFFIX"
        },
        navDeepLink {
            uriPattern = "http://18.222.237.167$PATH_PREFIX/{${RespondentSessionViewModel.ARG_SLUG}}/$PATH_SUFFIX"
        },
    )

    /**
     * AND-349 - PURE (no android.net.Uri) parse of a respond App Link URL to its slug, for the deep-link
     * unit test + the MainActivity VIEW-forwarding fallback. Returns the slug for a well-formed
     * .../questionnaires/published/{slug}/respond path (any scheme/host), else null. The slug segment is
     * URL-decoded. A blank slug or a path not ending in /respond yields null.
     */
    fun slugFromUrl(url: String?): String? {
        if (url.isNullOrBlank()) return null
        val uri = runCatching { java.net.URI(url) }.getOrNull() ?: return null
        val path = uri.path ?: return null
        val segments = path.split('/').filter { it.isNotBlank() }
        // Expect: questionnaires / published / {slug} / respond
        if (segments.size < 4) return null
        if (segments[0] != "questionnaires" || segments[1] != "published") return null
        if (segments.last() != PATH_SUFFIX) return null
        if (segments.size != 4) return null
        val slug = runCatching {
            java.net.URLDecoder.decode(segments[2], Charsets.UTF_8.name())
        }.getOrNull() ?: segments[2]
        return slug.takeIf { it.isNotBlank() }
    }
}

/**
 * AND-349 - registers the editable RESPONDENT RENDERER destination. Registered in BOTH top-level graphs
 * (an anonymous respondent may not be signed in). On a deep-link cold start the back stack may be empty;
 * Back falls back to the graph start destination.
 *
 * AND-395: the App Link deep links are NO LONGER attached here - they were re-pointed to the public
 * ENTRY destination ([PublicRespondDest]), which resolves the slug + anonymous session BEFORE forwarding
 * here once a session id exists (spec §4). This destination is now reached internally via
 * [QuestionnaireRespondDest.build].
 */
fun NavGraphBuilder.questionnaireRespondDestination(navController: NavHostController) {
    composable(
        route = QuestionnaireRespondDest.ROUTE,
        arguments = listOf(
            navArgument(RespondentSessionViewModel.ARG_SLUG) {
                type = NavType.StringType
                defaultValue = ""
            },
        ),
    ) {
        RespondRoute(
            onBack = {
                if (!navController.popBackStack()) {
                    navController.navigate(
                        navController.graph.startDestinationRoute ?: TlGraphs.UNAUTHENTICATED,
                    ) {
                        launchSingleTop = true
                    }
                }
            },
        )
    }
}
