package com.testlogon.android.navigation

import android.net.Uri
import androidx.navigation.NavDeepLink
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import androidx.navigation.navDeepLink
import com.testlogon.android.feature.questionnaire.respond.RespondentSessionViewModel
import com.testlogon.android.feature.questionnaire.respond.publicentry.PublicRespondScreen

/**
 * AND-395 - the PUBLIC (unauthenticated) respondent ENTRY destination for the published-questionnaire
 * response flow (epic E51). This is the unauth LANDING reached from the App Link
 * https://HOST/questionnaires/published/{slug}/respond; it resolves the slug + an anonymous session
 * (PublicRespondScreen / PublicRespondViewModel) and then forwards into AND-349's renderer destination
 * [QuestionnaireRespondDest] once a session id exists.
 *
 * The App Link deep links live HERE now (re-pointed from AND-349's renderer destination per spec §4):
 * the entry resolves session-before-form so a cold, never-logged-in user is dropped straight onto the
 * editable form (or the Submitted confirmation for a terminal session). Registered in BOTH top-level
 * graphs (mirroring AND-349 / AND-335) so AND-025's auth gate never bounces it to login (FR-1/FR-5).
 *
 * The hand-off navigation pops this entry route (inclusive) so Back from the form does not return to the
 * loading shim (FR-4). On a deep-link cold start the back stack may otherwise be empty.
 *
 * NOTE: KDoc here deliberately avoids the comment-terminator character pair.
 */
data object PublicRespondDest {
    const val ROUTE = "public_questionnaire_respond/{${RespondentSessionViewModel.ARG_SLUG}}"

    fun build(slug: String): String = "public_questionnaire_respond/${Uri.encode(slug)}"

    /**
     * AND-395 - the public-respond App Links (re-pointed from AND-349): a verified HTTPS App Link on the
     * production host plus a plaintext HTTP tap-through on the dev host (which cannot serve assetlinks).
     * The slug is the single path segment between the prefix and `/respond`.
     */
    fun deepLinks(): List<NavDeepLink> = listOf(
        navDeepLink {
            uriPattern =
                "https://{host}${QuestionnaireRespondDest.PATH_PREFIX}/" +
                "{${RespondentSessionViewModel.ARG_SLUG}}/${QuestionnaireRespondDest.PATH_SUFFIX}"
        },
        navDeepLink {
            uriPattern =
                "http://18.222.237.167${QuestionnaireRespondDest.PATH_PREFIX}/" +
                "{${RespondentSessionViewModel.ARG_SLUG}}/${QuestionnaireRespondDest.PATH_SUFFIX}"
        },
    )
}

/**
 * AND-395 - registers the public-entry destination + its App Link deep links, and the session hand-off
 * into AND-349's renderer destination. Registered in BOTH top-level graphs (anonymous respondent).
 */
fun NavGraphBuilder.publicQuestionnaireRespondDestination(navController: NavHostController) {
    composable(
        route = PublicRespondDest.ROUTE,
        arguments = listOf(
            navArgument(RespondentSessionViewModel.ARG_SLUG) {
                type = NavType.StringType
                defaultValue = ""
            },
        ),
        deepLinks = PublicRespondDest.deepLinks(),
    ) { backStackEntry ->
        val slug = backStackEntry.arguments?.getString(RespondentSessionViewModel.ARG_SLUG).orEmpty()
        PublicRespondScreen(
            slug = slug,
            // FR-4: forward to the editable renderer, popping the entry shim off the back stack.
            onSessionReady = {
                navController.navigate(QuestionnaireRespondDest.build(slug)) {
                    popUpTo(PublicRespondDest.ROUTE) { inclusive = true }
                    launchSingleTop = true
                }
            },
            // FR-3: a terminal (submitted) session opens directly to AND-349's confirmation state.
            onSubmittedSession = {
                navController.navigate(QuestionnaireRespondDest.build(slug)) {
                    popUpTo(PublicRespondDest.ROUTE) { inclusive = true }
                    launchSingleTop = true
                }
            },
        )
    }
}
