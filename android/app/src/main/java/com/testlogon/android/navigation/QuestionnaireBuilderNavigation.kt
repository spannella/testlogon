package com.testlogon.android.navigation

import android.net.Uri
import androidx.compose.runtime.getValue
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.core.model.LogoutReason
import com.testlogon.android.feature.questionnaire.builder.ui.BuilderRoute
import com.testlogon.android.feature.questionnaire.builder.ui.BuilderViewModel
import com.testlogon.android.feature.questionnaire.builder.ui.CreateDraftRoute
import com.testlogon.android.feature.questionnaire.builder.ui.DraftsListRoute

/**
 * Questionnaire BUILDER destinations: a drafts LIST -> CREATE -> per-draft BUILDER editor (web
 * QuestionnaireBuilderPage parity, plus a list+create entry the web reaches via a separate index). The
 * list refreshes when create/builder pops back (a counter bumped via the list's SavedStateHandle, the same
 * nav-result pattern the apikeys list uses for the one-time secret). A terminal 401 from any screen routes
 * to the Login re-auth handoff.
 */
data object QuestionnaireBuilderListDest {
    const val ROUTE = "questionnaire_builder"

    /** Nav-result key: bumped when create/builder pops back so the list re-fetches. */
    const val RESULT_REFRESH = "questionnaire_builder_refresh"
}

data object QuestionnaireBuilderCreateDest {
    const val ROUTE = "questionnaire_builder/create"
}

data object QuestionnaireBuilderEditDest {
    const val ROUTE = "questionnaire_builder/{questionnaireId}"

    fun build(questionnaireId: String): String = "questionnaire_builder/${Uri.encode(questionnaireId)}"
}

fun NavGraphBuilder.questionnaireBuilderDestinations(navController: NavHostController) {
    composable(route = QuestionnaireBuilderListDest.ROUTE) { backStackEntry ->
        val savedStateHandle = backStackEntry.savedStateHandle
        val refreshKey by savedStateHandle
            .getStateFlow(QuestionnaireBuilderListDest.RESULT_REFRESH, 0)
            .collectAsStateWithLifecycle()

        DraftsListRoute(
            onBack = { navController.popBackStack() },
            onCreate = {
                navController.navigate(QuestionnaireBuilderCreateDest.ROUTE) { launchSingleTop = true }
            },
            onOpenDraft = { id ->
                navController.navigate(QuestionnaireBuilderEditDest.build(id)) { launchSingleTop = true }
            },
            onNavigateToLogin = { navController.navigateToQuestionnaireBuilderReauth() },
            refreshKey = refreshKey,
        )
    }

    composable(route = QuestionnaireBuilderCreateDest.ROUTE) {
        CreateDraftRoute(
            onBack = { navController.popBackStack() },
            onCreated = { questionnaireId ->
                // Pop back to the list (bumping its refresh counter), then open the new draft in the builder.
                navController.previousBackStackEntry
                    ?.savedStateHandle
                    ?.let { handle ->
                        val prior = handle.get<Int>(QuestionnaireBuilderListDest.RESULT_REFRESH) ?: 0
                        handle[QuestionnaireBuilderListDest.RESULT_REFRESH] = prior + 1
                    }
                navController.popBackStack()
                navController.navigate(QuestionnaireBuilderEditDest.build(questionnaireId)) { launchSingleTop = true }
            },
            onNavigateToLogin = { navController.navigateToQuestionnaireBuilderReauth() },
        )
    }

    composable(
        route = QuestionnaireBuilderEditDest.ROUTE,
        arguments = listOf(
            navArgument(BuilderViewModel.ARG_QUESTIONNAIRE_ID) { type = NavType.StringType },
        ),
    ) {
        BuilderRoute(
            onBack = {
                // Refresh the list so a publish/edit shows on return.
                navController.previousBackStackEntry
                    ?.savedStateHandle
                    ?.let { handle ->
                        val prior = handle.get<Int>(QuestionnaireBuilderListDest.RESULT_REFRESH) ?: 0
                        handle[QuestionnaireBuilderListDest.RESULT_REFRESH] = prior + 1
                    }
                navController.popBackStack()
            },
            onNavigateToLogin = { navController.navigateToQuestionnaireBuilderReauth() },
        )
    }
}

private fun NavHostController.navigateToQuestionnaireBuilderReauth() {
    navigate(AuthDest.Login.build(LogoutReason.SESSION_EXPIRED.name)) { launchSingleTop = true }
}
