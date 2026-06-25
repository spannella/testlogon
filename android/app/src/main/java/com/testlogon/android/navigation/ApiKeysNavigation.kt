package com.testlogon.android.navigation

import androidx.compose.runtime.getValue
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.core.model.LogoutReason
import com.testlogon.android.feature.apikeys.ui.ApiKeysListRoute
import com.testlogon.android.feature.apikeys.ui.CreateApiKeyRoute

/**
 * B-APIKEY (batch 7) - the developer API-keys destinations: a LIST -> a CREATE. The list shows the caller's keys
 * (label / prefix / created+expiry / scopes) with a per-row revoke; create POSTs a new key and hands the
 * ONE-TIME secret back to the list (via the previous back-stack entry's SavedStateHandle - mirrors the PW14
 * payment-methods nav-result pattern) so it is displayed exactly once in a dialog and never persisted.
 *
 * NOTE on MFA: POST ui/api_keys + revoke are gated by the backend's require_fresh_mfa. For a session with MFA
 * factors configured the create/revoke can return 401 "Fresh MFA required"; that message surfaces inline (the
 * create VM does NOT route a fresh-MFA 401 to the login handoff). A session with no MFA factors creates/revokes
 * directly (verified live).
 */
data object ApiKeysListDest {
    const val ROUTE = "api_keys"

    /** Nav-result key: the one-time secret handed back from the create screen for one-time display. */
    const val RESULT_NEW_SECRET = "api_keys_new_secret"
}

data object ApiKeyCreateDest {
    const val ROUTE = "api_keys/create"
}

/** B-APIKEY (batch 7) - registers the API-keys list + create destinations in the authenticated graph. */
fun NavGraphBuilder.apiKeysDestinations(navController: NavHostController) {
    composable(route = ApiKeysListDest.ROUTE) { backStackEntry ->
        val savedStateHandle = backStackEntry.savedStateHandle
        val newSecret by savedStateHandle
            .getStateFlow<String?>(ApiKeysListDest.RESULT_NEW_SECRET, null)
            .collectAsStateWithLifecycle()

        ApiKeysListRoute(
            onBack = { navController.popBackStack() },
            onCreate = {
                navController.navigate(ApiKeyCreateDest.ROUTE) { launchSingleTop = true }
            },
            onNavigateToLogin = { navController.navigateToApiKeysReauth() },
            newSecret = newSecret,
            onSecretConsumed = { savedStateHandle[ApiKeysListDest.RESULT_NEW_SECRET] = null },
        )
    }
    composable(route = ApiKeyCreateDest.ROUTE) {
        CreateApiKeyRoute(
            onBack = { navController.popBackStack() },
            onCreated = { secret ->
                navController.previousBackStackEntry
                    ?.savedStateHandle?.set(ApiKeysListDest.RESULT_NEW_SECRET, secret)
                navController.popBackStack()
            },
            onNavigateToLogin = { navController.navigateToApiKeysReauth() },
        )
    }
}

/** Terminal-401 re-auth handoff: navigate to Login carrying SESSION_EXPIRED. Mirrors the AND-398 webhooks handoff. */
private fun NavHostController.navigateToApiKeysReauth() {
    navigate(AuthDest.Login.build(LogoutReason.SESSION_EXPIRED.name)) { launchSingleTop = true }
}
