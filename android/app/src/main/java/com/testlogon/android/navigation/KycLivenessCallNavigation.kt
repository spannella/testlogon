package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.feature.kyc.liveness.LivenessCallRoute
import com.testlogon.android.feature.kyc.liveness.LivenessCallViewModel

/**
 * AND-324 - the KYC scheduled liveness (video-verification) call destination. The required `caseId`
 * (a kyc_ case id) is a path argument read by the VM from SavedStateHandle; a blank case id lands the
 * screen in a non-recoverable "no KYC case" error.
 *
 * This is REAL REST scheduling, NOT in-app WebRTC: the screen's "Join call" action opens the call's
 * opaque join_url EXTERNALLY via ACTION_VIEW. No camera / permission / manifest change is involved.
 */
data object KycLivenessCallDest {
    const val ROUTE = "kyc/{caseId}/liveness-call"

    fun build(caseId: String): String = "kyc/$caseId/liveness-call"
}

/** AND-324 - registers the scheduled liveness-call screen in the authenticated graph. */
fun NavGraphBuilder.livenessCallDestination(navController: NavHostController) {
    composable(
        route = KycLivenessCallDest.ROUTE,
        arguments = listOf(
            navArgument(LivenessCallViewModel.ARG_CASE_ID) { type = NavType.StringType },
        ),
    ) {
        LivenessCallRoute(onBack = { navController.popBackStack() })
    }
}
