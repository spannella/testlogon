package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.feature.kyc.facial.FaceComparisonRoute
import com.testlogon.android.feature.kyc.facial.FaceComparisonViewModel

/**
 * AND-323 - the KYC facial-comparison (selfie capture + server-side face comparison) destination. The
 * required `caseId` (a kyc_ case id) is a path argument read by the VM from SavedStateHandle; a blank
 * case id lands the screen in a "no KYC case" error.
 */
data object KycFacialDest {
    const val ROUTE = "kyc/{caseId}/face-comparison"

    fun build(caseId: String): String = "kyc/$caseId/face-comparison"
}

/**
 * AND-323 - registers the facial-comparison screen in the authenticated graph. The screen owns its
 * system-intent camera / picker launchers and the runtime CAMERA permission request, so the only
 * callback it needs is [onDone] (the flow finished — pop back).
 */
fun NavGraphBuilder.faceComparisonDestination(navController: NavHostController) {
    composable(
        route = KycFacialDest.ROUTE,
        arguments = listOf(
            navArgument(FaceComparisonViewModel.ARG_CASE_ID) { type = NavType.StringType },
        ),
    ) {
        FaceComparisonRoute(onDone = { navController.popBackStack() })
    }
}
