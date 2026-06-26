package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.feature.kyc.idscanner.IdScannerRoute
import com.testlogon.android.feature.kyc.idscanner.IdScannerViewModel

/**
 * AND-322 - the KYC guided ID capture+scan destination. The required `caseId` (a kyc_ case id) is a path
 * argument read by the VM from SavedStateHandle; a blank case id lands the screen in a "no KYC case" error.
 */
data object KycIdScannerDest {
    const val ROUTE = "kyc/id-scan/{caseId}"

    fun build(caseId: String): String = "kyc/id-scan/$caseId"
}

/**
 * AND-322 - registers the ID-scanner screen in the authenticated graph. The screen owns its system-intent
 * camera / picker launchers and the runtime CAMERA permission request, so the only callback it needs is
 * [onDone] (the flow finished — pop back).
 */
fun NavGraphBuilder.idScannerDestination(navController: NavHostController) {
    composable(
        route = KycIdScannerDest.ROUTE,
        arguments = listOf(
            navArgument(IdScannerViewModel.ARG_CASE_ID) { type = NavType.StringType },
        ),
    ) {
        IdScannerRoute(
            onDone = {
                // Batch-9 (#18): when the scanner was launched from the KYC wizard, leave a result flag on the
                // wizard's back-stack entry so it can advance to the DONE step. Harmless no-op otherwise.
                navController.previousBackStackEntry
                    ?.savedStateHandle
                    ?.set(KycWizardDest.RESULT_ID_DONE, true)
                navController.popBackStack()
            },
        )
    }
}
