package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.feature.kyc.eidv.EidvRoute
import com.testlogon.android.feature.kyc.eidv.EidvViewModel

/**
 * AND-325 - the KYC electronic ID verification (eIDV) destination. The `caseId` (a kyc_ case id) is an
 * OPTIONAL path argument: when present the VM resumes from it (status-checked first, FR-6); when absent the
 * VM ensures a draft case lazily on Start (REUSING AND-319 KycApi.createCase).
 *
 * REAL REST REDIRECT eIDV: the screen opens the returned redirect_url EXTERNALLY via ACTION_VIEW. NO
 * camera / permission / manifest change is involved.
 */
data object KycEidvDest {
    const val ROUTE = "kyc/eidv?caseId={caseId}"

    /** Entry without a known case (the VM creates a draft on Start). */
    fun build(): String = "kyc/eidv"

    /** Entry resuming an existing case. */
    fun build(caseId: String): String = "kyc/eidv?caseId=$caseId"
}

/** AND-325 - registers the eIDV screen in the authenticated graph. */
fun NavGraphBuilder.eidvDestination(navController: NavHostController) {
    composable(
        route = KycEidvDest.ROUTE,
        arguments = listOf(
            navArgument(EidvViewModel.ARG_CASE_ID) {
                type = NavType.StringType
                nullable = true
                defaultValue = null
            },
        ),
    ) {
        EidvRoute(
            onBack = { navController.popBackStack() },
            onDone = { navController.popBackStack() },
        )
    }
}
