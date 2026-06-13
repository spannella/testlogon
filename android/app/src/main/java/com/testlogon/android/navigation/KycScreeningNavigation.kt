package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.feature.kyc.screening.ScreeningRoute
import com.testlogon.android.feature.kyc.screening.ScreeningViewModel

/**
 * AND-328 - the READ-ONLY KYC screening status destination (sanctions / PEP / adverse-media aggregated into
 * one status). The `caseId` (a kyc_ case id) is an OPTIONAL query argument: when absent, the repository
 * sources the latest case from KycApi.listCases; when present it scopes the read to that case. There are no
 * writes, so the only callback the screen needs is [onBack].
 */
data object KycScreeningDest {
    const val ROUTE = "kyc/screening?caseId={caseId}"

    /** Entry without a known case (the latest case is resolved server-side). */
    fun build(): String = "kyc/screening"

    /** Entry scoped to a specific case. */
    fun build(caseId: String): String = "kyc/screening?caseId=$caseId"
}

/** AND-328 - registers the READ-ONLY screening status screen in the authenticated graph. */
fun NavGraphBuilder.screeningDestination(navController: NavHostController) {
    composable(
        route = KycScreeningDest.ROUTE,
        arguments = listOf(
            navArgument(ScreeningViewModel.ARG_CASE_ID) {
                type = NavType.StringType
                nullable = true
                defaultValue = null
            },
        ),
    ) {
        ScreeningRoute(onBack = { navController.popBackStack() })
    }
}
