package com.testlogon.android.navigation

import android.net.Uri
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.feature.kyc.cases.KycCaseDetailRoute
import com.testlogon.android.feature.kyc.cases.KycCaseDetailViewModel
import com.testlogon.android.feature.kyc.cases.KycCaseListRoute

/**
 * AND-329 - the READ-ONLY KYC case-list + case-detail destinations.
 *
 * The list (`kyc/cases`) shows the caller's cases + the ongoing-monitoring banner; rows open the detail
 * (`kyc/cases/{caseId}`) which renders the prominent status + the synthesized timeline + reason codes. Both are
 * read-only (no writes); the only outward actions are open-case (list -> detail), start/re-verify (-> AND-320
 * tier status), and back.
 */
data object KycCasesDest {
    const val ROUTE = "kyc/cases"
}

/** The per-case detail destination; `caseId` is a required path arg (a kyc_ case id). */
data object KycCaseDetailDest {
    const val ROUTE = "kyc/cases/{caseId}"

    fun build(caseId: String): String = "kyc/cases/${Uri.encode(caseId)}"
}

/** AND-329 - registers the READ-ONLY KYC case-list + case-detail screens in the authenticated graph. */
fun NavGraphBuilder.kycCasesDestinations(navController: NavHostController) {
    composable(KycCasesDest.ROUTE) {
        KycCaseListRoute(
            onOpenCase = { caseId -> navController.navigate(KycCaseDetailDest.build(caseId)) },
            // KYC-ENTRY (batch 13): "Start / Continue verification" launches the guided STEP WIZARD
            // (email -> phone -> ID -> done) directly, so the KYC entry is never a read-only dead end.
            onStartVerification = { navController.navigate(KycWizardDest.ROUTE) },
            onBack = { navController.popBackStack() },
        )
    }
    composable(
        route = KycCaseDetailDest.ROUTE,
        arguments = listOf(
            navArgument(KycCaseDetailViewModel.ARG_CASE_ID) {
                type = NavType.StringType
            },
        ),
    ) {
        KycCaseDetailRoute(
            onBack = { navController.popBackStack() },
            // Re-verify deep-links to the AND-320 tier-status screen.
            onReVerify = { navController.navigate(KycTierDest.ROUTE) },
        )
    }
}
