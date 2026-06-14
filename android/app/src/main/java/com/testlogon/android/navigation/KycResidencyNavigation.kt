package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.feature.kyc.residency.ResidencyRoute
import com.testlogon.android.feature.kyc.residency.ResidencyViewModel

/**
 * AND-326 - the KYC residency / address-verification destination. The `caseId` (a kyc_ case id) is an
 * OPTIONAL path argument: it is read by the VM from SavedStateHandle and is required only for the
 * case-scoped structured ADDRESS verification (the proof-of-residency DOCUMENT upload works without it).
 *
 * BOTH surfaces are REAL REST. The screen owns its dependency-free system-intent capture / document-pick
 * launchers (reusing AND-321), so the only callback it needs is [onBack].
 */
data object KycResidencyDest {
    const val ROUTE = "kyc/residency?caseId={caseId}"

    /** Entry without a known case (proof upload only; address verify disabled until a case exists). */
    fun build(): String = "kyc/residency"

    /** Entry scoped to an existing case (enables address verification). */
    fun build(caseId: String): String = "kyc/residency?caseId=$caseId"
}

/** AND-326 - registers the residency / address-verification screen in the authenticated graph. */
fun NavGraphBuilder.residencyDestination(navController: NavHostController) {
    composable(
        route = KycResidencyDest.ROUTE,
        arguments = listOf(
            navArgument(ResidencyViewModel.ARG_CASE_ID) {
                type = NavType.StringType
                nullable = true
                defaultValue = null
            },
        ),
    ) {
        ResidencyRoute(onBack = { navController.popBackStack() })
    }
}
