package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.kyc.prooffunds.ProofOfFundsRoute

/**
 * AND-327 - the KYC proof-of-funds destination (summary + submissions + submit). REAL REST. The screen owns
 * its dependency-free system-intent capture / document-pick launchers (reusing AND-321) and uploads the
 * optional document via the AND-129 presign->PUT pipeline, so the only callback it needs is [onBack]. There
 * are no nav arguments.
 */
data object KycProofOfFundsDest {
    const val ROUTE = "kyc/proof-of-funds"

    fun build(): String = ROUTE
}

/** AND-327 - registers the proof-of-funds screen in the authenticated graph. */
fun NavGraphBuilder.proofOfFundsDestination(navController: NavHostController) {
    composable(route = KycProofOfFundsDest.ROUTE) {
        ProofOfFundsRoute(onBack = { navController.popBackStack() })
    }
}
