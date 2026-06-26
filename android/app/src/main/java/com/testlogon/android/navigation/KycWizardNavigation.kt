package com.testlogon.android.navigation

import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import androidx.hilt.navigation.compose.hiltViewModel
import com.testlogon.android.feature.kyc.wizard.KycWizardRoute
import com.testlogon.android.feature.kyc.wizard.KycWizardViewModel

/**
 * Batch-9 (#18) - the guided KYC verification wizard destination (email -> phone -> ID -> done).
 *
 * The wizard hands off the ID step to the proven [KycIdScannerDest] screen and learns the scanner finished via
 * a SavedStateHandle result flag the scanner sets on the wizard's back-stack entry (see [idScannerDestination]).
 * The wizard ViewModel is created HERE (not inside the route's hiltViewModel default) so the LaunchedEffect can
 * call onIdSubmitted() on the SAME instance the route renders.
 */
data object KycWizardDest {
    const val ROUTE = "kyc/wizard"

    /** Result key the ID-scanner sets on the wizard entry when both sides were uploaded+scanned. */
    const val RESULT_ID_DONE = "kyc_wizard_id_done"
}

fun NavGraphBuilder.kycWizardDestination(navController: NavHostController) {
    composable(KycWizardDest.ROUTE) { entry ->
        val viewModel: KycWizardViewModel = hiltViewModel(entry)

        // When the ID-scanner pops back having finished, it leaves a flag on THIS entry's SavedStateHandle.
        val handle = entry.savedStateHandle
        val idDone by handle.getStateFlow(KycWizardDest.RESULT_ID_DONE, false)
            .collectAsStateWithLifecycle()
        LaunchedEffect(idDone) {
            if (idDone) {
                viewModel.onIdSubmitted()
                handle[KycWizardDest.RESULT_ID_DONE] = false
            }
        }

        KycWizardRoute(
            onBack = { navController.popBackStack() },
            onLaunchIdScanner = { caseId -> navController.navigate(KycIdScannerDest.build(caseId)) },
            viewModel = viewModel,
        )
    }
}
