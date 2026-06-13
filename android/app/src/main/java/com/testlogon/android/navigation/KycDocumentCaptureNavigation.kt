package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.kyc.capture.DocumentCaptureRoute

/** AND-321 - the KYC identity-document capture+upload destination (system camera / picker + upload). */
data object KycDocumentCaptureDest {
    const val ROUTE = "kyc/capture"
}

/**
 * AND-321 - registers the KYC document capture+upload screen in the authenticated graph. The screen is
 * self-contained (it owns its camera/picker launchers and the runtime CAMERA permission request), so the
 * only callback it needs is [onBack].
 */
fun NavGraphBuilder.kycDocumentCaptureDestination(navController: NavHostController) {
    composable(KycDocumentCaptureDest.ROUTE) {
        DocumentCaptureRoute(onBack = { navController.popBackStack() })
    }
}
