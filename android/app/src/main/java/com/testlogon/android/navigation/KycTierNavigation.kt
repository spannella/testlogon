package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.kyc.TierStatusRoute

/** AND-320 — the KYC Tier Status destination (current tier + requirements checklist + Evaluate). */
data object KycTierDest {
    const val ROUTE = "kyc/tier"
}

/**
 * AND-320 — registers the KYC Tier Status screen in the authenticated graph.
 *
 * [TierStatusRoute.onOpenCase] is wired to a no-op for now: requirements carry no case id and the KYC case
 * screens (E42 / later tickets) are not yet wired, so there is nothing to open. Replace with a real
 * navigate() once the case route lands.
 */
fun NavGraphBuilder.kycTierDestination(navController: NavHostController) {
    composable(KycTierDest.ROUTE) {
        TierStatusRoute(
            onBack = { navController.popBackStack() },
            // KYC case detail route not available yet (E42); see KDoc above.
            onOpenCase = { /* no-op until the KYC case route lands */ },
            // Batch 8 (#16): each requirement's CTA + the "Begin verification" button route into the real
            // verification step screens so the first view is never a dead end. The tier screen has no case id,
            // so steps that strictly need one fall back to the document-capture / case-creation entry.
            onStartRequirement = { key -> navController.navigateForRequirement(key) },
        )
    }
}

/**
 * Batch 8 (#16): maps a tier-requirement key to its verification action screen. Email/phone verification has no
 * dedicated in-app screen (done at registration / on the web), and the case-scoped steps (liveness/eIDV) need a
 * case id the tier screen does not carry, so those route to the document-capture flow which kicks off the case.
 */
private fun NavHostController.navigateForRequirement(key: String) {
    val route = when (key) {
        "proof_of_address" -> KycResidencyDest.build()
        "kyc_case_approved", "business_kyc_approved", "api_access_approved", "verification_call",
        "questionnaire_completed", "email_verified", "phone_verified",
        -> KycDocumentCaptureDest.ROUTE
        else -> KycDocumentCaptureDest.ROUTE
    }
    navigate(route)
}
