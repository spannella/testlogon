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
 * Batch-9 (#18): maps a tier-requirement key to its verification action screen.
 *
 * The Tier-1 essentials (email verify, phone verify, government-ID upload, and the generic "Begin verification"
 * empty key) all route into the new guided KYC WIZARD, which walks the user through email -> phone -> ID step by
 * step with clear progress (replacing the old confusing jump straight to a bare document-capture screen).
 * Proof-of-address keeps its dedicated residency screen.
 */
private fun NavHostController.navigateForRequirement(key: String) {
    val route = when (key) {
        "proof_of_address" -> KycResidencyDest.build()
        // email/phone/ID and the "" Begin-verification key -> the guided wizard.
        else -> KycWizardDest.ROUTE
    }
    navigate(route)
}
