package com.testlogon.android.navigation

import androidx.navigation.NavController
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.legal.AboutScreen
import com.testlogon.android.feature.legal.CommunityGuidelinesScreen
import com.testlogon.android.feature.legal.ContactScreen
import com.testlogon.android.feature.legal.TermsScreen

/**
 * PAR-29 — the static legal destinations (About / Terms / Community Guidelines / Contact). About reuses
 * the pre-existing [MoreRoutes.ABOUT] route string (flipped from coming-soon); the other three add new
 * route constants surfaced from the Support hub.
 */
data object LegalRoutes {
    const val ABOUT = MoreRoutes.ABOUT
    const val TERMS = "legal/terms"
    const val GUIDELINES = "legal/guidelines"
    const val CONTACT = "legal/contact"
}

/** PAR-29 — registers the About / Terms / Community Guidelines / Contact static screens. */
fun NavGraphBuilder.legalDestinations(navController: NavHostController) {
    composable(route = LegalRoutes.ABOUT) {
        AboutScreen(onBack = { navController.popBackStack() })
    }
    composable(route = LegalRoutes.TERMS) {
        TermsScreen(onBack = { navController.popBackStack() })
    }
    composable(route = LegalRoutes.GUIDELINES) {
        CommunityGuidelinesScreen(onBack = { navController.popBackStack() })
    }
    composable(route = LegalRoutes.CONTACT) {
        ContactScreen(onBack = { navController.popBackStack() })
    }
}
