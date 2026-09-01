package com.testlogon.android.navigation

import android.net.Uri
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.feature.crm.LeadDetailRoute
import com.testlogon.android.feature.crm.LeadDetailViewModel
import com.testlogon.android.feature.crm.LeadsListRoute
import com.testlogon.android.feature.crm.PipelineRoute

/** CRM-AND-1 — the CRM leads list route (reached from the More hub / Growth). */
data object CrmLeadsDest {
    const val ROUTE = "crm/leads"
}

/** CRM-AND-1 — the CRM lead detail route; the arg is the STRING lead_id (path param). */
data object CrmLeadDetailDest {
    const val ARG_LEAD_ID = LeadDetailViewModel.ARG_LEAD_ID
    const val ROUTE = "crm/leads/{$ARG_LEAD_ID}"

    fun build(leadId: String): String = "crm/leads/${Uri.encode(leadId)}"
}

/** CRM-AND-1 — the sales-pipeline board route. */
data object CrmPipelineDest {
    const val ROUTE = "crm/pipeline"
}

/** CRM-AND-1 — registers the CRM leads list + detail + pipeline destinations in the authenticated graph. */
fun NavGraphBuilder.crmDestinations(navController: NavHostController) {
    composable(CrmLeadsDest.ROUTE) {
        LeadsListRoute(
            onLeadClick = { leadId ->
                navController.navigate(CrmLeadDetailDest.build(leadId)) { launchSingleTop = true }
            },
            onBack = { navController.popBackStack() },
        )
    }
    composable(
        route = CrmLeadDetailDest.ROUTE,
        arguments = listOf(
            navArgument(CrmLeadDetailDest.ARG_LEAD_ID) { type = NavType.StringType },
        ),
    ) {
        LeadDetailRoute(onBack = { navController.popBackStack() })
    }
    composable(CrmPipelineDest.ROUTE) {
        PipelineRoute(onBack = { navController.popBackStack() })
    }
}
