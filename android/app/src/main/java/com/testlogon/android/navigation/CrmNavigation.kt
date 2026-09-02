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
import com.testlogon.android.feature.crm.ProspectPoolRoute
import com.testlogon.android.feature.crm.ScoringRulesRoute
import com.testlogon.android.feature.crm.CrmProjectsRoute
import com.testlogon.android.feature.crm.CrmProjectDetailRoute
import com.testlogon.android.feature.crm.CrmProjectDetailViewModel
import com.testlogon.android.feature.crm.CrmEventsRoute
import com.testlogon.android.feature.crm.CrmEventDetailRoute
import com.testlogon.android.feature.crm.CrmEventDetailViewModel
import com.testlogon.android.feature.crm.CrmCampaignsRoute
import com.testlogon.android.feature.crm.CrmCampaignDetailRoute
import com.testlogon.android.feature.crm.CrmCampaignDetailViewModel

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

/** CRM-AND-LED — the marketing prospect pool route. */
data object CrmProspectsDest {
    const val ROUTE = "crm/prospects"
}

/** CRM-AND-LED — the admin lead-scoring-rules route (server admin-gated). */
data object CrmScoringRulesDest {
    const val ROUTE = "crm/scoring-rules"
}

/** CRM-AND-PEC — the CRM projects list route (Growth hub). */
data object CrmProjectsDest {
    const val ROUTE = "crm/projects"
}

/** CRM-AND-PEC — the CRM project detail route; the arg is the STRING project id (path param). */
data object CrmProjectDetailDest {
    const val ARG_PROJECT_ID = CrmProjectDetailViewModel.ARG_PROJECT_ID
    const val ROUTE = "crm/projects/{$ARG_PROJECT_ID}"

    fun build(projectId: String): String = "crm/projects/${Uri.encode(projectId)}"
}

/** CRM-AND-PEC — the CRM events list route (Growth hub). */
data object CrmEventsDest {
    const val ROUTE = "crm/events"
}

/** CRM-AND-PEC — the CRM event detail route; the arg is the STRING event id (path param). */
data object CrmEventDetailDest {
    const val ARG_EVENT_ID = CrmEventDetailViewModel.ARG_EVENT_ID
    const val ROUTE = "crm/events/{$ARG_EVENT_ID}"

    fun build(eventId: String): String = "crm/events/${Uri.encode(eventId)}"
}

/** CRM-AND-PEC — the CRM marketing campaigns list route (Growth hub). */
data object CrmCampaignsDest {
    const val ROUTE = "crm/campaigns"
}

/** CRM-AND-PEC — the CRM campaign detail route; the arg is the STRING campaign id (path param). */
data object CrmCampaignDetailDest {
    const val ARG_CAMPAIGN_ID = CrmCampaignDetailViewModel.ARG_CAMPAIGN_ID
    const val ROUTE = "crm/campaigns/{$ARG_CAMPAIGN_ID}"

    fun build(campaignId: String): String = "crm/campaigns/${Uri.encode(campaignId)}"
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
    composable(CrmProspectsDest.ROUTE) {
        ProspectPoolRoute(onBack = { navController.popBackStack() })
    }
    composable(CrmScoringRulesDest.ROUTE) {
        ScoringRulesRoute(onBack = { navController.popBackStack() })
    }
    // CRM-AND-PEC destinations
    composable(CrmProjectsDest.ROUTE) {
        CrmProjectsRoute(
            onProjectClick = { id ->
                navController.navigate(CrmProjectDetailDest.build(id)) { launchSingleTop = true }
            },
            onBack = { navController.popBackStack() },
        )
    }
    composable(
        route = CrmProjectDetailDest.ROUTE,
        arguments = listOf(
            navArgument(CrmProjectDetailDest.ARG_PROJECT_ID) { type = NavType.StringType },
        ),
    ) {
        CrmProjectDetailRoute(onBack = { navController.popBackStack() })
    }
    composable(CrmEventsDest.ROUTE) {
        CrmEventsRoute(
            onEventClick = { id ->
                navController.navigate(CrmEventDetailDest.build(id)) { launchSingleTop = true }
            },
            onBack = { navController.popBackStack() },
        )
    }
    composable(
        route = CrmEventDetailDest.ROUTE,
        arguments = listOf(
            navArgument(CrmEventDetailDest.ARG_EVENT_ID) { type = NavType.StringType },
        ),
    ) {
        CrmEventDetailRoute(onBack = { navController.popBackStack() })
    }
    composable(CrmCampaignsDest.ROUTE) {
        CrmCampaignsRoute(
            onCampaignClick = { id ->
                navController.navigate(CrmCampaignDetailDest.build(id)) { launchSingleTop = true }
            },
            onBack = { navController.popBackStack() },
        )
    }
    composable(
        route = CrmCampaignDetailDest.ROUTE,
        arguments = listOf(
            navArgument(CrmCampaignDetailDest.ARG_CAMPAIGN_ID) { type = NavType.StringType },
        ),
    ) {
        CrmCampaignDetailRoute(onBack = { navController.popBackStack() })
    }
}
