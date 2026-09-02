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
import com.testlogon.android.feature.crm.ForecastRoute
import com.testlogon.android.feature.crm.ForecastViewModel
import com.testlogon.android.feature.crm.PipelineReportRoute
import com.testlogon.android.feature.crm.PipelineReportViewModel
import com.testlogon.android.feature.crm.ContactRolesRoute
import com.testlogon.android.feature.crm.ContactRolesViewModel
import com.testlogon.android.feature.crm.QuotaRoute
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
import com.testlogon.android.feature.crm.CrmCampaignEditorRoute
import com.testlogon.android.feature.crm.CrmCampaignEditorViewModel
import com.testlogon.android.feature.crm.CrmEmailTemplatesRoute
import com.testlogon.android.feature.crm.CrmMarketingLeadsRoute

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

/** CRM-AND-OPP — the rep forecast worksheet route; optional period_key path arg (defaults to current month). */
data object CrmForecastDest {
    const val ARG_PERIOD_KEY = ForecastViewModel.ARG_PERIOD_KEY
    const val ROUTE = "crm/forecast/{$ARG_PERIOD_KEY}"

    fun build(periodKey: String): String = "crm/forecast/" + Uri.encode(periodKey.ifBlank { "current" })
}

/** CRM-AND-OPP — the pipeline funnel report route; the arg is "true" for the admin cross-user variant. */
data object CrmPipelineReportDest {
    const val ARG_ADMIN = PipelineReportViewModel.ARG_ADMIN
    const val ROUTE = "crm/pipeline-report/{$ARG_ADMIN}"

    fun build(admin: Boolean): String = "crm/pipeline-report/" + (if (admin) "true" else "false")
}

/** CRM-AND-OPP — the opportunity contact-roles route; the arg is the STRING opp_id (path param). */
data object CrmContactRolesDest {
    const val ARG_OPP_ID = ContactRolesViewModel.ARG_OPP_ID
    const val ROUTE = "crm/opportunities/{$ARG_OPP_ID}/contacts"

    fun build(oppId: String): String = "crm/opportunities/" + Uri.encode(oppId) + "/contacts"
}

/** CRM-AND-OPP — the admin sales-quota view/set route (server admin-gated via 403). */
data object CrmQuotaDest {
    const val ROUTE = "crm/quotas"
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

/** CMP — the campaign editor (create / edit). The path arg is the campaign id, or "new" to create. */
data object CrmCampaignEditorDest {
    const val ARG_CAMPAIGN_ID = CrmCampaignEditorViewModel.ARG_CAMPAIGN_ID
    const val ROUTE = "crm/campaigns/editor/{$ARG_CAMPAIGN_ID}"

    fun build(campaignId: String?): String =
        "crm/campaigns/editor/" + Uri.encode(campaignId?.ifBlank { null } ?: CrmCampaignEditorViewModel.NEW_SENTINEL)
}

/** CMP-002 — the HTML email-template editor list route. */
data object CrmEmailTemplatesDest {
    const val ROUTE = "crm/email-templates"
}

/** CMP-006 — the admin web-to-lead list route (server admin-gated → 403 surfaced as a banner). */
data object CrmMarketingLeadsDest {
    const val ROUTE = "crm/marketing-leads"
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
        PipelineRoute(
            onBack = { navController.popBackStack() },
            onOpenForecast = { navController.navigate(CrmForecastDest.build("")) { launchSingleTop = true } },
            onOpenReport = { navController.navigate(CrmPipelineReportDest.build(admin = false)) { launchSingleTop = true } },
            onOpenTeamReport = { navController.navigate(CrmPipelineReportDest.build(admin = true)) { launchSingleTop = true } },
            onOpenQuotas = { navController.navigate(CrmQuotaDest.ROUTE) { launchSingleTop = true } },
            onOpenContactRoles = { oppId ->
                navController.navigate(CrmContactRolesDest.build(oppId)) { launchSingleTop = true }
            },
        )
    }
    composable(
        route = CrmForecastDest.ROUTE,
        arguments = listOf(
            navArgument(CrmForecastDest.ARG_PERIOD_KEY) { type = NavType.StringType },
        ),
    ) {
        ForecastRoute(onBack = { navController.popBackStack() })
    }
    composable(
        route = CrmPipelineReportDest.ROUTE,
        arguments = listOf(
            navArgument(CrmPipelineReportDest.ARG_ADMIN) { type = NavType.StringType },
        ),
    ) {
        PipelineReportRoute(onBack = { navController.popBackStack() })
    }
    composable(
        route = CrmContactRolesDest.ROUTE,
        arguments = listOf(
            navArgument(CrmContactRolesDest.ARG_OPP_ID) { type = NavType.StringType },
        ),
    ) {
        ContactRolesRoute(onBack = { navController.popBackStack() })
    }
    composable(CrmQuotaDest.ROUTE) {
        QuotaRoute(onBack = { navController.popBackStack() })
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
            onNewCampaign = {
                navController.navigate(CrmCampaignEditorDest.build(null)) { launchSingleTop = true }
            },
            onOpenTemplates = {
                navController.navigate(CrmEmailTemplatesDest.ROUTE) { launchSingleTop = true }
            },
            onOpenLeads = {
                navController.navigate(CrmMarketingLeadsDest.ROUTE) { launchSingleTop = true }
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
        CrmCampaignDetailRoute(
            onBack = { navController.popBackStack() },
            onEdit = { id ->
                navController.navigate(CrmCampaignEditorDest.build(id)) { launchSingleTop = true }
            },
        )
    }
    composable(
        route = CrmCampaignEditorDest.ROUTE,
        arguments = listOf(
            navArgument(CrmCampaignEditorDest.ARG_CAMPAIGN_ID) { type = NavType.StringType },
        ),
    ) {
        CrmCampaignEditorRoute(
            onBack = { navController.popBackStack() },
            onSaved = { navController.popBackStack() },
        )
    }
    composable(CrmEmailTemplatesDest.ROUTE) {
        CrmEmailTemplatesRoute(onBack = { navController.popBackStack() })
    }
    composable(CrmMarketingLeadsDest.ROUTE) {
        CrmMarketingLeadsRoute(onBack = { navController.popBackStack() })
    }
}
