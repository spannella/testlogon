package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.core.model.LogoutReason
import com.testlogon.android.feature.agents.docs.ui.DocCoverageRoute
import com.testlogon.android.feature.agents.docs.ui.DocTemplatesRoute
import com.testlogon.android.feature.agents.feedback.ui.FeedbackRoute
import com.testlogon.android.feature.agents.fleet.ui.FleetDashboardRoute
import com.testlogon.android.feature.agents.llmkeys.ui.AddLlmKeyRoute
import com.testlogon.android.feature.agents.llmkeys.ui.LlmKeysListRoute
import com.testlogon.android.feature.agents.memory.ui.MemoryRoute
import com.testlogon.android.feature.agents.memory.ui.MemoryViewModel
import com.testlogon.android.feature.agents.memory.ui.MemoryWorkerPickerRoute
import com.testlogon.android.feature.agents.orchestrator.ui.OrchestratorRoute
import com.testlogon.android.feature.agents.orchestrator.ui.OrchestratorViewModel
import com.testlogon.android.feature.agents.prs.ui.PrDetailRoute
import com.testlogon.android.feature.agents.prs.ui.PrDetailViewModel
import com.testlogon.android.feature.agents.prs.ui.PrsListRoute
import com.testlogon.android.feature.agents.workers.ui.AgentTypesDashboardRoute
import com.testlogon.android.feature.agents.workers.ui.CreateWorkerRoute
import com.testlogon.android.feature.agents.workers.ui.WorkerDetailRoute
import com.testlogon.android.feature.agents.workers.ui.WorkerDetailViewModel
import com.testlogon.android.feature.agents.workers.ui.WorkersListRoute
import androidx.compose.runtime.getValue
import androidx.lifecycle.compose.collectAsStateWithLifecycle

/**
 * AGENTS-BASICS (web-parity) - destinations for the agents-BASICS surfaces:
 *  - WORKERS: list -> detail (+ provision log/sessions) + create (web /agents/workers)
 *  - LLM KEYS: list -> add (web /agents/llm-keys + AddLlmKeyDialog)
 *  - FLEET: dashboard (web /agents/fleet)
 *  - AGENT-TYPES dashboard/picker (web /agents/dashboard family) that feeds the B4 AgentConfigDest type-config
 *    screens with a WORKERS-backed typeId source (there is no agent-types registry endpoint).
 *  - FEEDBACK: list + per-item respond/skip (web /agents/feedback)
 *  - AGENT PRs: READ-ONLY list -> detail (web /agents/prs)
 *  - AGENT MEMORY: worker picker -> per-worker identity/project/entries (web /agents/memory/:workerId)
 *  - DOC-COVERAGE: coverage dashboard + a doc-templates screen (web /agents/docs + /agents/docs/templates)
 *
 * All routers are backend require_ui_session (the test acct CAN use them). Terminal-401 -> login handoff.
 */
data object WorkersListDest {
    const val ROUTE = "agents/workers"
}

data object WorkerCreateDest {
    const val ROUTE = "agents/workers/create"
}

data object WorkerDetailDest {
    const val ROUTE = "agents/workers/{workerId}"
    fun build(workerId: String): String = "agents/workers/${android.net.Uri.encode(workerId)}"
}

/** AGENT-ORCHESTRATOR (web-parity): the agent-loop console for one worker (reached from worker detail). */
data object OrchestratorDest {
    const val ROUTE = "agents/workers/{workerId}/orchestrator"
    fun build(workerId: String): String =
        "agents/workers/${android.net.Uri.encode(workerId)}/orchestrator"
}

data object LlmKeysListDest {
    const val ROUTE = "agents/llm-keys"
    /** Nav-result flag: an add succeeded (the list refreshes to show the new key). */
    const val RESULT_ADDED = "agents_llm_key_added"
}

data object LlmKeyAddDest {
    const val ROUTE = "agents/llm-keys/add"
}

data object FleetDashboardDest {
    const val ROUTE = "agents/fleet"
}

data object AgentTypesDashboardDest {
    const val ROUTE = "agents/types"
}

data object AgentFeedbackDest {
    const val ROUTE = "agents/feedback"
}

data object AgentPrsListDest {
    const val ROUTE = "agents/prs"
}

data object AgentPrDetailDest {
    const val ROUTE = "agents/prs/{prId}"
    fun build(prId: String): String = "agents/prs/${android.net.Uri.encode(prId)}"
}

data object AgentMemoryPickerDest {
    const val ROUTE = "agents/memory"
}

data object AgentMemoryDest {
    const val ROUTE = "agents/memory/{workerId}"
    fun build(workerId: String): String = "agents/memory/${android.net.Uri.encode(workerId)}"
}

data object DocCoverageDest {
    const val ROUTE = "agents/docs"
}

data object DocTemplatesDest {
    const val ROUTE = "agents/docs/templates"
}

fun NavGraphBuilder.agentsBasicsDestinations(navController: NavHostController) {
    // ---- Workers ----
    composable(route = WorkersListDest.ROUTE) {
        WorkersListRoute(
            onBack = { navController.popBackStack() },
            onCreate = { navController.navigate(WorkerCreateDest.ROUTE) { launchSingleTop = true } },
            onOpenWorker = { id -> navController.navigate(WorkerDetailDest.build(id)) { launchSingleTop = true } },
            onNavigateToLogin = { navController.navigateToAgentsReauth() },
        )
    }
    composable(route = WorkerCreateDest.ROUTE) {
        CreateWorkerRoute(
            onBack = { navController.popBackStack() },
            onCreated = { navController.popBackStack() },
            onNavigateToLogin = { navController.navigateToAgentsReauth() },
        )
    }
    composable(
        route = WorkerDetailDest.ROUTE,
        arguments = listOf(navArgument(WorkerDetailViewModel.ARG_WORKER_ID) { type = NavType.StringType }),
    ) {
        WorkerDetailRoute(
            onBack = { navController.popBackStack() },
            onOpenOrchestrator = { id ->
                navController.navigate(OrchestratorDest.build(id)) { launchSingleTop = true }
            },
            onNavigateToLogin = { navController.navigateToAgentsReauth() },
        )
    }

    // ---- Orchestrator (agent-loop console for one worker) ----
    composable(
        route = OrchestratorDest.ROUTE,
        arguments = listOf(navArgument(OrchestratorViewModel.ARG_WORKER_ID) { type = NavType.StringType }),
    ) {
        OrchestratorRoute(
            onBack = { navController.popBackStack() },
            onNavigateToLogin = { navController.navigateToAgentsReauth() },
        )
    }

    // ---- LLM keys ----
    composable(route = LlmKeysListDest.ROUTE) { backStackEntry ->
        val added by backStackEntry.savedStateHandle
            .getStateFlow(LlmKeysListDest.RESULT_ADDED, false)
            .collectAsStateWithLifecycle()
        LlmKeysListRoute(
            onBack = { navController.popBackStack() },
            onAdd = { navController.navigate(LlmKeyAddDest.ROUTE) { launchSingleTop = true } },
            onNavigateToLogin = { navController.navigateToAgentsReauth() },
            added = added,
            onAddedConsumed = { backStackEntry.savedStateHandle[LlmKeysListDest.RESULT_ADDED] = false },
        )
    }
    composable(route = LlmKeyAddDest.ROUTE) {
        AddLlmKeyRoute(
            onBack = { navController.popBackStack() },
            onAdded = {
                navController.previousBackStackEntry
                    ?.savedStateHandle?.set(LlmKeysListDest.RESULT_ADDED, true)
                navController.popBackStack()
            },
            onNavigateToLogin = { navController.navigateToAgentsReauth() },
        )
    }

    // ---- Fleet ----
    composable(route = FleetDashboardDest.ROUTE) {
        FleetDashboardRoute(
            onBack = { navController.popBackStack() },
            onNavigateToLogin = { navController.navigateToAgentsReauth() },
        )
    }

    // ---- Agent-types dashboard/picker -> feeds the B4 AgentConfigDest type-config screens ----
    composable(route = AgentTypesDashboardDest.ROUTE) {
        AgentTypesDashboardRoute(
            onBack = { navController.popBackStack() },
            onOpenConfig = { agentType, typeId ->
                navController.navigate(AgentConfigDest.route(agentType, typeId)) { launchSingleTop = true }
            },
            onNavigateToLogin = { navController.navigateToAgentsReauth() },
        )
    }

    // ---- Feedback (web /agents/feedback) ----
    composable(route = AgentFeedbackDest.ROUTE) {
        FeedbackRoute(
            onBack = { navController.popBackStack() },
            onNavigateToLogin = { navController.navigateToAgentsReauth() },
        )
    }

    // ---- Agent PRs (READ-ONLY list -> detail; web /agents/prs) ----
    composable(route = AgentPrsListDest.ROUTE) {
        PrsListRoute(
            onBack = { navController.popBackStack() },
            onOpenPr = { id -> navController.navigate(AgentPrDetailDest.build(id)) { launchSingleTop = true } },
            onNavigateToLogin = { navController.navigateToAgentsReauth() },
        )
    }
    composable(
        route = AgentPrDetailDest.ROUTE,
        arguments = listOf(navArgument(PrDetailViewModel.ARG_PR_ID) { type = NavType.StringType }),
    ) {
        PrDetailRoute(
            onBack = { navController.popBackStack() },
            onNavigateToLogin = { navController.navigateToAgentsReauth() },
        )
    }

    // ---- Agent memory (worker picker -> per-worker; web /agents/memory/:workerId) ----
    composable(route = AgentMemoryPickerDest.ROUTE) {
        MemoryWorkerPickerRoute(
            onBack = { navController.popBackStack() },
            onOpenMemory = { id -> navController.navigate(AgentMemoryDest.build(id)) { launchSingleTop = true } },
            onNavigateToLogin = { navController.navigateToAgentsReauth() },
        )
    }
    composable(
        route = AgentMemoryDest.ROUTE,
        arguments = listOf(navArgument(MemoryViewModel.ARG_WORKER_ID) { type = NavType.StringType }),
    ) {
        MemoryRoute(
            onBack = { navController.popBackStack() },
            onNavigateToLogin = { navController.navigateToAgentsReauth() },
        )
    }

    // ---- Doc coverage (+ templates; web /agents/docs + /agents/docs/templates) ----
    composable(route = DocCoverageDest.ROUTE) {
        DocCoverageRoute(
            onBack = { navController.popBackStack() },
            onOpenTemplates = { navController.navigate(DocTemplatesDest.ROUTE) { launchSingleTop = true } },
            onNavigateToLogin = { navController.navigateToAgentsReauth() },
        )
    }
    composable(route = DocTemplatesDest.ROUTE) {
        DocTemplatesRoute(
            onBack = { navController.popBackStack() },
            onNavigateToLogin = { navController.navigateToAgentsReauth() },
        )
    }
}

/** Terminal-401 re-auth handoff. Mirrors the B-APIKEY handoff. */
private fun NavHostController.navigateToAgentsReauth() {
    navigate(AuthDest.Login.build(LogoutReason.SESSION_EXPIRED.name)) { launchSingleTop = true }
}
