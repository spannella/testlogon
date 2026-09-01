@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.crm

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material3.Card
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.core.ui.state.OfflineBanner
import com.testlogon.android.data.crm.CrmSalesMath
import com.testlogon.android.data.crm.Opportunity

object CrmPipelineTestTags {
    const val SCREEN = "crm_pipeline_screen"
    const val CONTENT = "crm_pipeline_content"
    const val LOADING = "crm_pipeline_loading"
    const val ERROR = "crm_pipeline_error"
    const val FAB = "crm_pipeline_fab"
    const val OPEN_WEIGHTED = "crm_pipeline_open_weighted"
}

@Composable
fun PipelineRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: PipelineViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    PipelineScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::onRefresh,
        onRetry = viewModel::onRetry,
        onMoveStage = viewModel::moveStage,
        onCreate = viewModel::createOpportunity,
        onClearCreateError = viewModel::clearCreateError,
        onClearActionMessage = viewModel::clearActionMessage,
        modifier = modifier,
    )
}

@Composable
fun PipelineScreen(
    state: PipelineUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onMoveStage: (oppId: String, stage: String) -> Unit,
    onCreate: (name: String, stage: String, amountDollars: String, closeDate: Long, onCreated: () -> Unit) -> Unit,
    onClearCreateError: () -> Unit,
    onClearActionMessage: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val snackbarHostState = remember { SnackbarHostState() }
    var showCreate by remember { mutableStateOf(false) }

    LaunchedEffect(state.actionMessage) {
        state.actionMessage?.let {
            snackbarHostState.showSnackbar(it)
            onClearActionMessage()
        }
    }

    Scaffold(
        modifier = modifier.testTag(CrmPipelineTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = { Text("Sales pipeline") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
        floatingActionButton = {
            FloatingActionButton(
                onClick = { showCreate = true },
                modifier = Modifier.testTag(CrmPipelineTestTags.FAB),
            ) { Icon(Icons.Filled.Add, contentDescription = "New opportunity") }
        },
    ) { padding ->
        when (state.phase) {
            PipelineUiState.Phase.Loading -> LoadingState(
                modifier = Modifier.padding(padding).testTag(CrmPipelineTestTags.LOADING),
            )
            PipelineUiState.Phase.Error -> ErrorState(
                message = state.errorMessage ?: "Couldn't load the pipeline.",
                onRetry = onRetry,
                modifier = Modifier.padding(padding).testTag(CrmPipelineTestTags.ERROR),
            )
            PipelineUiState.Phase.Content -> PullToRefreshBox(
                isRefreshing = state.isRefreshing,
                onRefresh = onRefresh,
                modifier = Modifier.padding(padding).fillMaxSize(),
            ) {
                LazyColumn(
                    modifier = Modifier.fillMaxSize().testTag(CrmPipelineTestTags.CONTENT),
                    contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    if (state.isOffline) item { OfflineBanner(onRetry = onRetry) }
                    if (state.moduleDisabled) {
                        item { InfoBanner("The sales pipeline is not enabled for this account.") }
                    }
                    item { ForecastHeader(state) }
                    state.columns.forEach { column ->
                        if (column.opportunities.isNotEmpty()) {
                            item(key = "hdr_${column.stageKey}") { StageHeader(column.label, column.opportunities.size, column.weightedAmountCents) }
                            items(column.opportunities, key = { it.oppId }) { opp ->
                                OpportunityCard(
                                    opp = opp,
                                    stageKeys = state.columns.map { it.stageKey },
                                    moving = state.movingOppId == opp.oppId,
                                    onMoveStage = { newStage -> onMoveStage(opp.oppId, newStage) },
                                )
                            }
                        }
                    }
                    if (state.columns.all { it.opportunities.isEmpty() } && !state.moduleDisabled) {
                        item {
                            Text(
                                "No opportunities yet. Tap + to add one.",
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                }
            }
        }
    }

    if (showCreate) {
        val stageKeys = state.stages.map { it.stageKey }.ifEmpty { CrmSalesMath.STAGE_ORDER }
        val defaultClose = System.currentTimeMillis() / 1000 + 30L * 24 * 3600
        CreateOpportunitySheet(
            submitting = state.createSubmitting,
            error = state.createError,
            stageKeys = stageKeys.filterNot { CrmSalesMath.isClosedStage(it) },
            defaultStage = stageKeys.firstOrNull { !CrmSalesMath.isClosedStage(it) } ?: "prospecting",
            onDismiss = {
                showCreate = false
                onClearCreateError()
            },
            onSubmit = { name, stage, amount ->
                onCreate(name, stage, amount, defaultClose) { showCreate = false }
            },
        )
    }
}

@Composable
private fun ForecastHeader(state: PipelineUiState) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Forecast", style = MaterialTheme.typography.titleMedium)
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Stat(CrmSalesMath.formatCents(state.openWeightedCents), "Weighted", CrmPipelineTestTags.OPEN_WEIGHTED)
                Stat(CrmSalesMath.formatCents(state.openAmountCents), "Open", null)
                Stat(CrmSalesMath.formatCents(state.wonAmountCents), "Won", null)
                Stat("${state.winRatePct}%", "Win rate", null)
            }
        }
    }
}

@Composable
private fun Stat(value: String, label: String, testTag: String?) {
    Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = if (testTag != null) Modifier.testTag(testTag) else Modifier) {
        Text(value, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
        Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun StageHeader(label: String, count: Int, weightedCents: Long) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(top = 4.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text("$label ($count)", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
        Text(CrmSalesMath.formatCents(weightedCents), style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun OpportunityCard(
    opp: Opportunity,
    stageKeys: List<String>,
    moving: Boolean,
    onMoveStage: (String) -> Unit,
) {
    var menuOpen by remember { mutableStateOf(false) }
    Card(modifier = Modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(opp.name, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Medium)
                Text(
                    "${CrmSalesMath.formatCents(opp.amountCents)} · ${opp.probability}%",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Text(
                    "Weighted ${CrmSalesMath.formatCents(CrmSalesMath.weightedAmountCents(opp.amountCents, opp.probability, opp.stage))}",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Surface(color = MaterialTheme.colorScheme.secondaryContainer, contentColor = MaterialTheme.colorScheme.onSecondaryContainer, shape = MaterialTheme.shapes.small) {
                Text(
                    CrmSalesMath.stageLabel(opp.stage),
                    style = MaterialTheme.typography.labelSmall,
                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                )
            }
            IconButton(onClick = { menuOpen = true }, enabled = !moving) {
                Icon(Icons.Filled.MoreVert, contentDescription = "Move stage")
            }
            DropdownMenu(expanded = menuOpen, onDismissRequest = { menuOpen = false }) {
                stageKeys.filter { it != opp.stage }.forEach { stage ->
                    DropdownMenuItem(
                        text = { Text(CrmSalesMath.stageLabel(stage)) },
                        onClick = {
                            menuOpen = false
                            onMoveStage(stage)
                        },
                    )
                }
            }
        }
    }
}
