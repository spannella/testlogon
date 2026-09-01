@file:OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)

package com.testlogon.android.feature.marketingcampaigns

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.TabRow
import androidx.compose.material3.Tab
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.core.ui.state.OfflineBanner
import com.testlogon.android.data.marketing.campaigns.ContactList
import com.testlogon.android.data.marketing.campaigns.MarketingCampaign
import com.testlogon.android.data.marketing.campaigns.MarketingMath
import com.testlogon.android.data.marketing.campaigns.PartySegment

object MarketingCampaignsTestTags {
    const val SCREEN = "mktc_screen"
    const val LOADING = "mktc_loading"
    const val EMPTY = "mktc_empty"
    const val ERROR = "mktc_error"
    const val OFFLINE = "mktc_offline"
    const val FAB = "mktc_fab"
    const val TAB_PREFIX = "mktc_tab_"
    const val CAMPAIGN_PREFIX = "mktc_campaign_"
    const val LIST_PREFIX = "mktc_list_"
    const val SEGMENT_PREFIX = "mktc_segment_"
    const val CREATE_FORM = "mktc_create_form"
    const val CREATE_SUBMIT = "mktc_create_submit"
}

@Composable
fun MarketingCampaignsRoute(
    onBack: () -> Unit,
    onSessionExpired: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: MarketingCampaignsViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    val context = LocalContext.current

    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is MarketingCampaignsEffect.ShowMessage ->
                    snackbarHostState.showSnackbar(context.getString(effect.resId))
                is MarketingCampaignsEffect.ShowText ->
                    snackbarHostState.showSnackbar(effect.text)
            }
        }
    }
    LaunchedEffect(state.phase) {
        if (state.phase == MarketingCampaignsUiState.Phase.SessionExpired) onSessionExpired()
    }

    MarketingCampaignsScreen(
        state = state,
        snackbarHostState = snackbarHostState,
        onBack = onBack,
        onRefresh = viewModel::onRefresh,
        onRetry = viewModel::onRetry,
        onSelectTab = viewModel::onSelectTab,
        onOpenCreateCampaign = viewModel::onOpenCreateCampaign,
        onDismissCreateCampaign = viewModel::onDismissCreateCampaign,
        onCampaignNameChange = viewModel::onCampaignNameChange,
        onCampaignObjectiveChange = viewModel::onCampaignObjectiveChange,
        onCampaignBudgetChange = viewModel::onCampaignBudgetChange,
        onSubmitCreateCampaign = viewModel::onSubmitCreateCampaign,
        onTransition = viewModel::onTransition,
        onSend = viewModel::onSend,
        onOpenCreateList = viewModel::onOpenCreateList,
        onDismissCreateList = viewModel::onDismissCreateList,
        onListNameChange = viewModel::onListNameChange,
        onListDescriptionChange = viewModel::onListDescriptionChange,
        onSubmitCreateList = viewModel::onSubmitCreateList,
        modifier = modifier,
    )
}

@Composable
fun MarketingCampaignsScreen(
    state: MarketingCampaignsUiState,
    snackbarHostState: SnackbarHostState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onSelectTab: (MarketingCampaignsTab) -> Unit,
    onOpenCreateCampaign: () -> Unit,
    onDismissCreateCampaign: () -> Unit,
    onCampaignNameChange: (String) -> Unit,
    onCampaignObjectiveChange: (MarketingMath.CampaignObjective) -> Unit,
    onCampaignBudgetChange: (String) -> Unit,
    onSubmitCreateCampaign: () -> Unit,
    onTransition: (MarketingCampaign, MarketingMath.CampaignStatus) -> Unit,
    onSend: (MarketingCampaign) -> Unit,
    onOpenCreateList: () -> Unit,
    onDismissCreateList: () -> Unit,
    onListNameChange: (String) -> Unit,
    onListDescriptionChange: (String) -> Unit,
    onSubmitCreateList: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(MarketingCampaignsTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("Marketing campaigns") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
        floatingActionButton = {
            val canCreate = state.tab == MarketingCampaignsTab.CAMPAIGNS ||
                state.tab == MarketingCampaignsTab.LISTS
            if (state.phase == MarketingCampaignsUiState.Phase.Content && canCreate) {
                Button(
                    onClick = {
                        if (state.tab == MarketingCampaignsTab.CAMPAIGNS) onOpenCreateCampaign() else onOpenCreateList()
                    },
                    modifier = Modifier.testTag(MarketingCampaignsTestTags.FAB),
                ) {
                    Icon(Icons.Outlined.Add, contentDescription = null)
                    Text(if (state.tab == MarketingCampaignsTab.CAMPAIGNS) "New campaign" else "New list")
                }
            }
        },
    ) { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding)) {
            TabRow(selectedTabIndex = state.tab.ordinal) {
                MarketingCampaignsTab.entries.forEach { tab ->
                    Tab(
                        selected = state.tab == tab,
                        onClick = { onSelectTab(tab) },
                        text = { Text(tab.label) },
                        modifier = Modifier.testTag(MarketingCampaignsTestTags.TAB_PREFIX + tab.name),
                    )
                }
            }

            when (state.phase) {
                MarketingCampaignsUiState.Phase.Loading ->
                    LoadingState(modifier = Modifier.testTag(MarketingCampaignsTestTags.LOADING))
                MarketingCampaignsUiState.Phase.Error ->
                    ErrorState(
                        message = state.errorMessage ?: "Something went wrong.",
                        onRetry = onRetry,
                        modifier = Modifier.testTag(MarketingCampaignsTestTags.ERROR),
                    )
                MarketingCampaignsUiState.Phase.Offline ->
                    Column {
                        OfflineBanner(
                            onRetry = onRetry,
                            modifier = Modifier.testTag(MarketingCampaignsTestTags.OFFLINE),
                        )
                    }
                MarketingCampaignsUiState.Phase.SessionExpired -> Unit
                MarketingCampaignsUiState.Phase.Content ->
                    PullToRefreshBox(
                        isRefreshing = state.isRefreshing,
                        onRefresh = onRefresh,
                        modifier = Modifier.fillMaxSize(),
                    ) {
                        TabContent(
                            state = state,
                            onTransition = onTransition,
                            onSend = onSend,
                        )
                    }
            }
        }
    }

    if (state.createCampaign.isOpen) {
        CreateCampaignDialog(
            form = state.createCampaign,
            onDismiss = onDismissCreateCampaign,
            onNameChange = onCampaignNameChange,
            onObjectiveChange = onCampaignObjectiveChange,
            onBudgetChange = onCampaignBudgetChange,
            onSubmit = onSubmitCreateCampaign,
        )
    }
    if (state.createList.isOpen) {
        CreateListDialog(
            form = state.createList,
            onDismiss = onDismissCreateList,
            onNameChange = onListNameChange,
            onDescriptionChange = onListDescriptionChange,
            onSubmit = onSubmitCreateList,
        )
    }
}

@Composable
private fun TabContent(
    state: MarketingCampaignsUiState,
    onTransition: (MarketingCampaign, MarketingMath.CampaignStatus) -> Unit,
    onSend: (MarketingCampaign) -> Unit,
) {
    if (state.isEmptyForTab) {
        val title = when (state.tab) {
            MarketingCampaignsTab.CAMPAIGNS -> "No campaigns yet"
            MarketingCampaignsTab.LISTS -> "No contact lists yet"
            MarketingCampaignsTab.SEGMENTS -> "No segments yet"
        }
        val body = when (state.tab) {
            MarketingCampaignsTab.CAMPAIGNS -> "Create a campaign to reach your audience."
            MarketingCampaignsTab.LISTS -> "Create a list to group contacts."
            MarketingCampaignsTab.SEGMENTS -> "Segments are defined on the web console."
        }
        EmptyState(
            title = title,
            body = body,
            modifier = Modifier.testTag(MarketingCampaignsTestTags.EMPTY),
        )
        return
    }
    LazyColumn(
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
        modifier = Modifier.fillMaxSize(),
    ) {
        when (state.tab) {
            MarketingCampaignsTab.CAMPAIGNS -> items(state.campaigns, key = { it.id }) { c ->
                CampaignCard(
                    campaign = c,
                    busy = state.busyCampaignId == c.id,
                    onTransition = onTransition,
                    onSend = onSend,
                )
            }
            MarketingCampaignsTab.LISTS -> items(state.lists, key = { it.id }) { l -> ListCard(l) }
            MarketingCampaignsTab.SEGMENTS -> items(state.segments, key = { it.id }) { s -> SegmentCard(s) }
        }
    }
}

@Composable
private fun CampaignCard(
    campaign: MarketingCampaign,
    busy: Boolean,
    onTransition: (MarketingCampaign, MarketingMath.CampaignStatus) -> Unit,
    onSend: (MarketingCampaign) -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth().testTag(MarketingCampaignsTestTags.CAMPAIGN_PREFIX + campaign.id)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(campaign.name, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            Text(
                "${campaign.objective?.label ?: campaign.objectiveRaw} · ${campaign.budgetLabel}",
                style = MaterialTheme.typography.bodyMedium,
            )
            AssistChip(onClick = {}, label = { Text(campaign.status.name.lowercase()) })
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                if (campaign.canSend) {
                    OutlinedButton(onClick = { onSend(campaign) }, enabled = !busy) { Text("Send") }
                }
                campaign.allowedTransitions.forEach { target ->
                    OutlinedButton(onClick = { onTransition(campaign, target) }, enabled = !busy) {
                        Text(transitionVerb(target))
                    }
                }
            }
        }
    }
}

private fun transitionVerb(target: MarketingMath.CampaignStatus): String = when (target) {
    MarketingMath.CampaignStatus.SCHEDULED -> "Schedule"
    MarketingMath.CampaignStatus.ACTIVE -> "Activate"
    MarketingMath.CampaignStatus.PAUSED -> "Pause"
    MarketingMath.CampaignStatus.COMPLETED -> "Complete"
    MarketingMath.CampaignStatus.ARCHIVED -> "Archive"
    else -> target.name.lowercase()
}

@Composable
private fun ListCard(list: ContactList) {
    Card(modifier = Modifier.fillMaxWidth().testTag(MarketingCampaignsTestTags.LIST_PREFIX + list.id)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(list.name, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            list.description?.let { Text(it, style = MaterialTheme.typography.bodyMedium) }
            Text(list.sizeLabel, style = MaterialTheme.typography.bodySmall)
        }
    }
}

@Composable
private fun SegmentCard(segment: PartySegment) {
    Card(modifier = Modifier.fillMaxWidth().testTag(MarketingCampaignsTestTags.SEGMENT_PREFIX + segment.id)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(segment.name, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            segment.description?.let { Text(it, style = MaterialTheme.typography.bodyMedium) }
            segment.predicates.forEach { p ->
                Text("• ${p.summary}", style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

@Composable
private fun CreateCampaignDialog(
    form: CreateCampaignFormState,
    onDismiss: () -> Unit,
    onNameChange: (String) -> Unit,
    onObjectiveChange: (MarketingMath.CampaignObjective) -> Unit,
    onBudgetChange: (String) -> Unit,
    onSubmit: () -> Unit,
) {
    Dialog(onDismissRequest = onDismiss) {
        Card(modifier = Modifier.testTag(MarketingCampaignsTestTags.CREATE_FORM)) {
            Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text("New campaign", style = MaterialTheme.typography.titleLarge)
                OutlinedTextField(
                    value = form.name,
                    onValueChange = onNameChange,
                    label = { Text("Name") },
                    singleLine = true,
                    enabled = !form.isSubmitting,
                    modifier = Modifier.fillMaxWidth(),
                )
                ObjectiveDropdown(
                    selected = form.objective,
                    enabled = !form.isSubmitting,
                    onSelect = onObjectiveChange,
                )
                OutlinedTextField(
                    value = form.budget,
                    onValueChange = onBudgetChange,
                    label = { Text("Budget (USD)") },
                    singleLine = true,
                    enabled = !form.isSubmitting,
                    modifier = Modifier.fillMaxWidth(),
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.align(Alignment.End)) {
                    TextButton(onClick = onDismiss, enabled = !form.isSubmitting) { Text("Cancel") }
                    Button(
                        onClick = onSubmit,
                        enabled = form.canSubmit,
                        modifier = Modifier.testTag(MarketingCampaignsTestTags.CREATE_SUBMIT),
                    ) { Text("Create") }
                }
            }
        }
    }
}

@Composable
private fun ObjectiveDropdown(
    selected: MarketingMath.CampaignObjective,
    enabled: Boolean,
    onSelect: (MarketingMath.CampaignObjective) -> Unit,
) {
    var expanded by remember { mutableStateOf(false) }
    Box {
        OutlinedButton(onClick = { if (enabled) expanded = true }, enabled = enabled, modifier = Modifier.fillMaxWidth()) {
            Text("Objective: ${selected.label}")
        }
        DropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
            MarketingMath.CampaignObjective.ALL.forEach { o ->
                DropdownMenuItem(text = { Text(o.label) }, onClick = { onSelect(o); expanded = false })
            }
        }
    }
}

@Composable
private fun CreateListDialog(
    form: CreateListFormState,
    onDismiss: () -> Unit,
    onNameChange: (String) -> Unit,
    onDescriptionChange: (String) -> Unit,
    onSubmit: () -> Unit,
) {
    Dialog(onDismissRequest = onDismiss) {
        Card(modifier = Modifier.testTag(MarketingCampaignsTestTags.CREATE_FORM)) {
            Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text("New contact list", style = MaterialTheme.typography.titleLarge)
                OutlinedTextField(
                    value = form.name,
                    onValueChange = onNameChange,
                    label = { Text("Name") },
                    singleLine = true,
                    enabled = !form.isSubmitting,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = form.description,
                    onValueChange = onDescriptionChange,
                    label = { Text("Description (optional)") },
                    enabled = !form.isSubmitting,
                    modifier = Modifier.fillMaxWidth(),
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.align(Alignment.End)) {
                    TextButton(onClick = onDismiss, enabled = !form.isSubmitting) { Text("Cancel") }
                    Button(
                        onClick = onSubmit,
                        enabled = form.canSubmit,
                        modifier = Modifier.testTag(MarketingCampaignsTestTags.CREATE_SUBMIT),
                    ) { Text("Create") }
                }
            }
        }
    }
}
