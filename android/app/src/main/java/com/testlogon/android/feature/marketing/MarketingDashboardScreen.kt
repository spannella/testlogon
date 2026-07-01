@file:OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)

package com.testlogon.android.feature.marketing

import androidx.compose.foundation.horizontalScroll
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.BarChart
import androidx.compose.material.icons.outlined.CalendarMonth
import androidx.compose.material.icons.outlined.Campaign
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.core.ui.state.OfflineBanner
import com.testlogon.android.data.marketing.MarketingContent

object MarketingDashboardTestTags {
    const val SCREEN = "marketing_dashboard_screen"
    const val LIST = "marketing_content_list"
    const val LOADING = "marketing_dashboard_loading"
    const val EMPTY = "marketing_content_empty"
    const val ERROR = "marketing_dashboard_error"
    const val OFFLINE = "marketing_dashboard_offline"
    const val SESSION_EXPIRED = "marketing_dashboard_session_expired"
    const val CREATE = "marketing_create"
    const val CALENDAR = "marketing_open_calendar"
    const val ENGAGEMENT = "marketing_open_engagement"
    const val FORM = "marketing_create_form"
    const val FORM_TITLE = "marketing_create_title"
    const val FORM_BODY = "marketing_create_body"
    const val FORM_SUBMIT = "marketing_create_submit"
    const val CARD_PREFIX = "marketing_card_"
    const val TAB_PREFIX = "marketing_tab_"
}

@Composable
fun MarketingDashboardRoute(
    onBack: () -> Unit,
    onSessionExpired: () -> Unit,
    onOpenContent: (String) -> Unit,
    onOpenCalendar: () -> Unit,
    onOpenEngagement: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: MarketingDashboardViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    val context = LocalContext.current

    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is MarketingEffect.ShowMessage ->
                    snackbarHostState.showSnackbar(context.getString(effect.resId))
            }
        }
    }
    LaunchedEffect(state.phase) {
        if (state.phase == MarketingDashboardUiState.Phase.SessionExpired) onSessionExpired()
    }

    MarketingDashboardScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::onRefresh,
        onRetry = viewModel::onRetry,
        onSelectTab = viewModel::onSelectTab,
        onOpenCreate = viewModel::onOpenCreate,
        onDismissCreate = viewModel::onDismissCreate,
        onTypeChange = viewModel::onTypeChange,
        onTitleChange = viewModel::onTitleChange,
        onBodyChange = viewModel::onBodyChange,
        onSubmitCreate = viewModel::onSubmitCreate,
        onApprove = viewModel::onApprove,
        onPublish = viewModel::onPublish,
        onArchive = viewModel::onArchive,
        onDelete = viewModel::onDelete,
        onOpenContent = onOpenContent,
        onOpenCalendar = onOpenCalendar,
        onOpenEngagement = onOpenEngagement,
        snackbarHostState = snackbarHostState,
        modifier = modifier,
    )
}

@Composable
fun MarketingDashboardScreen(
    state: MarketingDashboardUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onSelectTab: (MarketingTab) -> Unit,
    onOpenCreate: () -> Unit,
    onDismissCreate: () -> Unit,
    onTypeChange: (String) -> Unit,
    onTitleChange: (String) -> Unit,
    onBodyChange: (String) -> Unit,
    onSubmitCreate: () -> Unit,
    onApprove: (MarketingContent) -> Unit,
    onPublish: (MarketingContent) -> Unit,
    onArchive: (MarketingContent) -> Unit,
    onDelete: (MarketingContent) -> Unit,
    onOpenContent: (String) -> Unit,
    onOpenCalendar: () -> Unit,
    onOpenEngagement: () -> Unit,
    modifier: Modifier = Modifier,
    snackbarHostState: SnackbarHostState = remember { SnackbarHostState() },
) {
    Scaffold(
        modifier = modifier.testTag(MarketingDashboardTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.marketing_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
                actions = {
                    IconButton(onClick = onOpenCalendar, modifier = Modifier.testTag(MarketingDashboardTestTags.CALENDAR)) {
                        Icon(Icons.Outlined.CalendarMonth, contentDescription = stringResource(R.string.marketing_calendar_title))
                    }
                    IconButton(onClick = onOpenEngagement, modifier = Modifier.testTag(MarketingDashboardTestTags.ENGAGEMENT)) {
                        Icon(Icons.Outlined.BarChart, contentDescription = stringResource(R.string.marketing_engagement_title))
                    }
                    IconButton(onClick = onOpenCreate, modifier = Modifier.testTag(MarketingDashboardTestTags.CREATE)) {
                        Icon(Icons.Outlined.Add, contentDescription = stringResource(R.string.marketing_new))
                    }
                },
            )
        },
    ) { padding ->
        Column(modifier = Modifier.padding(padding).fillMaxSize()) {
            FilterTabs(active = state.tab, onSelect = onSelectTab)
            Box(modifier = Modifier.fillMaxSize()) {
                when (state.phase) {
                    MarketingDashboardUiState.Phase.Loading ->
                        LoadingState(modifier = Modifier.testTag(MarketingDashboardTestTags.LOADING))
                    MarketingDashboardUiState.Phase.Error ->
                        ErrorState(
                            message = state.errorMessage ?: stringResource(R.string.marketing_error_generic),
                            onRetry = onRetry,
                            modifier = Modifier.testTag(MarketingDashboardTestTags.ERROR),
                        )
                    MarketingDashboardUiState.Phase.Offline ->
                        ErrorState(
                            message = state.errorMessage ?: stringResource(R.string.marketing_error_generic),
                            onRetry = onRetry,
                            modifier = Modifier.testTag(MarketingDashboardTestTags.OFFLINE),
                        )
                    MarketingDashboardUiState.Phase.SessionExpired ->
                        EmptyState(
                            title = stringResource(R.string.marketing_session_expired_title),
                            body = stringResource(R.string.marketing_session_expired_body),
                            modifier = Modifier.testTag(MarketingDashboardTestTags.SESSION_EXPIRED),
                        )
                    MarketingDashboardUiState.Phase.Empty ->
                        PullToRefreshBox(isRefreshing = state.isRefreshing, onRefresh = onRefresh, modifier = Modifier.fillMaxSize()) {
                            EmptyState(
                                title = stringResource(R.string.marketing_empty_title),
                                body = stringResource(R.string.marketing_empty_body),
                                imageVector = Icons.Outlined.Campaign,
                                actionLabel = stringResource(R.string.marketing_new),
                                onAction = onOpenCreate,
                                modifier = Modifier.testTag(MarketingDashboardTestTags.EMPTY),
                            )
                        }
                    MarketingDashboardUiState.Phase.Content -> {
                        val items = state.page?.items.orEmpty()
                        PullToRefreshBox(isRefreshing = state.isRefreshing, onRefresh = onRefresh, modifier = Modifier.fillMaxSize()) {
                            LazyColumn(
                                modifier = Modifier.testTag(MarketingDashboardTestTags.LIST).fillMaxSize(),
                                contentPadding = PaddingValues(16.dp),
                                verticalArrangement = Arrangement.spacedBy(12.dp),
                            ) {
                                if (state.isStale) item { OfflineBanner(onRetry = onRetry) }
                                items(items, key = { it.id }) { c ->
                                    ContentCard(
                                        content = c,
                                        isBusy = state.busyContentId == c.id,
                                        onOpen = { onOpenContent(c.id) },
                                        onApprove = { onApprove(c) },
                                        onPublish = { onPublish(c) },
                                        onArchive = { onArchive(c) },
                                        onDelete = { onDelete(c) },
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if (state.create.isOpen) {
        CreateContentDialog(
            form = state.create,
            onDismiss = onDismissCreate,
            onTypeChange = onTypeChange,
            onTitleChange = onTitleChange,
            onBodyChange = onBodyChange,
            onSubmit = onSubmitCreate,
        )
    }
}

@Composable
private fun FilterTabs(active: MarketingTab, onSelect: (MarketingTab) -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .horizontalScroll(rememberScrollState())
            .padding(horizontal = 16.dp, vertical = 8.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        MarketingTab.entries.forEach { tab ->
            FilterChip(
                selected = active == tab,
                onClick = { onSelect(tab) },
                label = { Text(tab.label) },
                modifier = Modifier.testTag(MarketingDashboardTestTags.TAB_PREFIX + tab.name),
            )
        }
    }
}

@Composable
private fun ContentCard(
    content: MarketingContent,
    isBusy: Boolean,
    onOpen: () -> Unit,
    onApprove: () -> Unit,
    onPublish: () -> Unit,
    onArchive: () -> Unit,
    onDelete: () -> Unit,
) {
    Card(
        modifier = Modifier.fillMaxWidth().testTag(MarketingDashboardTestTags.CARD_PREFIX + content.id),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
    ) {
        Column(modifier = Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = content.title.ifBlank { stringResource(R.string.marketing_untitled) },
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f),
                )
                LabelChip(content.status.name.lowercase())
            }
            LabelChip(content.contentType)
            content.summary?.let {
                Text(it, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 2, overflow = TextOverflow.Ellipsis)
            }
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = onOpen, enabled = !isBusy) { Text(stringResource(R.string.marketing_edit)) }
                if (content.canApprove) Button(onClick = onApprove, enabled = !isBusy) { Text(stringResource(R.string.marketing_approve)) }
                if (content.canPublish) Button(onClick = onPublish, enabled = !isBusy) { Text(stringResource(R.string.marketing_publish)) }
                if (content.canArchive) OutlinedButton(onClick = onArchive, enabled = !isBusy) { Text(stringResource(R.string.marketing_archive)) }
                if (content.canDelete) TextButton(onClick = onDelete, enabled = !isBusy) { Text(stringResource(R.string.marketing_delete)) }
            }
        }
    }
}

@Composable
private fun CreateContentDialog(
    form: CreateContentFormState,
    onDismiss: () -> Unit,
    onTypeChange: (String) -> Unit,
    onTitleChange: (String) -> Unit,
    onBodyChange: (String) -> Unit,
    onSubmit: () -> Unit,
) {
    Dialog(onDismissRequest = onDismiss) {
        Card(modifier = Modifier.fillMaxWidth().testTag(MarketingDashboardTestTags.FORM)) {
            Column(modifier = Modifier.fillMaxWidth().padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(stringResource(R.string.marketing_create_title), style = MaterialTheme.typography.titleLarge)
                MarketingDropdownField(
                    label = stringResource(R.string.marketing_field_type),
                    value = form.contentType,
                    options = CreateContentFormState.CONTENT_TYPES,
                    onSelect = onTypeChange,
                    enabled = !form.isSubmitting,
                )
                OutlinedTextField(
                    value = form.title,
                    onValueChange = onTitleChange,
                    label = { Text(stringResource(R.string.marketing_field_title)) },
                    singleLine = true,
                    enabled = !form.isSubmitting,
                    modifier = Modifier.fillMaxWidth().testTag(MarketingDashboardTestTags.FORM_TITLE),
                )
                OutlinedTextField(
                    value = form.body,
                    onValueChange = onBodyChange,
                    label = { Text(stringResource(R.string.marketing_field_body)) },
                    minLines = 4,
                    enabled = !form.isSubmitting,
                    modifier = Modifier.fillMaxWidth().testTag(MarketingDashboardTestTags.FORM_BODY),
                )
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                    TextButton(onClick = onDismiss, enabled = !form.isSubmitting) { Text(stringResource(R.string.action_cancel)) }
                    TextButton(
                        onClick = onSubmit,
                        enabled = form.canSubmit,
                        modifier = Modifier.testTag(MarketingDashboardTestTags.FORM_SUBMIT),
                    ) {
                        Text(stringResource(R.string.marketing_create_action))
                    }
                }
            }
        }
    }
}

@Composable
internal fun LabelChip(text: String) {
    AssistChip(
        onClick = {},
        enabled = false,
        label = { Text(text) },
        colors = AssistChipDefaults.assistChipColors(
            disabledContainerColor = MaterialTheme.colorScheme.secondaryContainer,
            disabledLabelColor = MaterialTheme.colorScheme.onSurface,
        ),
        border = null,
    )
}
