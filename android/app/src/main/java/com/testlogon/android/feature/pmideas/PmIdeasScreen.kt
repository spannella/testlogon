@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.pmideas

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.horizontalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Autorenew
import androidx.compose.material.icons.outlined.Lightbulb
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.ScrollableTabRow
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Tab
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
import com.testlogon.android.data.pmideas.PmIdea
import com.testlogon.android.data.pmideas.PmIdeaStatus

object PmIdeasTestTags {
    const val SCREEN = "pm_ideas_screen"
    const val LIST = "pm_ideas_list"
    const val LOADING = "pm_ideas_loading"
    const val EMPTY = "pm_ideas_empty"
    const val ERROR = "pm_ideas_error"
    const val OFFLINE = "pm_ideas_offline"
    const val SESSION_EXPIRED = "pm_ideas_session_expired"
    const val TRIGGER = "pm_trigger_review"
    const val CARD_PREFIX = "idea_card_"
    const val APPROVE_PREFIX = "idea_approve_"
    const val REJECT_PREFIX = "idea_reject_"
    const val REJECT_DIALOG = "pm_reject_dialog"
    const val REJECT_SUBMIT = "pm_reject_submit"
    const val DETAIL_DIALOG = "pm_idea_detail"
}

@Composable
fun PmIdeasRoute(
    onBack: () -> Unit,
    onSessionExpired: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: PmIdeasViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbar = remember { SnackbarHostState() }
    val context = LocalContext.current

    LaunchedEffect(viewModel) {
        viewModel.effects.collect { e ->
            if (e is PmIdeasEffect.ShowMessage) snackbar.showSnackbar(context.getString(e.resId))
        }
    }
    LaunchedEffect(state.phase) {
        if (state.phase == PmIdeasPhase.SessionExpired) onSessionExpired()
    }

    Scaffold(
        modifier = modifier.testTag(PmIdeasTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.pmideas_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack, modifier = Modifier.testTag("pm_ideas_back")) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.action_back))
                    }
                },
                actions = {
                    IconButton(
                        onClick = viewModel::onTriggerReview,
                        enabled = !state.isTriggeringReview,
                        modifier = Modifier.testTag(PmIdeasTestTags.TRIGGER),
                    ) {
                        Icon(Icons.Outlined.Autorenew, contentDescription = stringResource(R.string.pmideas_trigger_review))
                    }
                },
            )
        },
    ) { padding ->
        Column(modifier = Modifier.padding(padding).fillMaxSize()) {
            val tabs = listOf(PmIdeaStatus.PENDING, PmIdeaStatus.APPROVED, PmIdeaStatus.REJECTED, PmIdeaStatus.ARCHIVED)
            ScrollableTabRow(selectedTabIndex = tabs.indexOf(state.tab).coerceAtLeast(0), edgePadding = 0.dp) {
                tabs.forEach { t ->
                    Tab(
                        selected = state.tab == t,
                        onClick = { viewModel.onSelectTab(t) },
                        text = { Text(stringResource(tabLabel(t))) },
                        modifier = Modifier.testTag("pm_tab_${t.serverValue}"),
                    )
                }
            }
            Box(modifier = Modifier.fillMaxSize()) {
                when (state.phase) {
                    PmIdeasPhase.Loading -> LoadingState(modifier = Modifier.testTag(PmIdeasTestTags.LOADING))
                    PmIdeasPhase.Error -> ErrorState(
                        message = state.errorMessage ?: stringResource(R.string.pmideas_error_generic),
                        onRetry = viewModel::onRetry,
                        modifier = Modifier.testTag(PmIdeasTestTags.ERROR),
                    )
                    PmIdeasPhase.Offline -> ErrorState(
                        message = state.errorMessage ?: stringResource(R.string.pmideas_error_generic),
                        onRetry = viewModel::onRetry,
                        modifier = Modifier.testTag(PmIdeasTestTags.OFFLINE),
                    )
                    PmIdeasPhase.SessionExpired -> EmptyState(
                        title = stringResource(R.string.pmideas_session_expired_title),
                        body = stringResource(R.string.pmideas_session_expired_body),
                        modifier = Modifier.testTag(PmIdeasTestTags.SESSION_EXPIRED),
                    )
                    PmIdeasPhase.Empty -> PullToRefreshBox(state.isRefreshing, viewModel::onRefresh, Modifier.fillMaxSize()) {
                        EmptyState(
                            title = stringResource(R.string.pmideas_empty_title),
                            body = stringResource(R.string.pmideas_empty_body),
                            imageVector = Icons.Outlined.Lightbulb,
                            modifier = Modifier.testTag(PmIdeasTestTags.EMPTY),
                        )
                    }
                    PmIdeasPhase.Content -> PullToRefreshBox(state.isRefreshing, viewModel::onRefresh, Modifier.fillMaxSize()) {
                        LazyColumn(
                            modifier = Modifier.fillMaxSize().testTag(PmIdeasTestTags.LIST),
                            contentPadding = PaddingValues(16.dp),
                            verticalArrangement = Arrangement.spacedBy(12.dp),
                        ) {
                            items(state.ideas, key = { it.id }) { idea ->
                                IdeaCard(
                                    idea = idea,
                                    onOpen = { viewModel.onOpenDetail(idea) },
                                    onApprove = { viewModel.onApprove(idea.id) },
                                    onReject = { viewModel.onOpenReject(idea.id) },
                                )
                            }
                        }
                    }
                }
            }
        }
    }

    state.detail?.let { idea ->
        IdeaDetailDialog(
            idea = idea,
            onDismiss = viewModel::onDismissDetail,
            onApprove = { viewModel.onApprove(idea.id) },
            onReject = { viewModel.onOpenReject(idea.id) },
            onArchive = { viewModel.onArchive(idea.id) },
        )
    }

    if (state.rejectForm.isOpen) {
        RejectDialog(
            form = state.rejectForm,
            onDismiss = viewModel::onDismissReject,
            onReasonChange = viewModel::onRejectReasonChange,
            onSubmit = viewModel::onSubmitReject,
        )
    }
}

private fun tabLabel(t: PmIdeaStatus): Int = when (t) {
    PmIdeaStatus.PENDING -> R.string.pmideas_tab_pending
    PmIdeaStatus.APPROVED -> R.string.pmideas_tab_approved
    PmIdeaStatus.REJECTED -> R.string.pmideas_tab_rejected
    PmIdeaStatus.ARCHIVED -> R.string.pmideas_tab_archived
    PmIdeaStatus.UNKNOWN -> R.string.pmideas_tab_pending
}

@Composable
private fun IdeaCard(idea: PmIdea, onOpen: () -> Unit, onApprove: () -> Unit, onReject: () -> Unit) {
    Card(modifier = Modifier.fillMaxWidth().testTag(PmIdeasTestTags.CARD_PREFIX + idea.id), onClick = onOpen) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(idea.title, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold, maxLines = 2, overflow = TextOverflow.Ellipsis)
            Row(Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                if (idea.category.isNotBlank()) AssistChip(onClick = {}, enabled = false, label = { Text(idea.category) })
                if (idea.prioritySuggestion.isNotBlank()) AssistChip(onClick = {}, enabled = false, label = { Text(idea.prioritySuggestion) })
            }
            if (idea.userImpact.isNotBlank()) {
                Text(idea.userImpact, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 3, overflow = TextOverflow.Ellipsis)
            }
            idea.rejectionReason?.let {
                Text(stringResource(R.string.pmideas_rejection_reason, it), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
            }
            idea.createdTicketId?.let {
                Text(stringResource(R.string.pmideas_created_ticket, it), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.primary)
            }
            if (idea.canTriage) {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(onClick = onApprove, modifier = Modifier.testTag(PmIdeasTestTags.APPROVE_PREFIX + idea.id)) {
                        Text(stringResource(R.string.pmideas_approve))
                    }
                    OutlinedButton(onClick = onReject, modifier = Modifier.testTag(PmIdeasTestTags.REJECT_PREFIX + idea.id)) {
                        Text(stringResource(R.string.pmideas_reject))
                    }
                }
            }
        }
    }
}

@Composable
private fun IdeaDetailDialog(idea: PmIdea, onDismiss: () -> Unit, onApprove: () -> Unit, onReject: () -> Unit, onArchive: () -> Unit) {
    Dialog(onDismissRequest = onDismiss) {
        Card(modifier = Modifier.fillMaxWidth().testTag(PmIdeasTestTags.DETAIL_DIALOG)) {
            Column(Modifier.fillMaxWidth().padding(20.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(idea.title, style = MaterialTheme.typography.titleLarge)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    if (idea.category.isNotBlank()) AssistChip(onClick = {}, enabled = false, label = { Text(idea.category) })
                    if (idea.prioritySuggestion.isNotBlank()) AssistChip(onClick = {}, enabled = false, label = { Text(idea.prioritySuggestion) })
                }
                if (idea.description.isNotBlank()) {
                    Text(idea.description, style = MaterialTheme.typography.bodyMedium)
                }
                if (idea.userImpact.isNotBlank()) {
                    Text(stringResource(R.string.pmideas_user_impact, idea.userImpact), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                idea.mockupDescription?.let {
                    Text(stringResource(R.string.pmideas_mockup, it), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                idea.rejectionReason?.let {
                    Text(stringResource(R.string.pmideas_rejection_reason, it), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                }
                Row(Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    if (idea.canTriage) {
                        Button(onClick = onApprove) { Text(stringResource(R.string.pmideas_approve)) }
                        OutlinedButton(onClick = onReject) { Text(stringResource(R.string.pmideas_reject)) }
                    }
                    if (idea.status != PmIdeaStatus.ARCHIVED) {
                        TextButton(onClick = onArchive) { Text(stringResource(R.string.pmideas_archive)) }
                    }
                    TextButton(onClick = onDismiss) { Text(stringResource(R.string.pmideas_close)) }
                }
            }
        }
    }
}

@Composable
private fun RejectDialog(form: RejectFormState, onDismiss: () -> Unit, onReasonChange: (String) -> Unit, onSubmit: () -> Unit) {
    Dialog(onDismissRequest = onDismiss) {
        Card(modifier = Modifier.fillMaxWidth().testTag(PmIdeasTestTags.REJECT_DIALOG)) {
            Column(Modifier.fillMaxWidth().padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(stringResource(R.string.pmideas_reject_title), style = MaterialTheme.typography.titleLarge)
                OutlinedTextField(
                    value = form.reason,
                    onValueChange = onReasonChange,
                    label = { Text(stringResource(R.string.pmideas_reject_reason_label)) },
                    minLines = 3,
                    enabled = !form.isSubmitting,
                    modifier = Modifier.fillMaxWidth().testTag("pm_reject_reason"),
                )
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                    TextButton(onClick = onDismiss, enabled = !form.isSubmitting) { Text(stringResource(R.string.action_cancel)) }
                    TextButton(onClick = onSubmit, enabled = form.canSubmit, modifier = Modifier.testTag(PmIdeasTestTags.REJECT_SUBMIT)) {
                        Text(stringResource(R.string.pmideas_reject))
                    }
                }
            }
        }
    }
}
