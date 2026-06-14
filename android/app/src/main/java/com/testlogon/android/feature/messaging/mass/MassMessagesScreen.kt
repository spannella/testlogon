@file:OptIn(ExperimentalLayoutApi::class, ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.messaging.mass

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.InputChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.paging.LoadState
import androidx.paging.compose.collectAsLazyPagingItems
import androidx.paging.compose.itemKey
import com.testlogon.android.R
import com.testlogon.android.data.messaging.mass.CampaignMode
import com.testlogon.android.data.messaging.mass.CampaignStatus
import com.testlogon.android.data.messaging.mass.MassCampaign
import com.testlogon.android.feature.messaging.relativeTimeFromSeconds

/** AND-160 — stable testTags for the mass-messages screens. */
object MassMessagesTestTags {
    const val SCREEN = "mass_messages_screen"
    const val LIST = "mass_messages_list"
    const val ROW = "mass_messages_row"
    const val FAB = "mass_messages_fab"
    const val EMPTY = "mass_messages_empty"
    const val LOADING = "mass_messages_loading"
    const val ERROR = "mass_messages_error"
    const val UNAVAILABLE = "mass_messages_unavailable"
    const val SHEET = "mass_messages_sheet"
    const val TEXT = "mass_messages_text"
    const val RECIPIENT_SEARCH = "mass_messages_recipient_search"
    const val SUBMIT = "mass_messages_submit"
    const val CANCEL_ACTION = "mass_messages_cancel_action"
    const val CANCEL_DIALOG = "mass_messages_cancel_dialog"
}

/**
 * AND-160 — route-level mass-messages screen. Collects one-shot events (snackbar + list invalidation)
 * and renders the paged campaign list + create sheet. Self-gates on the mass-send capability (FR-8):
 * when disabled (or deep-linked while disabled) it renders an "unavailable" state instead of crashing.
 */
@Composable
fun MassMessagesRoute(
    onBack: () -> Unit,
    viewModel: MassMessagesViewModel = hiltViewModel(),
) {
    val ui by viewModel.uiState.collectAsStateWithLifecycle()
    val campaigns = viewModel.campaigns.collectAsLazyPagingItems()
    val snackbarHostState = remember { SnackbarHostState() }

    val createdMsg = stringResource(R.string.mass_messages_created_snack)
    val partialMsg = stringResource(R.string.mass_messages_created_partial_snack)
    val cancelledMsg = stringResource(R.string.mass_messages_cancelled_snack)

    LaunchedEffect(Unit) {
        viewModel.events.collect { event ->
            when (event) {
                is MassMessagesEvent.CreatedSnack -> snackbarHostState.showMessage(
                    if (event.rejectedCount > 0) partialMsg else createdMsg,
                )
                is MassMessagesEvent.CancelledSnack -> snackbarHostState.showMessage(cancelledMsg)
                is MassMessagesEvent.ErrorSnack -> snackbarHostState.showMessage(event.message)
                MassMessagesEvent.InvalidateList -> campaigns.refresh()
            }
        }
    }

    Scaffold(
        modifier = Modifier.testTag(MassMessagesTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.mass_messages_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
        floatingActionButton = {
            if (ui.isCreator) {
                ExtendedFloatingActionButton(
                    onClick = viewModel::openCreate,
                    icon = { Icon(Icons.Filled.Add, contentDescription = null) },
                    text = { Text(stringResource(R.string.mass_messages_new)) },
                    modifier = Modifier.testTag(MassMessagesTestTags.FAB),
                )
            }
        },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            if (!ui.isCreator) {
                CenteredMessage(
                    text = stringResource(R.string.mass_messages_unavailable),
                    tag = MassMessagesTestTags.UNAVAILABLE,
                )
                return@Box
            }

            val refresh = campaigns.loadState.refresh
            when {
                refresh is LoadState.Loading && campaigns.itemCount == 0 ->
                    Box(Modifier.fillMaxSize(), Alignment.Center) {
                        CircularProgressIndicator(Modifier.testTag(MassMessagesTestTags.LOADING))
                    }
                refresh is LoadState.Error && campaigns.itemCount == 0 ->
                    ErrorState(
                        message = (refresh.error.message ?: stringResource(R.string.mass_messages_error)),
                        onRetry = { campaigns.retry() },
                    )
                campaigns.itemCount == 0 && refresh is LoadState.NotLoading ->
                    CenteredMessage(
                        text = stringResource(R.string.mass_messages_empty),
                        tag = MassMessagesTestTags.EMPTY,
                    )
                else ->
                    LazyColumn(
                        Modifier.fillMaxSize().testTag(MassMessagesTestTags.LIST),
                    ) {
                        items(
                            count = campaigns.itemCount,
                            key = campaigns.itemKey { it.id },
                        ) { index ->
                            val campaign = campaigns[index] ?: return@items
                            MassCampaignRow(
                                campaign = campaign,
                                overlay = ui.cancelledOverlay[campaign.id],
                                onCancel = { viewModel.requestCancel(campaign.id) },
                            )
                        }
                        if (campaigns.loadState.append is LoadState.Error) {
                            item {
                                AppendError(onRetry = { campaigns.retry() })
                            }
                        }
                    }
            }

            if (ui.createSheet.visible) {
                CreateCampaignSheet(
                    state = ui.createSheet,
                    onDismiss = viewModel::dismissCreate,
                    onTextChange = viewModel::onTextChange,
                    onQueryChange = viewModel::onQueryChange,
                    onToggleRecipient = viewModel::onToggleRecipient,
                    onRemoveRecipient = viewModel::onRemoveRecipient,
                    onModeChange = viewModel::onModeChange,
                    onSubmit = viewModel::submitCreate,
                )
            }

            ui.pendingCancelId?.let { id ->
                val prior = (0 until campaigns.itemCount)
                    .firstNotNullOfOrNull { campaigns.peek(it)?.takeIf { c -> c.id == id } }
                AlertDialog(
                    modifier = Modifier.testTag(MassMessagesTestTags.CANCEL_DIALOG),
                    onDismissRequest = viewModel::dismissCancel,
                    title = { Text(stringResource(R.string.mass_messages_cancel_title)) },
                    text = { Text(stringResource(R.string.mass_messages_cancel_body)) },
                    confirmButton = {
                        TextButton(onClick = { viewModel.confirmCancel(id, prior) }) {
                            Text(stringResource(R.string.mass_messages_cancel_confirm))
                        }
                    },
                    dismissButton = {
                        TextButton(onClick = viewModel::dismissCancel) {
                            Text(stringResource(R.string.action_dismiss))
                        }
                    },
                )
            }
        }
    }
}

private suspend fun SnackbarHostState.showMessage(message: String) {
    currentSnackbarData?.dismiss()
    showSnackbar(message)
}

@Composable
private fun MassCampaignRow(
    campaign: MassCampaign,
    overlay: CampaignStatusOverlay?,
    onCancel: () -> Unit,
) {
    val effectiveStatus = when (overlay) {
        CampaignStatusOverlay.CANCELLED -> CampaignStatus.CANCELLED
        else -> campaign.status
    }
    val cancelling = overlay == CampaignStatusOverlay.CANCELLING
    Column(Modifier.fillMaxWidth().padding(16.dp).testTag(MassMessagesTestTags.ROW)) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Text(
                text = statusLabel(effectiveStatus),
                style = MaterialTheme.typography.titleMedium,
                modifier = Modifier.weight(1f),
            )
            if (effectiveStatus.isCancellable && !cancelling) {
                TextButton(
                    onClick = onCancel,
                    modifier = Modifier.testTag(MassMessagesTestTags.CANCEL_ACTION),
                ) { Text(stringResource(R.string.mass_messages_cancel_action)) }
            } else if (cancelling) {
                CircularProgressIndicator(Modifier.size(20.dp))
            }
        }
        Spacer(Modifier.size(4.dp))
        val c = campaign.counters
        Text(
            text = stringResource(
                R.string.mass_messages_progress,
                c.sent,
                c.queued,
                c.failed,
                c.cancelled,
                c.total,
            ),
            style = MaterialTheme.typography.bodyMedium,
        )
        val ts = campaign.sendAtEpochSeconds ?: campaign.createdAtEpochSeconds
        if (ts > 0L) {
            Text(
                text = relativeTimeFromSeconds(ts),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun CreateCampaignSheet(
    state: CreateSheetState,
    onDismiss: () -> Unit,
    onTextChange: (String) -> Unit,
    onQueryChange: (String) -> Unit,
    onToggleRecipient: (String) -> Unit,
    onRemoveRecipient: (String) -> Unit,
    onModeChange: (CampaignMode) -> Unit,
    onSubmit: () -> Unit,
) {
    ModalBottomSheet(onDismissRequest = onDismiss, modifier = Modifier.testTag(MassMessagesTestTags.SHEET)) {
        Column(Modifier.fillMaxWidth().padding(16.dp)) {
            Text(
                stringResource(R.string.mass_messages_new),
                style = MaterialTheme.typography.titleLarge,
            )
            Spacer(Modifier.size(8.dp))
            OutlinedTextField(
                value = state.text,
                onValueChange = onTextChange,
                label = { Text(stringResource(R.string.mass_messages_text_label)) },
                supportingText = { Text("${state.text.length} / ${CreateSheetState.MAX_TEXT_LENGTH}") },
                modifier = Modifier.fillMaxWidth().testTag(MassMessagesTestTags.TEXT),
            )
            Spacer(Modifier.size(8.dp))
            // Recipient selection reuses the contacts search picker.
            OutlinedTextField(
                value = state.query,
                onValueChange = onQueryChange,
                label = { Text(stringResource(R.string.mass_messages_recipients_label)) },
                modifier = Modifier.fillMaxWidth().testTag(MassMessagesTestTags.RECIPIENT_SEARCH),
            )
            if (state.selected.isNotEmpty()) {
                FlowRow(Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
                    state.selected.forEach { r ->
                        InputChip(
                            selected = true,
                            onClick = { onRemoveRecipient(r.conversationId) },
                            label = { Text(r.displayName, maxLines = 1, overflow = TextOverflow.Ellipsis) },
                            trailingIcon = { Icon(Icons.Filled.Close, contentDescription = null) },
                        )
                    }
                }
            }
            LazyColumn(Modifier.fillMaxWidth().heightIn(max = 200.dp)) {
                items(state.candidates, key = { it.conversationId }) { r ->
                    val selected = state.selectedIds.contains(r.conversationId)
                    Text(
                        text = r.displayName + if (selected) "  ✓" else "",
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { onToggleRecipient(r.conversationId) }
                            .padding(12.dp),
                    )
                }
            }
            Spacer(Modifier.size(8.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilterChip(
                    selected = state.mode == CampaignMode.IMMEDIATE,
                    onClick = { onModeChange(CampaignMode.IMMEDIATE) },
                    label = { Text(stringResource(R.string.mass_messages_mode_immediate)) },
                )
                FilterChip(
                    selected = state.mode == CampaignMode.SCHEDULED,
                    onClick = { onModeChange(CampaignMode.SCHEDULED) },
                    label = { Text(stringResource(R.string.mass_messages_mode_scheduled)) },
                )
            }
            state.errorMessage?.let {
                Spacer(Modifier.size(8.dp))
                Text(it, color = MaterialTheme.colorScheme.error)
            }
            Spacer(Modifier.size(12.dp))
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                TextButton(onClick = onDismiss) { Text(stringResource(R.string.action_dismiss)) }
                Spacer(Modifier.size(8.dp))
                TextButton(
                    onClick = onSubmit,
                    enabled = state.canSubmit,
                    modifier = Modifier.testTag(MassMessagesTestTags.SUBMIT),
                ) {
                    if (state.submitting) {
                        CircularProgressIndicator(Modifier.size(20.dp))
                    } else {
                        Text(stringResource(R.string.mass_messages_send))
                    }
                }
            }
        }
    }
}

@Composable
private fun ErrorState(message: String, onRetry: () -> Unit) {
    Column(
        Modifier.fillMaxSize().padding(24.dp).testTag(MassMessagesTestTags.ERROR),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Text(message, style = MaterialTheme.typography.bodyLarge)
        Spacer(Modifier.size(12.dp))
        TextButton(onClick = onRetry) { Text(stringResource(R.string.action_retry)) }
    }
}

@Composable
private fun AppendError(onRetry: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().padding(16.dp),
        horizontalArrangement = Arrangement.Center,
    ) {
        TextButton(onClick = onRetry) { Text(stringResource(R.string.action_retry)) }
    }
}

@Composable
private fun CenteredMessage(text: String, tag: String) {
    Box(Modifier.fillMaxSize().testTag(tag), Alignment.Center) {
        Text(text, style = MaterialTheme.typography.bodyLarge)
    }
}

private fun statusLabelRes(status: CampaignStatus): Int = when (status) {
    CampaignStatus.PENDING -> R.string.mass_messages_status_pending
    CampaignStatus.SCHEDULED -> R.string.mass_messages_status_scheduled
    CampaignStatus.PROCESSING -> R.string.mass_messages_status_processing
    CampaignStatus.COMPLETED -> R.string.mass_messages_status_completed
    CampaignStatus.FAILED -> R.string.mass_messages_status_failed
    CampaignStatus.CANCELLED -> R.string.mass_messages_status_cancelled
    CampaignStatus.UNKNOWN -> R.string.mass_messages_status_unknown
}

@Composable
private fun statusLabel(status: CampaignStatus): String = stringResource(statusLabelRes(status))
