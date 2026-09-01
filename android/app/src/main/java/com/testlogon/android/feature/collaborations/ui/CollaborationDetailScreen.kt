@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.collaborations.ui

import android.text.format.DateUtils
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.LockClock
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Slider
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.model.collaborations.CollabDispute
import com.testlogon.android.core.model.collaborations.CollabRevision
import com.testlogon.android.core.model.collaborations.CollabSplitRecordModel
import com.testlogon.android.core.model.collaborations.CollabStatus
import com.testlogon.android.core.model.collaborations.Collaboration
import com.testlogon.android.core.model.collaborations.CollaborationMath
import com.testlogon.android.core.model.collaborations.DisputeState
import com.testlogon.android.core.model.collaborations.SplitDistribution
import com.testlogon.android.core.model.syndicates.formatCents
import com.testlogon.android.core.ui.input.TlButton
import com.testlogon.android.core.ui.input.TlButtonVariant
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState

/** AND-358 / PAR-04 - stable testTags shared by the collaborations list + detail screens. */
object CollaborationsTestTags {
    const val DETAIL_SCREEN = "collab_detail_screen"
    const val STATUS = "collab_status"
    const val SPLIT_TOTAL = "collab_split_total"
    const val SPLIT_WARNING = "collab_split_warning"
    const val SESSION_EXPIRED = "collab_session_expired"
    const val STALE = "collab_stale"

    // PAR-04 deal actions.
    const val ACTIONS = "collab_actions"
    const val ACTION_ACCEPT = "collab_action_accept"
    const val ACTION_REJECT = "collab_action_reject"
    const val ACTION_COUNTER = "collab_action_counter"
    const val ACTION_CANCEL = "collab_action_cancel"
    const val ACTION_TERMINATE = "collab_action_terminate"
    const val COUNTER_SHEET = "collab_counter_sheet"
    const val COUNTER_SLIDER = "collab_counter_slider"
    const val COUNTER_SEND = "collab_counter_send"
    const val CONFIRM_DIALOG = "collab_confirm_dialog"
    const val CONFIRM_ACCEPT = "collab_confirm_accept"
    const val REVISIONS = "collab_revisions"

    // FIN-011 revenue records + disputes panel.
    const val SPLIT_RECORDS = "collab_split_records"
    const val DISPUTES = "collab_disputes"
    const val DISPUTE_SHEET = "collab_dispute_sheet"
    const val DISPUTE_REASON = "collab_dispute_reason"
    const val DISPUTE_SUBMIT = "collab_dispute_submit"
    const val RESOLVE_DIALOG = "collab_resolve_dialog"
    const val RESOLVE_TEXT = "collab_resolve_text"
    const val RESOLVE_ACCEPT = "collab_resolve_accept"
    const val RESOLVE_REJECT = "collab_resolve_reject"

    fun splitRow(userId: String) = "collab_split_row_$userId"
    fun distribution(index: Int) = "collab_distribution_$index"
    fun revision(index: Int) = "collab_revision_$index"
    fun splitRecord(index: Int) = "collab_split_record_$index"
    fun dispute(index: Int) = "collab_dispute_$index"
    fun disputeSplit(splitId: String) = "collab_dispute_split_$splitId"
}

/** AND-358 / PAR-04 - route-level detail entry; collects the detail state + one-shot action effects. */
@Composable
fun CollaborationDetailRoute(
    onBack: () -> Unit,
    viewModel: CollaborationDetailViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }

    val acceptedMsg = stringResource(R.string.collaboration_action_accepted)
    val rejectedMsg = stringResource(R.string.collaboration_action_rejected)
    val counteredMsg = stringResource(R.string.collaboration_action_countered)
    val cancelledMsg = stringResource(R.string.collaboration_action_cancelled)
    val terminatedMsg = stringResource(R.string.collaboration_action_terminated)
    val disputeFiledMsg = stringResource(R.string.collaboration_dispute_filed)
    val disputeResolvedMsg = stringResource(R.string.collaboration_dispute_resolved)

    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            val message = when (effect) {
                is CollaborationDetailEffect.ActionSucceeded -> when (effect.action) {
                    CollabAction.ACCEPT -> acceptedMsg
                    CollabAction.REJECT -> rejectedMsg
                    CollabAction.COUNTER -> counteredMsg
                    CollabAction.CANCEL -> cancelledMsg
                    CollabAction.TERMINATE -> terminatedMsg
                    CollabAction.FILE_DISPUTE -> disputeFiledMsg
                    CollabAction.RESOLVE_DISPUTE -> disputeResolvedMsg
                }
                is CollaborationDetailEffect.ActionFailed -> effect.message
            }
            snackbarHostState.showSnackbar(message)
        }
    }

    CollaborationDetailScreen(
        state = state,
        viewerId = viewModel.viewerId,
        snackbarHostState = snackbarHostState,
        onBack = onBack,
        onRetry = viewModel::retry,
        onAccept = viewModel::accept,
        onReject = viewModel::reject,
        onCounter = viewModel::counter,
        onCancel = viewModel::cancel,
        onTerminate = { viewModel.terminate() },
        onFileDispute = { splitId, reason -> viewModel.fileDispute(splitId, reason) },
        onResolveDispute = { disputeId, resolution, accept ->
            viewModel.resolveDispute(disputeId, resolution, accept)
        },
    )
}

/** AND-358 / PAR-04 - stateless collaboration detail (parties + status + split + revisions + deal actions). */
@Composable
fun CollaborationDetailScreen(
    state: CollaborationDetailUiState,
    viewerId: String?,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onAccept: () -> Unit,
    onReject: () -> Unit,
    onCounter: (Int) -> Unit,
    onCancel: () -> Unit,
    onTerminate: () -> Unit,
    onFileDispute: (splitId: String, reason: String) -> Unit,
    onResolveDispute: (disputeId: String, resolution: String, accept: Boolean) -> Unit,
    modifier: Modifier = Modifier,
    snackbarHostState: SnackbarHostState = remember { SnackbarHostState() },
) {
    Scaffold(
        modifier = modifier.testTag(CollaborationsTestTags.DETAIL_SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.collaboration_detail_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.collaborations_back),
                        )
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
    ) { padding ->
        when (state) {
            is CollaborationDetailUiState.Loading ->
                LoadingState(modifier = Modifier.padding(padding))

            is CollaborationDetailUiState.SessionExpired ->
                EmptyState(
                    title = stringResource(R.string.collaborations_session_expired_title),
                    body = stringResource(R.string.collaborations_session_expired_body),
                    imageVector = Icons.Outlined.LockClock,
                    modifier = Modifier
                        .padding(padding)
                        .testTag(CollaborationsTestTags.SESSION_EXPIRED),
                )

            is CollaborationDetailUiState.Error ->
                ErrorState(
                    message = state.error.message,
                    onRetry = onRetry,
                    modifier = Modifier.padding(padding),
                )

            is CollaborationDetailUiState.Content ->
                DetailBody(
                    state = state,
                    viewerId = viewerId,
                    onAccept = onAccept,
                    onReject = onReject,
                    onCounter = onCounter,
                    onCancel = onCancel,
                    onTerminate = onTerminate,
                    onFileDispute = onFileDispute,
                    onResolveDispute = onResolveDispute,
                    modifier = Modifier.padding(padding),
                )
        }
    }
}

/** PAR-04 - the destructive actions that require a confirm dialog before firing. */
private enum class ConfirmKind { REJECT, CANCEL, TERMINATE }

@Composable
private fun DetailBody(
    state: CollaborationDetailUiState.Content,
    viewerId: String?,
    onAccept: () -> Unit,
    onReject: () -> Unit,
    onCounter: (Int) -> Unit,
    onCancel: () -> Unit,
    onTerminate: () -> Unit,
    onFileDispute: (splitId: String, reason: String) -> Unit,
    onResolveDispute: (disputeId: String, resolution: String, accept: Boolean) -> Unit,
    modifier: Modifier = Modifier,
) {
    val collab = state.collab
    var showCounter by remember { mutableStateOf(false) }
    var confirm by remember { mutableStateOf<ConfirmKind?>(null) }
    // FIN-011 - the split record a file-dispute sheet is open for, and the dispute a resolve dialog is open for.
    var disputeForSplit by remember { mutableStateOf<CollabSplitRecordModel?>(null) }
    var resolveDispute by remember { mutableStateOf<CollabDispute?>(null) }
    val isParticipant = viewerId != null &&
        (viewerId == collab.initiatorId || viewerId == collab.recipientId)

    LazyColumn(modifier = modifier.fillMaxSize()) {
        if (state.isStale) {
            item(key = "stale") { StaleRow() }
        }
        item(key = "header") { Header(collab) }
        item(key = "parties") { PartiesSection(collab) }
        item(key = "split_heading") {
            SectionHeading(stringResource(R.string.collaboration_split_heading))
        }
        items(collab.shares, key = { "share_${it.userId}" }) { share ->
            SplitRow(
                userId = share.userId,
                percent = share.percent,
                isViewer = viewerId != null && share.userId == viewerId,
            )
        }
        item(key = "split_total") { SplitTotalRow(collab) }
        if (!collab.splitTotalsOk) {
            item(key = "split_warning") { SplitWarning(collab) }
        }

        // PAR-04 - the deal-action card (only when at least one action is valid for the current status).
        if (hasAnyAction(collab, viewerId)) {
            item(key = "actions") {
                ActionsCard(
                    collab = collab,
                    viewerId = viewerId,
                    busy = state.busy,
                    onAccept = onAccept,
                    onCounter = { showCounter = true },
                    onReject = { confirm = ConfirmKind.REJECT },
                    onCancel = { confirm = ConfirmKind.CANCEL },
                    onTerminate = { confirm = ConfirmKind.TERMINATE },
                )
            }
        }

        if (state.distributions.isNotEmpty()) {
            item(key = "dist_heading") {
                SectionHeading(stringResource(R.string.collaboration_distributions_heading))
            }
            itemsIndexed(state.distributions) { index, dist ->
                DistributionRow(dist = dist, index = index)
            }
        }

        if (state.revisions.isNotEmpty()) {
            item(key = "rev_heading") {
                SectionHeading(stringResource(R.string.collaboration_revisions_heading))
            }
            itemsIndexed(
                state.revisions,
                key = { _, r -> "rev_${r.revision}_${r.proposedAt ?: 0L}" },
            ) { index, rev ->
                RevisionRow(rev = rev, index = index, viewerId = viewerId)
            }
        }

        // FIN-011 - the executed-split revenue view (each record can be disputed by a participant).
        if (state.splitRecords.isNotEmpty()) {
            item(key = "records_heading") {
                SectionHeading(
                    stringResource(R.string.collaboration_records_heading),
                    modifier = Modifier.testTag(CollaborationsTestTags.SPLIT_RECORDS),
                )
            }
            itemsIndexed(
                state.splitRecords,
                key = { _, r -> "record_${r.splitId}" },
            ) { index, record ->
                SplitRecordRow(
                    record = record,
                    index = index,
                    canDispute = CollaborationMath.canFileDispute(record.disputeStatus, isParticipant),
                    busy = state.busy,
                    onDispute = { disputeForSplit = record },
                )
            }
        }

        // FIN-011 - the disputes panel (participant/admin can resolve an open dispute they didn't file).
        if (state.disputes.isNotEmpty()) {
            item(key = "disputes_heading") {
                SectionHeading(
                    stringResource(R.string.collaboration_disputes_heading),
                    modifier = Modifier.testTag(CollaborationsTestTags.DISPUTES),
                )
            }
            itemsIndexed(
                state.disputes,
                key = { _, d -> "dispute_${d.disputeId}" },
            ) { index, dispute ->
                DisputeRow(
                    dispute = dispute,
                    index = index,
                    canResolve = CollaborationMath.canResolveDispute(
                        disputeStatus = dispute.status,
                        filedBy = dispute.filedBy,
                        viewerId = viewerId,
                        isAdmin = false,
                        isParticipant = isParticipant,
                    ),
                    busy = state.busy,
                    onResolve = { resolveDispute = dispute },
                )
            }
        }
    }

    disputeForSplit?.let { record ->
        FileDisputeSheet(
            record = record,
            busy = state.busy,
            onDismiss = { disputeForSplit = null },
            onSubmit = { reason ->
                disputeForSplit = null
                onFileDispute(record.splitId, reason)
            },
        )
    }

    resolveDispute?.let { dispute ->
        ResolveDisputeDialog(
            dispute = dispute,
            onDismiss = { resolveDispute = null },
            onResolve = { resolution, accept ->
                resolveDispute = null
                onResolveDispute(dispute.disputeId, resolution, accept)
            },
        )
    }

    if (showCounter) {
        CounterOfferSheet(
            collab = collab,
            busy = state.busy,
            onDismiss = { showCounter = false },
            onSend = { pct ->
                showCounter = false
                onCounter(pct)
            },
        )
    }

    confirm?.let { kind ->
        ConfirmActionDialog(
            kind = kind,
            onDismiss = { confirm = null },
            onConfirm = {
                confirm = null
                when (kind) {
                    ConfirmKind.REJECT -> onReject()
                    ConfirmKind.CANCEL -> onCancel()
                    ConfirmKind.TERMINATE -> onTerminate()
                }
            },
        )
    }
}

/**
 * PAR-04 - true when ANY deal action is valid for the current status / viewer (drives whether the actions card
 * renders at all). Mirrors the iOS actionsCard guard: awaiting-response OR active OR (pending AND initiator).
 */
private fun hasAnyAction(collab: Collaboration, viewerId: String?): Boolean {
    val awaiting = collab.awaitingResponse(viewerId)
    val canCancel = collab.isPendingProposal && collab.isInitiator(viewerId)
    return awaiting || collab.isActiveAgreement || canCancel
}

/**
 * PAR-04 - the actions card. Per the iOS gating: the awaiting-response party gets Accept / Counter / Reject;
 * the initiator of a still-pending request gets Cancel; either party on an active agreement gets Terminate.
 * Every action disables while [busy].
 */
@Composable
private fun ActionsCard(
    collab: Collaboration,
    viewerId: String?,
    busy: Boolean,
    onAccept: () -> Unit,
    onCounter: () -> Unit,
    onReject: () -> Unit,
    onCancel: () -> Unit,
    onTerminate: () -> Unit,
) {
    val awaiting = collab.awaitingResponse(viewerId)
    val canCancel = collab.isPendingProposal && collab.isInitiator(viewerId)

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 8.dp)
            .testTag(CollaborationsTestTags.ACTIONS),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        SectionHeading(stringResource(R.string.collaboration_actions_heading))
        if (awaiting) {
            TlButton(
                text = stringResource(R.string.collaboration_action_accept),
                onClick = onAccept,
                enabled = !busy,
                loading = busy,
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag(CollaborationsTestTags.ACTION_ACCEPT),
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                TlButton(
                    text = stringResource(R.string.collaboration_action_counter),
                    onClick = onCounter,
                    variant = TlButtonVariant.Secondary,
                    enabled = !busy,
                    modifier = Modifier
                        .weight(1f)
                        .testTag(CollaborationsTestTags.ACTION_COUNTER),
                )
                TlButton(
                    text = stringResource(R.string.collaboration_action_reject),
                    onClick = onReject,
                    variant = TlButtonVariant.Secondary,
                    enabled = !busy,
                    modifier = Modifier
                        .weight(1f)
                        .testTag(CollaborationsTestTags.ACTION_REJECT),
                )
            }
        }
        if (canCancel) {
            TlButton(
                text = stringResource(R.string.collaboration_action_cancel),
                onClick = onCancel,
                variant = TlButtonVariant.Secondary,
                enabled = !busy,
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag(CollaborationsTestTags.ACTION_CANCEL),
            )
        }
        if (collab.isActiveAgreement) {
            TlButton(
                text = stringResource(R.string.collaboration_action_terminate),
                onClick = onTerminate,
                variant = TlButtonVariant.Secondary,
                enabled = !busy,
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag(CollaborationsTestTags.ACTION_TERMINATE),
            )
        }
    }
}

/**
 * PAR-04 - the counter-offer bottom sheet. The slider sets the INITIATOR's new percent (1..99); the recipient
 * gets the remainder (mirrors iOS CounterOfferSheet). The initial value is the initiator's current share (or
 * 50 when absent). Send is disabled while [busy].
 */
@Composable
private fun CounterOfferSheet(
    collab: Collaboration,
    busy: Boolean,
    onDismiss: () -> Unit,
    onSend: (Int) -> Unit,
) {
    val sheetState = rememberModalBottomSheetState()
    val initial = (collab.shareFor(collab.initiatorId) ?: DEFAULT_INITIATOR_PCT)
        .coerceIn(MIN_SPLIT_PCT, MAX_SPLIT_PCT)
    var pct by remember { mutableFloatStateOf(initial.toFloat()) }
    val initiatorPct = pct.toInt().coerceIn(MIN_SPLIT_PCT, MAX_SPLIT_PCT)

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState,
        modifier = Modifier.testTag(CollaborationsTestTags.COUNTER_SHEET),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp)
                .padding(bottom = 24.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(
                text = stringResource(R.string.collaboration_counter_title),
                style = MaterialTheme.typography.titleMedium,
            )
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Text(
                    text = stringResource(R.string.collaboration_counter_initiator, initiatorPct),
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.Bold,
                )
                Text(
                    text = stringResource(
                        R.string.collaboration_counter_recipient,
                        Collaboration.FULL_SHARE_PERCENT - initiatorPct,
                    ),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Slider(
                value = pct,
                onValueChange = { pct = it },
                valueRange = MIN_SPLIT_PCT.toFloat()..MAX_SPLIT_PCT.toFloat(),
                steps = (MAX_SPLIT_PCT - MIN_SPLIT_PCT) - 1,
                enabled = !busy,
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag(CollaborationsTestTags.COUNTER_SLIDER),
            )
            TlButton(
                text = stringResource(R.string.collaboration_counter_send),
                onClick = { onSend(initiatorPct) },
                enabled = !busy,
                loading = busy,
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag(CollaborationsTestTags.COUNTER_SEND),
            )
        }
    }
}

/** PAR-04 - the confirm dialog for a destructive action (reject / cancel / terminate). */
@Composable
private fun ConfirmActionDialog(
    kind: ConfirmKind,
    onDismiss: () -> Unit,
    onConfirm: () -> Unit,
) {
    val (title, body, confirmLabel, confirmTag) = when (kind) {
        ConfirmKind.REJECT -> ConfirmCopy(
            stringResource(R.string.collaboration_confirm_reject_title),
            stringResource(R.string.collaboration_confirm_reject_body),
            stringResource(R.string.collaboration_action_reject),
            CollaborationsTestTags.ACTION_REJECT,
        )
        ConfirmKind.CANCEL -> ConfirmCopy(
            stringResource(R.string.collaboration_confirm_cancel_title),
            stringResource(R.string.collaboration_confirm_cancel_body),
            stringResource(R.string.collaboration_action_cancel),
            CollaborationsTestTags.ACTION_CANCEL,
        )
        ConfirmKind.TERMINATE -> ConfirmCopy(
            stringResource(R.string.collaboration_confirm_terminate_title),
            stringResource(R.string.collaboration_confirm_terminate_body),
            stringResource(R.string.collaboration_action_terminate),
            CollaborationsTestTags.ACTION_TERMINATE,
        )
    }
    AlertDialog(
        modifier = Modifier.testTag(CollaborationsTestTags.CONFIRM_DIALOG),
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = { Text(body) },
        confirmButton = {
            TextButton(
                onClick = onConfirm,
                modifier = Modifier.testTag(confirmTag + "_confirm"),
            ) {
                Text(confirmLabel)
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.collaboration_confirm_dismiss))
            }
        },
    )
}

/** Small holder so the confirm dialog copy can be destructured. */
private data class ConfirmCopy(
    val title: String,
    val body: String,
    val confirmLabel: String,
    val tag: String,
)

@Composable
private fun RevisionRow(rev: CollabRevision, index: Int, viewerId: String?) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(CollaborationsTestTags.revision(index))
            .padding(horizontal = 16.dp, vertical = 8.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Text(
                text = stringResource(R.string.collaboration_revision_number, rev.revision),
                style = MaterialTheme.typography.titleSmall,
            )
            val when_ = relativeTime(rev.proposedAt)
            if (when_.isNotBlank()) {
                Text(
                    text = when_,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        val proposedBy = rev.proposedBy
        if (!proposedBy.isNullOrBlank()) {
            val label = if (viewerId != null && proposedBy == viewerId) {
                stringResource(R.string.collaboration_split_you, proposedBy)
            } else {
                proposedBy
            }
            Text(
                text = stringResource(R.string.collaboration_revision_proposed_by, label),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        rev.shares.forEach { share ->
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Text(text = share.userId, style = MaterialTheme.typography.bodySmall)
                Text(
                    text = stringResource(R.string.collaboration_percent, share.percent),
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }
        HorizontalDivider()
    }
}

@Composable
private fun StaleRow() {
    Surface(
        color = MaterialTheme.colorScheme.secondaryContainer,
        contentColor = MaterialTheme.colorScheme.onSecondaryContainer,
        modifier = Modifier
            .fillMaxWidth()
            .testTag(CollaborationsTestTags.STALE),
    ) {
        Text(
            text = stringResource(R.string.collaborations_stale_banner),
            style = MaterialTheme.typography.bodySmall,
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
        )
    }
}

@Composable
private fun Header(collab: Collaboration) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Text(
            text = collab.title.ifBlank { stringResource(R.string.collaborations_untitled) },
            style = MaterialTheme.typography.headlineSmall,
        )
        AssistChip(
            onClick = {},
            enabled = false,
            label = { Text(statusLabel(collab)) },
            colors = AssistChipDefaults.assistChipColors(),
            modifier = Modifier.testTag(CollaborationsTestTags.STATUS),
        )
        val description = collab.description
        if (!description.isNullOrBlank()) {
            Text(text = description, style = MaterialTheme.typography.bodyMedium)
        }
        val created = relativeTime(collab.createdAt)
        if (created.isNotBlank()) {
            Text(
                text = stringResource(R.string.collaboration_created, created),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        val updated = relativeTime(collab.updatedAt)
        if (updated.isNotBlank()) {
            Text(
                text = stringResource(R.string.collaboration_updated, updated),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun PartiesSection(collab: Collaboration) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        SectionHeading(stringResource(R.string.collaboration_parties_heading))
        LabelValueRow(
            label = stringResource(R.string.collaboration_party_initiator),
            value = collab.initiatorId ?: stringResource(R.string.collaborations_unknown_party),
        )
        LabelValueRow(
            label = stringResource(R.string.collaboration_party_recipient),
            value = collab.recipientId ?: stringResource(R.string.collaborations_unknown_party),
        )
    }
}

@Composable
private fun SplitRow(userId: String, percent: Int, isViewer: Boolean) {
    val label = if (isViewer) {
        stringResource(R.string.collaboration_split_you, userId)
    } else {
        userId
    }
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(CollaborationsTestTags.splitRow(userId))
            .padding(horizontal = 16.dp, vertical = 8.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(text = label, style = MaterialTheme.typography.bodyMedium)
        Text(
            text = stringResource(R.string.collaboration_percent, percent),
            style = MaterialTheme.typography.bodyMedium,
        )
    }
}

@Composable
private fun SplitTotalRow(collab: Collaboration) {
    HorizontalDivider()
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(CollaborationsTestTags.SPLIT_TOTAL)
            .padding(horizontal = 16.dp, vertical = 8.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(
            text = stringResource(R.string.collaboration_split_total),
            style = MaterialTheme.typography.titleSmall,
        )
        Text(
            text = stringResource(R.string.collaboration_percent, collab.splitTotalPercent),
            style = MaterialTheme.typography.titleSmall,
            fontWeight = FontWeight.Bold,
        )
    }
}

@Composable
private fun SplitWarning(collab: Collaboration) {
    Surface(
        color = MaterialTheme.colorScheme.errorContainer,
        contentColor = MaterialTheme.colorScheme.onErrorContainer,
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 4.dp)
            .testTag(CollaborationsTestTags.SPLIT_WARNING),
    ) {
        Text(
            text = stringResource(R.string.collaboration_split_warning, collab.splitTotalPercent),
            style = MaterialTheme.typography.bodySmall,
            modifier = Modifier.padding(12.dp),
        )
    }
}

@Composable
private fun DistributionRow(dist: SplitDistribution, index: Int) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(CollaborationsTestTags.distribution(index))
            .padding(horizontal = 16.dp, vertical = 8.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(
            text = dist.userId ?: stringResource(R.string.collaborations_unknown_party),
            style = MaterialTheme.typography.bodyMedium,
        )
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(
                text = stringResource(R.string.collaboration_percent, dist.percent),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            val cents = dist.amountCents
            if (cents != null) {
                Text(
                    text = formatCents(cents, FALLBACK_CURRENCY),
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
        }
    }
}

/**
 * FIN-011 - one executed split record (a revenue event that was auto-split across the parties). Shows the
 * gross + source + per-party distributions; a participant may file a dispute when [canDispute] (the record is
 * not already under an open / resolved dispute).
 */
@Composable
private fun SplitRecordRow(
    record: CollabSplitRecordModel,
    index: Int,
    canDispute: Boolean,
    busy: Boolean,
    onDispute: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(CollaborationsTestTags.splitRecord(index))
            .padding(horizontal = 16.dp, vertical = 8.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Text(
                text = formatCents(record.grossAmountCents, FALLBACK_CURRENCY),
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.Bold,
            )
            val source = record.source
            if (!source.isNullOrBlank()) {
                Text(
                    text = source,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        record.distributions.forEach { dist ->
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Text(
                    text = dist.userId ?: stringResource(R.string.collaborations_unknown_party),
                    style = MaterialTheme.typography.bodySmall,
                )
                val cents = dist.amountCents
                Text(
                    text = if (cents != null) {
                        formatCents(cents, FALLBACK_CURRENCY)
                    } else {
                        stringResource(R.string.collaboration_percent, dist.percent)
                    },
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }
        if (record.isDisputed) {
            Text(
                text = stringResource(R.string.collaboration_record_disputed),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error,
            )
        } else if (canDispute) {
            TlButton(
                text = stringResource(R.string.collaboration_dispute_file),
                onClick = onDispute,
                variant = TlButtonVariant.Secondary,
                enabled = !busy,
                modifier = Modifier.testTag(CollaborationsTestTags.disputeSplit(record.splitId)),
            )
        }
        HorizontalDivider()
    }
}

/**
 * FIN-011 - one dispute in the panel. Shows the filer + reason + state; a participant (not the filer) or an
 * admin may resolve an open dispute via [onResolve] when [canResolve].
 */
@Composable
private fun DisputeRow(
    dispute: CollabDispute,
    index: Int,
    canResolve: Boolean,
    busy: Boolean,
    onResolve: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(CollaborationsTestTags.dispute(index))
            .padding(horizontal = 16.dp, vertical = 8.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Text(
                text = dispute.filedBy?.takeIf { it.isNotBlank() }
                    ?: stringResource(R.string.collaborations_unknown_party),
                style = MaterialTheme.typography.titleSmall,
            )
            Text(
                text = disputeStateLabel(dispute.state),
                style = MaterialTheme.typography.bodySmall,
                color = if (dispute.isOpen) {
                    MaterialTheme.colorScheme.error
                } else {
                    MaterialTheme.colorScheme.onSurfaceVariant
                },
            )
        }
        if (dispute.reason.isNotBlank()) {
            Text(text = dispute.reason, style = MaterialTheme.typography.bodyMedium)
        }
        if (dispute.resolution.isNotBlank()) {
            Text(
                text = dispute.resolution,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        if (canResolve) {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                TlButton(
                    text = stringResource(R.string.collaboration_dispute_accept),
                    onClick = onResolve,
                    enabled = !busy,
                    modifier = Modifier
                        .weight(1f)
                        .testTag(CollaborationsTestTags.RESOLVE_ACCEPT),
                )
            }
        }
        HorizontalDivider()
    }
}

/**
 * FIN-011 - the file-dispute bottom sheet. A required free-text reason (>=10 chars server-side) is captured;
 * Submit is disabled while [busy] or the reason is too short.
 */
@Composable
private fun FileDisputeSheet(
    record: CollabSplitRecordModel,
    busy: Boolean,
    onDismiss: () -> Unit,
    onSubmit: (reason: String) -> Unit,
) {
    val sheetState = rememberModalBottomSheetState()
    var reason by remember { mutableStateOf("") }
    val canSubmit = !busy && reason.trim().length >= MIN_DISPUTE_REASON_LEN

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState,
        modifier = Modifier.testTag(CollaborationsTestTags.DISPUTE_SHEET),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp)
                .padding(bottom = 24.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(
                text = stringResource(R.string.collaboration_dispute_title),
                style = MaterialTheme.typography.titleMedium,
            )
            Text(
                text = formatCents(record.grossAmountCents, FALLBACK_CURRENCY),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            OutlinedTextField(
                value = reason,
                onValueChange = { reason = it },
                label = { Text(stringResource(R.string.collaboration_dispute_reason_hint)) },
                enabled = !busy,
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag(CollaborationsTestTags.DISPUTE_REASON),
            )
            TlButton(
                text = stringResource(R.string.collaboration_dispute_submit),
                onClick = { onSubmit(reason.trim()) },
                enabled = canSubmit,
                loading = busy,
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag(CollaborationsTestTags.DISPUTE_SUBMIT),
            )
        }
    }
}

/**
 * FIN-011 - the resolve-dispute dialog. A required resolution note (>=5 chars server-side) is captured; Accept
 * applies the proposed re-split, Reject keeps the original split. Both are disabled until the note is long
 * enough.
 */
@Composable
private fun ResolveDisputeDialog(
    dispute: CollabDispute,
    onDismiss: () -> Unit,
    onResolve: (resolution: String, accept: Boolean) -> Unit,
) {
    var text by remember { mutableStateOf("") }
    val canResolve = text.trim().length >= MIN_RESOLUTION_LEN

    AlertDialog(
        modifier = Modifier.testTag(CollaborationsTestTags.RESOLVE_DIALOG),
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.collaboration_resolve_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                if (dispute.reason.isNotBlank()) {
                    Text(text = dispute.reason, style = MaterialTheme.typography.bodyMedium)
                }
                OutlinedTextField(
                    value = text,
                    onValueChange = { text = it },
                    label = { Text(stringResource(R.string.collaboration_resolve_hint)) },
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag(CollaborationsTestTags.RESOLVE_TEXT),
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = { onResolve(text.trim(), true) },
                enabled = canResolve,
                modifier = Modifier.testTag(CollaborationsTestTags.RESOLVE_ACCEPT + "_confirm"),
            ) {
                Text(stringResource(R.string.collaboration_dispute_accept))
            }
        },
        dismissButton = {
            TextButton(
                onClick = { onResolve(text.trim(), false) },
                enabled = canResolve,
                modifier = Modifier.testTag(CollaborationsTestTags.RESOLVE_REJECT),
            ) {
                Text(stringResource(R.string.collaboration_dispute_reject))
            }
        },
    )
}

/** FIN-011 - a localized label for the parsed dispute state (falls back to a generic when UNKNOWN). */
@Composable
private fun disputeStateLabel(state: DisputeState): String = when (state) {
    DisputeState.OPEN -> stringResource(R.string.collaboration_dispute_state_open)
    DisputeState.RESOLVED -> stringResource(R.string.collaboration_dispute_state_resolved)
    DisputeState.NONE, DisputeState.UNKNOWN ->
        stringResource(R.string.collaboration_dispute_state_unknown)
}

@Composable
private fun SectionHeading(text: String, modifier: Modifier = Modifier) {
    Text(
        text = text,
        style = MaterialTheme.typography.titleSmall,
        modifier = modifier.padding(horizontal = 16.dp, vertical = 8.dp),
    )
}

@Composable
private fun LabelValueRow(label: String, value: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 2.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(text = label, style = MaterialTheme.typography.bodyMedium)
        Text(
            text = value,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

/**
 * AND-358 - the human status label. A recognized [CollabStatus] uses a localized string; an UNKNOWN status
 * falls back to the RAW wire string (or a generic "Unknown" when blank), since the wire status set is free.
 */
@Composable
fun statusLabel(collab: Collaboration): String = when (collab.statusEnum) {
    CollabStatus.PROPOSED -> stringResource(R.string.collaboration_status_proposed)
    CollabStatus.NEGOTIATING -> stringResource(R.string.collaboration_status_negotiating)
    CollabStatus.ACTIVE -> stringResource(R.string.collaboration_status_active)
    CollabStatus.COMPLETED -> stringResource(R.string.collaboration_status_completed)
    CollabStatus.CANCELLED -> stringResource(R.string.collaboration_status_cancelled)
    CollabStatus.DECLINED -> stringResource(R.string.collaboration_status_declined)
    CollabStatus.UNKNOWN ->
        collab.status.ifBlank { stringResource(R.string.collaboration_status_unknown) }
}

/**
 * AND-358 - relative-time copy from an INTEGER epoch-SECONDS value. UI-only (android.text.format), returns ""
 * for null / epoch timestamps. Mirrors the AND-356 syndicate helper.
 */
private fun relativeTime(epochSeconds: Long?, nowMs: Long = System.currentTimeMillis()): String {
    if (epochSeconds == null || epochSeconds <= 0L) return ""
    return DateUtils.getRelativeTimeSpanString(
        epochSeconds * 1000L,
        nowMs,
        DateUtils.MINUTE_IN_MILLIS,
    ).toString()
}

/**
 * AND-358 - the currency used to render the optional distribution amount_cents. The wire does NOT ship a
 * currency on the distributions, so a stable USD fallback keeps formatCents from crashing (currency display is
 * deferred with the rest of the per-distribution metadata).
 */
private const val FALLBACK_CURRENCY = "USD"

/** PAR-04 - the counter-offer split bounds (server: counter_split_pct is 1..99) + a neutral default. */
private const val MIN_SPLIT_PCT = 1
private const val MAX_SPLIT_PCT = 99
private const val DEFAULT_INITIATOR_PCT = 50

/** FIN-011 - minimum free-text lengths mirroring the server validators (reason >=10, resolution >=5). */
private const val MIN_DISPUTE_REASON_LEN = 10
private const val MIN_RESOLUTION_LEN = 5
