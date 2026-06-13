@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.sponsorship.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.model.sponsorship.DealAction
import com.testlogon.android.core.model.sponsorship.SponsorshipDealDetail
import com.testlogon.android.core.model.sponsorship.SponsorshipDealEvent
import com.testlogon.android.core.model.sponsorship.SponsorshipDealStatus
import com.testlogon.android.core.model.syndicates.formatCents
import com.testlogon.android.core.ui.input.TlButton
import com.testlogon.android.core.ui.input.TlButtonVariant
import com.testlogon.android.core.ui.input.TlTextField
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState

/** AND-366 - stable testTags for the sponsorship deal-detail screen + its action affordances. */
object SponsorshipDealTestTags {
    const val SCREEN = "deal_detail_screen"
    const val STATUS = "deal_status"
    const val ACCEPT = "deal_accept"
    const val REJECT = "deal_reject"
    const val NEGOTIATE = "deal_negotiate"
    const val COUNTER_COMPENSATION = "deal_counter_compensation"
    const val COUNTER_NOTE = "deal_counter_note"
    const val COUNTER_SUBMIT = "deal_counter_submit"
    const val REJECT_REASON = "deal_reject_reason"
    const val CONFIRM = "deal_confirm"
    const val ERROR_RETRY = "deal_error_retry"

    fun event(index: Int) = "deal_event_$index"
}

/**
 * AND-366 - route-level deal-detail entry. Collects the state and renders one-shot action effects (success /
 * failure) as transient messages; the dealId arrives via SavedStateHandle inside the ViewModel.
 */
@Composable
fun SponsorshipDealRoute(
    onBack: () -> Unit,
    viewModel: SponsorshipDealViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()

    LaunchedEffect(viewModel) {
        viewModel.effects.collect {
            // Effects drive a host-level snackbar; the screen itself renders inline state. No-op collect keeps
            // the channel drained so a buffered effect does not leak across recompositions.
        }
    }

    SponsorshipDealScreen(
        state = state,
        onBack = onBack,
        onRetry = viewModel::onRetry,
        onAccept = viewModel::accept,
        onReject = viewModel::reject,
        onOpenCounter = viewModel::openCounterForm,
        onDismissCounter = viewModel::dismissCounterForm,
        onCounterCompensationChanged = viewModel::onCounterCompensationChanged,
        onCounterNoteChanged = viewModel::onCounterNoteChanged,
        onSubmitCounter = viewModel::submitCounter,
    )
}

/** AND-366 - stateless sponsorship deal-detail screen. */
@Composable
fun SponsorshipDealScreen(
    state: SponsorshipDealUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onAccept: () -> Unit,
    onReject: (String) -> Unit,
    onOpenCounter: () -> Unit,
    onDismissCounter: () -> Unit,
    onCounterCompensationChanged: (String) -> Unit,
    onCounterNoteChanged: (String) -> Unit,
    onSubmitCounter: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(SponsorshipDealTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.sponsorship_deal_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.sponsorship_back),
                        )
                    }
                },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
        ) {
            when (state) {
                is SponsorshipDealUiState.Loading -> LoadingState()
                is SponsorshipDealUiState.Error ->
                    ErrorState(
                        message = state.error.message,
                        onRetry = onRetry,
                        modifier = Modifier.testTag(SponsorshipDealTestTags.ERROR_RETRY),
                    )
                is SponsorshipDealUiState.Content ->
                    DealContent(
                        state = state,
                        onAccept = onAccept,
                        onReject = onReject,
                        onOpenCounter = onOpenCounter,
                        onDismissCounter = onDismissCounter,
                        onCounterCompensationChanged = onCounterCompensationChanged,
                        onCounterNoteChanged = onCounterNoteChanged,
                        onSubmitCounter = onSubmitCounter,
                    )
            }
        }
    }
}

@Composable
private fun DealContent(
    state: SponsorshipDealUiState.Content,
    onAccept: () -> Unit,
    onReject: (String) -> Unit,
    onOpenCounter: () -> Unit,
    onDismissCounter: () -> Unit,
    onCounterCompensationChanged: (String) -> Unit,
    onCounterNoteChanged: (String) -> Unit,
    onSubmitCounter: () -> Unit,
) {
    var showAcceptConfirm by rememberSaveable { mutableStateOf(false) }
    var showRejectConfirm by rememberSaveable { mutableStateOf(false) }
    var rejectReason by rememberSaveable { mutableStateOf("") }

    val deal = state.deal
    val actionsDisabled = state.actionInFlight != null

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item { PartiesSection(deal) }
        item { HorizontalDivider() }
        item { BriefSection(deal) }
        item { TermsSection(deal) }
        item { StatusBanner(deal) }

        if (deal.statusEnum.isTerminal) {
            item {
                Text(
                    text = stringResource(R.string.sponsorship_deal_read_only),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }

        if (state.availableActions.isNotEmpty()) {
            item {
                ActionButtons(
                    available = state.availableActions,
                    inFlight = state.actionInFlight,
                    disabled = actionsDisabled,
                    onAccept = { showAcceptConfirm = true },
                    onReject = {
                        rejectReason = ""
                        showRejectConfirm = true
                    },
                    onNegotiate = onOpenCounter,
                )
            }
        }

        item { HorizontalDivider() }
        item {
            Text(
                text = stringResource(R.string.sponsorship_deal_history_title),
                style = MaterialTheme.typography.titleMedium,
            )
        }
        if (state.history.isEmpty()) {
            item {
                Text(
                    text = stringResource(R.string.sponsorship_deal_history_empty),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        } else {
            itemsIndexed(state.history) { index, event ->
                EventRow(index = index, event = event)
            }
        }
    }

    if (showAcceptConfirm) {
        ConfirmDialog(
            title = stringResource(R.string.sponsorship_deal_accept_confirm_title),
            body = stringResource(R.string.sponsorship_deal_accept_confirm_body),
            confirmLabel = stringResource(R.string.sponsorship_deal_accept),
            onConfirm = {
                showAcceptConfirm = false
                onAccept()
            },
            onDismiss = { showAcceptConfirm = false },
        )
    }

    if (showRejectConfirm) {
        RejectDialog(
            reason = rejectReason,
            onReasonChange = { rejectReason = it },
            onConfirm = {
                showRejectConfirm = false
                onReject(rejectReason)
            },
            onDismiss = { showRejectConfirm = false },
        )
    }

    val counterForm = state.counterForm
    if (counterForm != null) {
        CounterDialog(
            form = counterForm,
            onCompensationChange = onCounterCompensationChanged,
            onNoteChange = onCounterNoteChanged,
            onSubmit = onSubmitCounter,
            onDismiss = onDismissCounter,
        )
    }
}

@Composable
private fun PartiesSection(deal: SponsorshipDealDetail) {
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(
            text = stringResource(
                R.string.sponsorship_deal_advertiser,
                deal.advertiserSub ?: stringResource(R.string.sponsorship_advertiser_unknown),
            ),
            style = MaterialTheme.typography.titleSmall,
        )
        Text(
            text = stringResource(
                R.string.sponsorship_deal_creator,
                deal.creatorSub ?: stringResource(R.string.sponsorship_deal_party_unknown),
            ),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun BriefSection(deal: SponsorshipDealDetail) {
    val brief = deal.brief
    if (!brief.isNullOrBlank()) {
        Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(
                text = stringResource(R.string.sponsorship_deal_brief_title),
                style = MaterialTheme.typography.titleSmall,
            )
            Text(text = brief, style = MaterialTheme.typography.bodyMedium)
        }
    }
}

@Composable
private fun TermsSection(deal: SponsorshipDealDetail) {
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Text(
            text = stringResource(R.string.sponsorship_deal_terms_title),
            style = MaterialTheme.typography.titleSmall,
        )
        deal.compensationCents?.let {
            TermRow(stringResource(R.string.sponsorship_deal_compensation), formatCents(it))
        }
        deal.cpmBonusCents?.let {
            TermRow(stringResource(R.string.sponsorship_deal_cpm_bonus), formatCents(it))
        }
        deal.platformCommissionBps?.let {
            TermRow(
                stringResource(R.string.sponsorship_deal_commission),
                stringResource(R.string.sponsorship_deal_bps_value, it),
            )
        }
        deal.deadline?.takeIf { it.isNotBlank() }?.let {
            TermRow(stringResource(R.string.sponsorship_deal_deadline), it)
        }
        if (deal.deliverables.isNotEmpty()) {
            Text(
                text = stringResource(R.string.sponsorship_deal_deliverables_title),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            deal.deliverables.forEach { item ->
                Text(
                    text = stringResource(R.string.sponsorship_deal_deliverable_item, item),
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
        }
    }
}

@Composable
private fun TermRow(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(label, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, style = MaterialTheme.typography.bodyMedium)
    }
}

@Composable
private fun StatusBanner(deal: SponsorshipDealDetail) {
    AssistChip(
        onClick = {},
        enabled = false,
        label = { Text(statusLabel(deal.statusEnum, deal.status)) },
        colors = AssistChipDefaults.assistChipColors(),
        modifier = Modifier.testTag(SponsorshipDealTestTags.STATUS),
    )
}

@Composable
private fun ActionButtons(
    available: Set<DealAction>,
    inFlight: DealAction?,
    disabled: Boolean,
    onAccept: () -> Unit,
    onReject: () -> Unit,
    onNegotiate: () -> Unit,
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        if (DealAction.ACCEPT in available) {
            TlButton(
                text = stringResource(R.string.sponsorship_deal_accept),
                onClick = onAccept,
                enabled = !disabled,
                loading = inFlight == DealAction.ACCEPT,
                modifier = Modifier
                    .heightIn(min = 48.dp)
                    .testTag(SponsorshipDealTestTags.ACCEPT),
            )
        }
        if (DealAction.NEGOTIATE in available) {
            TlButton(
                text = stringResource(R.string.sponsorship_deal_negotiate),
                onClick = onNegotiate,
                variant = TlButtonVariant.Secondary,
                enabled = !disabled,
                loading = inFlight == DealAction.NEGOTIATE,
                modifier = Modifier
                    .heightIn(min = 48.dp)
                    .testTag(SponsorshipDealTestTags.NEGOTIATE),
            )
        }
        if (DealAction.REJECT in available) {
            TlButton(
                text = stringResource(R.string.sponsorship_deal_reject),
                onClick = onReject,
                variant = TlButtonVariant.Text,
                enabled = !disabled,
                loading = inFlight == DealAction.REJECT,
                modifier = Modifier
                    .heightIn(min = 48.dp)
                    .testTag(SponsorshipDealTestTags.REJECT),
            )
        }
    }
}

@Composable
private fun EventRow(index: Int, event: SponsorshipDealEvent) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 48.dp)
            .testTag(SponsorshipDealTestTags.event(index)),
        verticalArrangement = Arrangement.spacedBy(2.dp),
    ) {
        Text(
            text = event.eventType?.takeIf { it.isNotBlank() }
                ?: stringResource(R.string.sponsorship_deal_event_unknown),
            style = MaterialTheme.typography.bodyMedium,
        )
        val actor = event.actorSub
        if (!actor.isNullOrBlank()) {
            Text(
                text = stringResource(R.string.sponsorship_deal_event_actor, actor),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        val details = event.detailsText
        if (!details.isNullOrBlank()) {
            Text(
                text = details,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun ConfirmDialog(
    title: String,
    body: String,
    confirmLabel: String,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = { Text(body) },
        confirmButton = {
            TextButton(
                onClick = onConfirm,
                modifier = Modifier.testTag(SponsorshipDealTestTags.CONFIRM),
            ) { Text(confirmLabel) }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.sponsorship_deal_cancel))
            }
        },
    )
}

@Composable
private fun RejectDialog(
    reason: String,
    onReasonChange: (String) -> Unit,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.sponsorship_deal_reject_confirm_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(stringResource(R.string.sponsorship_deal_reject_confirm_body))
                TlTextField(
                    value = reason,
                    onValueChange = onReasonChange,
                    label = stringResource(R.string.sponsorship_deal_reject_reason_label),
                    singleLine = false,
                    helperText = stringResource(R.string.sponsorship_deal_reject_reason_helper),
                    modifier = Modifier.testTag(SponsorshipDealTestTags.REJECT_REASON),
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = onConfirm,
                modifier = Modifier.testTag(SponsorshipDealTestTags.CONFIRM),
            ) { Text(stringResource(R.string.sponsorship_deal_reject)) }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.sponsorship_deal_cancel))
            }
        },
    )
}

@Composable
private fun CounterDialog(
    form: CounterForm,
    onCompensationChange: (String) -> Unit,
    onNoteChange: (String) -> Unit,
    onSubmit: () -> Unit,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = { if (!form.submitting) onDismiss() },
        title = { Text(stringResource(R.string.sponsorship_deal_counter_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                TlTextField(
                    value = form.compensationText,
                    onValueChange = onCompensationChange,
                    label = stringResource(R.string.sponsorship_deal_counter_compensation_label),
                    enabled = !form.submitting,
                    errorText = form.compensationError?.let { counterErrorText(it) },
                    helperText = stringResource(R.string.sponsorship_deal_counter_compensation_helper),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Decimal),
                    modifier = Modifier.testTag(SponsorshipDealTestTags.COUNTER_COMPENSATION),
                )
                TlTextField(
                    value = form.note,
                    onValueChange = onNoteChange,
                    label = stringResource(R.string.sponsorship_deal_counter_note_label),
                    enabled = !form.submitting,
                    singleLine = false,
                    errorText = form.noteError?.let { counterErrorText(it) },
                    helperText = stringResource(R.string.sponsorship_deal_counter_note_helper),
                    modifier = Modifier.testTag(SponsorshipDealTestTags.COUNTER_NOTE),
                )
            }
        },
        confirmButton = {
            TlButton(
                text = stringResource(R.string.sponsorship_deal_counter_submit),
                onClick = onSubmit,
                loading = form.submitting,
                modifier = Modifier.testTag(SponsorshipDealTestTags.COUNTER_SUBMIT),
            )
        },
        dismissButton = {
            TextButton(onClick = onDismiss, enabled = !form.submitting) {
                Text(stringResource(R.string.sponsorship_deal_cancel))
            }
        },
    )
}

/** The localized per-field error copy for the counter form (server text is never rendered). */
@Composable
private fun counterErrorText(error: CounterFieldError): String = when (error) {
    CounterFieldError.CLIENT_COMPENSATION_TOO_LOW ->
        stringResource(R.string.sponsorship_deal_counter_error_too_low)
    CounterFieldError.CLIENT_COMPENSATION_INVALID ->
        stringResource(R.string.sponsorship_deal_counter_error_invalid)
    CounterFieldError.CLIENT_NOTE_TOO_LONG ->
        stringResource(R.string.sponsorship_deal_counter_error_note_long)
    CounterFieldError.SERVER ->
        stringResource(R.string.sponsorship_deal_counter_error_server)
}

/**
 * AND-366 - the human status label. A recognized status uses a localized string; an UNKNOWN status falls back
 * to the RAW wire token (or a generic "Unknown" when blank), forward-compat for any new server token. Shares
 * the AND-365 inbox status strings.
 */
@Composable
private fun statusLabel(statusEnum: SponsorshipDealStatus, raw: String): String = when (statusEnum) {
    SponsorshipDealStatus.PROPOSED -> stringResource(R.string.sponsorship_status_proposed)
    SponsorshipDealStatus.NEGOTIATING -> stringResource(R.string.sponsorship_status_negotiating)
    SponsorshipDealStatus.ACCEPTED -> stringResource(R.string.sponsorship_status_accepted)
    SponsorshipDealStatus.CONTENT_SUBMITTED -> stringResource(R.string.sponsorship_status_content_submitted)
    SponsorshipDealStatus.COMPLETED -> stringResource(R.string.sponsorship_status_completed)
    SponsorshipDealStatus.REJECTED -> stringResource(R.string.sponsorship_status_rejected)
    SponsorshipDealStatus.CANCELLED -> stringResource(R.string.sponsorship_status_cancelled)
    SponsorshipDealStatus.UNKNOWN -> raw.ifBlank { stringResource(R.string.sponsorship_status_unknown) }
}
