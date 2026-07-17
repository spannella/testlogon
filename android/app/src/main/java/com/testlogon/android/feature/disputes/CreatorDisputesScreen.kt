@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.disputes

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.compose.material3.AlertDialog
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.i18n.asString
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.disputes.Dispute

/** DISP-024 — stable testTags for the creator "Respond to dispute" screen. */
object CreatorDisputesTestTags {
    const val SCREEN = "creator_disputes_screen"
    const val LIST = "creator_disputes_list"
    const val EMPTY = "creator_disputes_empty"
    const val ERROR = "creator_disputes_error"
    const val ROW = "creator_dispute_row"
    const val RESPOND = "creator_dispute_respond"
    const val RESPOND_INPUT = "creator_dispute_respond_input"
    const val RESPOND_SUBMIT = "creator_dispute_respond_submit"
}

/** DISP-024 — route-level creator inbound-dispute queue. */
@Composable
fun CreatorDisputesRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: CreatorDisputesViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    val respondState by viewModel.respond.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    val submittedMsg = stringResource(R.string.creator_disputes_response_submitted)
    // Resolve the error UiText -> String at composable scope (asString() is @Composable;
    // it cannot be called inside the LaunchedEffect coroutine below).
    val errorText = respondState.errorMessage?.asString()

    LaunchedEffect(respondState.submittedDisputeId, errorText) {
        if (respondState.submittedDisputeId != null) {
            snackbarHostState.showSnackbar(submittedMsg)
            viewModel.consumeRespondEvent()
        } else if (errorText != null) {
            snackbarHostState.showSnackbar(errorText)
            viewModel.consumeRespondEvent()
        }
    }

    CreatorDisputesScreen(
        state = state,
        submitting = respondState.submitting,
        snackbarHostState = snackbarHostState,
        onRespond = viewModel::respond,
        onRetry = viewModel::load,
        onBack = onBack,
        modifier = modifier,
    )
}

@Composable
fun CreatorDisputesScreen(
    state: CreatorDisputesUiState,
    submitting: Boolean,
    snackbarHostState: SnackbarHostState,
    onRespond: (disputeId: String, text: String) -> Unit,
    onRetry: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    var respondTarget by remember { mutableStateOf<Dispute?>(null) }

    Scaffold(
        modifier = modifier.testTag(CreatorDisputesTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.creator_disputes_title)) },
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
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            when (val s = state) {
                is CreatorDisputesUiState.Loading ->
                    LoadingState(message = stringResource(R.string.disputes_loading))

                is CreatorDisputesUiState.Empty ->
                    EmptyState(
                        title = stringResource(R.string.creator_disputes_empty_title),
                        body = stringResource(R.string.creator_disputes_empty_body),
                        modifier = Modifier.testTag(CreatorDisputesTestTags.EMPTY),
                    )

                is CreatorDisputesUiState.Failure ->
                    ErrorState(
                        message = s.message.asString(),
                        onRetry = onRetry,
                        modifier = Modifier.testTag(CreatorDisputesTestTags.ERROR),
                    )

                is CreatorDisputesUiState.Content ->
                    LazyColumn(
                        modifier = Modifier.fillMaxSize().testTag(CreatorDisputesTestTags.LIST),
                        contentPadding = androidx.compose.foundation.layout.PaddingValues(12.dp),
                        verticalArrangement = Arrangement.spacedBy(10.dp),
                    ) {
                        items(items = s.disputes, key = { it.id }) { dispute ->
                            CreatorDisputeCard(dispute = dispute, onRespond = { respondTarget = dispute })
                        }
                    }
            }
        }
    }

    val target = respondTarget
    if (target != null) {
        RespondDialog(
            submitting = submitting,
            onDismiss = { if (!submitting) respondTarget = null },
            onSubmit = { text ->
                onRespond(target.id, text)
                respondTarget = null
            },
        )
    }
}

@Composable
private fun CreatorDisputeCard(dispute: Dispute, onRespond: () -> Unit) {
    val amountText = formatDisputeMoney(dispute.amount)
    val statusText = stringResource(disputeStatusLabelRes(dispute.status))
    val dateText = formatDisputeDate(dispute.createdAtEpochSeconds)
        ?: stringResource(R.string.disputes_date_unknown)
    Card(modifier = Modifier.fillMaxWidth().testTag(CreatorDisputesTestTags.ROW)) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Text(text = amountText, style = MaterialTheme.typography.titleMedium)
                AssistChip(onClick = {}, label = { Text(statusText) })
            }
            Text(
                text = dispute.reasonDetail?.let { "${dispute.reason} — $it" } ?: dispute.reason,
                style = MaterialTheme.typography.bodyMedium,
            )
            Text(
                text = dateText,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            dispute.creatorResponse?.let { resp ->
                Text(
                    text = "${stringResource(R.string.creator_disputes_your_response)}: $resp",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            if (dispute.creatorCanRespond) {
                Button(
                    onClick = onRespond,
                    modifier = Modifier.testTag(CreatorDisputesTestTags.RESPOND),
                ) {
                    Text(stringResource(R.string.creator_disputes_respond))
                }
            } else if (dispute.creatorResponse == null) {
                Text(
                    text = stringResource(R.string.creator_disputes_awaiting_review),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
private fun RespondDialog(
    submitting: Boolean,
    onDismiss: () -> Unit,
    onSubmit: (String) -> Unit,
) {
    var text by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.creator_disputes_respond_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    text = stringResource(R.string.creator_disputes_respond_hint),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                OutlinedTextField(
                    value = text,
                    onValueChange = { text = it },
                    modifier = Modifier.fillMaxWidth().testTag(CreatorDisputesTestTags.RESPOND_INPUT),
                    minLines = 3,
                )
            }
        },
        confirmButton = {
            Button(
                onClick = { onSubmit(text) },
                enabled = text.isNotBlank() && !submitting,
                modifier = Modifier.testTag(CreatorDisputesTestTags.RESPOND_SUBMIT),
            ) {
                Text(stringResource(R.string.creator_disputes_respond_submit))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss, enabled = !submitting) {
                Text(stringResource(R.string.action_cancel))
            }
        },
    )
}
