@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.messaging.helpdesk

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
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
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.data.messaging.Message
import com.testlogon.android.data.messaging.helpdesk.HelpdeskAssignment

/** AND-162 — stable testTags for the helpdesk detail screen. */
object HelpdeskDetailTestTags {
    const val SCREEN = "helpdesk_detail_screen"
    const val THREAD = "helpdesk_detail_thread"
    const val CLAIM = "helpdesk_detail_claim"
    const val HEADER = "helpdesk_detail_header"
    const val COMPOSER = "helpdesk_detail_composer"
    const val SEND = "helpdesk_detail_send"
    const val RETRY_CLAIM = "helpdesk_detail_retry_claim"
}

/**
 * AND-162 — route-level helpdesk detail screen. Renders the conversation thread (reusing the observed
 * messages) plus a claim/assignee header bar; the reply composer is enabled only when ASSIGNED_TO_ME.
 */
@Composable
fun HelpdeskDetailRoute(
    onBack: () -> Unit,
    onQueueChanged: () -> Unit = {},
    viewModel: HelpdeskDetailViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }

    LaunchedEffect(Unit) {
        viewModel.events.collect { event ->
            when (event) {
                HelpdeskDetailEvent.QueueChanged -> onQueueChanged()
                is HelpdeskDetailEvent.ErrorSnack -> {
                    snackbarHostState.currentSnackbarData?.dismiss()
                    snackbarHostState.showSnackbar(event.message)
                }
            }
        }
    }

    Scaffold(
        modifier = Modifier.testTag(HelpdeskDetailTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.helpdesk_detail_title)) },
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
        Column(Modifier.fillMaxSize().padding(padding)) {
            ClaimHeaderBar(
                assignment = state.assignment,
                assignee = state.assignedAgentUserId,
                claim = state.claim,
                onClaim = viewModel::onClaimClick,
                onRetryClaim = viewModel::onRetryClaim,
            )
            LazyColumn(Modifier.weight(1f).fillMaxWidth().testTag(HelpdeskDetailTestTags.THREAD)) {
                items(state.messages, key = { it.id ?: it.clientId }) { msg ->
                    ThreadBubble(msg)
                }
            }
            ReplyComposer(
                draft = state.draft,
                enabled = state.replyEnabled,
                assignment = state.assignment,
                onDraftChange = viewModel::onDraftChange,
                onSend = viewModel::onSendReply,
            )
        }
    }
}

@Composable
private fun ClaimHeaderBar(
    assignment: HelpdeskAssignment,
    assignee: String?,
    claim: ClaimState,
    onClaim: () -> Unit,
    onRetryClaim: () -> Unit,
) {
    val stateDesc = when (assignment) {
        HelpdeskAssignment.UNCLAIMED -> stringResource(R.string.helpdesk_header_unclaimed)
        HelpdeskAssignment.ASSIGNED_TO_ME -> stringResource(R.string.helpdesk_header_assigned_me)
        HelpdeskAssignment.ASSIGNED_TO_OTHER ->
            stringResource(R.string.helpdesk_header_assigned_other, assignee ?: "")
        HelpdeskAssignment.CLOSED -> stringResource(R.string.helpdesk_header_closed)
    }
    Surface(tonalElevation = 2.dp, modifier = Modifier.fillMaxWidth()) {
        Column(
            Modifier
                .fillMaxWidth()
                .padding(16.dp)
                .testTag(HelpdeskDetailTestTags.HEADER)
                .semantics { stateDescription = stateDesc },
        ) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Text(stateDesc, style = MaterialTheme.typography.titleMedium, modifier = Modifier.weight(1f))
                if (assignment == HelpdeskAssignment.UNCLAIMED) {
                    when (claim) {
                        ClaimState.Claiming ->
                            CircularProgressIndicator(
                                Modifier
                                    .size(24.dp)
                                    .semantics { stateDescription = "Claiming" },
                            )
                        else ->
                            Button(
                                onClick = onClaim,
                                modifier = Modifier.testTag(HelpdeskDetailTestTags.CLAIM),
                            ) { Text(stringResource(R.string.helpdesk_claim)) }
                    }
                }
            }
            if (claim is ClaimState.Failed) {
                Spacer(Modifier.size(8.dp))
                Text(
                    text = claimErrorMessage(claim.error),
                    color = MaterialTheme.colorScheme.error,
                    modifier = Modifier.semantics { liveRegion = LiveRegionMode.Assertive },
                )
                if (claim.retryable) {
                    TextButton(
                        onClick = onRetryClaim,
                        modifier = Modifier.testTag(HelpdeskDetailTestTags.RETRY_CLAIM),
                    ) { Text(stringResource(R.string.action_retry)) }
                }
            }
        }
    }
}

@Composable
private fun ReplyComposer(
    draft: String,
    enabled: Boolean,
    assignment: HelpdeskAssignment,
    onDraftChange: (String) -> Unit,
    onSend: () -> Unit,
) {
    val hint = when (assignment) {
        HelpdeskAssignment.ASSIGNED_TO_ME -> stringResource(R.string.helpdesk_reply_hint)
        HelpdeskAssignment.ASSIGNED_TO_OTHER -> stringResource(R.string.helpdesk_reply_disabled_other)
        HelpdeskAssignment.CLOSED -> stringResource(R.string.helpdesk_reply_disabled_closed)
        HelpdeskAssignment.UNCLAIMED -> stringResource(R.string.helpdesk_reply_disabled_unclaimed)
    }
    Row(
        Modifier.fillMaxWidth().imePadding().padding(8.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        OutlinedTextField(
            value = draft,
            onValueChange = onDraftChange,
            enabled = enabled,
            placeholder = { Text(hint) },
            modifier = Modifier.weight(1f).testTag(HelpdeskDetailTestTags.COMPOSER),
        )
        IconButton(
            onClick = onSend,
            enabled = enabled && draft.isNotBlank(),
            modifier = Modifier.testTag(HelpdeskDetailTestTags.SEND),
        ) {
            Icon(
                Icons.AutoMirrored.Filled.Send,
                contentDescription = stringResource(R.string.helpdesk_reply_send_cd),
            )
        }
    }
}

@Composable
private fun ThreadBubble(message: Message) {
    Box(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 4.dp)) {
        Text(message.text, style = MaterialTheme.typography.bodyLarge)
    }
}

@Composable
private fun claimErrorMessage(error: ClaimError): String = stringResource(
    when (error) {
        ClaimError.ALREADY_CLAIMED -> R.string.helpdesk_claim_err_already
        ClaimError.CLOSED -> R.string.helpdesk_claim_err_closed
        ClaimError.FORBIDDEN -> R.string.helpdesk_claim_err_forbidden
        ClaimError.NOT_AVAILABLE -> R.string.helpdesk_claim_err_not_available
        ClaimError.NOT_FOUND -> R.string.helpdesk_claim_err_not_found
        ClaimError.NETWORK -> R.string.helpdesk_claim_err_network
        ClaimError.UNKNOWN -> R.string.helpdesk_claim_err_unknown
    },
)
