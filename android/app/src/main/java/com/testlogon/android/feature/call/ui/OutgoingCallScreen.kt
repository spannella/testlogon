package com.testlogon.android.feature.call.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.input.TlButton
import com.testlogon.android.core.ui.input.TlButtonVariant

/**
 * AND-296 — outgoing-call screen (peer name + phase label + duration once connected + a single End/Close).
 * No mute/cam controls here (AND-298). The one-shot Finish effect is collected in a LaunchedEffect (Channel
 * + receiveAsFlow) so navigation back happens exactly once and no @Composable runs inside the effect lambda.
 */
@Composable
fun OutgoingCallRoute(
    onFinished: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: OutgoingCallViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    LaunchedEffect(viewModel) {
        viewModel.effect.collect { effect ->
            when (effect) {
                OutgoingCallEffect.Finish -> onFinished()
            }
        }
    }
    OutgoingCallScreen(
        state = state,
        onHangUp = viewModel::onHangUp,
        onClose = viewModel::onClose,
        onRetry = viewModel::start,
        modifier = modifier,
    )
}

@Composable
fun OutgoingCallScreen(
    state: CallUiState,
    onHangUp: () -> Unit,
    onClose: () -> Unit,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val peerName = state.peerName ?: stringResource(R.string.call_unknown_caller)
    val phaseLabel = phaseLabel(state)
    val endCd = stringResource(R.string.call_end_cd)
    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(24.dp)
            .testTag("outgoing_call_screen"),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Text(
            text = peerName,
            style = MaterialTheme.typography.headlineMedium,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(8.dp))
        Text(
            text = phaseLabel,
            style = MaterialTheme.typography.bodyLarge,
            modifier = Modifier
                .testTag("outgoing_call_phase")
                .semantics { liveRegion = LiveRegionMode.Polite },
        )
        if (state.mediaUnavailable) {
            Spacer(Modifier.height(8.dp))
            Text(
                text = stringResource(R.string.call_media_unavailable),
                style = MaterialTheme.typography.bodyMedium,
                textAlign = TextAlign.Center,
                modifier = Modifier.testTag("outgoing_call_media_unavailable"),
            )
        }
        Spacer(Modifier.height(48.dp))
        when (state.phase) {
            CallUiPhase.FAILED -> {
                TlButton(
                    text = stringResource(R.string.call_retry),
                    onClick = onRetry,
                    variant = TlButtonVariant.Primary,
                    modifier = Modifier.testTag("outgoing_call_retry"),
                )
                Spacer(Modifier.height(12.dp))
                TlButton(
                    text = stringResource(R.string.call_close),
                    onClick = onClose,
                    variant = TlButtonVariant.Secondary,
                    modifier = Modifier.testTag("outgoing_call_close"),
                )
            }
            CallUiPhase.ENDED -> {
                TlButton(
                    text = stringResource(R.string.call_close),
                    onClick = onClose,
                    variant = TlButtonVariant.Secondary,
                    modifier = Modifier.testTag("outgoing_call_close"),
                )
            }
            else -> {
                TlButton(
                    text = stringResource(R.string.call_end),
                    onClick = onHangUp,
                    variant = TlButtonVariant.Secondary,
                    modifier = Modifier
                        .testTag("outgoing_call_end")
                        .semantics { contentDescription = endCd },
                )
            }
        }
    }
}

@Composable
private fun phaseLabel(state: CallUiState): String = when (state.phase) {
    CallUiPhase.CALLING -> stringResource(R.string.call_status_calling)
    CallUiPhase.RINGING -> stringResource(R.string.call_status_ringing)
    CallUiPhase.CONNECTING -> stringResource(R.string.call_status_connecting)
    CallUiPhase.CONNECTED -> formatDuration(state.elapsedSeconds)
    CallUiPhase.ENDING -> stringResource(R.string.call_status_ending)
    CallUiPhase.ENDED -> stringResource(R.string.call_status_ended)
    CallUiPhase.FAILED -> stringResource(R.string.call_status_failed)
}

/** Locale-independent mm:ss (java.time avoided per gotchas; pure integer math, JVM-testable). */
internal fun formatDuration(totalSeconds: Long): String {
    val s = totalSeconds.coerceAtLeast(0)
    val minutes = s / 60
    val seconds = s % 60
    return "%02d:%02d".format(minutes, seconds)
}
