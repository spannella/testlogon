package com.testlogon.android.feature.call.incoming

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
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
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.input.TlButton
import com.testlogon.android.core.ui.input.TlButtonVariant
import com.testlogon.android.data.call.CallMode

/**
 * AND-297 — full-screen incoming-call UI (caller name + kind + large Accept/Decline). Renders over the
 * lock screen via [IncomingCallActivity]; exposes ONLY caller display name + call kind (no message/thread
 * content). Accept first in focus order for TalkBack; ≥48dp targets via [TlButton] defaults.
 *
 * One-shot finish is handled by [onFinished] (called from a LaunchedEffect on a terminal state) so no
 * @Composable is invoked inside a non-composable lambda.
 */
@Composable
fun IncomingCallScreen(
    controller: IncomingCallController,
    onAccept: () -> Unit,
    onDecline: () -> Unit,
    onFinished: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val state by controller.state.collectAsStateWithLifecycle()

    when (val s = state) {
        is IncomingCallState.Ringing -> RingingContent(
            callerName = s.invite.callerName,
            mode = s.invite.mode,
            onAccept = onAccept,
            onDecline = onDecline,
            modifier = modifier,
        )
        is IncomingCallState.Connecting -> StatusContent(
            text = stringForStatus(R.string.call_status_connecting),
            modifier = modifier,
        )
        is IncomingCallState.Connected -> {
            LaunchedEffect(s.callId) { onFinished() }
        }
        is IncomingCallState.Failed -> StatusContent(text = s.message, modifier = modifier)
        is IncomingCallState.Idle, is IncomingCallState.Dismissed -> {
            LaunchedEffect(Unit) { onFinished() }
        }
    }
}

@Composable
private fun RingingContent(
    callerName: String?,
    mode: CallMode,
    onAccept: () -> Unit,
    onDecline: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val name = callerName ?: androidx.compose.ui.res.stringResource(R.string.call_unknown_caller)
    val kindLabel = androidx.compose.ui.res.stringResource(
        if (mode == CallMode.VIDEO) R.string.call_kind_video else R.string.call_kind_audio,
    )
    val acceptCd = androidx.compose.ui.res.stringResource(R.string.call_accept_cd, name)
    val declineCd = androidx.compose.ui.res.stringResource(R.string.call_decline_cd, name)
    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(24.dp)
            .testTag("incoming_call_screen"),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Text(
            text = name,
            style = MaterialTheme.typography.headlineMedium,
            textAlign = TextAlign.Center,
            modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
        )
        Spacer(Modifier.height(8.dp))
        Text(text = kindLabel, style = MaterialTheme.typography.bodyLarge)
        Spacer(Modifier.height(48.dp))
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceEvenly,
        ) {
            TlButton(
                text = androidx.compose.ui.res.stringResource(R.string.call_accept),
                onClick = onAccept,
                variant = TlButtonVariant.Primary,
                modifier = Modifier
                    .testTag("incoming_call_accept")
                    .semantics { contentDescription = acceptCd },
            )
            TlButton(
                text = androidx.compose.ui.res.stringResource(R.string.call_decline),
                onClick = onDecline,
                variant = TlButtonVariant.Secondary,
                modifier = Modifier
                    .testTag("incoming_call_decline")
                    .semantics { contentDescription = declineCd },
            )
        }
    }
}

@Composable
private fun StatusContent(text: String, modifier: Modifier = Modifier) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(24.dp)
            .testTag("incoming_call_status"),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Text(
            text = text,
            style = MaterialTheme.typography.titleLarge,
            modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
        )
    }
}

@Composable
private fun stringForStatus(resId: Int): String = androidx.compose.ui.res.stringResource(resId)
