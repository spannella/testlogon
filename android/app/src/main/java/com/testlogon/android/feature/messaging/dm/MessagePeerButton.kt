package com.testlogon.android.feature.messaging.dm

import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Message
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R

/** Stable testTags for the start-DM affordance (AND-127). */
object StartDmTestTags {
    const val BUTTON = "start_dm_button"
}

/**
 * AND-127 — the "Message" affordance shown on a profile / contact surface for [peerUserId].
 *
 * Tapping it runs DM find-or-create and, on success, invokes [onOpenThread] with the resolved
 * conversation id (navigating into the AND-123 thread). The button is disabled + shows progress
 * while a request is in flight (debounced). Failures are reported via [onError] (host a snackbar);
 * the affordance re-enables and no navigation occurs.
 */
@Composable
fun MessagePeerButton(
    peerUserId: String,
    onOpenThread: (conversationId: String) -> Unit,
    modifier: Modifier = Modifier,
    onError: (String) -> Unit = {},
    viewModel: StartDmViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()

    LaunchedEffect(Unit) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is StartDmEffect.OpenThread -> onOpenThread(effect.conversationId)
            }
        }
    }

    LaunchedEffect(state.errorMessage) {
        state.errorMessage?.let {
            onError(it)
            viewModel.consumeError()
        }
    }

    val cd = stringResource(R.string.dm_message_cd)
    Button(
        onClick = { viewModel.startDm(peerUserId) },
        enabled = !state.inFlight,
        modifier = modifier
            .testTag(StartDmTestTags.BUTTON)
            .semantics { contentDescription = cd },
    ) {
        if (state.inFlight) {
            CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp)
        } else {
            Icon(Icons.AutoMirrored.Filled.Message, contentDescription = null, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(8.dp))
            Text(stringResource(R.string.dm_message))
        }
    }
}
