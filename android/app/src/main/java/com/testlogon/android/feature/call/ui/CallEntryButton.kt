package com.testlogon.android.feature.call.ui

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Call
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import com.testlogon.android.R
import com.testlogon.android.data.call.CallMode

/**
 * AND-296 — reusable "Call" affordance for a thread top bar or a profile screen.
 *
 * The caller supplies the resolved conversationId + calleeUserId (resolving/creating a 1:1 conversation is
 * out of scope here per AND-296 FR-1) and an [onPlaceCall] that navigates to the outgoing-call route via
 * [CallRoutes.outgoing], guarding the single-active-call invariant at the entry point.
 */
@Composable
fun CallEntryButton(
    conversationId: String,
    calleeUserId: String,
    onPlaceCall: (route: String) -> Unit,
    modifier: Modifier = Modifier,
    mode: CallMode = CallMode.AUDIO,
    peerName: String? = null,
    enabled: Boolean = true,
) {
    val cd = stringResource(R.string.call_start_cd)
    IconButton(
        onClick = {
            onPlaceCall(
                com.testlogon.android.feature.call.nav.CallRoutes.outgoing(
                    conversationId = conversationId,
                    calleeUserId = calleeUserId,
                    mode = mode.wire,
                    peerName = peerName,
                ),
            )
        },
        enabled = enabled,
        modifier = modifier.testTag("call_entry_button"),
    ) {
        Icon(Icons.Outlined.Call, contentDescription = cd)
    }
}
