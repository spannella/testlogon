@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.vnc

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.DesktopWindows
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.data.vnc.CreateVncSessionDto
import com.testlogon.android.data.vnc.VncTransferFallbackDto
import com.testlogon.android.feature.infracommon.InfraDropdown

object RemoteDesktopTestTags {
    const val SCREEN = "remotedesktop_screen"
    const val TARGET = "remotedesktop_target"
    const val TARGET_CUSTOM = "remotedesktop_target_custom"
    const val START = "remotedesktop_start"
    const val SESSION_CARD = "remotedesktop_session_card"
    const val COPY_WS = "remotedesktop_copy_ws"
    const val FALLBACK = "remotedesktop_fallback"
    const val END = "remotedesktop_end"
    const val OPEN_LIVE = "remotedesktop_open_live"
    const val CLOSE_LIVE = "remotedesktop_close_live"
    const val LIVE_STATUS = "remotedesktop_live_status"
    const val UNREACHABLE = "remotedesktop_unreachable"
}

private val KNOWN_TARGETS = listOf("demo", "ops-admin")

@Composable
fun RemoteDesktopRoute(
    onBack: () -> Unit,
    viewModel: RemoteDesktopViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    RemoteDesktopScreen(
        state = state,
        onBack = onBack,
        onSetTarget = viewModel::setTarget,
        onStart = viewModel::createSession,
        onLoadFallback = viewModel::loadFallback,
        onEnd = viewModel::endSession,
        onMessageShown = viewModel::clearMessage,
    )
}

@Composable
fun RemoteDesktopScreen(
    state: RemoteDesktopUiState,
    onBack: () -> Unit,
    onSetTarget: (String) -> Unit,
    onStart: () -> Unit,
    onLoadFallback: () -> Unit,
    onEnd: () -> Unit,
    onMessageShown: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val snackbar = remember { SnackbarHostState() }
    val clipboard = LocalClipboardManager.current

    LaunchedEffect(state.message, state.errorMessage) {
        val msg = state.message ?: state.errorMessage
        if (msg != null) { snackbar.showSnackbar(msg); onMessageShown() }
    }

    Scaffold(
        modifier = modifier.testTag(RemoteDesktopTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            TopAppBar(
                title = { Text("Remote desktop") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            if (state.session == null) {
                ConnectCard(state = state, onSetTarget = onSetTarget, onStart = onStart)
            } else {
                SessionCard(
                    session = state.session,
                    fallback = state.fallback,
                    fallbackLoading = state.fallbackLoading,
                    ending = state.ending,
                    onCopyWs = { clipboard.setText(AnnotatedString(state.session.wsUrl)) },
                    onLoadFallback = onLoadFallback,
                    onEnd = onEnd,
                )
            }
        }
    }
}

@Composable
private fun ConnectCard(
    state: RemoteDesktopUiState,
    onSetTarget: (String) -> Unit,
    onStart: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Icon(Icons.Outlined.DesktopWindows, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                Text("Start a remote desktop session", style = MaterialTheme.typography.titleMedium)
            }
            Text(
                "Broker a VNC session to a registered target. The session is validated and audited server-side.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            val isKnown = state.targetId in KNOWN_TARGETS
            InfraDropdown(
                label = "Target",
                options = KNOWN_TARGETS + "custom",
                selected = if (isKnown) state.targetId else "custom",
                labelFor = { if (it == "custom") "Custom target ID" else it },
                onSelect = { if (it == "custom") onSetTarget("") else onSetTarget(it) },
                fieldTestTag = RemoteDesktopTestTags.TARGET,
            )
            if (!isKnown) {
                OutlinedTextField(
                    value = state.targetId,
                    onValueChange = onSetTarget,
                    label = { Text("Target ID") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth().testTag(RemoteDesktopTestTags.TARGET_CUSTOM),
                )
            }
            Button(
                onClick = onStart,
                enabled = !state.creating && state.targetId.isNotBlank(),
                modifier = Modifier.fillMaxWidth().testTag(RemoteDesktopTestTags.START),
            ) { Text(if (state.creating) "Starting..." else "Start session") }
        }
    }
}

@Composable
private fun SessionCard(
    session: CreateVncSessionDto,
    fallback: VncTransferFallbackDto?,
    fallbackLoading: Boolean,
    ending: Boolean,
    onCopyWs: () -> Unit,
    onLoadFallback: () -> Unit,
    onEnd: () -> Unit,
) {
    // Reachability gate: only attempt the live WebView viewer when the ws host could actually be
    // reached from this device. Otherwise stay honest and show the connection-details fallback.
    val verdict = remember(session.wsUrl) { VncReachability.assess(session.wsUrl) }
    var liveOpen by remember(session.sessionId) { mutableStateOf(false) }
    var liveStatus by remember(session.sessionId) { mutableStateOf(VncViewerStatus.Unknown) }
    var liveDetail by remember(session.sessionId) { mutableStateOf("") }

    Card(modifier = Modifier.fillMaxWidth().testTag(RemoteDesktopTestTags.SESSION_CARD)) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text("Session ready", style = MaterialTheme.typography.titleMedium)
            Text("Session ID: ${session.sessionId}", style = MaterialTheme.typography.bodySmall)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                if (session.capabilities.clipboard) AssistChip(onClick = {}, enabled = false, label = { Text("clipboard") })
                if (session.capabilities.fileTransfer) AssistChip(onClick = {}, enabled = false, label = { Text("file transfer") })
                if (session.capabilities.dragDropUpload) AssistChip(onClick = {}, enabled = false, label = { Text("drag+drop") })
            }
            Text(
                "Idle timeout ${session.timeoutPolicy.idleTimeoutSeconds}s - max ${session.timeoutPolicy.maxSessionDurationSeconds}s",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            HorizontalDivider()

            // ---- LIVE VIEW (real noVNC RFB over WebView) ----
            if (liveOpen && verdict.reachable) {
                Text("Live view", style = MaterialTheme.typography.titleSmall)
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(360.dp),
                ) {
                    VncWebView(
                        wsUrl = session.wsUrl,
                        connectParams = session.connectParams,
                        onStatusChanged = { s, d -> liveStatus = s; liveDetail = d },
                    )
                }
                val statusLine = when (liveStatus) {
                    VncViewerStatus.Connecting -> "Connecting to the remote desktop..."
                    VncViewerStatus.Connected -> "Connected."
                    VncViewerStatus.Disconnected -> "Disconnected."
                    VncViewerStatus.Timeout -> "Still connecting - the bridge may be unreachable."
                    VncViewerStatus.Error -> "Connection failed: ${liveDetail.ifBlank { "bridge unreachable" }}"
                    VncViewerStatus.Unknown -> "Starting viewer..."
                }
                Text(
                    statusLine,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.testTag(RemoteDesktopTestTags.LIVE_STATUS),
                )
                OutlinedButton(
                    onClick = { liveOpen = false },
                    modifier = Modifier.fillMaxWidth().testTag(RemoteDesktopTestTags.CLOSE_LIVE),
                ) { Text("Close live view") }
            } else if (verdict.reachable) {
                Row(verticalAlignment = Alignment.Top, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Icon(Icons.Outlined.DesktopWindows, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text("Open the live desktop", style = MaterialTheme.typography.titleSmall)
                        Text(
                            "Attach a live noVNC session over the brokered WebSocket, in-app.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
                Button(
                    onClick = { liveOpen = true },
                    modifier = Modifier.fillMaxWidth().testTag(RemoteDesktopTestTags.OPEN_LIVE),
                ) { Text("Open live view") }
            } else {
                // Honest infra-blocked state: the ws_url can't be reached from a phone.
                Row(
                    verticalAlignment = Alignment.Top,
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    modifier = Modifier.testTag(RemoteDesktopTestTags.UNREACHABLE),
                ) {
                    Icon(Icons.Outlined.Info, contentDescription = null, tint = MaterialTheme.colorScheme.tertiary)
                    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text("Live view unavailable from this device", style = MaterialTheme.typography.titleSmall)
                        Text(
                            verdict.reason ?: "The VNC bridge is not reachable from this device.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        Text(
                            "Use the connection details below in a desktop VNC/noVNC client, or deploy a " +
                                "public websockify gateway so the app can attach the live view.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            }

            HorizontalDivider()

            Text("WebSocket:", style = MaterialTheme.typography.labelMedium)
            Text(session.wsUrl, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)
            if (session.connectParams.isNotEmpty()) {
                Text("Connect params:", style = MaterialTheme.typography.labelMedium)
                session.connectParams.forEach { (k, v) ->
                    Text("$k = $v", style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)
                }
            }
            OutlinedButton(
                onClick = onCopyWs,
                modifier = Modifier.fillMaxWidth().testTag(RemoteDesktopTestTags.COPY_WS),
            ) { Text("Copy WebSocket URL") }

            HorizontalDivider()

            if (fallback == null) {
                OutlinedButton(
                    onClick = onLoadFallback,
                    enabled = !fallbackLoading,
                    modifier = Modifier.fillMaxWidth().testTag(RemoteDesktopTestTags.FALLBACK),
                ) { Text(if (fallbackLoading) "Loading..." else "File transfer fallback") }
            } else {
                Text(fallback.label.ifBlank { "Transfer fallback (${fallback.method})" }, style = MaterialTheme.typography.titleSmall)
                if (fallback.instructions.isNotBlank()) {
                    Text(fallback.instructions, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                if (fallback.url.isNotBlank()) {
                    Text(fallback.url, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)
                }
            }

            HorizontalDivider()

            Button(
                onClick = onEnd,
                enabled = !ending,
                modifier = Modifier.fillMaxWidth().testTag(RemoteDesktopTestTags.END),
            ) { Text(if (ending) "Closing..." else "End session") }
        }
    }
}
