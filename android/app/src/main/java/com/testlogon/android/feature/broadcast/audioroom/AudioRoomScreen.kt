package com.testlogon.android.feature.broadcast.audioroom

import android.Manifest
import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.wrapContentSize
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Mic
import androidx.compose.material.icons.filled.MicOff
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.feature.broadcast.chat.LiveChatPanel

/** #104 AUDIO ROOM — testTags for on-device automation. */
const val AUDIOROOM_SCREEN = "audioroom_screen"
const val AUDIOROOM_LISTENER_COUNT = "audioroom_listener_count"
const val AUDIOROOM_SPEAKER_TILE = "audioroom_speaker_tile"
const val AUDIOROOM_HANDS_LIST = "audioroom_hands_list"
const val AUDIOROOM_HAND_ROW = "audioroom_hand_row"
const val AUDIOROOM_PROMOTE = "audioroom_promote"
const val AUDIOROOM_RAISE_HAND = "audioroom_raise_hand"
const val AUDIOROOM_MIC_TOGGLE = "audioroom_mic_toggle"
const val AUDIOROOM_LEAVE = "audioroom_leave"
const val AUDIOROOM_CHAT = "audioroom_chat"

@Composable
fun AudioRoomRoute(
    onBack: () -> Unit,
    viewModel: AudioRoomViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val context = LocalContext.current

    val micPermissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted -> viewModel.onMicPermission(granted) }

    // Speakers/host need RECORD_AUDIO to publish. Seed the current grant state, and request it the moment
    // the caller is (or becomes) a publisher.
    LaunchedEffect(state.canPublish) {
        val granted = ContextCompat.checkSelfPermission(
            context, Manifest.permission.RECORD_AUDIO,
        ) == PackageManager.PERMISSION_GRANTED
        viewModel.setNeedsMicPermission(!granted)
        if (state.canPublish && !granted) {
            micPermissionLauncher.launch(Manifest.permission.RECORD_AUDIO)
        } else if (state.canPublish && granted) {
            viewModel.onMicPermission(true)
        }
    }

    // Disconnect LiveKit + fire leave/viewers-leave when the screen leaves composition.
    DisposableEffect(Unit) {
        onDispose { viewModel.leave() }
    }

    AudioRoomScreen(
        state = state,
        onBack = { viewModel.leave(); onBack() },
        onRaiseHand = viewModel::raiseHand,
        onToggleMic = {
            if (state.needsMicPermission) micPermissionLauncher.launch(Manifest.permission.RECORD_AUDIO)
            else viewModel.toggleMic()
        },
        onLeave = { viewModel.leave(); onBack() },
        onPromote = viewModel::hostPromote,
        onDemote = viewModel::hostDemote,
        onMute = viewModel::hostMute,
        onUnmute = viewModel::hostUnmute,
        onRetry = viewModel::join,
    )
}

@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
fun AudioRoomScreen(
    state: AudioRoomUiState,
    onBack: () -> Unit,
    onRaiseHand: () -> Unit,
    onToggleMic: () -> Unit,
    onLeave: () -> Unit,
    onPromote: (String) -> Unit,
    onDemote: (String) -> Unit,
    onMute: (String) -> Unit,
    onUnmute: (String) -> Unit,
    onRetry: () -> Unit,
) {
    Scaffold(
        modifier = Modifier.testTag(AUDIOROOM_SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(if (state.isHost) "Your audio room" else "Audio room") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding)) {
            // Presence header
            Row(
                modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    text = "${state.speakerCount} on stage · ${state.stageMaxSlots} slots",
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.SemiBold,
                )
                Spacer(Modifier.width(12.dp))
                Text(
                    text = "${state.listenerCount} listening",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.testTag(AUDIOROOM_LISTENER_COUNT),
                )
            }

            when {
                state.fatalError != null -> ErrorState(state.fatalError, onRetry)
                state.connecting && state.speakers.isEmpty() -> ConnectingState()
                else -> AudioRoomContent(
                    state = state,
                    onPromote = onPromote,
                    onDemote = onDemote,
                    onMute = onMute,
                    onUnmute = onUnmute,
                    onRaiseHand = onRaiseHand,
                    onToggleMic = onToggleMic,
                    onLeave = onLeave,
                )
            }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun androidx.compose.foundation.layout.ColumnScope.AudioRoomContent(
    state: AudioRoomUiState,
    onPromote: (String) -> Unit,
    onDemote: (String) -> Unit,
    onMute: (String) -> Unit,
    onUnmute: (String) -> Unit,
    onRaiseHand: () -> Unit,
    onToggleMic: () -> Unit,
    onLeave: () -> Unit,
) {
    // Speaker stage (audio-first tiles). Long-press (host only) opens per-speaker controls.
    FlowRow(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp)
            .verticalScroll(rememberScrollState())
            .weight(1f, fill = false),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        state.speakers.forEach { spk ->
            SpeakerTile(
                speaker = spk,
                hostControls = state.isHost && !spk.isSelf,
                onMute = { onMute(spk.identity) },
                onUnmute = { onUnmute(spk.identity) },
                onRemove = { onDemote(spk.identity) },
            )
        }
    }

    // Host: pending raise-hand requests.
    if (state.isHost && state.hands.isNotEmpty()) {
        HorizontalDivider()
        Column(modifier = Modifier.fillMaxWidth().padding(12.dp).testTag(AUDIOROOM_HANDS_LIST)) {
            Text("Requests to speak", fontWeight = FontWeight.SemiBold)
            Spacer(Modifier.size(4.dp))
            state.hands.forEach { hand ->
                Row(
                    modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp).testTag(AUDIOROOM_HAND_ROW),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text("✋ ${hand.displayName}", modifier = Modifier.weight(1f))
                    OutlinedButton(onClick = { onDemote(hand.userId) }) { Text("Dismiss") }
                    Spacer(Modifier.width(8.dp))
                    Button(
                        onClick = { onPromote(hand.userId) },
                        modifier = Modifier.testTag(AUDIOROOM_PROMOTE),
                    ) { Text("Add") }
                }
            }
        }
    }

    HorizontalDivider()
    ControlBar(
        state = state,
        onRaiseHand = onRaiseHand,
        onToggleMic = onToggleMic,
        onLeave = onLeave,
    )

    HorizontalDivider()
    // Rich live chat (reused verbatim), keyed to the same session id.
    LiveChatPanel(
        sessionId = state.sessionId,
        isHost = state.isHost,
        modifier = Modifier.fillMaxWidth().weight(1.4f).testTag(AUDIOROOM_CHAT),
    )
}

@Composable
private fun ControlBar(
    state: AudioRoomUiState,
    onRaiseHand: () -> Unit,
    onToggleMic: () -> Unit,
    onLeave: () -> Unit,
) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(12.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        if (state.canPublish) {
            Button(
                onClick = onToggleMic,
                modifier = Modifier.testTag(AUDIOROOM_MIC_TOGGLE),
            ) {
                Icon(
                    imageVector = if (state.micEnabled) Icons.Filled.Mic else Icons.Filled.MicOff,
                    contentDescription = null,
                    modifier = Modifier.size(18.dp),
                )
                Spacer(Modifier.width(8.dp))
                Text(if (state.micEnabled) "Mute" else "Unmute")
            }
        } else {
            Button(
                onClick = onRaiseHand,
                enabled = !state.handRaised,
                modifier = Modifier.testTag(AUDIOROOM_RAISE_HAND),
            ) {
                Text(if (state.handRaised) "Hand raised ✋" else "Raise hand ✋")
            }
        }
        Spacer(Modifier.weight(1f))
        OutlinedButton(onClick = onLeave, modifier = Modifier.testTag(AUDIOROOM_LEAVE)) {
            Text("Leave")
        }
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun SpeakerTile(
    speaker: SpeakerUi,
    hostControls: Boolean,
    onMute: () -> Unit,
    onUnmute: () -> Unit,
    onRemove: () -> Unit,
) {
    var menuOpen by remember { mutableStateOf(false) }
    val ringColor = if (speaker.isSpeaking) Color(0xFF2E7D32) else Color.Transparent
    Column(
        modifier = Modifier
            .width(84.dp)
            .padding(4.dp)
            .combinedClickable(
                onClick = {},
                onLongClick = { if (hostControls) menuOpen = true },
            )
            .testTag(AUDIOROOM_SPEAKER_TILE),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Box(contentAlignment = Alignment.Center) {
            Surface(
                shape = CircleShape,
                color = MaterialTheme.colorScheme.secondaryContainer,
                border = BorderStroke(3.dp, ringColor),
                modifier = Modifier.size(56.dp),
            ) {
                Box(contentAlignment = Alignment.Center, modifier = Modifier.fillMaxSize()) {
                    Text(
                        text = speaker.displayName.take(1).uppercase(),
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold,
                    )
                }
            }
            if (speaker.micMuted) {
                Surface(
                    shape = CircleShape,
                    color = MaterialTheme.colorScheme.errorContainer,
                    modifier = Modifier.size(20.dp).align(Alignment.BottomEnd),
                ) {
                    Icon(
                        Icons.Filled.MicOff,
                        contentDescription = "muted",
                        modifier = Modifier.padding(3.dp),
                        tint = MaterialTheme.colorScheme.onErrorContainer,
                    )
                }
            }
            DropdownMenu(expanded = menuOpen, onDismissRequest = { menuOpen = false }) {
                if (speaker.micMuted) {
                    DropdownMenuItem(text = { Text("Unmute") }, onClick = { menuOpen = false; onUnmute() })
                } else {
                    DropdownMenuItem(text = { Text("Force mute") }, onClick = { menuOpen = false; onMute() })
                }
                DropdownMenuItem(
                    text = { Text("Remove from stage") },
                    onClick = { menuOpen = false; onRemove() },
                )
            }
        }
        Text(
            text = if (speaker.isHost) "${speaker.displayName} (host)" else speaker.displayName,
            style = MaterialTheme.typography.labelSmall,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
    }
}

@Composable
private fun ConnectingState() {
    Box(
        modifier = Modifier.fillMaxWidth().padding(48.dp).wrapContentSize(Alignment.Center),
        contentAlignment = Alignment.Center,
    ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            CircularProgressIndicator()
            Spacer(Modifier.size(12.dp))
            Text("Joining the audio room…")
        }
    }
}

@Composable
private fun ErrorState(message: String, onRetry: () -> Unit) {
    Box(
        modifier = Modifier.fillMaxWidth().padding(32.dp).wrapContentSize(Alignment.Center),
        contentAlignment = Alignment.Center,
    ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Text(message, color = MaterialTheme.colorScheme.error)
            Spacer(Modifier.size(12.dp))
            Button(onClick = onRetry) { Text("Retry") }
        }
    }
}
