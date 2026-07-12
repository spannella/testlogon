package com.testlogon.android.feature.broadcast.audioroom

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Mic
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.ViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import com.testlogon.android.data.broadcast.BroadcastApi
import com.testlogon.android.navigation.HOST_BROADCAST_PROFILE_ID
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject
import com.testlogon.android.core.model.ApiResult

const val AUDIOROOM_DISCOVERY = "audioroom_discovery"
const val AUDIOROOM_START = "audioroom_start"
const val AUDIOROOM_DISCOVERY_ROW = "audioroom_discovery_row"

/** A live audio-room row for the discovery strip. */
data class AudioRoomListItem(val sessionId: String, val title: String, val host: String?)

data class AudioRoomDiscoveryState(
    val loading: Boolean = false,
    val rooms: List<AudioRoomListItem> = emptyList(),
    val creating: Boolean = false,
)

/**
 * #104 — a self-contained discovery + start VM for the browse "Live" tab. Kept OUT of the tested video
 * [BroadcastBrowseViewModel] so it adds ZERO blast radius to the existing broadcast/video flows: it lists
 * audio rooms via GET broadcast/live?mode=audio_room and creates a new mode=audio_room session on Start.
 */
@HiltViewModel
class AudioRoomDiscoveryViewModel @Inject constructor(
    private val broadcastApi: BroadcastApi,
    private val repo: AudioRoomRepository,
) : ViewModel() {

    private val _state = MutableStateFlow(AudioRoomDiscoveryState())
    val state: StateFlow<AudioRoomDiscoveryState> = _state.asStateFlow()

    init { refresh() }

    fun refresh() {
        _state.update { it.copy(loading = true) }
        viewModelScope.launch {
            val rooms = try {
                broadcastApi.listLiveSessions(limit = 50, mode = "audio_room").items.map {
                    AudioRoomListItem(
                        sessionId = it.id,
                        title = it.name?.takeIf { n -> n.isNotBlank() } ?: "Audio room",
                        host = it.createdBy.takeIf { h -> h.isNotBlank() },
                    )
                }
            } catch (e: Exception) {
                emptyList()
            }
            _state.update { it.copy(loading = false, rooms = rooms) }
        }
    }

    /** Create a new audio room (mode=audio_room) and, on success, hand the sessionId to [onCreated]. */
    fun startAudioRoom(onCreated: (String) -> Unit) {
        if (_state.value.creating) return
        _state.update { it.copy(creating = true) }
        viewModelScope.launch {
            val result = repo.createAudioRoom(HOST_BROADCAST_PROFILE_ID)
            _state.update { it.copy(creating = false) }
            if (result is ApiResult.Success) onCreated(result.data)
        }
    }
}

/**
 * #104 — the audio-rooms strip rendered at the top of the browse Live tab: a "Start audio room" action +
 * the currently-live audio rooms (distinct mic icon/label vs the video sessions below).
 */
@Composable
fun AudioRoomDiscoverySection(
    onOpenAudioRoom: (String) -> Unit,
    modifier: Modifier = Modifier,
    viewModel: AudioRoomDiscoveryViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    Column(modifier = modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp).testTag(AUDIOROOM_DISCOVERY)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Filled.Mic, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
            Spacer(Modifier.width(8.dp))
            Text("Audio rooms", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
            Spacer(Modifier.width(12.dp))
            if (state.creating) {
                CircularProgressIndicator(modifier = Modifier.width(18.dp))
            } else {
                OutlinedButton(
                    onClick = { viewModel.startAudioRoom(onOpenAudioRoom) },
                    modifier = Modifier.testTag(AUDIOROOM_START),
                ) { Text("Start audio room") }
            }
        }
        Spacer(Modifier.width(8.dp))
        state.rooms.forEach { room ->
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 8.dp)
                    .clickable { onOpenAudioRoom(room.sessionId) }
                    .testTag(AUDIOROOM_DISCOVERY_ROW),
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth().padding(12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Icon(Icons.Filled.Mic, contentDescription = null)
                    Column(modifier = Modifier.fillMaxWidth()) {
                        Text(room.title, fontWeight = FontWeight.SemiBold)
                        if (room.host != null) {
                            Text(
                                room.host,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                }
            }
        }
    }
}
