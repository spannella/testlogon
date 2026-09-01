@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.watchparties

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.watchparties.ParticipantRole
import com.testlogon.android.data.watchparties.WatchParty
import com.testlogon.android.data.watchparties.WatchPartyMath
import com.testlogon.android.data.watchparties.WatchPartyParticipant

/** Stable testTags for the party detail screen. */
object WatchPartyDetailTestTags {
    const val SCREEN = "watch_party_detail_screen"
    const val LOADING = "watch_party_detail_loading"
    const val ERROR = "watch_party_detail_error"
    const val OFFLINE = "watch_party_detail_offline"
    const val SESSION_EXPIRED = "watch_party_detail_session_expired"
    const val JOIN = "watch_party_detail_join"
    const val LEAVE = "watch_party_detail_leave"
    const val SYNC_CARD = "watch_party_detail_sync_card"
    const val SYNC_STATUS = "watch_party_detail_sync_status"
    const val HOST_CONTROLS = "watch_party_detail_host_controls"
    const val PLAY = "watch_party_detail_play"
    const val PAUSE = "watch_party_detail_pause"
    const val SEEK = "watch_party_detail_seek"
    const val END = "watch_party_detail_end"
    const val COHOST_PREFIX = "watch_party_detail_cohost_"
    const val KICK_PREFIX = "watch_party_detail_kick_"
}

/** Route-level party detail entry. */
@Composable
fun WatchPartyDetailRoute(
    onBack: () -> Unit,
    onSessionExpired: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: WatchPartyDetailViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    val context = LocalContext.current

    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is WatchPartyDetailEffect.ShowMessage ->
                    snackbarHostState.showSnackbar(context.getString(effect.resId))
            }
        }
    }

    LaunchedEffect(state.phase) {
        if (state.phase == WatchPartyDetailUiState.Phase.SessionExpired) onSessionExpired()
    }

    WatchPartyDetailScreen(
        state = state,
        onBack = onBack,
        onRetry = viewModel::onRetry,
        onJoin = viewModel::onJoin,
        onLeave = viewModel::onLeave,
        onPlay = viewModel::onPlay,
        onPause = viewModel::onPause,
        onSeek = viewModel::onSeek,
        onGrantCoHost = viewModel::onGrantCoHost,
        onKick = viewModel::onKick,
        onEnd = viewModel::onEnd,
        snackbarHostState = snackbarHostState,
        modifier = modifier,
    )
}

@Composable
fun WatchPartyDetailScreen(
    state: WatchPartyDetailUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onJoin: () -> Unit,
    onLeave: () -> Unit,
    onPlay: () -> Unit = {},
    onPause: () -> Unit = {},
    onSeek: (Double) -> Unit = {},
    onGrantCoHost: (String) -> Unit = {},
    onKick: (String) -> Unit = {},
    onEnd: () -> Unit = {},
    modifier: Modifier = Modifier,
    snackbarHostState: SnackbarHostState = remember { SnackbarHostState() },
) {
    Scaffold(
        modifier = modifier.testTag(WatchPartyDetailTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = {
                    Text(state.party?.displayTitle ?: stringResource(R.string.watch_parties_detail_title))
                },
                navigationIcon = {
                    IconButton(onClick = onBack, modifier = Modifier.testTag("watch_party_detail_back")) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
            )
        },
    ) { padding ->
        Box(modifier = Modifier.padding(padding).fillMaxSize()) {
            when (state.phase) {
                WatchPartyDetailUiState.Phase.Loading ->
                    LoadingState(modifier = Modifier.testTag(WatchPartyDetailTestTags.LOADING))

                WatchPartyDetailUiState.Phase.Error ->
                    ErrorState(
                        message = state.errorMessage
                            ?: stringResource(R.string.watch_parties_error_generic),
                        onRetry = onRetry,
                        modifier = Modifier.testTag(WatchPartyDetailTestTags.ERROR),
                    )

                WatchPartyDetailUiState.Phase.Offline ->
                    ErrorState(
                        message = state.errorMessage
                            ?: stringResource(R.string.watch_parties_error_generic),
                        onRetry = onRetry,
                        modifier = Modifier.testTag(WatchPartyDetailTestTags.OFFLINE),
                    )

                WatchPartyDetailUiState.Phase.SessionExpired ->
                    Text(
                        text = stringResource(R.string.watch_parties_session_expired_body),
                        modifier = Modifier.padding(24.dp).testTag(WatchPartyDetailTestTags.SESSION_EXPIRED),
                    )

                WatchPartyDetailUiState.Phase.Content ->
                    state.party?.let { party ->
                        DetailContent(
                            state = state,
                            party = party,
                            participants = state.activeParticipants,
                            isMutating = state.isMutating,
                            playbackSync = state.playbackSync,
                            onJoin = onJoin,
                            onLeave = onLeave,
                            onPlay = onPlay,
                            onPause = onPause,
                            onSeek = onSeek,
                            onGrantCoHost = onGrantCoHost,
                            onKick = onKick,
                            onEnd = onEnd,
                        )
                    }
            }
        }
    }
}

@Composable
private fun DetailContent(
    state: WatchPartyDetailUiState,
    party: WatchParty,
    participants: List<WatchPartyParticipant>,
    isMutating: Boolean,
    playbackSync: WatchPartyDetailUiState.PlaybackSyncState?,
    onJoin: () -> Unit,
    onLeave: () -> Unit,
    onPlay: () -> Unit,
    onPause: () -> Unit,
    onSeek: (Double) -> Unit,
    onGrantCoHost: (String) -> Unit,
    onKick: (String) -> Unit,
    onEnd: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        // Header: title + video + status
        Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text(
                    text = party.displayTitle,
                    style = MaterialTheme.typography.headlineSmall,
                    fontWeight = FontWeight.SemiBold,
                    modifier = Modifier.weight(1f),
                )
                AssistChip(onClick = {}, label = { Text(statusLabel(party.status)) })
            }
            if (party.videoTitle.isNotBlank()) {
                Text(
                    text = party.videoTitle,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }

        // Live playback sync (ENGAGE-004): the host-authoritative state reconciled from the realtime
        // event stream (/messaging/events/poll). Falls back to a "waiting for host" note until the
        // first frame arrives. The extrapolated position advances while the host is playing.
        Card(modifier = Modifier.fillMaxWidth().testTag(WatchPartyDetailTestTags.SYNC_CARD)) {
            Column(
                modifier = Modifier.fillMaxWidth().padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                Text(
                    text = stringResource(R.string.watch_parties_detail_sync_live_title),
                    style = MaterialTheme.typography.titleSmall,
                )
                val nowSeconds = System.currentTimeMillis() / 1000L
                val syncBody = when {
                    playbackSync == null ->
                        stringResource(R.string.watch_parties_detail_sync_waiting)
                    playbackSync.isPlaying -> stringResource(
                        R.string.watch_parties_detail_sync_playing,
                        formatClock(playbackSync.targetPositionSeconds(nowSeconds)),
                    )
                    else -> stringResource(
                        R.string.watch_parties_detail_sync_paused,
                        formatClock(playbackSync.positionSeconds),
                    )
                }
                Text(
                    text = syncBody,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.testTag(WatchPartyDetailTestTags.SYNC_STATUS),
                )
            }
        }

        // Host controls (v2): only visible to a driver (host / active co-host). Playback transport for
        // anyone who can control; grant-co-host / kick / end are host-only (gated in the VM too).
        if (state.canControlPlayback) {
            val nowSeconds = System.currentTimeMillis() / 1000L
            val currentPos = playbackSync?.targetPositionSeconds(nowSeconds)
                ?: party.positionSeconds.toDouble()
            HostControlsCard(
                isPlaying = playbackSync?.isPlaying == true,
                isControlling = state.isControlling,
                canManage = state.canManageParty,
                currentPositionSeconds = currentPos,
                onPlay = onPlay,
                onPause = onPause,
                onSeek = onSeek,
                onEnd = onEnd,
            )
        }

        // Info card
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier = Modifier.fillMaxWidth().padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                InfoRow(
                    label = stringResource(R.string.watch_parties_detail_participants_label),
                    value = stringResource(
                        R.string.watch_parties_participants_count,
                        party.participantCount,
                        party.maxParticipants,
                    ),
                )
                if (party.inviteCode.isNotBlank()) {
                    InfoRow(
                        label = stringResource(R.string.watch_parties_detail_invite_label),
                        value = party.inviteCode,
                    )
                }
                party.formattedCreated().takeIf { it.isNotBlank() }?.let {
                    InfoRow(
                        label = stringResource(R.string.watch_parties_detail_created_label),
                        value = it,
                    )
                }
            }
        }

        // Participants
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier = Modifier.fillMaxWidth().padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text(
                    text = stringResource(R.string.watch_parties_detail_participants_header),
                    style = MaterialTheme.typography.titleSmall,
                )
                if (participants.isEmpty()) {
                    Text(
                        text = stringResource(R.string.watch_parties_detail_participants_empty),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                } else {
                    participants.forEachIndexed { index, p ->
                        if (index > 0) HorizontalDivider()
                        Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(8.dp),
                            ) {
                                Text(
                                    text = p.userSub,
                                    style = MaterialTheme.typography.bodyMedium,
                                    modifier = Modifier.weight(1f),
                                )
                                Text(
                                    text = roleLabel(p.role),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                            // Host-only moderation for this participant.
                            if (state.canManageParty && WatchPartyMath.canTargetParticipant(party, state.currentUserSub, p)) {
                                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                    if (state.canPromote(p)) {
                                        OutlinedButton(
                                            onClick = { onGrantCoHost(p.userSub) },
                                            enabled = !state.isControlling,
                                            modifier = Modifier.testTag(WatchPartyDetailTestTags.COHOST_PREFIX + p.userSub),
                                        ) {
                                            Text(stringResource(R.string.watch_parties_action_make_cohost))
                                        }
                                    }
                                    OutlinedButton(
                                        onClick = { onKick(p.userSub) },
                                        enabled = !state.isControlling,
                                        modifier = Modifier.testTag(WatchPartyDetailTestTags.KICK_PREFIX + p.userSub),
                                    ) {
                                        Text(stringResource(R.string.watch_parties_action_kick))
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Actions (Join / Leave) - hidden once the party has ended.
        if (!party.isEnded) {
            Button(
                onClick = onJoin,
                enabled = !isMutating,
                modifier = Modifier.fillMaxWidth().testTag(WatchPartyDetailTestTags.JOIN),
            ) {
                Text(stringResource(R.string.watch_parties_detail_join_action))
            }
            OutlinedButton(
                onClick = onLeave,
                enabled = !isMutating,
                modifier = Modifier.fillMaxWidth().testTag(WatchPartyDetailTestTags.LEAVE),
            ) {
                Text(stringResource(R.string.watch_parties_detail_leave_action))
            }
        } else {
            Text(
                text = stringResource(R.string.watch_parties_detail_ended_note),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

/** Host / co-host playback transport + (host-only) End. Gated by the caller. */
@Composable
private fun HostControlsCard(
    isPlaying: Boolean,
    isControlling: Boolean,
    canManage: Boolean,
    currentPositionSeconds: Double,
    onPlay: () -> Unit,
    onPause: () -> Unit,
    onSeek: (Double) -> Unit,
    onEnd: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth().testTag(WatchPartyDetailTestTags.HOST_CONTROLS)) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(
                text = stringResource(R.string.watch_parties_detail_host_controls_title),
                style = MaterialTheme.typography.titleSmall,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(
                    onClick = { onSeek((currentPositionSeconds - SEEK_STEP_SECONDS).coerceAtLeast(0.0)) },
                    enabled = !isControlling,
                    modifier = Modifier.testTag(WatchPartyDetailTestTags.SEEK + "_back"),
                ) {
                    Text(stringResource(R.string.watch_parties_action_seek_back))
                }
                if (isPlaying) {
                    Button(
                        onClick = onPause,
                        enabled = !isControlling,
                        modifier = Modifier.weight(1f).testTag(WatchPartyDetailTestTags.PAUSE),
                    ) {
                        Text(stringResource(R.string.watch_parties_action_pause))
                    }
                } else {
                    Button(
                        onClick = onPlay,
                        enabled = !isControlling,
                        modifier = Modifier.weight(1f).testTag(WatchPartyDetailTestTags.PLAY),
                    ) {
                        Text(stringResource(R.string.watch_parties_action_play))
                    }
                }
                OutlinedButton(
                    onClick = { onSeek(currentPositionSeconds + SEEK_STEP_SECONDS) },
                    enabled = !isControlling,
                    modifier = Modifier.testTag(WatchPartyDetailTestTags.SEEK + "_fwd"),
                ) {
                    Text(stringResource(R.string.watch_parties_action_seek_forward))
                }
            }
            if (canManage) {
                OutlinedButton(
                    onClick = onEnd,
                    enabled = !isControlling,
                    modifier = Modifier.fillMaxWidth().testTag(WatchPartyDetailTestTags.END),
                ) {
                    Text(stringResource(R.string.watch_parties_action_end))
                }
            }
        }
    }
}

private const val SEEK_STEP_SECONDS = 10.0

@Composable
private fun InfoRow(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.weight(1f),
        )
        Text(
            text = value,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurface,
        )
    }
}

@Composable
private fun roleLabel(role: ParticipantRole): String = stringResource(
    when (role) {
        ParticipantRole.HOST -> R.string.watch_parties_role_host
        ParticipantRole.CO_HOST -> R.string.watch_parties_role_cohost
        ParticipantRole.MEMBER -> R.string.watch_parties_role_member
    },
)

/** Format a position in seconds as mm:ss (or h:mm:ss past an hour) for the live-sync status line. */
private fun formatClock(seconds: Double): String {
    val total = seconds.toLong().coerceAtLeast(0L)
    val h = total / 3600
    val m = (total % 3600) / 60
    val sec = total % 60
    return if (h > 0) "%d:%02d:%02d".format(h, m, sec) else "%d:%02d".format(m, sec)
}
