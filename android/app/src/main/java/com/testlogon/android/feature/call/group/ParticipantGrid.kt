package com.testlogon.android.feature.call.group

import android.content.res.Configuration
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.testlogon.android.R
import com.testlogon.android.data.call.group.GroupParticipant

/**
 * AND-299 / AND-300 — the participant grid.
 *
 * Renders two modes, driven by [pinnedUserId]:
 *  - GRID (pinnedUserId == null): a [LazyVerticalGrid] whose column count comes from the pure
 *    [GridLayoutPolicy] (orientation read from [LocalConfiguration]); tiles are ordered by
 *    [GridLayoutPolicy.order] and keyed by userId.
 *  - PINNED / FOCUS (pinnedUserId != null): the pinned participant fills a large focus area (top ~70% in
 *    portrait / start ~70% in landscape) with the rest in a scrollable FILMSTRIP (LazyRow portrait /
 *    LazyColumn landscape), keyed by userId.
 *
 * Edge state: when only the self/local tile is present (no remote peers) the AND-299
 * `group_call_waiting` copy is shown full-bleed (testTag `groupcall_waiting`). [activeSpeakerUserId] +
 * [onPin]/[onUnpin] are forwarded to each [ParticipantTile].
 */
@Composable
fun ParticipantGrid(
    participants: List<GroupParticipant>,
    activeSpeakerUserId: String?,
    pinnedUserId: String?,
    onPin: (String) -> Unit,
    onUnpin: () -> Unit,
    modifier: Modifier = Modifier,
) {
    // 0-remote edge state: only the self tile (or nobody) is present -> show the waiting banner full-bleed.
    val remoteCount = participants.count { !it.isSelf }
    if (remoteCount == 0) {
        WaitingForOthers(modifier = modifier.fillMaxSize())
        return
    }

    val configuration = LocalConfiguration.current
    val isLandscape = configuration.orientation == Configuration.ORIENTATION_LANDSCAPE
    val orientation = if (isLandscape) GridOrientation.Landscape else GridOrientation.Portrait

    val ordered = GridLayoutPolicy.order(
        participants = participants,
        pinnedUserId = pinnedUserId,
        activeSpeakerUserId = activeSpeakerUserId,
    )
    val pinned = pinnedUserId?.let { id -> ordered.firstOrNull { it.userId == id } }

    if (pinned == null) {
        GridMode(
            ordered = ordered,
            orientation = orientation,
            activeSpeakerUserId = activeSpeakerUserId,
            onPin = onPin,
            onUnpin = onUnpin,
            modifier = modifier,
        )
    } else {
        FocusMode(
            pinned = pinned,
            others = ordered.filterNot { it.userId == pinned.userId },
            isLandscape = isLandscape,
            activeSpeakerUserId = activeSpeakerUserId,
            onPin = onPin,
            onUnpin = onUnpin,
            modifier = modifier,
        )
    }
}

@Composable
private fun GridMode(
    ordered: List<GroupParticipant>,
    orientation: GridOrientation,
    activeSpeakerUserId: String?,
    onPin: (String) -> Unit,
    onUnpin: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val spec = GridLayoutPolicy.spec(ordered.size, orientation)
    LazyVerticalGrid(
        columns = GridCells.Fixed(spec.columns),
        modifier = modifier
            .fillMaxSize()
            .testTag("groupcall_grid")
            .padding(4.dp),
    ) {
        items(items = ordered, key = { it.userId }) { participant ->
            ParticipantTile(
                participant = participant,
                isActiveSpeaker = participant.userId == activeSpeakerUserId,
                isPinned = false,
                onPin = onPin,
                onUnpin = onUnpin,
            )
        }
    }
}

@Composable
private fun FocusMode(
    pinned: GroupParticipant,
    others: List<GroupParticipant>,
    isLandscape: Boolean,
    activeSpeakerUserId: String?,
    onPin: (String) -> Unit,
    onUnpin: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val focusTile: @Composable (Modifier) -> Unit = { focusModifier ->
        Box(modifier = focusModifier.testTag("groupcall_focus")) {
            ParticipantTile(
                participant = pinned,
                isActiveSpeaker = pinned.userId == activeSpeakerUserId,
                isPinned = true,
                onPin = onPin,
                onUnpin = onUnpin,
                modifier = Modifier.fillMaxSize(),
            )
        }
    }

    val filmstripTile: @Composable (GroupParticipant) -> Unit = { participant ->
        Box(
            modifier = if (isLandscape) Modifier.height(120.dp) else Modifier.width(120.dp),
        ) {
            ParticipantTile(
                participant = participant,
                isActiveSpeaker = participant.userId == activeSpeakerUserId,
                isPinned = false,
                onPin = onPin,
                onUnpin = onUnpin,
            )
        }
    }

    if (isLandscape) {
        Row(modifier = modifier.fillMaxSize()) {
            focusTile(Modifier.weight(0.7f).fillMaxHeight())
            LazyColumn(
                modifier = Modifier
                    .weight(0.3f)
                    .fillMaxHeight()
                    .testTag("groupcall_filmstrip"),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                items(items = others, key = { it.userId }) { filmstripTile(it) }
            }
        }
    } else {
        Column(modifier = modifier.fillMaxSize()) {
            focusTile(Modifier.weight(0.7f).fillMaxWidth())
            LazyRow(
                modifier = Modifier
                    .weight(0.3f)
                    .fillMaxWidth()
                    .testTag("groupcall_filmstrip"),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                items(items = others, key = { it.userId }) { filmstripTile(it) }
            }
        }
    }
}

@Composable
private fun WaitingForOthers(modifier: Modifier = Modifier) {
    Box(
        modifier = modifier.testTag("groupcall_waiting"),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            text = stringResource(R.string.group_call_waiting),
            style = MaterialTheme.typography.titleMedium,
            color = MaterialTheme.colorScheme.onSurface,
        )
    }
}
