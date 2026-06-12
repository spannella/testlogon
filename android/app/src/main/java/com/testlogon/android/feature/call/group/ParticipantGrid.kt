package com.testlogon.android.feature.call.group

import android.content.res.Configuration
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import com.testlogon.android.data.call.group.GroupParticipant

/**
 * AND-299 — the participant grid.
 *
 * Column count is derived from the pure [GridLayoutPolicy] (orientation read from [LocalConfiguration]);
 * each cell is a [ParticipantTile] keyed by userId. The grid scrolls naturally when participants overflow
 * (LazyVerticalGrid), which covers the policy's scrollable breakpoints.
 */
@Composable
fun ParticipantGrid(
    participants: List<GroupParticipant>,
    activeSpeakerUserId: String?,
    modifier: Modifier = Modifier,
) {
    val configuration = LocalConfiguration.current
    val orientation = if (configuration.orientation == Configuration.ORIENTATION_LANDSCAPE) {
        GridOrientation.Landscape
    } else {
        GridOrientation.Portrait
    }
    val spec = GridLayoutPolicy.spec(participants.size, orientation)

    LazyVerticalGrid(
        columns = GridCells.Fixed(spec.columns),
        modifier = modifier
            .fillMaxSize()
            .testTag("groupcall_grid")
            .padding(4.dp),
    ) {
        items(items = participants, key = { it.userId }) { participant ->
            ParticipantTile(
                participant = participant,
                isActiveSpeaker = participant.userId == activeSpeakerUserId,
            )
        }
    }
}
