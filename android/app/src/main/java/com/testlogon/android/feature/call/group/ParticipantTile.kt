package com.testlogon.android.feature.call.group

import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.MicOff
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.SignalCellularAlt
import androidx.compose.material.icons.filled.SignalCellularOff
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.testlogon.android.R
import com.testlogon.android.core.webrtc.ui.LocalVideoPreview
import com.testlogon.android.core.webrtc.ui.RemoteVideoView
import com.testlogon.android.data.call.group.ConnQuality
import com.testlogon.android.data.call.group.GroupParticipant

/**
 * AND-299 — a single participant tile in the group-call grid.
 *
 * Renders the (FLAGGED) local/remote video placeholder when the camera is on, or an avatar/initials
 * placeholder when off. Overlays the (truncated) display name, a mic-muted glyph, a connection-quality
 * glyph, and a "speaking" border when [isActiveSpeaker]. Every labeled element carries a contentDescription.
 * Media is FLAGGED — these placeholders never host a real SurfaceViewRenderer.
 */
@Composable
fun ParticipantTile(
    participant: GroupParticipant,
    isActiveSpeaker: Boolean,
    modifier: Modifier = Modifier,
) {
    val name = participant.displayName ?: stringResource(R.string.call_unknown_caller)
    val speakingBorder = if (isActiveSpeaker) {
        Modifier.border(
            width = 3.dp,
            color = MaterialTheme.colorScheme.primary,
            shape = RoundedCornerShape(12.dp),
        )
    } else {
        Modifier
    }

    Surface(
        modifier = modifier
            .testTag(TAG_TILE)
            .aspectRatio(1f)
            .padding(4.dp)
            .then(speakingBorder),
        shape = RoundedCornerShape(12.dp),
        color = MaterialTheme.colorScheme.surfaceVariant,
    ) {
        Box(modifier = Modifier.fillMaxSize()) {
            if (participant.cameraOff) {
                AvatarPlaceholder(name = name)
            } else if (participant.isSelf) {
                LocalVideoPreview(modifier = Modifier.fillMaxSize(), hasTrack = false)
            } else {
                RemoteVideoView(modifier = Modifier.fillMaxSize(), hasTrack = false)
            }

            // Bottom overlay row: mic glyph + name + quality glyph.
            Row(
                modifier = Modifier
                    .align(Alignment.BottomStart)
                    .fillMaxWidth()
                    .padding(horizontal = 8.dp, vertical = 6.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                if (participant.micMuted) {
                    Icon(
                        imageVector = Icons.Filled.MicOff,
                        contentDescription = stringResource(R.string.participant_muted_cd, name),
                        modifier = Modifier.size(16.dp),
                        tint = MaterialTheme.colorScheme.error,
                    )
                }
                Text(
                    text = name,
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f),
                )
                QualityGlyph(quality = participant.quality, name = name)
            }
        }
    }
}

@Composable
private fun AvatarPlaceholder(name: String) {
    Box(
        modifier = Modifier
            .fillMaxSize()
            .semantics { contentDescription = name },
        contentAlignment = Alignment.Center,
    ) {
        Icon(
            imageVector = Icons.Filled.Person,
            contentDescription = null,
            modifier = Modifier.size(48.dp),
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun QualityGlyph(quality: ConnQuality, name: String) {
    val icon: ImageVector? = when (quality) {
        ConnQuality.Good, ConnQuality.Fair -> Icons.Filled.SignalCellularAlt
        ConnQuality.Poor -> Icons.Filled.SignalCellularOff
        ConnQuality.Unknown -> null
    }
    val cd = when (quality) {
        ConnQuality.Good -> stringResource(R.string.call_quality_good)
        ConnQuality.Fair -> stringResource(R.string.call_quality_good)
        ConnQuality.Poor -> stringResource(R.string.call_quality_poor)
        ConnQuality.Unknown -> null
    }
    if (icon == null || cd == null) return
    Icon(
        imageVector = icon,
        contentDescription = cd,
        modifier = Modifier.size(16.dp),
        tint = MaterialTheme.colorScheme.onSurfaceVariant,
    )
}

const val TAG_TILE = "participant_tile"
