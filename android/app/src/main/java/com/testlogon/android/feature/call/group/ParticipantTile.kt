package com.testlogon.android.feature.call.group

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.border
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.sizeIn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.GraphicEq
import androidx.compose.material.icons.filled.MicOff
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.SignalCellularAlt
import androidx.compose.material.icons.filled.SignalCellularOff
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.CustomAccessibilityAction
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.customActions
import androidx.compose.ui.semantics.onClick
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.testlogon.android.R
import com.testlogon.android.core.webrtc.ui.LocalVideoPreview
import com.testlogon.android.core.webrtc.ui.RemoteVideoView
import com.testlogon.android.data.call.group.ConnQuality
import com.testlogon.android.data.call.group.GroupParticipant
import com.testlogon.android.data.call.group.ParticipantState

/**
 * AND-299 / AND-300 — a single participant tile in the group-call grid / filmstrip.
 *
 * Renders the (FLAGGED) local/remote video placeholder when the camera is on, or an avatar placeholder when
 * off; media is FLAGGED so a real track never attaches (always the placeholder/avatar). Overlays the
 * (truncated) display name, a mic-muted glyph, and a connection-quality glyph.
 *
 * AND-300 additions:
 *  - Active-speaker indication that is NOT color-only when [isActiveSpeaker]: a 2dp border AND a "speaking"
 *    [Icons.Filled.GraphicEq] glyph.
 *  - Long-press to pin ([combinedClickable]: onLongClick -> [onPin]); when already [isPinned] a tap
 *    ([onUnpin]) removes the pin.
 *  - RECONNECTING / failed (LOST) tiles are dimmed with a spinner overlay.
 *  - Merged semantics: a single contentDescription "<name>, <muted|unmuted>, <speaking?>" plus a custom
 *    pin/unpin accessibility action and an onClick action (so the node stays findable after
 *    [clearAndSetSemantics]); 48dp minimum target.
 */
@OptIn(ExperimentalFoundationApi::class)
@Composable
fun ParticipantTile(
    participant: GroupParticipant,
    isActiveSpeaker: Boolean,
    isPinned: Boolean,
    onPin: (String) -> Unit,
    onUnpin: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val name = participant.displayName ?: stringResource(R.string.call_unknown_caller)
    val isReconnecting = participant.state == ParticipantState.Reconnecting ||
        participant.state == ParticipantState.Failed

    val speakingBorder = if (isActiveSpeaker) {
        Modifier.border(
            width = 2.dp,
            color = MaterialTheme.colorScheme.primary,
            shape = RoundedCornerShape(12.dp),
        )
    } else {
        Modifier
    }

    // Merged a11y label + custom action. We use semantics(mergeDescendants = true) rather than
    // clearAndSetSemantics so the inner glyph/spinner testTags survive in the unmerged tree (the screen
    // tests find them with useUnmergedTree = true); the child glyphs carry no contentDescription so they do
    // not pollute the merged label. testTag is placed FIRST and an onClick action keeps the node actionable.
    val mutedLabel = stringResource(
        if (participant.micMuted) R.string.participant_muted_cd else R.string.call_unmute_cd,
        name,
    )
    val speakingLabel = if (isActiveSpeaker) stringResource(R.string.participant_speaking_cd, name) else null
    val mergedCd = listOfNotNull(name, mutedLabel, speakingLabel).joinToString(", ")
    val pinActionLabel = if (isPinned) {
        stringResource(R.string.group_call_unpin_cd, name)
    } else {
        stringResource(R.string.group_call_pin_cd, name)
    }

    Surface(
        modifier = modifier
            .testTag(TAG_TILE)
            .sizeIn(minWidth = 48.dp, minHeight = 48.dp)
            .aspectRatio(1f)
            .padding(4.dp)
            .then(speakingBorder)
            .combinedClickable(
                onClick = { if (isPinned) onUnpin() },
                onLongClick = { onPin(participant.userId) },
            )
            .semantics(mergeDescendants = true) {
                contentDescription = mergedCd
                onClick(label = pinActionLabel) {
                    if (isPinned) onUnpin() else onPin(participant.userId)
                    true
                }
                customActions = listOf(
                    CustomAccessibilityAction(label = pinActionLabel) {
                        if (isPinned) onUnpin() else onPin(participant.userId)
                        true
                    },
                )
            },
        shape = RoundedCornerShape(12.dp),
        color = MaterialTheme.colorScheme.surfaceVariant,
    ) {
        Box(modifier = Modifier.fillMaxSize()) {
            Box(modifier = Modifier.fillMaxSize().alpha(if (isReconnecting) 0.4f else 1f)) {
                if (participant.cameraOff) {
                    AvatarPlaceholder(name = name)
                } else if (participant.isSelf) {
                    LocalVideoPreview(modifier = Modifier.fillMaxSize(), hasTrack = false)
                } else {
                    RemoteVideoView(modifier = Modifier.fillMaxSize(), hasTrack = false)
                }
            }

            if (isReconnecting) {
                CircularProgressIndicator(
                    modifier = Modifier
                        .align(Alignment.Center)
                        .size(32.dp)
                        .testTag(TAG_RECONNECTING),
                )
            }

            // Top-end speaking glyph (non-color-only active-speaker cue, paired with the border).
            if (isActiveSpeaker) {
                Icon(
                    imageVector = Icons.Filled.GraphicEq,
                    contentDescription = null,
                    modifier = Modifier
                        .align(Alignment.TopEnd)
                        .padding(6.dp)
                        .size(18.dp)
                        .testTag(TAG_SPEAKING),
                    tint = MaterialTheme.colorScheme.primary,
                )
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
                        contentDescription = null,
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
                QualityGlyph(quality = participant.quality)
            }
        }
    }
}

@Composable
private fun AvatarPlaceholder(name: String) {
    Box(
        modifier = Modifier.fillMaxSize(),
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
private fun QualityGlyph(quality: ConnQuality) {
    val icon: ImageVector? = when (quality) {
        ConnQuality.Good, ConnQuality.Fair -> Icons.Filled.SignalCellularAlt
        ConnQuality.Poor -> Icons.Filled.SignalCellularOff
        ConnQuality.Unknown -> null
    }
    if (icon == null) return
    Icon(
        imageVector = icon,
        contentDescription = null,
        modifier = Modifier.size(16.dp),
        tint = MaterialTheme.colorScheme.onSurfaceVariant,
    )
}

const val TAG_TILE = "participant_tile"
const val TAG_SPEAKING = "participant_speaking"
const val TAG_RECONNECTING = "participant_reconnecting"
