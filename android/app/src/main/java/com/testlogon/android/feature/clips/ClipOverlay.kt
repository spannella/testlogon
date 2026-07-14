package com.testlogon.android.feature.clips

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Bookmark
import androidx.compose.material.icons.filled.FavoriteBorder
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.VolumeOff
import androidx.compose.material.icons.filled.VolumeUp
import androidx.compose.material.icons.outlined.BookmarkBorder
import androidx.compose.material.icons.outlined.ChatBubbleOutline
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.testlogon.android.R
import com.testlogon.android.data.clips.Clip

/** AND-196 — stable test tags for the clips overlay chrome. */
object ClipOverlayTestTags {
    const val OVERLAY = "clip_overlay"
    const val AUTHOR = "clip_overlay_author"
    const val TITLE = "clip_overlay_title"
    const val LIKE = "clip_overlay_like"
    const val COMMENT = "clip_overlay_comment"
    const val SHARE = "clip_overlay_share"
    const val BOOKMARK = "clip_overlay_bookmark"
    const val MUTE = "clip_overlay_mute"
}

/** AND-196 — the social actions surfaced on a clip; behavior is delegated to feed-interaction tickets. */
enum class ClipAction { LIKE, COMMENT, SHARE, BOOKMARK, AUTHOR, MUTE }

/**
 * AND-196 — overlay chrome over a clip page: author handle (tap -> public profile), caption/title,
 * an action rail (like/comment/share/bookmark) that delegates to the feed-interaction flows, and a
 * mute toggle local to the viewer. Touch pass-through is NOT needed — the player surface sits below.
 *
 * P0-consumer/bookmarks: [bookmarked] fills the bookmark icon when the clip's source video is saved.
 */
@Composable
fun ClipOverlay(
    clip: Clip,
    muted: Boolean,
    bookmarked: Boolean,
    onAction: (ClipAction) -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(12.dp)
            .testTag(ClipOverlayTestTags.OVERLAY),
        verticalArrangement = Arrangement.Bottom,
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.Bottom,
        ) {
            // Caption column (author + title), bottom-start.
            Column(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                val author = clip.broadcasterDisplayName.ifBlank { clip.creatorDisplayName }
                if (author.isNotBlank()) {
                    Text(
                        text = "@$author",
                        color = Color.White,
                        style = MaterialTheme.typography.titleSmall,
                        modifier = Modifier
                            .testTag(ClipOverlayTestTags.AUTHOR)
                            .clickable { onAction(ClipAction.AUTHOR) }
                            .semantics { role = Role.Button; contentDescription = author }
                            .background(Color.Black.copy(alpha = 0.4f))
                            .padding(horizontal = 6.dp, vertical = 2.dp),
                    )
                }
                if (clip.title.isNotBlank()) {
                    Text(
                        text = clip.title,
                        color = Color.White,
                        style = MaterialTheme.typography.bodyMedium,
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier
                            .testTag(ClipOverlayTestTags.TITLE)
                            .background(Color.Black.copy(alpha = 0.4f))
                            .padding(horizontal = 6.dp, vertical = 2.dp),
                    )
                }
            }

            // Action rail, bottom-end.
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                RailButton(
                    icon = Icons.Filled.FavoriteBorder,
                    label = stringResource(R.string.clip_action_like),
                    tag = ClipOverlayTestTags.LIKE,
                    onClick = { onAction(ClipAction.LIKE) },
                )
                RailButton(
                    icon = Icons.Outlined.ChatBubbleOutline,
                    label = stringResource(R.string.clip_action_comment),
                    tag = ClipOverlayTestTags.COMMENT,
                    onClick = { onAction(ClipAction.COMMENT) },
                )
                RailButton(
                    icon = Icons.Filled.Share,
                    label = stringResource(R.string.clip_action_share),
                    tag = ClipOverlayTestTags.SHARE,
                    onClick = { onAction(ClipAction.SHARE) },
                )
                RailButton(
                    icon = if (bookmarked) Icons.Filled.Bookmark else Icons.Outlined.BookmarkBorder,
                    label = if (bookmarked) {
                        stringResource(R.string.clip_action_bookmark_remove)
                    } else {
                        stringResource(R.string.clip_action_bookmark)
                    },
                    tag = ClipOverlayTestTags.BOOKMARK,
                    onClick = { onAction(ClipAction.BOOKMARK) },
                )
                RailButton(
                    icon = if (muted) Icons.Filled.VolumeOff else Icons.Filled.VolumeUp,
                    label = if (muted) {
                        stringResource(R.string.clip_action_unmute)
                    } else {
                        stringResource(R.string.clip_action_mute)
                    },
                    tag = ClipOverlayTestTags.MUTE,
                    onClick = { onAction(ClipAction.MUTE) },
                )
            }
        }
    }
}

@Composable
private fun RailButton(
    icon: ImageVector,
    label: String,
    tag: String,
    onClick: () -> Unit,
) {
    IconButton(
        onClick = onClick,
        modifier = Modifier.testTag(tag),
    ) {
        Icon(
            imageVector = icon,
            contentDescription = label,
            tint = Color.White,
            modifier = Modifier.semantics { role = Role.Button; contentDescription = label },
        )
    }
}
