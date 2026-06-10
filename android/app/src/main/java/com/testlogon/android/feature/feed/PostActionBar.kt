package com.testlogon.android.feature.feed

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Favorite
import androidx.compose.material.icons.outlined.ChatBubbleOutline
import androidx.compose.material.icons.outlined.FavoriteBorder
import androidx.compose.material.icons.outlined.MoreVert
import androidx.compose.material.icons.outlined.ThumbDownOffAlt
import androidx.compose.material.icons.outlined.VisibilityOff
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.unit.dp
import com.testlogon.android.R

/** Stable test tags for the post action bar (AND-173 / AND-174 / AND-175). */
object PostActionTestTags {
    const val LIKE = "post_like"
    const val COMMENT = "post_comment"
    const val OVERFLOW = "post_overflow"
    const val MENU_HIDE = "post_menu_hide"
    const val MENU_NOT_INTERESTED = "post_menu_not_interested"
}

/**
 * AND-173 / AND-174 / AND-175 — the like + comment + overflow action row beneath a post's content.
 *
 * Like is optimistic and never disabled (AND-173 FR-3). The comment control shows the count and routes
 * to the comments surface. The overflow menu hosts Hide / Not interested (AND-175). All copy is from
 * strings.xml; the like control exposes role + state/content descriptions for TalkBack.
 */
@Composable
fun PostActionBar(
    liked: Boolean,
    likeCount: Int,
    commentCount: Int,
    onLikeToggle: () -> Unit,
    onCommentClick: () -> Unit,
    onHide: () -> Unit,
    onNotInterested: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Row(
        modifier = modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        LikeButton(liked = liked, likeCount = likeCount, onToggle = onLikeToggle)
        CommentButton(commentCount = commentCount, onClick = onCommentClick)
        Box(modifier = Modifier.weight(1f))
        PostOverflowMenu(onHide = onHide, onNotInterested = onNotInterested)
    }
}

@Composable
fun LikeButton(
    liked: Boolean,
    likeCount: Int,
    onToggle: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val tint by animateColorAsState(
        targetValue = if (liked) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
        label = "likeTint",
    )
    val scale by animateFloatAsState(targetValue = if (liked) 1.15f else 1f, label = "likeScale")
    val icon: ImageVector = if (liked) Icons.Filled.Favorite else Icons.Outlined.FavoriteBorder
    val action = stringResource(if (liked) R.string.feed_unlike else R.string.feed_like)
    val state = stringResource(if (liked) R.string.feed_liked_state else R.string.feed_not_liked_state)
    val countDesc = pluralStringResource(R.plurals.feed_like_count_desc, likeCount, action, likeCount)

    Row(
        modifier = modifier
            .clearAndSetSemantics {
                role = Role.Button
                stateDescription = state
                contentDescription = countDesc
            }
            .testTag(PostActionTestTags.LIKE),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        IconButton(onClick = onToggle, modifier = Modifier.size(48.dp)) {
            Icon(imageVector = icon, contentDescription = null, tint = tint, modifier = Modifier.scale(scale))
        }
        if (likeCount > 0) {
            Text(
                text = compactCount(likeCount),
                style = MaterialTheme.typography.labelLarge,
                color = tint,
            )
        }
    }
}

@Composable
private fun CommentButton(commentCount: Int, onClick: () -> Unit, modifier: Modifier = Modifier) {
    val countDesc = pluralStringResource(R.plurals.feed_comment_count, commentCount, commentCount)
    Row(
        modifier = modifier
            .clearAndSetSemantics {
                role = Role.Button
                contentDescription = countDesc
            }
            .testTag(PostActionTestTags.COMMENT),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        IconButton(onClick = onClick, modifier = Modifier.size(48.dp)) {
            Icon(
                imageVector = Icons.Outlined.ChatBubbleOutline,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        if (commentCount > 0) {
            Text(
                text = compactCount(commentCount),
                style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun PostOverflowMenu(
    onHide: () -> Unit,
    onNotInterested: () -> Unit,
    modifier: Modifier = Modifier,
) {
    var expanded by remember { mutableStateOf(false) }
    Box(modifier = modifier) {
        IconButton(
            onClick = { expanded = true },
            modifier = Modifier.size(48.dp).testTag(PostActionTestTags.OVERFLOW),
        ) {
            Icon(
                imageVector = Icons.Outlined.MoreVert,
                contentDescription = stringResource(R.string.feed_action_more),
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        DropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
            DropdownMenuItem(
                text = { Text(stringResource(R.string.feed_action_hide)) },
                leadingIcon = { Icon(Icons.Outlined.VisibilityOff, contentDescription = null) },
                onClick = {
                    expanded = false
                    onHide()
                },
                modifier = Modifier.testTag(PostActionTestTags.MENU_HIDE),
            )
            DropdownMenuItem(
                text = { Text(stringResource(R.string.feed_action_not_interested)) },
                leadingIcon = { Icon(Icons.Outlined.ThumbDownOffAlt, contentDescription = null) },
                onClick = {
                    expanded = false
                    onNotInterested()
                },
                modifier = Modifier.testTag(PostActionTestTags.MENU_NOT_INTERESTED),
            )
        }
    }
}

/** Compact count formatting (1234 -> "1.2K") for like / comment chips. Locale-agnostic, JVM-safe. */
internal fun compactCount(count: Int): String = when {
    count < 1_000 -> count.toString()
    count < 1_000_000 -> trimZero(count / 1_000.0) + "K"
    else -> trimZero(count / 1_000_000.0) + "M"
}

private fun trimZero(value: Double): String {
    val rounded = (value * 10).toLong() / 10.0
    return if (rounded % 1.0 == 0.0) rounded.toLong().toString() else rounded.toString()
}
