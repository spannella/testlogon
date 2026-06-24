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
import androidx.compose.material.icons.filled.Bookmark
import androidx.compose.material.icons.filled.Favorite
import androidx.compose.material.icons.outlined.Edit
import androidx.compose.material.icons.outlined.BookmarkBorder
import androidx.compose.material.icons.outlined.ChatBubbleOutline
import androidx.compose.material.icons.outlined.FavoriteBorder
import androidx.compose.material.icons.outlined.MoreVert
import androidx.compose.material.icons.outlined.Paid
import androidx.compose.material.icons.outlined.Share
import androidx.compose.material.icons.outlined.ThumbDownOffAlt
import androidx.compose.material.icons.outlined.VisibilityOff
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.IconToggleButton
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
import androidx.compose.ui.semantics.onClick
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
    const val MENU_EDIT = "post_menu_edit"
    const val BOOKMARK = "post_bookmark"
    const val SHARE = "post_share"
    const val TIP = "post_tip"
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
    // AND-176 / AND-178 — share, bookmark, tip affordances.
    bookmarked: Boolean = false,
    bookmarkEnabled: Boolean = true,
    onToggleBookmark: () -> Unit = {},
    onShare: () -> Unit = {},
    showTip: Boolean = true,
    onTip: () -> Unit = {},
    // FD12 — when non-null, the overflow menu shows an Edit item (own posts only).
    onEdit: (() -> Unit)? = null,
) {
    Row(
        modifier = modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        LikeButton(liked = liked, likeCount = likeCount, onToggle = onLikeToggle)
        CommentButton(commentCount = commentCount, onClick = onCommentClick)
        if (showTip) {
            TipButton(onClick = onTip)
        }
        BookmarkToggle(checked = bookmarked, enabled = bookmarkEnabled, onCheckedChange = { onToggleBookmark() })
        ShareButton(onClick = onShare)
        Box(modifier = Modifier.weight(1f))
        PostOverflowMenu(onHide = onHide, onNotInterested = onNotInterested, onEdit = onEdit)
    }
}

@Composable
fun BookmarkToggle(
    checked: Boolean,
    enabled: Boolean,
    onCheckedChange: (Boolean) -> Unit,
    modifier: Modifier = Modifier,
) {
    val desc = stringResource(if (checked) R.string.feed_remove_bookmark else R.string.feed_add_bookmark)
    val tint = if (checked) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant
    IconToggleButton(
        checked = checked,
        enabled = enabled,
        onCheckedChange = onCheckedChange,
        modifier = modifier.size(48.dp).testTag(PostActionTestTags.BOOKMARK),
    ) {
        Icon(
            imageVector = if (checked) Icons.Filled.Bookmark else Icons.Outlined.BookmarkBorder,
            contentDescription = desc,
            tint = tint,
        )
    }
}

@Composable
private fun ShareButton(onClick: () -> Unit, modifier: Modifier = Modifier) {
    IconButton(onClick = onClick, modifier = modifier.size(48.dp).testTag(PostActionTestTags.SHARE)) {
        Icon(
            imageVector = Icons.Outlined.Share,
            contentDescription = stringResource(R.string.feed_share),
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun TipButton(onClick: () -> Unit, modifier: Modifier = Modifier) {
    IconButton(onClick = onClick, modifier = modifier.size(48.dp).testTag(PostActionTestTags.TIP)) {
        Icon(
            imageVector = Icons.Outlined.Paid,
            contentDescription = stringResource(R.string.tip_action),
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
        )
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
            // testTag must precede clearAndSetSemantics, which otherwise clears the tag off the node and
            // makes the merged Button unfindable; onClick re-exposes the inner IconButton's (cleared)
            // click action so the labelled Button is activatable by accessibility services and tests.
            .testTag(PostActionTestTags.LIKE)
            .clearAndSetSemantics {
                role = Role.Button
                stateDescription = state
                contentDescription = countDesc
                onClick(label = action) { onToggle(); true }
            },
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
    onEdit: (() -> Unit)? = null,
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
            if (onEdit != null) {
                DropdownMenuItem(
                    text = { Text("Edit post") },
                    leadingIcon = { Icon(Icons.Outlined.Edit, contentDescription = null) },
                    onClick = {
                        expanded = false
                        onEdit()
                    },
                    modifier = Modifier.testTag(PostActionTestTags.MENU_EDIT),
                )
            }
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
