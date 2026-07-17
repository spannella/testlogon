package com.testlogon.android.feature.feed

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Bookmark
import androidx.compose.material.icons.filled.Favorite
import androidx.compose.material.icons.outlined.AddReaction
import androidx.compose.material.icons.outlined.Block
import androidx.compose.material.icons.outlined.Edit
import androidx.compose.material.icons.outlined.Flag
import androidx.compose.material.icons.outlined.BookmarkBorder
import androidx.compose.material.icons.outlined.ChatBubbleOutline
import androidx.compose.material.icons.outlined.FavoriteBorder
import androidx.compose.material.icons.outlined.MoreVert
import androidx.compose.material.icons.outlined.Paid
import androidx.compose.material.icons.outlined.Repeat
import androidx.compose.material.icons.outlined.Share
import androidx.compose.material.icons.outlined.ThumbDownOffAlt
import androidx.compose.material.icons.outlined.VisibilityOff
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.TextButton
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
    const val REACT = "post_react"
    const val EMOJI_PICKER = "post_emoji_picker"
    const val REACTION_CHIPS = "post_reaction_chips"
    const val COMMENT = "post_comment"
    // SOCIAL-002 — repost affordance + its menu items.
    const val REPOST = "post_repost"
    const val MENU_REPOST = "post_menu_repost"
    const val MENU_QUOTE_REPOST = "post_menu_quote_repost"
    const val MENU_UNDO_REPOST = "post_menu_undo_repost"
    const val QUOTE_REPOST_FIELD = "post_quote_repost_field"
    const val QUOTE_REPOST_SUBMIT = "post_quote_repost_submit"
    const val OVERFLOW = "post_overflow"
    const val MENU_HIDE = "post_menu_hide"
    const val MENU_NOT_INTERESTED = "post_menu_not_interested"
    const val MENU_EDIT = "post_menu_edit"
    const val MENU_REPORT = "post_menu_report"
    const val BOOKMARK = "post_bookmark"
    const val SHARE = "post_share"
    const val TIP = "post_tip"
    // TIP-204 - money-reaction (tip) affordances.
    const val TIP_REACT = "tip_react_post_open"
    const val TIP_REACT_CHIPS = "tip_react_post_chips"
    // TIPX-C1 - running direct-tip total badge.
    const val TIP_TOTAL = "post_tip_total"
}

/** TIP-204 - the money-reaction glyph used for the post tip-react affordance + chip. */
private const val TIP_REACT_EMOJI = "💰"

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
    // SOCIAL-002 — public reposting: toggle + count, with a Repost / Quote repost / Undo menu.
    // [repostEnabled] is false for the viewer's own post and locked posts (backend rejects both).
    reposted: Boolean = false,
    repostCount: Int = 0,
    repostEnabled: Boolean = true,
    onRepost: () -> Unit = {},
    onQuoteRepost: (quote: String) -> Unit = {},
    onUndoRepost: () -> Unit = {},
    // AND-176 / AND-178 — share, bookmark, tip affordances.
    bookmarked: Boolean = false,
    bookmarkEnabled: Boolean = true,
    onToggleBookmark: () -> Unit = {},
    onShare: () -> Unit = {},
    showTip: Boolean = true,
    onTip: () -> Unit = {},
    // FD12 — when non-null, the overflow menu shows an Edit item (own posts only).
    onEdit: (() -> Unit)? = null,
    // MOD-C1 — when non-null, the overflow shows a Report item that opens the moderation report sheet.
    onReport: (() -> Unit)? = null,
    // P0-BLOCK — when non-null, the overflow shows a Block-author item (blocks the post author).
    onBlockAuthor: (() -> Unit)? = null,
    // #20 — full emoji reactions (distinct from the like toggle).
    reactions: List<com.testlogon.android.data.feed.ReactionTally> = emptyList(),
    onToggleReaction: (String) -> Unit = {},
    // TIP-204 - money-REACTION: tip option in the reaction picker + money-reaction chips on the post.
    tipReactions: List<com.testlogon.android.data.feed.TipReactionBadge> = emptyList(),
    onTipReact: (String) -> Unit = {},
    // TIPX-C1 - running total (cents) of DIRECT tips on this post; when > 0 a "Tipped $X" badge renders.
    tipTotalCents: Int = 0,
) {
    var reactionPickerOpen by remember { mutableStateOf(false) }
    // SOCIAL-002 — the quote-repost composer dialog (opened from the repost menu's "Quote repost").
    var quoteDialogOpen by remember { mutableStateOf(false) }
    Column(modifier = modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            LikeButton(liked = liked, likeCount = likeCount, onToggle = onLikeToggle)
            // #20 — open the curated emoji reaction picker.
            ReactButton(onClick = { reactionPickerOpen = !reactionPickerOpen })
            CommentButton(commentCount = commentCount, onClick = onCommentClick)
            // SOCIAL-002 — repost between Comment and Tip/Share (mirrors the web RepostButton position).
            RepostButton(
                reposted = reposted,
                repostCount = repostCount,
                enabled = repostEnabled,
                onRepost = onRepost,
                onQuoteRepost = { quoteDialogOpen = true },
                onUndoRepost = onUndoRepost,
            )
            if (showTip) {
                TipButton(onClick = onTip)
            }
            BookmarkToggle(checked = bookmarked, enabled = bookmarkEnabled, onCheckedChange = { onToggleBookmark() })
            ShareButton(onClick = onShare)
            Box(modifier = Modifier.weight(1f))
            PostOverflowMenu(onHide = onHide, onNotInterested = onNotInterested, onEdit = onEdit, onReport = onReport, onBlockAuthor = onBlockAuthor)
        }
        // #20 — curated emoji picker (toggled by the React button).
        if (reactionPickerOpen) {
            PostEmojiPicker(
                selected = reactions.filter { it.reactedByMe }.map { it.emoji }.toSet(),
                onPick = {
                    onToggleReaction(it)
                    reactionPickerOpen = false
                },
                onTipReact = {
                    onTipReact(it)
                    reactionPickerOpen = false
                },
            )
        }
        // #20 — under-post reaction chips (emoji + count; tap to toggle).
        if (reactions.isNotEmpty()) {
            PostReactionChips(reactions = reactions, onToggle = onToggleReaction)
        }
        // TIP-204 - money-reaction (tip) chips on the post, distinct from the free emoji chips.
        if (tipReactions.isNotEmpty()) {
            PostTipReactionChips(tipReactions = tipReactions)
        }
        // TIPX-C1 - the running DIRECT-tip total, shown to BOTH parties so a tip completes
        // charge -> credit -> render (mirrors the comment "Tipped $X" badge).
        if (tipTotalCents > 0) {
            PostTipTotalBadge(tipTotalCents = tipTotalCents)
        }
    }
    // SOCIAL-002 — quote-repost composer (≤500 chars). Confirm reposts with the trimmed commentary.
    if (quoteDialogOpen) {
        QuoteRepostDialog(
            onSubmit = { quote ->
                quoteDialogOpen = false
                onQuoteRepost(quote)
            },
            onDismiss = { quoteDialogOpen = false },
        )
    }
}

/**
 * SOCIAL-002 — the repost affordance: a Repeat icon + count that opens a small menu. When the viewer has
 * NOT reposted, the menu offers Repost / Quote repost; when they HAVE, it offers Undo repost (mirrors the
 * web RepostButton popover). Disabled (with the count still shown) for the viewer's own post + locked
 * posts, which the backend rejects.
 */
@Composable
private fun RepostButton(
    reposted: Boolean,
    repostCount: Int,
    enabled: Boolean,
    onRepost: () -> Unit,
    onQuoteRepost: () -> Unit,
    onUndoRepost: () -> Unit,
    modifier: Modifier = Modifier,
) {
    var menuOpen by remember { mutableStateOf(false) }
    val tint = when {
        !enabled -> MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.38f)
        reposted -> MaterialTheme.colorScheme.primary
        else -> MaterialTheme.colorScheme.onSurfaceVariant
    }
    Box(modifier = modifier) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            IconButton(
                onClick = { menuOpen = true },
                enabled = enabled,
                modifier = Modifier.size(48.dp).testTag(PostActionTestTags.REPOST),
            ) {
                Icon(
                    imageVector = Icons.Outlined.Repeat,
                    contentDescription = stringResource(R.string.feed_repost),
                    tint = tint,
                )
            }
            if (repostCount > 0) {
                Text(
                    text = compactCount(repostCount),
                    style = MaterialTheme.typography.labelLarge,
                    color = tint,
                )
            }
        }
        DropdownMenu(expanded = menuOpen, onDismissRequest = { menuOpen = false }) {
            if (reposted) {
                DropdownMenuItem(
                    text = { Text(stringResource(R.string.feed_undo_repost)) },
                    leadingIcon = { Icon(Icons.Outlined.Repeat, contentDescription = null) },
                    onClick = {
                        menuOpen = false
                        onUndoRepost()
                    },
                    modifier = Modifier.testTag(PostActionTestTags.MENU_UNDO_REPOST),
                )
            } else {
                DropdownMenuItem(
                    text = { Text(stringResource(R.string.feed_repost)) },
                    leadingIcon = { Icon(Icons.Outlined.Repeat, contentDescription = null) },
                    onClick = {
                        menuOpen = false
                        onRepost()
                    },
                    modifier = Modifier.testTag(PostActionTestTags.MENU_REPOST),
                )
                DropdownMenuItem(
                    text = { Text(stringResource(R.string.feed_quote_repost)) },
                    leadingIcon = { Icon(Icons.Outlined.Edit, contentDescription = null) },
                    onClick = {
                        menuOpen = false
                        onQuoteRepost()
                    },
                    modifier = Modifier.testTag(PostActionTestTags.MENU_QUOTE_REPOST),
                )
            }
        }
    }
}

/** SOCIAL-002 — inline quote-repost composer: a ≤500-char commentary field with a live counter. */
@Composable
private fun QuoteRepostDialog(
    onSubmit: (String) -> Unit,
    onDismiss: () -> Unit,
) {
    var text by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.feed_quote_repost)) },
        text = {
            Column {
                OutlinedTextField(
                    value = text,
                    onValueChange = { if (it.length <= QUOTE_MAX_LEN) text = it },
                    placeholder = { Text(stringResource(R.string.feed_quote_repost_hint)) },
                    modifier = Modifier.fillMaxWidth().testTag(PostActionTestTags.QUOTE_REPOST_FIELD),
                )
                Text(
                    text = "${text.length}/$QUOTE_MAX_LEN",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 4.dp),
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = { onSubmit(text.trim()) },
                modifier = Modifier.testTag(PostActionTestTags.QUOTE_REPOST_SUBMIT),
            ) { Text(stringResource(R.string.feed_repost)) }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.feed_repost_cancel)) }
        },
    )
}

/** SOCIAL-002 — server-enforced quote length cap (RepostRequest.quote max_length=500). */
private const val QUOTE_MAX_LEN = 500

@Composable
private fun ReactButton(onClick: () -> Unit, modifier: Modifier = Modifier) {
    IconButton(onClick = onClick, modifier = modifier.size(48.dp).testTag(PostActionTestTags.REACT)) {
        Icon(
            imageVector = Icons.Outlined.AddReaction,
            contentDescription = "React",
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

/** #20 — curated reaction emoji row for a post (matches the comment reaction bar). */
@OptIn(androidx.compose.foundation.layout.ExperimentalLayoutApi::class)
@Composable
private fun PostEmojiPicker(
    selected: Set<String>,
    onPick: (String) -> Unit,
    onTipReact: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    androidx.compose.foundation.layout.FlowRow(
        modifier = modifier.fillMaxWidth().padding(vertical = 4.dp).testTag(PostActionTestTags.EMOJI_PICKER),
        horizontalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        com.testlogon.android.data.feed.REACTION_EMOJIS.forEach { emoji ->
            androidx.compose.material3.FilterChip(
                selected = emoji in selected,
                onClick = { onPick(emoji) },
                label = { Text(emoji) },
            )
        }
        // TIP-204 - money-REACTION: opens the shared TipSheet (amount + a money glyph); on confirm
        // POSTs the post tip-react. Distinct from the free emoji reactions and the direct Tip action.
        androidx.compose.material3.AssistChip(
            onClick = { onTipReact(TIP_REACT_EMOJI) },
            label = { Text(TIP_REACT_EMOJI + " " + stringResource(R.string.post_tip_react)) },
            modifier = Modifier.testTag(PostActionTestTags.TIP_REACT),
        )
    }
}

/** TIPX-C1 - the post's running DIRECT-tip total, "Tipped $X", shown to both the author and viewers. */
@Composable
private fun PostTipTotalBadge(tipTotalCents: Int, modifier: Modifier = Modifier) {
    Text(
        text = "Tipped $" + String.format(java.util.Locale.US, "%.2f", tipTotalCents / 100.0),
        style = MaterialTheme.typography.labelMedium,
        color = MaterialTheme.colorScheme.primary,
        modifier = modifier.padding(start = 8.dp, top = 2.dp, bottom = 4.dp).testTag(PostActionTestTags.TIP_TOTAL),
    )
}

/** TIP-204 - under-post MONEY-reaction chip row (tip reactions); glyph + amount, non-toggling. */
@OptIn(androidx.compose.foundation.layout.ExperimentalLayoutApi::class)
@Composable
private fun PostTipReactionChips(
    tipReactions: List<com.testlogon.android.data.feed.TipReactionBadge>,
    modifier: Modifier = Modifier,
) {
    androidx.compose.foundation.layout.FlowRow(
        modifier = modifier.fillMaxWidth().padding(start = 8.dp, top = 2.dp, bottom = 4.dp).testTag(PostActionTestTags.TIP_REACT_CHIPS),
        horizontalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        tipReactions.forEach { t ->
            val amount = String.format(java.util.Locale.US, "$%.2f", t.amountCents / 100.0)
            val glyph = t.emoji.ifBlank { TIP_REACT_EMOJI }
            androidx.compose.material3.AssistChip(
                onClick = {},
                label = { Text(glyph + " " + amount) },
            )
        }
    }
}

/** #20 — under-post reaction chip row. */
@OptIn(androidx.compose.foundation.layout.ExperimentalLayoutApi::class)
@Composable
private fun PostReactionChips(
    reactions: List<com.testlogon.android.data.feed.ReactionTally>,
    onToggle: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    androidx.compose.foundation.layout.FlowRow(
        modifier = modifier.fillMaxWidth().padding(start = 8.dp, top = 2.dp, bottom = 4.dp).testTag(PostActionTestTags.REACTION_CHIPS),
        horizontalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        reactions.forEach { r ->
            androidx.compose.material3.FilterChip(
                selected = r.reactedByMe,
                onClick = { onToggle(r.emoji) },
                label = { Text("${r.emoji} ${r.count}") },
            )
        }
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
    onReport: (() -> Unit)? = null,
    onBlockAuthor: (() -> Unit)? = null,
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
            // MOD-C1 - report this post (main / group / syndicate feeds share this bar via PostItem).
            if (onReport != null) {
                DropdownMenuItem(
                    text = { Text(stringResource(R.string.msg_action_report)) },
                    leadingIcon = { Icon(Icons.Outlined.Flag, contentDescription = null) },
                    onClick = {
                        expanded = false
                        onReport()
                    },
                    modifier = Modifier.testTag(PostActionTestTags.MENU_REPORT),
                )
            }
            // P0-BLOCK — block the post author (either-direction block hides content + stops contact).
            if (onBlockAuthor != null) {
                DropdownMenuItem(
                    text = { Text(stringResource(R.string.block_author_action)) },
                    leadingIcon = { Icon(Icons.Outlined.Block, contentDescription = null) },
                    onClick = {
                        expanded = false
                        onBlockAuthor()
                    },
                    modifier = Modifier.testTag("post_block_author"),
                )
            }
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
