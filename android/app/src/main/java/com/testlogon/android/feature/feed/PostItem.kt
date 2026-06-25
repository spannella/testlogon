package com.testlogon.android.feature.feed

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.Surface
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.testlogon.android.data.feed.FeedPost
import com.testlogon.android.data.feed.Paywall

/** Stable test tags for a feed post row (AND-099). */
object PostItemTestTags {
    const val ITEM = "post_item"
    const val HEADER = "post_header"
    const val BODY = "post_body"
    const val LOCKED_BADGE = "post_locked_badge"
}

/**
 * AND-099 / AND-101 — canonical, stateless post row. Renders the author header (monogram avatar from
 * author_id + relative timestamp), then either the open content (body + media) OR, for a locked post,
 * a [PaywallCard] in place of all protected content. Pure presentation; all inputs arrive via an
 * immutable [FeedPost] plus stable callbacks. Safe to place inside a LazyColumn.
 *
 * NOTE: locked posts are already redacted at the mapper (body null, media empty), so the locked branch
 * is structurally unable to leak protected content.
 */
@Composable
fun PostItem(
    post: FeedPost,
    modifier: Modifier = Modifier,
    onPostClick: (FeedPost) -> Unit = {},
    onAuthorClick: (authorId: String) -> Unit = {},
    // Resolved human display name for the author; falls back to authorId when null/blank.
    authorName: String? = null,
    // ID15 - resolved profile_photo_url for the author; null => show the monogram avatar.
    authorPhotoUrl: String? = null,
    onMediaClick: (post: FeedPost, index: Int) -> Unit = { _, _ -> },
    onLinkClick: (url: String) -> Unit = {},
    onUnlockClick: (postId: String) -> Unit = {},
    // AND-173 / AND-174 / AND-175 — content-engagement affordances. Null => hide the action bar
    // (e.g. in pure-render preview/test contexts that don't wire engagement).
    showActionBar: Boolean = true,
    onLikeToggle: (FeedPost) -> Unit = {},
    // #20 — toggle an emoji reaction on this post.
    onToggleReaction: (post: FeedPost, emoji: String) -> Unit = { _, _ -> },
    onCommentClick: (FeedPost) -> Unit = {},
    onHide: (FeedPost) -> Unit = {},
    onNotInterested: (FeedPost) -> Unit = {},
    // AND-176 / AND-178 — share, bookmark, tip.
    isBookmarked: Boolean = false,
    onToggleBookmark: (FeedPost) -> Unit = {},
    onShare: (FeedPost) -> Unit = {},
    onTip: (FeedPost) -> Unit = {},
    // FD13 — hide the Tip action when this is the viewer's own post (can't tip yourself).
    showTip: Boolean = true,
    // FD12 — when non-null, an Edit item appears in the post overflow (own posts only).
    onEdit: ((FeedPost) -> Unit)? = null,
    // AND-177 — unlock flow state driving the paywall CTA.
    unlockState: UnlockState = UnlockState.Idle,
    // AND-179 — poll state + vote callbacks; null => render the post's embedded poll read-only.
    pollState: PollCardState? = null,
    onPollOptionClick: (postId: String, questionId: String, optionId: String) -> Unit = { _, _, _ -> },
    onPollRetry: (postId: String, questionId: String, optionId: String) -> Unit = { _, _, _ -> },
) {
    Column(
        modifier = modifier
            .fillMaxWidth()
            .clickable { onPostClick(post) }
            .testTag(PostItemTestTags.ITEM),
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            PostAuthorHeader(
                authorId = post.authorId,
                authorName = authorName,
                authorPhotoUrl = authorPhotoUrl,
                createdAtEpochSeconds = post.createdAtEpochSeconds,
                isLocked = post.isLocked,
                onClick = { onAuthorClick(post.authorId) },
            )

            when (val paywall = post.paywall) {
                is Paywall.Locked -> PaywallCard(
                    locked = paywall,
                    onUnlockClick = { onUnlockClick(post.id) },
                    style = PaywallStyle.Feed,
                    unlockState = unlockState,
                )
                Paywall.Unlocked -> {
                    val body = post.body
                    if (!body.isNullOrBlank()) {
                        PostBody(text = body, onLinkClick = onLinkClick)
                    }
                    if (post.media.isNotEmpty()) {
                        FeedMediaGrid(
                            media = post.media,
                            onItemClick = { index -> onMediaClick(post, index) },
                        )
                    }
                    // AND-179 — embedded poll. Use the hoisted vote state when provided; otherwise
                    // render the post's own poll read-only (Results) so it never crashes a row.
                    val poll = post.poll
                    if (poll != null) {
                        PollCard(
                            state = pollState ?: PollCardState.Results(poll),
                            onOptionClick = { q, o -> onPollOptionClick(post.id, q, o) },
                            onRetry = { q, o -> onPollRetry(post.id, q, o) },
                        )
                    }
                }
            }

            if (showActionBar) {
                PostActionBar(
                    liked = post.likedByMe,
                    likeCount = post.likeCount,
                    commentCount = post.commentCount,
                    onLikeToggle = { onLikeToggle(post) },
                    onCommentClick = { onCommentClick(post) },
                    onHide = { onHide(post) },
                    onNotInterested = { onNotInterested(post) },
                    bookmarked = isBookmarked,
                    onToggleBookmark = { onToggleBookmark(post) },
                    onShare = { onShare(post) },
                    onTip = { onTip(post) },
                    showTip = showTip,
                    onEdit = onEdit?.let { edit -> { edit(post) } },
                    reactions = post.reactions,
                    onToggleReaction = { emoji -> onToggleReaction(post, emoji) },
                )
            }
        }
        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
    }
}

@Composable
private fun PostAuthorHeader(
    authorId: String,
    authorName: String?,
    authorPhotoUrl: String?,
    createdAtEpochSeconds: Long,
    isLocked: Boolean,
    onClick: () -> Unit,
) {
    val label = authorName?.takeIf { it.isNotBlank() } ?: authorId
    val relative = relativeTime(createdAtEpochSeconds)
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onClick() }
            .testTag(PostItemTestTags.HEADER),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        com.testlogon.android.feature.common.TlAvatar(
            name = label,
            photoUrl = authorPhotoUrl,
            size = 36.dp,
            textStyle = MaterialTheme.typography.labelLarge,
        )
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = label,
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            if (relative.isNotEmpty()) {
                Text(
                    text = relative,
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        if (isLocked) {
            // #19 — a prominent lock chip so a tip-/price-locked post reads as locked at a glance.
            Surface(
                color = MaterialTheme.colorScheme.tertiaryContainer,
                shape = RoundedCornerShape(50),
                modifier = Modifier.testTag(PostItemTestTags.LOCKED_BADGE),
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp),
                ) {
                    Icon(
                        Icons.Filled.Lock,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.onTertiaryContainer,
                        modifier = Modifier.size(12.dp),
                    )
                    Text(
                        text = "Locked",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onTertiaryContainer,
                        fontWeight = FontWeight.SemiBold,
                        modifier = Modifier.padding(start = 4.dp),
                    )
                }
            }
        }
    }
}

@Composable
private fun PostBody(text: String, onLinkClick: (String) -> Unit) {
    val linkColor = MaterialTheme.colorScheme.primary
    val annotated = remember(text, linkColor) {
        buildPostAnnotatedString(text = text, linkColor = linkColor, onLinkClick = onLinkClick)
    }
    Text(
        text = annotated,
        style = MaterialTheme.typography.bodyLarge,
        modifier = Modifier.fillMaxWidth().testTag(PostItemTestTags.BODY),
    )
}

/** First two non-blank chars of author_id, upper-cased (web parity: author_id.slice(0,2)). */
internal fun monogram(authorId: String): String {
    val cleaned = authorId.trim().filter { !it.isWhitespace() }
    if (cleaned.isEmpty()) return "?"
    return cleaned.take(2).uppercase()
}
