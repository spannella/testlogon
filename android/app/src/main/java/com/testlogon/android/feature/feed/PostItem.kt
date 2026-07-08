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
import androidx.compose.material.icons.outlined.Group
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.Button
import androidx.compose.material3.Surface
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
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
import com.testlogon.android.data.feed.SponsoredInfo

/** Stable test tags for a feed post row (AND-099). */
object PostItemTestTags {
    const val ITEM = "post_item"
    const val HEADER = "post_header"
    const val BODY = "post_body"
    const val LOCKED_BADGE = "post_locked_badge"
}

/** ADV-105 — test tags for the sponsored (paid) feed card. */
object SponsoredItemTestTags {
    const val ITEM = "sponsored_item"
    const val LABEL = "sponsored_label"
    const val CTA = "sponsored_cta"
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
    onTipReact: (post: FeedPost, emoji: String) -> Unit = { _, _ -> },
    // FD13 — hide the Tip action when this is the viewer's own post (can't tip yourself).
    showTip: Boolean = true,
    // #3 — true when the viewer authored this post; surfaces the "Locked · $X" badge on the author's own
    // (un-redacted) view of a locked post so they can see at a glance that it is monetized + for how much.
    isOwnPost: Boolean = false,
    // FD12 — when non-null, an Edit item appears in the post overflow (own posts only).
    onEdit: ((FeedPost) -> Unit)? = null,
    // AND-177 — unlock flow state driving the paywall CTA.
    unlockState: UnlockState = UnlockState.Idle,
    // AND-179 — poll state + vote callbacks; null => render the post's embedded poll read-only.
    pollState: PollCardState? = null,
    onPollOptionClick: (postId: String, questionId: String, optionId: String) -> Unit = { _, _, _ -> },
    onPollRetry: (postId: String, questionId: String, optionId: String) -> Unit = { _, _, _ -> },
    // Write-in polls: submit a voter write-in / page the remaining options.
    onPollWriteIn: (postId: String, questionId: String, text: String) -> Unit = { _, _, _ -> },
    onPollShowMore: (postId: String, questionId: String, offset: Int) -> Unit = { _, _, _ -> },
    // ADV-106 — sponsored-unit tracking. Impression fires when the card becomes viewport-visible; click
    // fires on the CTA/card tap. No-ops for organic posts (never invoked when post.sponsored == null).
    onSponsoredImpression: (FeedPost) -> Unit = {},
    onSponsoredClick: (FeedPost) -> Unit = {},
) {
    // ADV-105 — a server-injected sponsored (paid) unit renders as a DISTINCT card (label + CTA), not a
    // normal author post. It is never locked, so body/media come straight off the FeedPost.
    val sponsored = post.sponsored
    if (sponsored != null) {
        SponsoredPostItem(
            post = post,
            info = sponsored,
            modifier = modifier,
            onImpression = onSponsoredImpression,
            onClick = onSponsoredClick,
        )
        return
    }
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
                // #3 — the author's own locked post shows a priced badge (the body is visible to them).
                ownerLock = if (isOwnPost) post.authorLock else null,
                onClick = { onAuthorClick(post.authorId) },
            )

            // #4 (B-GROUPUNIFY) — group posts are bridged into the unified feed + "Your posts"; badge them
            // so it is clear they were shared to a group (vs the personal feed). The dedicated group feed
            // is the same data filtered to one group_id.
            if (post.groupId != null) {
                androidx.compose.material3.AssistChip(
                    onClick = {},
                    enabled = false,
                    leadingIcon = {
                        androidx.compose.material3.Icon(
                            Icons.Outlined.Group,
                            contentDescription = null,
                            modifier = Modifier.size(16.dp),
                        )
                    },
                    label = { Text("Posted in a group") },
                    modifier = Modifier.testTag("post_group_badge"),
                )
            }

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
                            onWriteIn = { q, text -> onPollWriteIn(post.id, q, text) },
                            onShowMore = { q, offset -> onPollShowMore(post.id, q, offset) },
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
                    tipReactions = post.tipReactions,
                    onTipReact = { emoji -> onTipReact(post, emoji) },
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
    // #3 — non-null when the viewer authored this (locked) post: show a priced "Locked · $X" badge.
    ownerLock: com.testlogon.android.data.feed.AuthorLock?,
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
        // #3 / #19 — a prominent lock chip. For the AUTHOR's own locked post the body is visible, so the
        // chip carries the price ("Locked · $4.99") to make it clear the post is monetized + for how much;
        // for a viewer who can't see the content it's the plain "Locked" chip.
        val lockLabel = when {
            ownerLock != null -> lockBadgeLabel(ownerLock)
            isLocked -> "Locked"
            else -> null
        }
        if (lockLabel != null) {
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
                        text = lockLabel,
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

/**
 * #3 — label for the author's lock badge. "Locked · $4.99" for a fixed price, "Locked · Tip lottery"
 * for a lottery lock, otherwise just "Locked" (no fixed price / unknown).
 */
internal fun lockBadgeLabel(lock: com.testlogon.android.data.feed.AuthorLock): String {
    val cents = lock.priceCents
    return when {
        cents != null && cents > 0 -> "Locked · " + formatCentsUsd(cents)
        lock.lockType == com.testlogon.android.data.feed.LockType.TIP_LOTTERY -> "Locked · Tip lottery"
        else -> "Locked"
    }
}

/** Cents -> "$X.XX" (USD assumed; no currency field in the contract). */
internal fun formatCentsUsd(cents: Int): String {
    val whole = cents / 100
    val frac = cents % 100
    return "$" + whole + "." + frac.toString().padStart(2, '0')
}

/** First two non-blank chars of author_id, upper-cased (web parity: author_id.slice(0,2)). */
internal fun monogram(authorId: String): String {
    val cleaned = authorId.trim().filter { !it.isWhitespace() }
    if (cleaned.isEmpty()) return "?"
    return cleaned.take(2).uppercase()
}

/**
 * ADV-105 / ADV-106 — the distinct SPONSORED card. Differs from an organic post: a "Sponsored" pill
 * (in place of the author monogram/timestamp), the advertiser/sponsor label, optional headline, the ad
 * body + media, and a primary CTA button. There is no like/comment/tip action bar.
 *
 * Tracking: an impression is fired ONCE when this card first enters composition. A LazyColumn only
 * composes rows at/near the viewport, so first composition is a good proxy for "became viewport-visible";
 * de-duplication (so a scroll-away/return doesn't double-count) is handled by the ViewModel keyed on the
 * ad_click_id. A click fires on the CTA button and on tapping the card/media.
 */
@Composable
private fun SponsoredPostItem(
    post: FeedPost,
    info: SponsoredInfo,
    modifier: Modifier = Modifier,
    onImpression: (FeedPost) -> Unit,
    onClick: (FeedPost) -> Unit,
) {
    LaunchedEffect(info.adClickId ?: info.creativeId) { onImpression(post) }
    Column(
        modifier = modifier
            .fillMaxWidth()
            .clickable { onClick(post) }
            .testTag(SponsoredItemTestTags.ITEM),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .background(MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f))
                .padding(horizontal = 16.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            // "Sponsored" pill — the disclosure that this is a paid unit.
            Surface(
                color = MaterialTheme.colorScheme.tertiaryContainer,
                shape = RoundedCornerShape(50),
                modifier = Modifier.testTag(SponsoredItemTestTags.LABEL),
            ) {
                Text(
                    text = "Sponsored",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onTertiaryContainer,
                    fontWeight = FontWeight.SemiBold,
                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp),
                )
            }
            // Advertiser / sponsor label.
            Text(
                text = info.label,
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            info.headline?.let { headline ->
                Text(
                    text = headline,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                )
            }
            post.body?.takeIf { it.isNotBlank() }?.let { body ->
                Text(
                    text = body,
                    style = MaterialTheme.typography.bodyLarge,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
            if (post.media.isNotEmpty()) {
                FeedMediaGrid(
                    media = post.media,
                    onItemClick = { onClick(post) },
                )
            }
            Button(
                onClick = { onClick(post) },
                modifier = Modifier.testTag(SponsoredItemTestTags.CTA),
            ) {
                Text(info.ctaText ?: "Learn more")
            }
        }
    }
    HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
}
