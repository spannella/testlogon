package com.testlogon.android.feature.discover

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import coil.compose.AsyncImage
import com.testlogon.android.R
import com.testlogon.android.data.discover.RecommendationItem

/** AND-184 — stable test tags. */
object RecommendationsTestTags {
    const val SECTION = "recommendations_section"
    const val RAIL = "recommendations_rail"
    const val CARD = "recommendations_card"
    const val NOT_INTERESTED = "recommendations_not_interested"
    const val RETRY = "recommendations_retry"
    const val FALLBACK = "recommendations_fallback"
}

/**
 * AND-184 — the "For You" recommendations section: a labeled horizontal rail of media cards. Renders
 * a skeleton-free loading slot, collapses on Empty, shows an inline (section-scoped) retry on Error,
 * and a non-blocking "trending" notice on cold-start fallback. Inserted as a single item into the
 * AND-182 discover LazyColumn so it never blocks the discover grid.
 */
@Composable
fun RecommendationsSection(
    state: RecommendationsUiState,
    onItemClick: (videoId: String) -> Unit,
    onNotInterested: (videoId: String) -> Unit,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
) {
    when (state) {
        RecommendationsUiState.Loading ->
            Column(modifier.fillMaxWidth().testTag(RecommendationsTestTags.SECTION).padding(16.dp)) {
                Text(stringResource(R.string.recommendations_loading), style = MaterialTheme.typography.bodyMedium)
            }
        RecommendationsUiState.Empty -> Unit // collapse (FR-7)
        is RecommendationsUiState.Error ->
            Column(modifier.fillMaxWidth().testTag(RecommendationsTestTags.SECTION).padding(16.dp)) {
                Text(state.message, style = MaterialTheme.typography.bodyMedium)
                TextButton(onClick = onRetry, modifier = Modifier.testTag(RecommendationsTestTags.RETRY)) {
                    Text(stringResource(R.string.action_retry))
                }
            }
        is RecommendationsUiState.Content ->
            Column(modifier.fillMaxWidth().testTag(RecommendationsTestTags.SECTION)) {
                Text(
                    text = stringResource(R.string.recommendations_title),
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 4.dp)
                        .semantics { heading() },
                )
                if (state.isTrendingFallback) {
                    Text(
                        text = stringResource(R.string.recommendations_trending_notice),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier
                            .padding(horizontal = 16.dp, vertical = 2.dp)
                            .testTag(RecommendationsTestTags.FALLBACK),
                    )
                }
                LazyRow(
                    contentPadding = PaddingValues(horizontal = 16.dp),
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                    modifier = Modifier.fillMaxWidth().testTag(RecommendationsTestTags.RAIL),
                ) {
                    items(state.items, key = { it.id }) { item ->
                        RecommendationCard(
                            item = item,
                            onClick = { onItemClick(item.id) },
                            onNotInterested = { onNotInterested(item.id) },
                        )
                    }
                }
            }
    }
}

@Composable
private fun RecommendationCard(
    item: RecommendationItem,
    onClick: () -> Unit,
    onNotInterested: () -> Unit,
) {
    Column(
        modifier = Modifier
            .width(160.dp)
            .clickable(onClick = onClick)
            .testTag(RecommendationsTestTags.CARD),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        Box(Modifier.fillMaxWidth()) {
            AsyncImage(
                model = item.posterUrl,
                contentDescription = item.title,
                contentScale = ContentScale.Crop,
                modifier = Modifier
                    .fillMaxWidth()
                    .aspectRatio(16f / 9f)
                    .clip(RoundedCornerShape(8.dp)),
            )
            IconButton(
                onClick = onNotInterested,
                modifier = Modifier
                    .align(Alignment.TopEnd)
                    .testTag(RecommendationsTestTags.NOT_INTERESTED),
            ) {
                Icon(
                    imageVector = Icons.Filled.Close,
                    contentDescription = stringResource(R.string.feed_action_not_interested),
                )
            }
        }
        Text(
            text = item.title,
            style = MaterialTheme.typography.bodyMedium,
            maxLines = 2,
            overflow = TextOverflow.Ellipsis,
        )
        if (!item.reason.isNullOrBlank()) {
            Text(
                text = item.reason,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
    }
}
