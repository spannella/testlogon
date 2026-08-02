package com.testlogon.android.feature.stories

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import coil.compose.AsyncImage
import com.testlogon.android.R
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.stories.StoryBarItem

/** Stable test tags for the stories tray (AND-199). */
object StoriesTrayTestTags {
    const val TRAY = "stories_tray"
    const val RING = "story_ring"
    const val CREATE = "story_create_tile"
}

/**
 * AND-199 — horizontal tray of per-author story rings rendered above the feed. Unseen authors get a
 * vivid gradient ring; seen authors a muted ring (server `has_unseen` OR-merged with the local viewed
 * set in the repository). Ordering follows server order (web parity — no client sort).
 *
 * PAR-01 — the tray always leads with a "＋ Your story" tile (a plus variant of the story ring) that
 * launches the create-story screen. The tile is shown even when there are no active stories, so the
 * tray no longer collapses to 0 height unconditionally.
 */
@Composable
fun StoriesTray(
    state: ApiResult<List<StoryBarItem>>,
    onRingClick: (userId: String) -> Unit,
    onCreateClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val entries = (state as? ApiResult.Success)?.data.orEmpty()

    LazyRow(
        modifier = modifier.testTag(StoriesTrayTestTags.TRAY),
        contentPadding = PaddingValues(horizontal = 12.dp, vertical = 8.dp),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item(key = "__create__") {
            CreateStoryTile(onClick = onCreateClick)
        }
        items(items = entries, key = { it.userId }) { entry ->
            StoryRing(entry = entry, onClick = { onRingClick(entry.userId) })
        }
    }
}

/** PAR-01 — the leading "＋ Your story" tile: a plus-badged ring that opens the create-story screen. */
@Composable
fun CreateStoryTile(
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val cd = stringResource(R.string.create_story_tray_cd)
    Column(
        modifier = modifier
            .width(72.dp)
            .testTag(StoriesTrayTestTags.CREATE)
            .clickable(onClick = onClick)
            .semantics { role = Role.Button; contentDescription = cd },
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Box(
            modifier = Modifier
                .size(64.dp)
                .border(width = 1.dp, color = MaterialTheme.colorScheme.outlineVariant, shape = CircleShape)
                .padding(4.dp)
                .clip(CircleShape)
                .background(MaterialTheme.colorScheme.surfaceVariant),
            contentAlignment = Alignment.Center,
        ) {
            Icon(
                imageVector = Icons.Filled.Add,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
            )
        }
        Text(
            text = stringResource(R.string.create_story_tray_cta),
            style = MaterialTheme.typography.labelSmall,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
            textAlign = TextAlign.Center,
            modifier = Modifier.padding(top = 4.dp),
        )
    }
}

/** AND-199 — a single circular avatar with an unseen/seen ring + a user-id-derived label. */
@Composable
fun StoryRing(
    entry: StoryBarItem,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val seenLabel = stringResource(R.string.story_ring_seen, entry.displayLabel)
    val unseenLabel = stringResource(R.string.story_ring_unseen, entry.displayLabel)
    val cd = if (entry.hasUnseen) unseenLabel else seenLabel

    // Non-color cue: unseen rings are a thicker gradient stroke; seen rings a thin muted stroke.
    val unseenBrush = Brush.linearGradient(
        listOf(
            MaterialTheme.colorScheme.primary,
            MaterialTheme.colorScheme.tertiary,
            MaterialTheme.colorScheme.secondary,
        ),
    )
    val seenBrush = Brush.linearGradient(
        listOf(
            MaterialTheme.colorScheme.outlineVariant,
            MaterialTheme.colorScheme.outlineVariant,
        ),
    )
    val strokeWidth = if (entry.hasUnseen) 3.dp else 1.dp

    Column(
        modifier = modifier
            .width(72.dp)
            .testTag(StoriesTrayTestTags.RING)
            .clickable(onClick = onClick)
            .semantics { role = Role.Button; contentDescription = cd },
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Box(
            modifier = Modifier
                .size(64.dp)
                .border(width = strokeWidth, brush = if (entry.hasUnseen) unseenBrush else seenBrush, shape = CircleShape)
                .padding(4.dp)
                .clip(CircleShape)
                .background(MaterialTheme.colorScheme.surfaceVariant),
            contentAlignment = Alignment.Center,
        ) {
            if (entry.latestMediaUrl != null) {
                AsyncImage(
                    model = entry.latestMediaUrl,
                    contentDescription = null,
                    modifier = Modifier.fillMaxSize().clip(CircleShape),
                )
            } else {
                Text(
                    text = entry.displayLabel.take(1).uppercase(),
                    style = MaterialTheme.typography.titleMedium,
                )
            }
        }
        Text(
            text = entry.displayLabel,
            style = MaterialTheme.typography.labelSmall,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
            textAlign = TextAlign.Center,
            modifier = Modifier.padding(top = 4.dp),
        )
    }
}
