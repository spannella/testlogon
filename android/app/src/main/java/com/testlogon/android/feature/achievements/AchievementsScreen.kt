package com.testlogon.android.feature.achievements

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.EmojiEvents
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import coil.compose.AsyncImage
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.achievements.Achievement
import com.testlogon.android.data.achievements.AchievementCatalog

/** Stable testTags for the achievements screen (AND-093 / AND-096). */
object AchievementsTestTags {
    const val SCREEN = "achievements_screen"
    const val LIST = "achievements_list"
    const val HEADER = "achievements_header"
    const val EARNED_SECTION = "achievements_earned_header"
    const val LOCKED_SECTION = "achievements_locked_header"
    const val ROW = "achievement_row"
    const val EMPTY = "achievements_empty"
    const val ERROR = "achievements_error"
    fun progress(id: String) = "achievement_progress_$id"
    fun leaderboardEntry() = "leaderboard_entry"
}

/** AND-093 — route-level Achievements entry, reached from the More hub. */
@Composable
fun AchievementsRoute(
    onBack: () -> Unit,
    onOpenLeaderboard: () -> Unit = {},
    modifier: Modifier = Modifier,
    viewModel: AchievementsViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    LaunchedEffect(Unit) {
        viewModel.events.collect { event ->
            when (event) {
                is AchievementsEvent.ShowError -> snackbarHostState.showSnackbar(event.message)
            }
        }
    }
    AchievementsScreen(
        state = state,
        snackbarHostState = snackbarHostState,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::retry,
        onOpenLeaderboard = onOpenLeaderboard,
        onBack = onBack,
        modifier = modifier,
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AchievementsScreen(
    state: AchievementsUiState,
    snackbarHostState: SnackbarHostState,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onOpenLeaderboard: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(AchievementsTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("Achievements") },
                navigationIcon = {
                    IconButton(onClick = onBack, modifier = Modifier.testTag("achievements_back")) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    IconButton(
                        onClick = onOpenLeaderboard,
                        modifier = Modifier.testTag("achievements_leaderboard_action"),
                    ) {
                        Icon(Icons.Filled.EmojiEvents, contentDescription = "Leaderboard")
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            when (state) {
                is AchievementsUiState.Loading -> LoadingState()
                is AchievementsUiState.Empty ->
                    EmptyState(
                        title = "No achievements yet",
                        body = "Earn badges by using the app.",
                        modifier = Modifier.testTag(AchievementsTestTags.EMPTY),
                    )
                is AchievementsUiState.Error ->
                    ErrorState(
                        message = state.message,
                        onRetry = onRetry,
                        modifier = Modifier.testTag(AchievementsTestTags.ERROR),
                    )
                is AchievementsUiState.Content ->
                    AchievementsContent(
                        catalog = state.catalog,
                        isRefreshing = state.isRefreshing,
                        onRefresh = onRefresh,
                    )
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun AchievementsContent(
    catalog: AchievementCatalog,
    isRefreshing: Boolean,
    onRefresh: () -> Unit,
) {
    PullToRefreshBox(
        isRefreshing = isRefreshing,
        onRefresh = onRefresh,
        modifier = Modifier.fillMaxSize(),
    ) {
        LazyColumn(modifier = Modifier.fillMaxSize().testTag(AchievementsTestTags.LIST)) {
            item(key = "header") {
                AchievementsHeader(
                    earnedCount = catalog.earnedCount,
                    totalPoints = catalog.totalPoints,
                    total = catalog.total,
                )
            }
            if (catalog.earned.isNotEmpty()) {
                item(key = "earned_header") {
                    SectionHeader("Earned", AchievementsTestTags.EARNED_SECTION)
                }
                items(catalog.earned, key = { "e_${it.id}" }) { AchievementRow(it) }
            }
            if (catalog.locked.isNotEmpty()) {
                item(key = "locked_header") {
                    SectionHeader("Locked", AchievementsTestTags.LOCKED_SECTION)
                }
                items(catalog.locked, key = { "l_${it.id}" }) { AchievementRow(it) }
            }
        }
    }
}

@Composable
private fun AchievementsHeader(earnedCount: Int, totalPoints: Int, total: Int) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 16.dp)
            .testTag(AchievementsTestTags.HEADER),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        Text(
            text = "$earnedCount badges earned · $totalPoints points",
            style = MaterialTheme.typography.titleMedium,
        )
        if (total > 0) {
            Text(
                text = "$earnedCount of $total unlocked",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun SectionHeader(title: String, tag: String) {
    Text(
        text = title,
        style = MaterialTheme.typography.titleSmall,
        color = MaterialTheme.colorScheme.primary,
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 8.dp)
            .testTag(tag),
    )
}

@Composable
private fun AchievementRow(item: Achievement) {
    val statusWord = if (item.earned) "earned" else "locked"
    val progress = item.progress
    val cd = buildString {
        append(item.title).append(", ").append(statusWord)
        if (progress != null) append(", ").append(progress.current).append(" of ").append(progress.target)
    }
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 12.dp)
            .testTag(AchievementsTestTags.ROW)
            // Merge (not clear) so the inner progress node + its testTag / range-info remain
            // reachable while TalkBack reads a single combined row description.
            .semantics(mergeDescendants = true) { contentDescription = cd },
        verticalAlignment = Alignment.CenterVertically,
    ) {
        BadgeIcon(item)
        Column(
            modifier = Modifier
                .weight(1f)
                .padding(start = 12.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = item.title,
                    style = MaterialTheme.typography.titleSmall,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f, fill = false),
                )
                item.rarity?.let { rarity ->
                    Surface(
                        color = MaterialTheme.colorScheme.secondaryContainer,
                        modifier = Modifier.padding(start = 8.dp),
                    ) {
                        Text(
                            text = rarity.replaceFirstChar { it.uppercase() },
                            style = MaterialTheme.typography.labelSmall,
                            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                        )
                    }
                }
            }
            item.description?.let {
                Text(
                    text = it,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            if (!item.earned && progress != null) {
                LinearProgressIndicator(
                    progress = { progress.fraction },
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag(AchievementsTestTags.progress(item.id)),
                )
                Text(
                    text = progress.label,
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
private fun BadgeIcon(item: Achievement) {
    Box(
        modifier = Modifier.size(40.dp),
        contentAlignment = Alignment.Center,
    ) {
        when {
            item.iconUrl != null -> AsyncImage(
                model = item.iconUrl,
                contentDescription = null,
                modifier = Modifier.fillMaxSize(),
            )
            else -> Icon(
                imageVector = fallbackIcon(item.earned),
                contentDescription = null,
                tint = if (item.earned) {
                    MaterialTheme.colorScheme.primary
                } else {
                    MaterialTheme.colorScheme.onSurfaceVariant
                },
            )
        }
    }
}

private fun fallbackIcon(earned: Boolean): ImageVector =
    if (earned) Icons.Filled.EmojiEvents else Icons.Filled.Lock
