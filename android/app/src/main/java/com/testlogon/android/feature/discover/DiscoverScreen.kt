@file:OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)

package com.testlogon.android.feature.discover

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.AssistChip
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.core.ui.state.StaleBanner
import com.testlogon.android.data.discover.DiscoverContent
import com.testlogon.android.data.discover.DiscoverCreator
import com.testlogon.android.data.discover.DiscoverTag
import androidx.compose.runtime.LaunchedEffect

/** AND-182 — stable test tags. */
object DiscoverTestTags {
    const val SCREEN = "discover_screen"
    const val LIST = "discover_list"
    const val TAG_CHIP = "discover_tag_chip"
    const val CREATOR = "discover_creator"
    const val STALE = "discover_stale"
    const val SEARCH = "discover_search"
}

/**
 * AND-182 / AND-184 — route-level discover surface. Collects [DiscoverUiState], consumes one-shot nav
 * events, and hosts the recommendations rail (AND-184) above the discover sections.
 */
@Composable
fun DiscoverRoute(
    onOpenProfile: (userId: String) -> Unit,
    onOpenTag: (tag: String) -> Unit,
    onOpenVideo: (videoId: String) -> Unit,
    onOpenSearch: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: DiscoverViewModel = hiltViewModel(),
    recommendationsViewModel: RecommendationsViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val recsState by recommendationsViewModel.state.collectAsStateWithLifecycle()

    LaunchedEffect(Unit) {
        viewModel.navEvents.collect { event ->
            when (event) {
                is DiscoverNavEvent.OpenProfile -> onOpenProfile(event.userId)
                is DiscoverNavEvent.OpenTag -> onOpenTag(event.tag)
            }
        }
    }

    DiscoverScreen(
        state = state,
        recommendations = recsState,
        onOpenSearch = onOpenSearch,
        onCreatorClick = viewModel::onCreatorClick,
        onTagClick = viewModel::onTagClick,
        onRecommendationClick = onOpenVideo,
        onRecommendationNotInterested = recommendationsViewModel::onNotInterested,
        onRecommendationRetry = recommendationsViewModel::retry,
        onRefresh = {
            viewModel.refresh()
            recommendationsViewModel.retry()
        },
        onRetry = viewModel::retry,
        modifier = modifier,
    )
}

@Composable
fun DiscoverScreen(
    state: DiscoverUiState,
    recommendations: RecommendationsUiState,
    onOpenSearch: () -> Unit,
    onCreatorClick: (String) -> Unit,
    onTagClick: (String) -> Unit,
    onRecommendationClick: (String) -> Unit,
    onRecommendationNotInterested: (String) -> Unit,
    onRecommendationRetry: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(DiscoverTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.discover_title)) },
                actions = {
                    IconButton(
                        onClick = onOpenSearch,
                        modifier = Modifier.testTag(DiscoverTestTags.SEARCH),
                    ) {
                        Icon(
                            Icons.Filled.Search,
                            contentDescription = stringResource(R.string.multi_search_open),
                        )
                    }
                },
            )
        },
    ) { padding ->
        val isRefreshing = (state as? DiscoverUiState.Content)?.isRefreshing == true
        PullToRefreshBox(
            isRefreshing = isRefreshing,
            onRefresh = onRefresh,
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
        ) {
            when (state) {
                DiscoverUiState.Loading -> LoadingState()
                DiscoverUiState.Empty ->
                    // Even with an empty discover set, recommendations may still render.
                    DiscoverContentList(
                        content = DiscoverContent(emptyList(), emptyList(), emptyList()),
                        isStale = false,
                        recommendations = recommendations,
                        onCreatorClick = onCreatorClick,
                        onTagClick = onTagClick,
                        onRecommendationClick = onRecommendationClick,
                        onRecommendationNotInterested = onRecommendationNotInterested,
                        onRecommendationRetry = onRecommendationRetry,
                        onStaleRetry = onRetry,
                        emptyDiscover = true,
                    )
                is DiscoverUiState.Error -> ErrorState(message = state.message, onRetry = onRetry)
                DiscoverUiState.Offline ->
                    ErrorState(
                        message = stringResource(R.string.discover_offline),
                        onRetry = onRetry,
                    )
                is DiscoverUiState.Content ->
                    DiscoverContentList(
                        content = state.content,
                        isStale = state.isStale,
                        recommendations = recommendations,
                        onCreatorClick = onCreatorClick,
                        onTagClick = onTagClick,
                        onRecommendationClick = onRecommendationClick,
                        onRecommendationNotInterested = onRecommendationNotInterested,
                        onRecommendationRetry = onRecommendationRetry,
                        onStaleRetry = onRetry,
                        emptyDiscover = false,
                    )
            }
        }
    }
}

@Composable
private fun DiscoverContentList(
    content: DiscoverContent,
    isStale: Boolean,
    recommendations: RecommendationsUiState,
    onCreatorClick: (String) -> Unit,
    onTagClick: (String) -> Unit,
    onRecommendationClick: (String) -> Unit,
    onRecommendationNotInterested: (String) -> Unit,
    onRecommendationRetry: () -> Unit,
    onStaleRetry: () -> Unit,
    emptyDiscover: Boolean,
) {
    // Resolve strings in composition (the LazyColumn content lambda is not @Composable).
    val suggestedTitle = stringResource(R.string.discover_section_suggested)
    val trendingCreatorsTitle = stringResource(R.string.discover_section_trending_creators)
    val trendingTagsTitle = stringResource(R.string.discover_section_trending_tags)
    val emptyTitle = stringResource(R.string.discover_empty)

    LazyColumn(
        modifier = Modifier.fillMaxSize().testTag(DiscoverTestTags.LIST),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        if (isStale) {
            item {
                StaleBanner(
                    stale = true,
                    refreshing = false,
                    onRetry = onStaleRetry,
                    modifier = Modifier.testTag(DiscoverTestTags.STALE),
                )
            }
        }

        // AND-184 — recommendations section above the discover sections.
        item {
            RecommendationsSection(
                state = recommendations,
                onItemClick = onRecommendationClick,
                onNotInterested = onRecommendationNotInterested,
                onRetry = onRecommendationRetry,
            )
        }

        if (content.suggested.isNotEmpty()) {
            sectionHeader(suggestedTitle)
            creatorRail(content.suggested, onCreatorClick)
        }
        if (content.trendingCreators.isNotEmpty()) {
            sectionHeader(trendingCreatorsTitle)
            creatorRail(content.trendingCreators, onCreatorClick)
        }
        if (content.trendingTags.isNotEmpty()) {
            sectionHeader(trendingTagsTitle)
            item { TagChips(content.trendingTags, onTagClick) }
        }

        if (emptyDiscover && recommendations !is RecommendationsUiState.Content) {
            item {
                EmptyState(
                    title = emptyTitle,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        }
    }
}

private fun androidx.compose.foundation.lazy.LazyListScope.sectionHeader(title: String) {
    item {
        Text(
            text = title,
            style = MaterialTheme.typography.titleMedium,
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 4.dp)
                .semantics { heading() },
        )
    }
}

private fun androidx.compose.foundation.lazy.LazyListScope.creatorRail(
    creators: List<DiscoverCreator>,
    onCreatorClick: (String) -> Unit,
) {
    item {
        LazyRow(
            contentPadding = PaddingValues(horizontal = 8.dp),
            horizontalArrangement = Arrangement.spacedBy(4.dp),
            modifier = Modifier.fillMaxWidth(),
        ) {
            items(creators, key = { it.userId }) { creator ->
                Box(modifier = Modifier.width(240.dp).testTag(DiscoverTestTags.CREATOR)) {
                    CreatorRow(
                        displayName = creator.displayName,
                        subtitle = creator.description,
                        avatarUrl = creator.profilePhotoUrl,
                        onClick = { onCreatorClick(creator.userId) },
                        contentDescription = creatorContentDescription(creator),
                    )
                }
            }
        }
    }
}

@Composable
private fun creatorContentDescription(creator: DiscoverCreator): String =
    pluralStringResource(
        R.plurals.discover_creator_cd,
        creator.followerCount,
        creator.displayName,
        creator.followerCount,
    )

@Composable
private fun TagChips(tags: List<DiscoverTag>, onTagClick: (String) -> Unit) {
    FlowRow(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        tags.forEach { tag ->
            AssistChip(
                onClick = { onTagClick(tag.tag) },
                label = { Text(stringResource(R.string.discover_tag_label, tag.tag)) },
                modifier = Modifier.testTag(DiscoverTestTags.TAG_CHIP),
            )
        }
    }
}
