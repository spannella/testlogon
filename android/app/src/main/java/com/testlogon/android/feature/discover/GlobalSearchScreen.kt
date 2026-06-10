@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.discover

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Clear
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.PrimaryScrollableTabRow
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Tab
import androidx.compose.material3.Text
import androidx.compose.material3.TextField
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.core.ui.state.StaleBanner
import com.testlogon.android.data.discover.SearchCategory
import com.testlogon.android.data.discover.SearchEntityType
import com.testlogon.android.data.discover.SearchResult
import com.testlogon.android.data.discover.SearchResults

/** AND-185 — stable test tags. */
object GlobalSearchTestTags {
    const val SCREEN = "multi_search_screen"
    const val INPUT = "multi_search_input"
    const val CLEAR = "multi_search_clear"
    const val TABS = "multi_search_tabs"
    const val TAB = "multi_search_tab"
    const val LIST = "multi_search_list"
    const val ROW = "multi_search_row"
    const val SEE_ALL = "multi_search_see_all"
    const val STALE = "multi_search_stale"
}

/** AND-185 — slice cap for each category on the "All" tab. */
private const val ALL_TAB_SLICE = 3

/**
 * AND-185 — route-level global multi-entity search, reachable from the conversation-list / global
 * search entry. Distinct from AND-152 message search. Tapping a row resolves the server `url` to an
 * in-app destination via [onOpenResult].
 */
@Composable
fun MultiSearchRoute(
    onOpenResult: (SearchResult) -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: GlobalSearchViewModel = hiltViewModel(),
) {
    val query by viewModel.query.collectAsStateWithLifecycle()
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val tab by viewModel.selectedTab.collectAsStateWithLifecycle()

    MultiSearchScreen(
        query = query,
        state = state,
        selectedTab = tab,
        onQueryChange = viewModel::onQueryChange,
        onClearQuery = viewModel::clearQuery,
        onTabSelected = viewModel::onTabSelected,
        onRetry = viewModel::retry,
        onOpenResult = onOpenResult,
        onBack = onBack,
        modifier = modifier,
    )
}

@Composable
fun MultiSearchScreen(
    query: String,
    state: MultiSearchUiState,
    selectedTab: MultiSearchTab,
    onQueryChange: (String) -> Unit,
    onClearQuery: () -> Unit,
    onTabSelected: (MultiSearchTab) -> Unit,
    onRetry: () -> Unit,
    onOpenResult: (SearchResult) -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(GlobalSearchTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = {
                    TextField(
                        value = query,
                        onValueChange = onQueryChange,
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth().testTag(GlobalSearchTestTags.INPUT),
                        leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
                        placeholder = { Text(stringResource(R.string.multi_search_hint)) },
                        keyboardOptions = KeyboardOptions(imeAction = ImeAction.Search),
                        trailingIcon = {
                            if (query.isNotEmpty()) {
                                IconButton(
                                    onClick = onClearQuery,
                                    modifier = Modifier.testTag(GlobalSearchTestTags.CLEAR),
                                ) {
                                    Icon(Icons.Filled.Clear, contentDescription = stringResource(R.string.search_clear))
                                }
                            }
                        },
                    )
                },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
            )
        },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            when (state) {
                MultiSearchUiState.Idle -> EmptyState(title = stringResource(R.string.multi_search_prompt))
                MultiSearchUiState.Loading -> LoadingState()
                is MultiSearchUiState.Empty ->
                    EmptyState(title = stringResource(R.string.multi_search_no_results, state.query))
                is MultiSearchUiState.Error -> ErrorState(message = state.message, onRetry = onRetry)
                is MultiSearchUiState.Success ->
                    SuccessContent(
                        results = state.results,
                        stale = state.stale,
                        selectedTab = selectedTab,
                        onTabSelected = onTabSelected,
                        onOpenResult = onOpenResult,
                        onRetry = onRetry,
                    )
            }
        }
    }
}

@Composable
private fun SuccessContent(
    results: SearchResults,
    stale: Boolean,
    selectedTab: MultiSearchTab,
    onTabSelected: (MultiSearchTab) -> Unit,
    onOpenResult: (SearchResult) -> Unit,
    onRetry: () -> Unit,
) {
    Column(Modifier.fillMaxSize()) {
        if (stale) {
            StaleBanner(
                stale = true,
                refreshing = false,
                onRetry = onRetry,
                modifier = Modifier.testTag(GlobalSearchTestTags.STALE),
            )
        }

        val tabs: List<MultiSearchTab> =
            listOf(MultiSearchTab.All) + results.categories.map { MultiSearchTab.Category(it.type) }
        // If a restored tab is no longer present, fall back to All for selection display.
        val effectiveTab = if (selectedTab in tabs) selectedTab else MultiSearchTab.All
        val selectedIndex = tabs.indexOf(effectiveTab).coerceAtLeast(0)

        PrimaryScrollableTabRow(
            selectedTabIndex = selectedIndex,
            modifier = Modifier.fillMaxWidth().testTag(GlobalSearchTestTags.TABS),
        ) {
            tabs.forEach { tab ->
                val label = tabLabel(tab, results)
                Tab(
                    selected = tab == effectiveTab,
                    onClick = { onTabSelected(tab) },
                    text = { Text(label) },
                    modifier = Modifier.testTag(GlobalSearchTestTags.TAB),
                )
            }
        }

        Text(
            text = stringResource(R.string.multi_search_result_count, results.totalCount),
            style = MaterialTheme.typography.labelMedium,
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 8.dp)
                .semantics { liveRegion = LiveRegionMode.Polite },
        )

        when (effectiveTab) {
            MultiSearchTab.All ->
                AllResultsList(
                    results = results,
                    onOpenResult = onOpenResult,
                    onSeeAll = { type -> onTabSelected(MultiSearchTab.Category(type)) },
                )
            is MultiSearchTab.Category ->
                CategoryResultsList(
                    category = results.categories.first { it.type == effectiveTab.type },
                    onOpenResult = onOpenResult,
                )
        }
    }
}

@Composable
private fun AllResultsList(
    results: SearchResults,
    onOpenResult: (SearchResult) -> Unit,
    onSeeAll: (SearchEntityType) -> Unit,
) {
    LazyColumn(modifier = Modifier.fillMaxSize().testTag(GlobalSearchTestTags.LIST)) {
        results.categories.forEach { category ->
            item(key = "header_${category.type.name}") {
                Text(
                    text = categoryLabel(category.type),
                    style = MaterialTheme.typography.titleSmall,
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
                )
            }
            val slice = category.items.take(ALL_TAB_SLICE)
            items(slice, key = { "${category.type.name}_${it.id}" }) { result ->
                ResultRow(result = result, onClick = { onOpenResult(result) })
            }
            if (category.items.size > ALL_TAB_SLICE || category.hasMore) {
                item(key = "seeall_${category.type.name}") {
                    Text(
                        text = stringResource(R.string.multi_search_see_all, category.totalEstimate),
                        style = MaterialTheme.typography.labelLarge,
                        color = MaterialTheme.colorScheme.primary,
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { onSeeAll(category.type) }
                            .padding(horizontal = 16.dp, vertical = 12.dp)
                            .testTag(GlobalSearchTestTags.SEE_ALL),
                    )
                }
            }
        }
    }
}

@Composable
private fun CategoryResultsList(
    category: SearchCategory,
    onOpenResult: (SearchResult) -> Unit,
) {
    LazyColumn(modifier = Modifier.fillMaxSize().testTag(GlobalSearchTestTags.LIST)) {
        if (category.hasMore) {
            item {
                Text(
                    text = stringResource(
                        R.string.multi_search_truncated,
                        category.items.size,
                        category.totalEstimate,
                    ),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
                )
            }
        }
        items(category.items, key = { it.id }) { result ->
            ResultRow(result = result, onClick = { onOpenResult(result) })
        }
    }
}

@Composable
private fun ResultRow(result: SearchResult, onClick: () -> Unit) {
    // Reuse the avatar-style CreatorRow for user/contact results; a text row for the rest.
    when (result.type) {
        SearchEntityType.USER, SearchEntityType.CONTACT ->
            CreatorRow(
                displayName = result.title,
                subtitle = result.snippet,
                avatarUrl = result.thumbnailUrl,
                onClick = onClick,
                modifier = Modifier.testTag(GlobalSearchTestTags.ROW),
            )
        else ->
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable(onClick = onClick)
                    .padding(horizontal = 16.dp, vertical = 12.dp)
                    .testTag(GlobalSearchTestTags.ROW),
            ) {
                Text(
                    text = result.title,
                    style = MaterialTheme.typography.bodyLarge,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                if (!result.snippet.isNullOrBlank()) {
                    Text(
                        text = result.snippet,
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
            }
    }
}

@Composable
private fun tabLabel(tab: MultiSearchTab, results: SearchResults): String = when (tab) {
    MultiSearchTab.All -> stringResource(R.string.multi_search_tab_all)
    is MultiSearchTab.Category -> {
        val category = results.categories.firstOrNull { it.type == tab.type }
        val count = category?.count ?: 0
        "${categoryLabel(tab.type)} ($count)"
    }
}

@Composable
private fun categoryLabel(type: SearchEntityType): String = stringResource(
    when (type) {
        SearchEntityType.USER -> R.string.multi_search_cat_users
        SearchEntityType.POST -> R.string.multi_search_cat_posts
        SearchEntityType.VIDEO -> R.string.multi_search_cat_videos
        SearchEntityType.CATALOG -> R.string.multi_search_cat_catalog
        SearchEntityType.FILE -> R.string.multi_search_cat_files
        SearchEntityType.MESSAGE -> R.string.multi_search_cat_messages
        SearchEntityType.TICKET -> R.string.multi_search_cat_tickets
        SearchEntityType.CONTACT -> R.string.multi_search_cat_contacts
        SearchEntityType.CALENDAR -> R.string.multi_search_cat_calendar
        SearchEntityType.OTHER -> R.string.multi_search_cat_other
    },
)
