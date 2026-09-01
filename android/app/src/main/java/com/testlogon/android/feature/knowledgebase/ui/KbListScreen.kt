@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.knowledgebase.ui

import android.text.format.DateUtils
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.MenuBook
import androidx.compose.material.icons.outlined.Search
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.model.kb.KbArticleSummary
import com.testlogon.android.core.model.kb.KbCategory
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.core.ui.state.StaleBanner
import com.testlogon.android.data.knowledgebase.KbMath

/** KB-AND-1 - stable testTags for the Knowledge Base list / search screen + its rows. */
object KbListTestTags {
    const val SCREEN = "kb_list_screen"
    const val SEARCH = "kb_search_field"
    const val EMPTY = "kb_empty"
    const val ERROR_RETRY = "kb_error_retry"

    fun row(articleId: String) = "kb_article_row_$articleId"
}

/**
 * KB-AND-1 - route-level entry for the Knowledge Base list (screen 1). Collects the state, wires the one-shot
 * NavigateToLogin effect to the re-auth handoff, and taps through to an article's detail.
 */
@Composable
fun KbListRoute(
    onBack: () -> Unit,
    onOpenArticle: (String) -> Unit,
    onNavigateToLogin: () -> Unit,
    viewModel: KbListViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()

    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is KbEffect.NavigateToLogin -> onNavigateToLogin()
            }
        }
    }

    KbListScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::onRetry,
        onQueryChange = viewModel::onQueryChange,
        onSelectCategory = viewModel::onSelectCategory,
        onArticleClick = onOpenArticle,
    )
}

/** KB-AND-1 - stateless Knowledge Base list: search box + optional category chips + article rows. */
@Composable
fun KbListScreen(
    state: KbListUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onQueryChange: (String) -> Unit,
    onSelectCategory: (String?) -> Unit,
    onArticleClick: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(KbListTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.kb_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.kb_back),
                        )
                    }
                },
            )
        },
    ) { padding ->
        val content = state as? KbListUiState.Content
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
        ) {
            KbSearchField(
                query = content?.query.orEmpty(),
                onQueryChange = onQueryChange,
            )
            if (content != null && content.categories.isNotEmpty()) {
                KbCategoryChips(
                    categories = content.categories,
                    selectedId = content.selectedCategoryId,
                    onSelect = onSelectCategory,
                )
            }
            val isRefreshing = content?.isRefreshing == true
            PullToRefreshBox(
                isRefreshing = isRefreshing,
                onRefresh = onRefresh,
                modifier = Modifier.fillMaxSize(),
            ) {
                when (state) {
                    is KbListUiState.Loading -> LoadingState()

                    is KbListUiState.Empty ->
                        EmptyState(
                            modifier = Modifier.testTag(KbListTestTags.EMPTY),
                            title = stringResource(R.string.kb_empty_title),
                            body = stringResource(R.string.kb_empty_body),
                            imageVector = Icons.Outlined.MenuBook,
                        )

                    is KbListUiState.Error ->
                        ErrorState(
                            modifier = Modifier.testTag(KbListTestTags.ERROR_RETRY),
                            message = state.error.message,
                            onRetry = onRetry,
                        )

                    is KbListUiState.Content ->
                        KbListContent(state = state, onRetry = onRetry, onArticleClick = onArticleClick)
                }
            }
        }
    }
}

@Composable
private fun KbSearchField(
    query: String,
    onQueryChange: (String) -> Unit,
) {
    OutlinedTextField(
        value = query,
        onValueChange = onQueryChange,
        singleLine = true,
        leadingIcon = { Icon(Icons.Outlined.Search, contentDescription = null) },
        placeholder = { Text(stringResource(R.string.kb_search_placeholder)) },
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 8.dp)
            .testTag(KbListTestTags.SEARCH),
    )
}

@Composable
private fun KbCategoryChips(
    categories: List<KbCategory>,
    selectedId: String?,
    onSelect: (String?) -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .horizontalScroll(rememberScrollState())
            .padding(horizontal = 16.dp, vertical = 4.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        FilterChip(
            selected = selectedId == null,
            onClick = { onSelect(null) },
            label = { Text(stringResource(R.string.kb_category_all)) },
        )
        categories.forEach { cat ->
            FilterChip(
                selected = selectedId == cat.categoryId,
                onClick = { onSelect(cat.categoryId) },
                label = {
                    Text(cat.name?.ifBlank { null } ?: stringResource(R.string.kb_category_untitled))
                },
            )
        }
    }
}

@Composable
private fun KbListContent(
    state: KbListUiState.Content,
    onRetry: () -> Unit,
    onArticleClick: (String) -> Unit,
) {
    Column(modifier = Modifier.fillMaxSize()) {
        StaleBanner(stale = state.isStale, refreshing = false, onRetry = onRetry)
        if (state.articles.isEmpty()) {
            EmptyState(
                modifier = Modifier.testTag(KbListTestTags.EMPTY),
                title = stringResource(R.string.kb_no_results_title),
                body = stringResource(R.string.kb_no_results_body),
                imageVector = Icons.Outlined.Search,
            )
        } else {
            LazyColumn(modifier = Modifier.fillMaxSize()) {
                items(items = state.articles, key = { it.articleId }) { article ->
                    KbArticleRow(article = article, onClick = { onArticleClick(article.articleId) })
                }
            }
        }
    }
}

@Composable
private fun KbArticleRow(
    article: KbArticleSummary,
    onClick: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 48.dp)
            .testTag(KbListTestTags.row(article.articleId))
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(
            modifier = Modifier.weight(1f),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Text(
                text = article.title?.ifBlank { null } ?: stringResource(R.string.kb_article_untitled),
                style = MaterialTheme.typography.titleSmall,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
            )
            val snippet = KbMath.snippet(article.excerpt, null)
            if (snippet.isNotBlank()) {
                Text(
                    text = snippet,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            val meta = buildRowMeta(article)
            if (meta.isNotBlank()) {
                Text(
                    text = meta,
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

/** Composes the secondary meta line: category • helpfulness • updated-time (blank parts dropped). */
@Composable
private fun buildRowMeta(article: KbArticleSummary): String {
    val parts = mutableListOf<String>()
    article.category?.ifBlank { null }?.let { parts.add(it) }
    val pct = KbMath.helpfulnessPercent(article.helpfulCount, article.notHelpfulCount)
    if (pct.isNotBlank()) parts.add(stringResource(R.string.kb_helpful_pct, pct))
    val updated = kbRelativeTime(article.updatedAt)
    if (updated.isNotBlank()) parts.add(stringResource(R.string.kb_updated, updated))
    return parts.joinToString("  •  ")
}

/**
 * KB-AND-1 - relative-time copy from an EPOCH-SECONDS value. UI-only (android.text.format); returns "" for
 * null / non-positive timestamps. Mirrors the AND-372 tickets helper.
 */
internal fun kbRelativeTime(epochSeconds: Long?, nowMs: Long = System.currentTimeMillis()): String {
    if (epochSeconds == null || epochSeconds <= 0L) return ""
    return DateUtils.getRelativeTimeSpanString(
        epochSeconds * 1000L,
        nowMs,
        DateUtils.MINUTE_IN_MILLIS,
    ).toString()
}
