@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.knowledgebase.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Article
import androidx.compose.material3.AssistChip
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.model.kb.KbArticle
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.core.ui.state.StaleBanner

/** KB-AND-1 - stable testTags for the Knowledge Base article detail screen. */
object KbDetailTestTags {
    const val SCREEN = "kb_detail_screen"
    const val NOT_FOUND = "kb_detail_not_found"
    const val ERROR_RETRY = "kb_detail_error_retry"
    const val BODY = "kb_detail_body"
}

/**
 * KB-AND-1 - route-level entry for the Knowledge Base article detail (screen 2). Collects the state and wires
 * the one-shot NavigateToLogin effect to the re-auth handoff.
 */
@Composable
fun KbDetailRoute(
    onBack: () -> Unit,
    onNavigateToLogin: () -> Unit,
    viewModel: KbDetailViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()

    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is KbEffect.NavigateToLogin -> onNavigateToLogin()
            }
        }
    }

    KbDetailScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::onRetry,
    )
}

/** KB-AND-1 - stateless Knowledge Base article detail (title + tags + plain-text body). */
@Composable
fun KbDetailScreen(
    state: KbDetailUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(KbDetailTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.kb_detail_title)) },
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
        val isRefreshing = (state as? KbDetailUiState.Content)?.isRefreshing == true
        PullToRefreshBox(
            isRefreshing = isRefreshing,
            onRefresh = onRefresh,
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
        ) {
            when (state) {
                is KbDetailUiState.Loading -> LoadingState()

                is KbDetailUiState.NotFound ->
                    EmptyState(
                        modifier = Modifier.testTag(KbDetailTestTags.NOT_FOUND),
                        title = stringResource(R.string.kb_detail_not_found_title),
                        body = stringResource(R.string.kb_detail_not_found_body),
                        imageVector = Icons.Outlined.Article,
                    )

                is KbDetailUiState.Error ->
                    ErrorState(
                        modifier = Modifier.testTag(KbDetailTestTags.ERROR_RETRY),
                        message = state.error.message,
                        onRetry = onRetry,
                    )

                is KbDetailUiState.Content ->
                    KbDetailContent(article = state.article, isStale = state.isStale, onRetry = onRetry)
            }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun KbDetailContent(
    article: KbArticle,
    isStale: Boolean,
    onRetry: () -> Unit,
) {
    Column(modifier = Modifier.fillMaxSize()) {
        StaleBanner(stale = isStale, refreshing = false, onRetry = onRetry)
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(
                text = article.title?.ifBlank { null } ?: stringResource(R.string.kb_article_untitled),
                style = MaterialTheme.typography.headlineSmall,
            )
            val meta = detailMeta(article)
            if (meta.isNotBlank()) {
                Text(
                    text = meta,
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            if (article.tags.isNotEmpty()) {
                FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    article.tags.forEach { tag ->
                        AssistChip(onClick = {}, enabled = false, label = { Text(tag) })
                    }
                }
            }
            HorizontalDivider()
            val body = article.body?.ifBlank { null } ?: article.excerpt?.ifBlank { null }
            Text(
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag(KbDetailTestTags.BODY),
                text = body ?: stringResource(R.string.kb_detail_empty_body),
                style = MaterialTheme.typography.bodyMedium,
            )
        }
    }
}

/** Category • helpfulness • updated-time meta line for the detail header (blank parts dropped). */
@Composable
private fun detailMeta(article: KbArticle): String {
    val parts = mutableListOf<String>()
    article.category?.ifBlank { null }?.let { parts.add(it) }
    val pct = com.testlogon.android.data.knowledgebase.KbMath
        .helpfulnessPercent(article.helpfulCount, article.notHelpfulCount)
    if (pct.isNotBlank()) parts.add(stringResource(R.string.kb_helpful_pct, pct))
    val updated = kbRelativeTime(article.updatedAt)
    if (updated.isNotBlank()) parts.add(stringResource(R.string.kb_updated, updated))
    return parts.joinToString("  •  ")
}
