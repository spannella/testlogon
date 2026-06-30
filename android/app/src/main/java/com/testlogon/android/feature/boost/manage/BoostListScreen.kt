@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.boost.manage

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.model.ads.ContentBoost
import com.testlogon.android.core.model.syndicates.formatCents
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState

/** Stable testTags for the boost list screen. */
object BoostListTestTags {
    const val SCREEN = "boost_list_screen"
    const val LIST = "boost_list"
    const val EMPTY = "boost_list_empty"
    const val ERROR_RETRY = "boost_list_error_retry"
    const val REFRESH = "boost_list_refresh"
    fun row(boostId: String) = "boost_list_row_$boostId"
}

@Composable
fun BoostListRoute(
    onBack: () -> Unit,
    onOpenBoost: (String) -> Unit,
    viewModel: BoostListViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    BoostListScreen(
        state = state,
        onBack = onBack,
        onRetry = viewModel::onRetry,
        onRefresh = viewModel::refresh,
        onOpenBoost = onOpenBoost,
    )
}

@Composable
fun BoostListScreen(
    state: BoostListUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onRefresh: () -> Unit,
    onOpenBoost: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(BoostListTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("Your boosts") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    IconButton(onClick = onRefresh, modifier = Modifier.testTag(BoostListTestTags.REFRESH)) {
                        Icon(Icons.Filled.Refresh, contentDescription = "Refresh")
                    }
                },
            )
        },
    ) { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding)) {
            when (state) {
                is BoostListUiState.Loading -> LoadingState()
                is BoostListUiState.Error -> ErrorState(
                    message = state.error.message,
                    onRetry = onRetry,
                    modifier = Modifier.testTag(BoostListTestTags.ERROR_RETRY),
                )
                is BoostListUiState.Content ->
                    if (state.boosts.isEmpty()) {
                        EmptyState(
                            title = "No boosts yet",
                            body = "Boost a post, video, or broadcast to promote its reach. Your boosts will appear here.",
                            modifier = Modifier.testTag(BoostListTestTags.EMPTY),
                        )
                    } else {
                        LazyColumn(
                            modifier = Modifier.fillMaxSize().testTag(BoostListTestTags.LIST),
                            contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
                            verticalArrangement = Arrangement.spacedBy(12.dp),
                        ) {
                            itemsIndexed(
                                state.boosts,
                                // Composite key (id + index) so a backend that returns duplicate
                                // boost_ids cannot crash the LazyColumn (the VM also de-dups by id).
                                key = { index, boost -> "${boost.boostId}#$index" },
                            ) { _, boost ->
                                BoostRow(boost, onClick = { onOpenBoost(boost.boostId) })
                            }
                        }
                    }
            }
        }
    }
}

@Composable
private fun BoostRow(boost: ContentBoost, onClick: () -> Unit) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .testTag(BoostListTestTags.row(boost.boostId)),
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Text(
                    boost.boostId,
                    style = MaterialTheme.typography.titleSmall,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f),
                )
                Text(boost.status, style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary)
            }
            val spent = boost.spentCents ?: 0L
            val remaining = boost.remainingCents ?: (boost.budgetCents - spent)
            Text(
                text = "${formatCents(spent)} / ${formatCents(boost.budgetCents)} spent - ${formatCents(remaining)} remaining",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}
