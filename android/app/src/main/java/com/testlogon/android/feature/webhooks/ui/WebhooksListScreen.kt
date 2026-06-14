@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.webhooks.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Webhook
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
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
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.model.webhooks.Webhook
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.core.ui.state.StaleBanner

/** AND-398 - stable testTags for the webhooks list screen + its rows. */
object WebhooksListTestTags {
    const val SCREEN = "webhooks_list_screen"
    const val EMPTY = "webhooks_empty"
    const val EMPTY_CREATE = "webhooks_empty_create"
    const val ERROR_RETRY = "webhooks_error_retry"
    const val CREATE_FAB = "webhooks_create_fab"

    fun row(id: String) = "webhook_row_$id"
}

/**
 * AND-398 - route-level entry for the webhooks list (screen 1). Collects the state, wires the one-shot
 * NavigateToLogin effect to the re-auth handoff, taps a row through to the detail, and the FAB / empty-state CTA
 * to the create screen. Refreshes on (re)entry so a create round-trip shows the new endpoint.
 */
@Composable
fun WebhooksListRoute(
    onBack: () -> Unit,
    onOpenWebhook: (String) -> Unit,
    onCreate: () -> Unit,
    onNavigateToLogin: () -> Unit,
    viewModel: WebhooksListViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()

    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is WebhooksEffect.NavigateToLogin -> onNavigateToLogin()
                is WebhooksEffect.CreateSucceeded -> Unit // not emitted by the list VM
            }
        }
    }

    WebhooksListScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::onRetry,
        onCreate = onCreate,
        onWebhookClick = onOpenWebhook,
    )
}

/** AND-398 - stateless webhook-endpoints list (URL primary + event count + enabled/disabled status). */
@Composable
fun WebhooksListScreen(
    state: WebhooksListUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onCreate: () -> Unit,
    onWebhookClick: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(WebhooksListTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.webhooks_list_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.webhooks_back),
                        )
                    }
                },
            )
        },
        floatingActionButton = {
            if (state is WebhooksListUiState.Content) {
                FloatingActionButton(
                    onClick = onCreate,
                    modifier = Modifier.testTag(WebhooksListTestTags.CREATE_FAB),
                ) {
                    Icon(
                        Icons.Outlined.Webhook,
                        contentDescription = stringResource(R.string.webhooks_create_title),
                    )
                }
            }
        },
    ) { padding ->
        val isRefreshing = (state as? WebhooksListUiState.Content)?.isRefreshing == true
        PullToRefreshBox(
            isRefreshing = isRefreshing,
            onRefresh = onRefresh,
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
        ) {
            when (state) {
                is WebhooksListUiState.Loading -> LoadingState()

                is WebhooksListUiState.Empty ->
                    EmptyState(
                        modifier = Modifier.testTag(WebhooksListTestTags.EMPTY),
                        title = stringResource(R.string.webhooks_empty_title),
                        body = stringResource(R.string.webhooks_empty_body),
                        imageVector = Icons.Outlined.Webhook,
                        actionLabel = stringResource(R.string.webhooks_create_cta),
                        onAction = onCreate,
                    )

                is WebhooksListUiState.Error ->
                    ErrorState(
                        modifier = Modifier.testTag(WebhooksListTestTags.ERROR_RETRY),
                        message = state.message,
                        onRetry = onRetry,
                    )

                is WebhooksListUiState.Content ->
                    WebhooksContent(state = state, onRetry = onRetry, onWebhookClick = onWebhookClick)
            }
        }
    }
}

@Composable
private fun WebhooksContent(
    state: WebhooksListUiState.Content,
    onRetry: () -> Unit,
    onWebhookClick: (String) -> Unit,
) {
    Column(modifier = Modifier.fillMaxSize()) {
        StaleBanner(stale = state.isStale, refreshing = false, onRetry = onRetry)
        LazyColumn(modifier = Modifier.fillMaxSize()) {
            items(items = state.items, key = { it.id }) { webhook ->
                WebhookRow(webhook = webhook, onClick = { onWebhookClick(webhook.id) })
            }
        }
    }
}

/**
 * AND-398 - one endpoint row. A merged contentDescription (FR / §9 a11y: "Webhook to {url}, {n} events,
 * {enabled|disabled}") is applied via semantics(mergeDescendants=true) so a screen reader announces a single,
 * complete description; the child Texts remain in the unmerged tree (testable) and visible. Status is conveyed
 * by text (not colour alone).
 */
@Composable
private fun WebhookRow(
    webhook: Webhook,
    onClick: () -> Unit,
) {
    val statusText = stringResource(
        if (webhook.enabled) R.string.webhooks_status_enabled else R.string.webhooks_status_disabled,
    )
    val eventsText = pluralStringResource(
        R.plurals.webhooks_event_count,
        webhook.events.size,
        webhook.events.size,
    )
    val rowDescription = stringResource(
        R.string.webhooks_row_content_description,
        webhook.url,
        eventsText,
        statusText,
    )
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 48.dp)
            .testTag(WebhooksListTestTags.row(webhook.id))
            .clickable(onClick = onClick)
            .semantics(mergeDescendants = true) { contentDescription = rowDescription }
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        Text(
            text = webhook.url,
            style = MaterialTheme.typography.titleSmall,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
        Row(
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                text = eventsText,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                text = statusText,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}
