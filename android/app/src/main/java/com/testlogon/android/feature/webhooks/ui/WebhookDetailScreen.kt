@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.webhooks.ui

import android.text.format.DateUtils
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.SearchOff
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
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
import com.testlogon.android.core.model.webhooks.Webhook
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState

/** AND-398 - stable testTags for the webhook detail screen. */
object WebhookDetailTestTags {
    const val SCREEN = "webhook_detail_screen"
    const val NOT_FOUND = "webhook_detail_not_found"
    const val URL = "webhook_detail_url"
    const val EVENTS = "webhook_detail_events"
}

/**
 * AND-398 - route-level entry for the webhook detail (screen 2). Collects state and wires NavigateToLogin to the
 * re-auth handoff.
 */
@Composable
fun WebhookDetailRoute(
    onBack: () -> Unit,
    onNavigateToLogin: () -> Unit,
    viewModel: WebhookDetailViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()

    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is WebhooksEffect.NavigateToLogin -> onNavigateToLogin()
                is WebhooksEffect.CreateSucceeded -> Unit // not emitted by the detail VM
            }
        }
    }

    WebhookDetailScreen(
        state = state,
        onBack = onBack,
        onRetry = viewModel::load,
    )
}

/** AND-398 - stateless detail (URL, full event list, enabled flag, creation time, masked secret indicator). */
@Composable
fun WebhookDetailScreen(
    state: WebhookDetailUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(WebhookDetailTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.webhooks_detail_title)) },
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
    ) { padding ->
        val content = Modifier
            .fillMaxSize()
            .padding(padding)
        when (state) {
            is WebhookDetailUiState.Loading -> LoadingState(modifier = content)

            is WebhookDetailUiState.NotFound ->
                EmptyState(
                    modifier = content.testTag(WebhookDetailTestTags.NOT_FOUND),
                    title = stringResource(R.string.webhooks_detail_not_found_title),
                    body = stringResource(R.string.webhooks_detail_not_found_body),
                    imageVector = Icons.Outlined.SearchOff,
                )

            is WebhookDetailUiState.Error ->
                ErrorState(modifier = content, message = state.message, onRetry = onRetry)

            is WebhookDetailUiState.Content ->
                DetailBody(webhook = state.webhook, modifier = content)
        }
    }
}

@Composable
private fun DetailBody(webhook: Webhook, modifier: Modifier = Modifier) {
    Column(
        modifier = modifier
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Field(label = stringResource(R.string.webhooks_field_url), value = webhook.url, tag = WebhookDetailTestTags.URL)

        if (webhook.description.isNotBlank()) {
            Field(label = stringResource(R.string.webhooks_field_description), value = webhook.description)
        }

        Field(
            label = stringResource(R.string.webhooks_field_status),
            value = stringResource(
                if (webhook.enabled) R.string.webhooks_status_enabled else R.string.webhooks_status_disabled,
            ),
        )

        Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(
                text = stringResource(R.string.webhooks_field_events),
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag(WebhookDetailTestTags.EVENTS),
                verticalArrangement = Arrangement.spacedBy(2.dp),
            ) {
                if (webhook.events.isEmpty()) {
                    Text(
                        text = stringResource(R.string.webhooks_events_none),
                        style = MaterialTheme.typography.bodyMedium,
                    )
                } else {
                    webhook.events.forEach { event ->
                        Text(text = event, style = MaterialTheme.typography.bodyMedium)
                    }
                }
            }
        }

        val created = relativeTime(webhook.createdAt)
        if (created.isNotBlank()) {
            Field(label = stringResource(R.string.webhooks_field_created), value = created)
        }

        if (webhook.secretSet) {
            HorizontalDivider()
            Text(
                text = stringResource(R.string.webhooks_secret_configured),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun Field(label: String, value: String, tag: String? = null) {
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(
            text = label,
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        val valueModifier = if (tag != null) Modifier.testTag(tag) else Modifier
        Text(text = value, style = MaterialTheme.typography.bodyLarge, modifier = valueModifier)
    }
}

/**
 * AND-398 - relative-time copy from an EPOCH-SECONDS value. UI-only (android.text.format); returns "" for null
 * / non-positive timestamps. Mirrors the AND-372 helper.
 */
internal fun relativeTime(epochSeconds: Long?, nowMs: Long = System.currentTimeMillis()): String {
    if (epochSeconds == null || epochSeconds <= 0L) return ""
    return DateUtils.getRelativeTimeSpanString(
        epochSeconds * 1000L,
        nowMs,
        DateUtils.MINUTE_IN_MILLIS,
    ).toString()
}
