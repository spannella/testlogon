@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.apikeys.ui

import androidx.compose.foundation.layout.Arrangement
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
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.ContentCopy
import androidx.compose.material.icons.outlined.Delete
import androidx.compose.material.icons.outlined.VpnKey
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.core.ui.state.StaleBanner
import com.testlogon.android.feature.apikeys.data.ApiKey
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle

/** B-APIKEY (batch 7) - stable testTags for the API-keys list screen + its rows. */
object ApiKeysListTestTags {
    const val SCREEN = "api_keys_list_screen"
    const val EMPTY = "api_keys_empty"
    const val ERROR_RETRY = "api_keys_error_retry"
    const val CREATE_FAB = "api_keys_create_fab"
    const val SECRET_DIALOG = "api_keys_secret_dialog"
    const val SECRET_COPY = "api_keys_secret_copy"

    fun row(id: String) = "api_key_row_$id"
    fun revoke(id: String) = "api_key_revoke_$id"
}

/**
 * B-APIKEY (batch 7) - route-level entry for the API-keys list. Collects the state, wires the one-shot
 * NavigateToLogin effect to the re-auth handoff, the FAB / empty CTA to the create screen, and accepts an
 * optional [newSecret] (handed back from the create screen via the nav result) to display once.
 */
@Composable
fun ApiKeysListRoute(
    onBack: () -> Unit,
    onCreate: () -> Unit,
    onNavigateToLogin: () -> Unit,
    newSecret: String? = null,
    onSecretConsumed: () -> Unit = {},
    viewModel: ApiKeysListViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()

    LaunchedEffect(newSecret) {
        if (newSecret != null) {
            viewModel.showNewSecret(newSecret)
            onSecretConsumed()
        }
    }

    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is ApiKeysEffect.NavigateToLogin -> onNavigateToLogin()
                is ApiKeysEffect.CreateSucceeded -> Unit // not emitted by the list VM
            }
        }
    }

    ApiKeysListScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::onRetry,
        onCreate = onCreate,
        onRevoke = viewModel::revoke,
        onDismissSecret = viewModel::dismissNewSecret,
    )
}

/** B-APIKEY (batch 7) - stateless API-keys list (label + prefix + created/expiry + revoke; one-time secret dialog). */
@Composable
fun ApiKeysListScreen(
    state: ApiKeysListUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onCreate: () -> Unit,
    onRevoke: (String) -> Unit,
    onDismissSecret: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(ApiKeysListTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.api_keys_list_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.api_keys_back),
                        )
                    }
                },
            )
        },
        floatingActionButton = {
            if (state is ApiKeysListUiState.Content || state is ApiKeysListUiState.Empty) {
                FloatingActionButton(
                    onClick = onCreate,
                    modifier = Modifier.testTag(ApiKeysListTestTags.CREATE_FAB),
                ) {
                    Icon(Icons.Outlined.Add, contentDescription = stringResource(R.string.api_keys_create_title))
                }
            }
        },
    ) { padding ->
        val isRefreshing = (state as? ApiKeysListUiState.Content)?.isRefreshing == true
        PullToRefreshBox(
            isRefreshing = isRefreshing,
            onRefresh = onRefresh,
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
        ) {
            when (state) {
                is ApiKeysListUiState.Loading -> LoadingState()

                is ApiKeysListUiState.Empty ->
                    EmptyState(
                        modifier = Modifier.testTag(ApiKeysListTestTags.EMPTY),
                        title = stringResource(R.string.api_keys_empty_title),
                        body = stringResource(R.string.api_keys_empty_body),
                        imageVector = Icons.Outlined.VpnKey,
                        actionLabel = stringResource(R.string.api_keys_create_cta),
                        onAction = onCreate,
                    )

                is ApiKeysListUiState.Error ->
                    ErrorState(
                        modifier = Modifier.testTag(ApiKeysListTestTags.ERROR_RETRY),
                        message = state.message,
                        onRetry = onRetry,
                    )

                is ApiKeysListUiState.Content ->
                    ApiKeysContent(state = state, onRetry = onRetry, onRevoke = onRevoke)
            }
        }
    }

    val secret = (state as? ApiKeysListUiState.Content)?.newSecret
    if (secret != null) {
        SecretDialog(secret = secret, onDismiss = onDismissSecret)
    }
}

@Composable
private fun ApiKeysContent(
    state: ApiKeysListUiState.Content,
    onRetry: () -> Unit,
    onRevoke: (String) -> Unit,
) {
    Column(modifier = Modifier.fillMaxSize()) {
        StaleBanner(stale = state.isStale, refreshing = false, onRetry = onRetry)
        if (state.actionError != null) {
            Text(
                text = state.actionError,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error,
                modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
            )
        }
        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            items(items = state.items, key = { it.id }) { key ->
                ApiKeyRow(
                    key = key,
                    revoking = state.revokingId == key.id,
                    onRevoke = { onRevoke(key.id) },
                )
            }
        }
    }
}

@Composable
private fun ApiKeyRow(
    key: ApiKey,
    revoking: Boolean,
    onRevoke: () -> Unit,
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(ApiKeysListTestTags.row(key.id)),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(
                    text = key.label.ifBlank { stringResource(R.string.api_keys_unnamed) },
                    style = MaterialTheme.typography.titleSmall,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                if (key.prefix.isNotBlank()) {
                    Text(
                        text = key.prefix + "…",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Text(
                    text = subtitle(key),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                if (key.capabilities.isNotEmpty()) {
                    Text(
                        text = stringResource(R.string.api_keys_scopes_prefix, key.capabilities.joinToString(", ")),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
            }
            if (revoking) {
                CircularProgressIndicator(strokeWidth = 2.dp, modifier = Modifier.size(20.dp))
            } else {
                IconButton(
                    onClick = onRevoke,
                    modifier = Modifier.testTag(ApiKeysListTestTags.revoke(key.id)),
                ) {
                    Icon(
                        Icons.Outlined.Delete,
                        contentDescription = stringResource(R.string.api_keys_revoke),
                        tint = MaterialTheme.colorScheme.error,
                    )
                }
            }
        }
    }
}

@Composable
private fun subtitle(key: ApiKey): String {
    val created = key.createdAt?.let { formatDate(it) }
    val expires = key.expiresAt?.let { formatDate(it) }
    return when {
        created != null && expires != null ->
            stringResource(R.string.api_keys_created_expires, created, expires)
        created != null -> stringResource(R.string.api_keys_created, created)
        expires != null -> stringResource(R.string.api_keys_expires, expires)
        else -> stringResource(R.string.api_keys_no_expiry)
    }
}

private val dateFormatter: DateTimeFormatter =
    DateTimeFormatter.ofLocalizedDate(FormatStyle.MEDIUM)

private fun formatDate(epochSeconds: Long): String =
    runCatching {
        Instant.ofEpochSecond(epochSeconds).atZone(ZoneId.systemDefault()).toLocalDate().format(dateFormatter)
    }.getOrDefault("")

@Composable
private fun SecretDialog(secret: String, onDismiss: () -> Unit) {
    val clipboard = LocalClipboardManager.current
    var copied by remember { mutableStateOf(false) }
    AlertDialog(
        modifier = Modifier.testTag(ApiKeysListTestTags.SECRET_DIALOG),
        onDismissRequest = onDismiss,
        icon = { Icon(Icons.Outlined.VpnKey, contentDescription = null) },
        title = { Text(stringResource(R.string.api_keys_secret_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(stringResource(R.string.api_keys_secret_warning))
                Card {
                    Text(
                        text = secret,
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.fillMaxWidth().padding(12.dp),
                    )
                }
                if (copied) {
                    Text(
                        text = stringResource(R.string.api_keys_secret_copied),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.primary,
                    )
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.api_keys_secret_done)) }
        },
        dismissButton = {
            TextButton(
                onClick = {
                    clipboard.setText(AnnotatedString(secret))
                    copied = true
                },
                modifier = Modifier.testTag(ApiKeysListTestTags.SECRET_COPY),
            ) {
                Icon(Icons.Outlined.ContentCopy, contentDescription = null, modifier = Modifier.size(18.dp))
                Text(stringResource(R.string.api_keys_secret_copy))
            }
        },
    )
}
