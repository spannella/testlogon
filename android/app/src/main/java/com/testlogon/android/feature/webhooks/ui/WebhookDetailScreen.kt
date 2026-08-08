@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.webhooks.ui

import android.text.format.DateUtils
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Send
import androidx.compose.material.icons.filled.VpnKey
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.SearchOff
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.TextButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.remember
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import kotlinx.coroutines.launch
import com.testlogon.android.R
import com.testlogon.android.core.model.webhooks.Webhook
import com.testlogon.android.core.model.webhooks.WebhookTestResult
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState

/** AND-398 - stable testTags for the webhook detail screen. */
object WebhookDetailTestTags {
    const val SCREEN = "webhook_detail_screen"
    const val NOT_FOUND = "webhook_detail_not_found"
    const val URL = "webhook_detail_url"
    const val EVENTS = "webhook_detail_events"

    // PAR-26 - test-send + rotate-secret.
    const val TEST_BUTTON = "webhook_detail_test_button"
    const val TEST_RESULT = "webhook_detail_test_result"
    const val ROTATE_BUTTON = "webhook_detail_rotate_button"
    const val ROTATE_REVEAL = "webhook_detail_rotate_reveal"
    const val ROTATE_SECRET = "webhook_detail_rotate_secret"
    const val ROTATE_COPY = "webhook_detail_rotate_copy"
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
    val testState by viewModel.testState.collectAsStateWithLifecycle()
    val rotateState by viewModel.rotateState.collectAsStateWithLifecycle()

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
        testState = testState,
        rotateState = rotateState,
        onBack = onBack,
        onRetry = viewModel::load,
        onRunTest = viewModel::runTest,
        onClearTest = viewModel::clearTest,
        onRotateSecret = viewModel::rotateSecret,
        onClearRotate = viewModel::clearRotate,
    )
}

/** AND-398 - stateless detail (URL, full event list, enabled flag, creation time, masked secret indicator). */
@Composable
fun WebhookDetailScreen(
    state: WebhookDetailUiState,
    testState: WebhookDetailViewModel.TestState,
    rotateState: WebhookDetailViewModel.RotateState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onRunTest: () -> Unit,
    onClearTest: () -> Unit,
    onRotateSecret: () -> Unit,
    onClearRotate: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val snackbarHostState = remember { SnackbarHostState() }
    Scaffold(
        modifier = modifier.testTag(WebhookDetailTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbarHostState) },
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
                DetailBody(
                    webhook = state.webhook,
                    testState = testState,
                    rotateState = rotateState,
                    snackbarHostState = snackbarHostState,
                    onRunTest = onRunTest,
                    onClearTest = onClearTest,
                    onRotateSecret = onRotateSecret,
                    onClearRotate = onClearRotate,
                    modifier = content,
                )
        }
    }
}

@Composable
private fun DetailBody(
    webhook: Webhook,
    testState: WebhookDetailViewModel.TestState,
    rotateState: WebhookDetailViewModel.RotateState,
    snackbarHostState: SnackbarHostState,
    onRunTest: () -> Unit,
    onClearTest: () -> Unit,
    onRotateSecret: () -> Unit,
    onClearRotate: () -> Unit,
    modifier: Modifier = Modifier,
) {
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

        HorizontalDivider()

        // PAR-26 - test-send.
        TestSection(
            testState = testState,
            onRunTest = onRunTest,
            onClearTest = onClearTest,
        )

        // PAR-26 - rotate signing secret (one-time reveal).
        RotateSection(
            rotateState = rotateState,
            snackbarHostState = snackbarHostState,
            onRotateSecret = onRotateSecret,
            onClearRotate = onClearRotate,
        )
    }
}

@Composable
private fun TestSection(
    testState: WebhookDetailViewModel.TestState,
    onRunTest: () -> Unit,
    onClearTest: () -> Unit,
) {
    val running = testState is WebhookDetailViewModel.TestState.Running
    Button(
        onClick = onRunTest,
        enabled = !running,
        modifier = Modifier.fillMaxWidth().testTag(WebhookDetailTestTags.TEST_BUTTON),
    ) {
        if (running) {
            CircularProgressIndicator(strokeWidth = 2.dp, modifier = Modifier.size(18.dp))
            Text(stringResource(R.string.webhooks_test_sending), modifier = Modifier.padding(start = 8.dp))
        } else {
            Icon(Icons.Filled.Send, contentDescription = null)
            Text(stringResource(R.string.webhooks_test_button), modifier = Modifier.padding(start = 8.dp))
        }
    }
    when (testState) {
        is WebhookDetailViewModel.TestState.Result ->
            TestResultCard(result = testState.result, onDismiss = onClearTest)
        is WebhookDetailViewModel.TestState.Error ->
            TestOutcomeCard(
                title = stringResource(R.string.webhooks_test_failed),
                success = false,
                lines = listOf(testState.message),
                onDismiss = onClearTest,
            )
        else -> Unit
    }
}

@Composable
private fun TestResultCard(result: WebhookTestResult, onDismiss: () -> Unit) {
    // A 200 status="failed" (unreachable host) is surfaced as a failed delivery, NOT a transport error.
    val lines = buildList {
        result.responseCode?.let { add(stringResource(R.string.webhooks_test_response_code, it)) }
        result.error?.takeIf { it.isNotBlank() }
            ?.let { add(stringResource(R.string.webhooks_test_error_label, it)) }
    }
    TestOutcomeCard(
        title = stringResource(
            if (result.succeeded) R.string.webhooks_test_succeeded else R.string.webhooks_test_failed,
        ),
        success = result.succeeded,
        lines = lines,
        onDismiss = onDismiss,
    )
}

@Composable
private fun TestOutcomeCard(
    title: String,
    success: Boolean,
    lines: List<String>,
    onDismiss: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth().testTag(WebhookDetailTestTags.TEST_RESULT)) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Text(
                text = stringResource(R.string.webhooks_test_result_title),
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                text = title,
                style = MaterialTheme.typography.titleSmall,
                color = if (success) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error,
            )
            lines.forEach { Text(text = it, style = MaterialTheme.typography.bodyMedium) }
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.webhooks_test_dismiss))
            }
        }
    }
}

@Composable
private fun RotateSection(
    rotateState: WebhookDetailViewModel.RotateState,
    snackbarHostState: SnackbarHostState,
    onRotateSecret: () -> Unit,
    onClearRotate: () -> Unit,
) {
    val rotating = rotateState is WebhookDetailViewModel.RotateState.Running
    OutlinedButton(
        onClick = onRotateSecret,
        enabled = !rotating,
        modifier = Modifier.fillMaxWidth().testTag(WebhookDetailTestTags.ROTATE_BUTTON),
    ) {
        if (rotating) {
            CircularProgressIndicator(strokeWidth = 2.dp, modifier = Modifier.size(18.dp))
            Text(stringResource(R.string.webhooks_rotate_rotating), modifier = Modifier.padding(start = 8.dp))
        } else {
            Icon(Icons.Filled.VpnKey, contentDescription = null)
            Text(stringResource(R.string.webhooks_rotate_button), modifier = Modifier.padding(start = 8.dp))
        }
    }
    when (rotateState) {
        is WebhookDetailViewModel.RotateState.Revealed ->
            RotateRevealCard(
                secret = rotateState.secret,
                snackbarHostState = snackbarHostState,
                onDone = onClearRotate,
            )
        is WebhookDetailViewModel.RotateState.Error ->
            TestOutcomeCard(
                title = stringResource(R.string.webhooks_test_failed),
                success = false,
                lines = listOf(rotateState.message),
                onDismiss = onClearRotate,
            )
        else -> Unit
    }
}

@Composable
private fun RotateRevealCard(
    secret: String,
    snackbarHostState: SnackbarHostState,
    onDone: () -> Unit,
) {
    val clipboard = LocalClipboardManager.current
    val scope = androidx.compose.runtime.rememberCoroutineScope()
    val copiedMsg = stringResource(R.string.webhooks_rotate_copied)
    Card(modifier = Modifier.fillMaxWidth().testTag(WebhookDetailTestTags.ROTATE_REVEAL)) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(
                text = stringResource(R.string.webhooks_rotate_revealed_title),
                style = MaterialTheme.typography.titleSmall,
            )
            Text(
                text = stringResource(R.string.webhooks_rotate_revealed_body),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                text = secret,
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.testTag(WebhookDetailTestTags.ROTATE_SECRET),
            )
            OutlinedButton(
                onClick = {
                    clipboard.setText(AnnotatedString(secret))
                    scope.launch { snackbarHostState.showSnackbar(copiedMsg) }
                },
                modifier = Modifier.fillMaxWidth().testTag(WebhookDetailTestTags.ROTATE_COPY),
            ) {
                Icon(Icons.Filled.ContentCopy, contentDescription = null)
                Text(stringResource(R.string.webhooks_rotate_copy), modifier = Modifier.padding(start = 8.dp))
            }
            TextButton(onClick = onDone) {
                Text(stringResource(R.string.webhooks_rotate_done))
            }
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
