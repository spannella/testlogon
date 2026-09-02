@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.jira.ui

import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import androidx.browser.customtabs.CustomTabsIntent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.jira.JiraMath

/** JIRA-AND-1 - stable testTags for the Jira sync screen. */
object JiraSyncTestTags {
    const val SCREEN = "jira_sync_screen"
    const val CONNECT = "jira_connect_button"
    const val ISSUE_KEY_INPUT = "jira_issue_key_input"
    const val LINK = "jira_link_button"
    const val UNLINK = "jira_unlink_button"
    const val KEEP_INTERNAL = "jira_keep_internal"
    const val KEEP_JIRA = "jira_keep_jira"
    const val STATE_LABEL = "jira_state_label"
}

/**
 * JIRA-AND-1 - the default redirect URI supplied to the OAuth connect call. The dev backend echoes it into the
 * authorize URL; the user returns to the app manually after consent and re-loads the status (there is NO
 * app-registered deep-link scheme this wave - the AndroidManifest is intentionally untouched).
 */
private const val JIRA_REDIRECT_URI = "https://testlogon.local/integrations/jira/callback"

/**
 * JIRA-AND-1 - route-level entry for the Jira sync surface of a ticket. Collects the state, opens the OAuth
 * authorize URL in a Chrome Custom Tab on [JiraSyncEffect.OpenConnectUrl] (reusing the androidx.browser idiom;
 * never a WebView), and routes the terminal-401 to login.
 */
@Composable
fun JiraSyncRoute(
    onBack: () -> Unit,
    onNavigateToLogin: () -> Unit,
    viewModel: JiraSyncViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val context = LocalContext.current

    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is JiraSyncEffect.NavigateToLogin -> onNavigateToLogin()
                is JiraSyncEffect.OpenConnectUrl -> openCustomTab(context, effect.url)
            }
        }
    }

    JiraSyncScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::load,
        onConnect = { viewModel.onConnect(JIRA_REDIRECT_URI) },
        onIssueKeyChanged = viewModel::onIssueKeyChanged,
        onLink = viewModel::onLinkExisting,
        onUnlink = viewModel::onUnlink,
        onResolve = viewModel::onResolveConflict,
    )
}

/** Opens [url] in a Custom Tab with an ACTION_VIEW fallback (mirrors the SSO / calendar launchers). */
private fun openCustomTab(context: android.content.Context, url: String) {
    val uri = Uri.parse(url)
    try {
        val intent = CustomTabsIntent.Builder().setShowTitle(true).build()
        intent.intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        intent.launchUrl(context, uri)
    } catch (_: ActivityNotFoundException) {
        try {
            context.startActivity(Intent(Intent.ACTION_VIEW, uri).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        } catch (_: ActivityNotFoundException) {
            // No browser available; nothing more to do.
        }
    }
}

/** JIRA-AND-1 - stateless Jira sync surface. */
@Composable
fun JiraSyncScreen(
    state: JiraSyncUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onConnect: () -> Unit,
    onIssueKeyChanged: (String) -> Unit,
    onLink: () -> Unit,
    onUnlink: () -> Unit,
    onResolve: (JiraMath.JiraConflictChoice) -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(JiraSyncTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("Jira sync") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        when {
            state.loading -> LoadingState(modifier = Modifier.padding(padding))
            state.error != null -> ErrorState(
                modifier = Modifier.padding(padding),
                message = state.error.message,
                onRetry = onRefresh,
            )
            else -> JiraSyncBody(
                state = state,
                modifier = Modifier.padding(padding),
                onConnect = onConnect,
                onIssueKeyChanged = onIssueKeyChanged,
                onLink = onLink,
                onUnlink = onUnlink,
                onResolve = onResolve,
            )
        }
    }
}

@Composable
private fun JiraSyncBody(
    state: JiraSyncUiState,
    modifier: Modifier,
    onConnect: () -> Unit,
    onIssueKeyChanged: (String) -> Unit,
    onLink: () -> Unit,
    onUnlink: () -> Unit,
    onResolve: (JiraMath.JiraConflictChoice) -> Unit,
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        // --- Connection card ---
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Connection", style = MaterialTheme.typography.titleMedium)
                Text(
                    if (state.connected) "Connected to Jira" else "Not connected",
                    style = MaterialTheme.typography.bodyMedium,
                )
                if (!state.connected) {
                    Button(
                        onClick = onConnect,
                        enabled = !state.working,
                        modifier = Modifier.testTag(JiraSyncTestTags.CONNECT),
                    ) {
                        Text("Connect Jira")
                    }
                }
            }
        }

        // --- Sync-status card ---
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Ticket sync", style = MaterialTheme.typography.titleMedium)
                val summary = state.summary
                if (summary == null || !summary.linked) {
                    Text(
                        "This ticket is not linked to a Jira issue yet.",
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.testTag(JiraSyncTestTags.STATE_LABEL),
                    )
                    if (state.connected) {
                        OutlinedTextField(
                            value = state.issueKeyDraft,
                            onValueChange = onIssueKeyChanged,
                            label = { Text("Jira issue key (e.g. ABC-123)") },
                            singleLine = true,
                            modifier = Modifier
                                .fillMaxWidth()
                                .testTag(JiraSyncTestTags.ISSUE_KEY_INPUT),
                        )
                        Button(
                            onClick = onLink,
                            enabled = !state.working && state.issueKeyDraft.isNotBlank(),
                            modifier = Modifier.testTag(JiraSyncTestTags.LINK),
                        ) {
                            Text("Link issue")
                        }
                    }
                } else {
                    LinkedSummary(summary = summary)
                    HorizontalDivider()
                    OutlinedButton(
                        onClick = onUnlink,
                        enabled = !state.working,
                        modifier = Modifier.testTag(JiraSyncTestTags.UNLINK),
                    ) {
                        Text("Unlink")
                    }
                    if (summary.state == JiraMath.JiraLinkState.CONFLICT) {
                        ConflictSection(summary = summary, working = state.working, onResolve = onResolve)
                    }
                }
                if (state.actionError != null) {
                    Text(
                        state.actionError,
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
                if (state.working) {
                    CircularProgressIndicator()
                }
            }
        }
    }
}

@Composable
private fun LinkedSummary(summary: JiraMath.JiraSyncSummary) {
    Text(
        "Linked to ${summary.issueKey ?: "issue"}",
        style = MaterialTheme.typography.bodyLarge,
        fontWeight = FontWeight.SemiBold,
    )
    Text(
        "Sync state: ${summary.rawState}",
        style = MaterialTheme.typography.bodyMedium,
        modifier = Modifier.testTag(JiraSyncTestTags.STATE_LABEL),
    )
    if (summary.jiraStatus != null) {
        Text("Jira status: ${summary.jiraStatus}", style = MaterialTheme.typography.bodySmall)
    }
}

@Composable
private fun ConflictSection(
    summary: JiraMath.JiraSyncSummary,
    working: Boolean,
    onResolve: (JiraMath.JiraConflictChoice) -> Unit,
) {
    HorizontalDivider()
    Text("Conflict", style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.error)
    summary.conflictRows.forEach { row ->
        Column(modifier = Modifier.fillMaxWidth()) {
            Text(row.field, style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.SemiBold)
            Text("Yours: ${row.localValue}", style = MaterialTheme.typography.bodySmall)
            Text("Jira: ${row.remoteValue}", style = MaterialTheme.typography.bodySmall)
        }
    }
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        OutlinedButton(
            onClick = { onResolve(JiraMath.JiraConflictChoice.KEEP_INTERNAL) },
            enabled = !working,
            modifier = Modifier.testTag(JiraSyncTestTags.KEEP_INTERNAL),
        ) {
            Text("Keep yours")
        }
        Button(
            onClick = { onResolve(JiraMath.JiraConflictChoice.KEEP_JIRA) },
            enabled = !working,
            modifier = Modifier.testTag(JiraSyncTestTags.KEEP_JIRA),
        ) {
            Text("Keep Jira")
        }
    }
}
