@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.contacts

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.material.icons.filled.PersonSearch
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.runtime.getValue
import androidx.compose.ui.platform.LocalContext

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.PersonAdd
import androidx.compose.material.icons.filled.Star
import androidx.compose.material.icons.outlined.StarBorder
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState

/** Feature 1 — stable test tags for the Contacts hub. */
object ContactsHubTestTags {
    const val SCREEN = "contacts_hub_screen"
    const val CONTACTS_SECTION = "contacts_hub_saved"
    const val SUGGESTIONS_SECTION = "contacts_hub_suggestions"
    fun contactRow(userId: String) = "contacts_hub_contact_$userId"
    fun suggestionRow(userId: String) = "contacts_hub_suggestion_$userId"
    fun favorite(userId: String) = "contacts_hub_fav_$userId"
    fun addSuggestion(userId: String) = "contacts_hub_add_$userId"

    // Feature 2 — device contact sync.
    const val FIND_PEOPLE_BUTTON = "contacts_hub_find_people"
    const val MATCH_SECTION = "contacts_hub_matches"
    const val SYNC_PROGRESS = "contacts_hub_sync_progress"
    fun matchRow(userId: String) = "contacts_hub_match_$userId"
    fun addMatch(userId: String) = "contacts_hub_addmatch_$userId"
}

/**
 * Feature 1 — route-level Contacts hub: a favorites-first saved address book PLUS a
 * "people you may know" section. Reached from the More hub and from the conversation list.
 */
@Composable
fun ContactsHubRoute(
    onOpenContactCard: (userId: String) -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: ContactsHubViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    val matchState by viewModel.matchState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { androidx.compose.material3.SnackbarHostState() }
    val context = LocalContext.current

    LaunchedEffect(Unit) {
        viewModel.events.collect { event ->
            when (event) {
                is ContactsHubEvent.ShowSnackbar -> snackbarHostState.showSnackbar(event.message)
                is ContactsHubEvent.OpenContactCard -> onOpenContactCard(event.userId)
            }
        }
    }

    // Feature 2 — runtime READ_CONTACTS request behind the explicit "Find people you know" action.
    val permissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted ->
        if (granted) {
            viewModel.onPermissionGranted()
        } else {
            val activity = context as? Activity
            // If we can no longer show a rationale after a denial, it's permanently denied.
            val permanently = activity != null &&
                !ActivityCompat.shouldShowRequestPermissionRationale(activity, Manifest.permission.READ_CONTACTS)
            viewModel.onPermissionDenied(permanentlyDenied = permanently)
        }
    }

    val requestFindPeople: () -> Unit = {
        val already = ContextCompat.checkSelfPermission(
            context, Manifest.permission.READ_CONTACTS,
        ) == PackageManager.PERMISSION_GRANTED
        if (already) viewModel.onPermissionGranted()
        else permissionLauncher.launch(Manifest.permission.READ_CONTACTS)
    }

    ContactsHubScreen(
        state = state,
        matchState = matchState,
        snackbarHostState = snackbarHostState,
        onBack = onBack,
        onRetry = { viewModel.refresh() },
        onOpenContact = viewModel::onOpenContact,
        onToggleFavorite = viewModel::onToggleFavorite,
        onSaveSuggestion = viewModel::onSaveSuggestion,
        onFindPeople = requestFindPeople,
        onRetrySync = requestFindPeople,
        onDismissSync = viewModel::onDismissSync,
        onAddMatch = viewModel::onAddMatch,
        onOpenAppSettings = {
            val intent = Intent(
                android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                android.net.Uri.fromParts("package", context.packageName, null),
            ).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            context.startActivity(intent)
        },
        onInvite = {
            // Optional v1 invite: OS share-sheet with a join link (no fake SMS pipeline).
            val share = Intent(Intent.ACTION_SEND).apply {
                type = "text/plain"
                putExtra(Intent.EXTRA_TEXT, "Join me on TestLogon: https://tl-api.bitbazaar.cc/")
            }
            context.startActivity(Intent.createChooser(share, "Invite to TestLogon"))
        },
        modifier = modifier,
    )
}

@Composable
private fun ContactsHubScreen(
    state: ContactsHubUiState,
    matchState: MatchSyncState,
    snackbarHostState: androidx.compose.material3.SnackbarHostState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onOpenContact: (String) -> Unit,
    onToggleFavorite: (String, Boolean) -> Unit,
    onSaveSuggestion: (String) -> Unit,
    onFindPeople: () -> Unit,
    onRetrySync: () -> Unit,
    onDismissSync: () -> Unit,
    onAddMatch: (String) -> Unit,
    onOpenAppSettings: () -> Unit,
    onInvite: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(ContactsHubTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("Contacts") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
        snackbarHost = { androidx.compose.material3.SnackbarHost(snackbarHostState) },
    ) { padding ->
        when (state) {
            is ContactsHubUiState.Loading ->
                LoadingState(modifier = Modifier.padding(padding).fillMaxSize())

            is ContactsHubUiState.Error ->
                ErrorState(
                    message = state.message,
                    onRetry = onRetry,
                    modifier = Modifier.padding(padding).fillMaxSize(),
                )

            is ContactsHubUiState.Content -> {
                LazyColumn(
                    modifier = Modifier.padding(padding).fillMaxSize(),
                    contentPadding = androidx.compose.foundation.layout.PaddingValues(vertical = 8.dp),
                ) {
                    // Feature 2 - always-visible "Find people you know" entry (device contact sync).
                    item { FindPeopleCta(onFindPeople = onFindPeople) }

                    // Feature 2 - matched-from-your-address-book results (when a sync produced any).
                    val results = matchState as? MatchSyncState.Results
                    if (results != null && results.matches.isNotEmpty()) {
                        item { SectionHeader("From your contacts", ContactsHubTestTags.MATCH_SECTION) }
                        items(results.matches, key = { "match_" + it.userId }) { row ->
                            MatchRowItem(
                                row = row,
                                onOpen = { onOpenContact(row.userId) },
                                onAdd = { onAddMatch(row.userId) },
                            )
                        }
                        item { HorizontalDivider(modifier = Modifier.padding(vertical = 4.dp)) }
                    }

                    if (state.isFullyEmpty && (results == null || results.matches.isEmpty())) {
                        item {
                            EmptyState(
                                title = "No contacts yet",
                                body = "Find people you know, or save people you message or follow.",
                                modifier = Modifier.fillMaxWidth().padding(vertical = 24.dp),
                            )
                        }
                    }
                    if (state.contacts.isNotEmpty()) {
                        item { SectionHeader("Saved contacts", ContactsHubTestTags.CONTACTS_SECTION) }
                        items(state.contacts, key = { it.userId }) { row ->
                            ContactRowItem(
                                row = row,
                                onOpen = { onOpenContact(row.userId) },
                                onToggleFavorite = { onToggleFavorite(row.userId, !row.isFavorite) },
                            )
                        }
                    }
                    if (state.suggestions.isNotEmpty()) {
                        item { SectionHeader("People you may know", ContactsHubTestTags.SUGGESTIONS_SECTION) }
                        items(state.suggestions, key = { it.userId }) { row ->
                            SuggestionRowItem(
                                row = row,
                                onOpen = { onOpenContact(row.userId) },
                                onAdd = { onSaveSuggestion(row.userId) },
                            )
                        }
                    }
                }
            }
        }
    }

    // Feature 2 - sync-phase overlays (progress / permission / empty / failure) as dialogs.
    ContactSyncOverlay(
        matchState = matchState,
        onRetrySync = onRetrySync,
        onDismiss = onDismissSync,
        onOpenAppSettings = onOpenAppSettings,
        onInvite = onInvite,
    )
}

@Composable
private fun FindPeopleCta(onFindPeople: () -> Unit) {
    Column(modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp)) {
        Button(
            onClick = onFindPeople,
            modifier = Modifier.fillMaxWidth().testTag(ContactsHubTestTags.FIND_PEOPLE_BUTTON),
        ) {
            Icon(Icons.Filled.PersonSearch, contentDescription = null, modifier = Modifier.size(18.dp))
            Text("Find people you know", modifier = Modifier.padding(start = 8.dp))
        }
        Spacer(Modifier.height(4.dp))
        Text(
            text = "We hash your contacts on your device and never upload them.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun ContactSyncOverlay(
    matchState: MatchSyncState,
    onRetrySync: () -> Unit,
    onDismiss: () -> Unit,
    onOpenAppSettings: () -> Unit,
    onInvite: () -> Unit,
) {
    when (matchState) {
        is MatchSyncState.Idle -> Unit
        is MatchSyncState.Results -> {
            // Non-empty results render inline in the list; only the EMPTY result shows a dialog.
            if (matchState.isEmpty) {
                AlertDialog(
                    onDismissRequest = onDismiss,
                    title = { Text("No matches found") },
                    text = { Text("None of your contacts are on TestLogon yet. Invite them to connect.") },
                    confirmButton = { TextButton(onClick = { onInvite() }) { Text("Invite") } },
                    dismissButton = { TextButton(onClick = onDismiss) { Text("Close") } },
                )
            }
        }
        is MatchSyncState.Syncing -> {
            AlertDialog(
                onDismissRequest = { },
                title = { Text("Finding people you know") },
                text = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(20.dp).testTag(ContactsHubTestTags.SYNC_PROGRESS),
                        )
                        Text(
                            "Hashing your contacts on-device...",
                            modifier = Modifier.padding(start = 12.dp),
                        )
                    }
                },
                confirmButton = { },
            )
        }
        is MatchSyncState.PermissionNeeded -> {
            AlertDialog(
                onDismissRequest = onDismiss,
                title = { Text("Contacts permission needed") },
                text = {
                    Text(
                        if (matchState.permanentlyDenied) {
                            "To find people you know, allow Contacts access in Settings. " +
                                "Your contacts are hashed on-device and never uploaded."
                        } else {
                            "We need Contacts access to match people you know. " +
                                "Your contacts are hashed on-device and never uploaded."
                        },
                    )
                },
                confirmButton = {
                    if (matchState.permanentlyDenied) {
                        TextButton(onClick = { onOpenAppSettings() }) { Text("Open settings") }
                    } else {
                        TextButton(onClick = { onRetrySync() }) { Text("Allow") }
                    }
                },
                dismissButton = { TextButton(onClick = onDismiss) { Text("Not now") } },
            )
        }
        is MatchSyncState.Failed -> {
            AlertDialog(
                onDismissRequest = onDismiss,
                title = { Text("Could not find people") },
                text = { Text(matchState.message) },
                confirmButton = { TextButton(onClick = { onRetrySync() }) { Text("Retry") } },
                dismissButton = { TextButton(onClick = onDismiss) { Text("Close") } },
            )
        }
    }
}

@Composable
private fun MatchRowItem(
    row: MatchRow,
    onOpen: () -> Unit,
    onAdd: () -> Unit,
) {
    val label = when (row.matchedBy) {
        "phone" -> "In your contacts by phone"
        "email" -> "In your contacts by email"
        else -> "In your contacts"
    }
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onOpen)
            .padding(horizontal = 16.dp, vertical = 10.dp)
            .testTag(ContactsHubTestTags.matchRow(row.userId)),
    ) {
        InitialsAvatar(row.displayName)
        Column(modifier = Modifier.weight(1f).padding(start = 12.dp)) {
            Text(
                text = row.displayName,
                style = MaterialTheme.typography.bodyLarge,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                text = label,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
        if (row.adding) {
            CircularProgressIndicator(modifier = Modifier.size(20.dp))
        } else {
            TextButton(
                onClick = onAdd,
                modifier = Modifier.testTag(ContactsHubTestTags.addMatch(row.userId)),
            ) {
                Icon(Icons.Filled.PersonAdd, contentDescription = null, modifier = Modifier.size(18.dp))
                Text("Add", modifier = Modifier.padding(start = 6.dp))
            }
        }
    }
}

@Composable
private fun SectionHeader(title: String, tag: String) {
    Text(
        text = title,
        style = MaterialTheme.typography.titleSmall,
        color = MaterialTheme.colorScheme.primary,
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 8.dp)
            .testTag(tag),
    )
}

@Composable
private fun ContactRowItem(
    row: ContactRow,
    onOpen: () -> Unit,
    onToggleFavorite: () -> Unit,
) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onOpen)
            .padding(horizontal = 16.dp, vertical = 10.dp)
            .testTag(ContactsHubTestTags.contactRow(row.userId)),
    ) {
        InitialsAvatar(row.displayName)
        Column(modifier = Modifier.weight(1f).padding(start = 12.dp)) {
            Text(
                text = row.displayName,
                style = MaterialTheme.typography.bodyLarge,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
        IconButton(
            onClick = onToggleFavorite,
            modifier = Modifier.testTag(ContactsHubTestTags.favorite(row.userId)),
        ) {
            if (row.isFavorite) {
                Icon(Icons.Filled.Star, contentDescription = "Unfavorite", tint = MaterialTheme.colorScheme.primary)
            } else {
                Icon(Icons.Outlined.StarBorder, contentDescription = "Favorite")
            }
        }
    }
}

@Composable
private fun SuggestionRowItem(
    row: SuggestionRow,
    onOpen: () -> Unit,
    onAdd: () -> Unit,
) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onOpen)
            .padding(horizontal = 16.dp, vertical = 10.dp)
            .testTag(ContactsHubTestTags.suggestionRow(row.userId)),
    ) {
        InitialsAvatar(row.displayName)
        Column(modifier = Modifier.weight(1f).padding(start = 12.dp)) {
            Text(
                text = row.displayName,
                style = MaterialTheme.typography.bodyLarge,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            if (row.hint.isNotBlank()) {
                Text(
                    text = row.hint,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }
        if (row.adding) {
            CircularProgressIndicator(modifier = Modifier.size(20.dp))
        } else {
            TextButton(
                onClick = onAdd,
                modifier = Modifier.testTag(ContactsHubTestTags.addSuggestion(row.userId)),
            ) {
                Icon(Icons.Filled.PersonAdd, contentDescription = null, modifier = Modifier.size(18.dp))
                Text("Add", modifier = Modifier.padding(start = 6.dp))
            }
        }
    }
}

@Composable
private fun InitialsAvatar(displayName: String) {
    val initials = displayName.trim()
        .split(Regex("\\s+"))
        .filter { it.isNotEmpty() }
        .take(2)
        .joinToString("") { it.first().uppercase() }
        .ifBlank { "?" }
    Surface(
        shape = CircleShape,
        color = MaterialTheme.colorScheme.secondaryContainer,
        modifier = Modifier.size(40.dp),
    ) {
        Box(contentAlignment = Alignment.Center) {
            Text(
                text = initials,
                style = MaterialTheme.typography.titleSmall,
                color = MaterialTheme.colorScheme.onSecondaryContainer,
            )
        }
    }
}
