@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.contacts

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
    val snackbarHostState = remember { androidx.compose.material3.SnackbarHostState() }

    LaunchedEffect(Unit) {
        viewModel.events.collect { event ->
            when (event) {
                is ContactsHubEvent.ShowSnackbar -> snackbarHostState.showSnackbar(event.message)
                is ContactsHubEvent.OpenContactCard -> onOpenContactCard(event.userId)
            }
        }
    }

    ContactsHubScreen(
        state = state,
        snackbarHostState = snackbarHostState,
        onBack = onBack,
        onRetry = { viewModel.refresh() },
        onOpenContact = viewModel::onOpenContact,
        onToggleFavorite = viewModel::onToggleFavorite,
        onSaveSuggestion = viewModel::onSaveSuggestion,
        modifier = modifier,
    )
}

@Composable
private fun ContactsHubScreen(
    state: ContactsHubUiState,
    snackbarHostState: androidx.compose.material3.SnackbarHostState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onOpenContact: (String) -> Unit,
    onToggleFavorite: (String, Boolean) -> Unit,
    onSaveSuggestion: (String) -> Unit,
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
                if (state.isFullyEmpty) {
                    EmptyState(
                        title = "No contacts yet",
                        body = "Save people you message or follow to build your address book.",
                        modifier = Modifier.padding(padding).fillMaxSize(),
                    )
                } else {
                    LazyColumn(
                        modifier = Modifier.padding(padding).fillMaxSize(),
                        contentPadding = androidx.compose.foundation.layout.PaddingValues(vertical = 8.dp),
                    ) {
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
