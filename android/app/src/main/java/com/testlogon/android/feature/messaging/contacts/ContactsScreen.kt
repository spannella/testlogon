package com.testlogon.android.feature.messaging.contacts

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Clear
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.SnackbarResult
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextField
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.messaging.Contact

/** AND-153 — stable testTags for the contacts (people-search) screen. */
object ContactsTestTags {
    const val SCREEN = "contacts_screen"
    const val INPUT = "contacts_search_input"
    const val CLEAR = "contacts_search_clear"
    const val LIST = "contacts_list"
    const val ROW = "contacts_row"
    const val ROW_SPINNER = "contacts_row_spinner"
}

/**
 * AND-153 / AND-154 — route-level contacts screen. Hosts the search field + result list, collects the
 * one-shot navigation/snackbar effects, and delegates DM navigation to [onOpenThread] (the NavHost
 * owns the actual `navController.navigate`, keeping the ViewModel free of navigation types).
 */
@Composable
fun ContactsRoute(
    onOpenThread: (conversationId: String) -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: ContactsViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    val retryLabel = stringResource(R.string.action_retry)

    LaunchedEffect(Unit) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is ContactsEffect.OpenThread -> onOpenThread(effect.conversationId)
                is ContactsEffect.ShowError -> {
                    val result = snackbarHostState.showSnackbar(
                        message = effect.message,
                        actionLabel = effect.retryUserId?.let { retryLabel },
                    )
                    if (result == SnackbarResult.ActionPerformed && effect.retryUserId != null) {
                        viewModel.retryStartDm(effect.retryUserId)
                    }
                }
            }
        }
    }

    ContactsScreen(
        state = state,
        snackbarHostState = snackbarHostState,
        onQueryChange = viewModel::onQueryChange,
        onClear = viewModel::onClear,
        onRetry = viewModel::retry,
        onContactClick = viewModel::onContactClick,
        onBack = onBack,
        modifier = modifier,
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ContactsScreen(
    state: ContactsUiState,
    onQueryChange: (String) -> Unit,
    onClear: () -> Unit,
    onRetry: () -> Unit,
    onContactClick: (Contact) -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    snackbarHostState: SnackbarHostState = remember { SnackbarHostState() },
) {
    val searchHint = stringResource(R.string.contacts_search_hint)
    Scaffold(
        modifier = modifier.testTag(ContactsTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = {
                    TextField(
                        value = state.query,
                        onValueChange = onQueryChange,
                        singleLine = true,
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag(ContactsTestTags.INPUT)
                            .semantics { contentDescription = searchHint },
                        placeholder = { Text(searchHint) },
                        keyboardOptions = KeyboardOptions(imeAction = ImeAction.Search),
                        keyboardActions = KeyboardActions(),
                        trailingIcon = {
                            if (state.query.isNotEmpty()) {
                                IconButton(
                                    onClick = onClear,
                                    modifier = Modifier.testTag(ContactsTestTags.CLEAR),
                                ) {
                                    Icon(
                                        Icons.Filled.Clear,
                                        contentDescription = stringResource(R.string.contacts_clear_cd),
                                    )
                                }
                            }
                        },
                    )
                },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
            )
        },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            when (val phase = state.phase) {
                ContactsPhase.Idle ->
                    EmptyState(title = stringResource(R.string.contacts_idle_prompt))
                ContactsPhase.Loading -> LoadingState()
                is ContactsPhase.Empty ->
                    EmptyState(title = stringResource(R.string.contacts_empty_query, phase.query))
                is ContactsPhase.Error ->
                    ErrorState(message = phase.message, onRetry = onRetry)
                ContactsPhase.Results ->
                    ContactsList(
                        contacts = state.contacts,
                        pendingDmUserId = state.pendingDmUserId,
                        onContactClick = onContactClick,
                    )
            }
        }
    }
}

@Composable
private fun ContactsList(
    contacts: List<Contact>,
    pendingDmUserId: String?,
    onContactClick: (Contact) -> Unit,
) {
    LazyColumn(modifier = Modifier.fillMaxSize().testTag(ContactsTestTags.LIST)) {
        items(contacts, key = { it.id }) { contact ->
            ContactRow(
                contact = contact,
                isPending = contact.id == pendingDmUserId,
                onClick = { onContactClick(contact) },
            )
        }
    }
}

@Composable
private fun ContactRow(
    contact: Contact,
    isPending: Boolean,
    onClick: () -> Unit,
) {
    val rowCd = stringResource(R.string.contacts_row_cd, contact.displayName)
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 48.dp)
            .clickable(enabled = !isPending, onClick = onClick)
            .semantics(mergeDescendants = true) {
                role = Role.Button
                contentDescription = rowCd
            }
            .padding(horizontal = 16.dp, vertical = 12.dp)
            .testTag(ContactsTestTags.ROW),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        InitialsAvatar(displayName = contact.displayName)
        Text(
            text = contact.displayName,
            style = MaterialTheme.typography.bodyLarge,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier
                .weight(1f)
                .padding(start = 12.dp),
        )
        if (isPending) {
            CircularProgressIndicator(
                strokeWidth = 2.dp,
                modifier = Modifier
                    .size(20.dp)
                    .testTag(ContactsTestTags.ROW_SPINNER),
            )
        }
    }
}

/**
 * AND-153 — initials-only avatar. The contacts search endpoint returns no avatar URL, so there is no
 * Coil network load here; the placeholder is purely decorative (cleared from semantics).
 */
@Composable
private fun InitialsAvatar(displayName: String) {
    val initials = remember(displayName) { initialsOf(displayName) }
    Surface(
        shape = CircleShape,
        color = MaterialTheme.colorScheme.primaryContainer,
        modifier = Modifier.size(40.dp).clearAndSetSemantics { },
    ) {
        Box(contentAlignment = Alignment.Center) {
            Text(
                text = initials,
                style = MaterialTheme.typography.titleSmall,
                color = MaterialTheme.colorScheme.onPrimaryContainer,
            )
        }
    }
}

/** Pure: up to two leading initials from the display name; "?" when blank. JVM-testable. */
internal fun initialsOf(displayName: String): String {
    val parts = displayName.trim().split(Regex("\\s+")).filter { it.isNotEmpty() }
    return when {
        parts.isEmpty() -> "?"
        parts.size == 1 -> parts[0].take(1).uppercase()
        else -> (parts[0].take(1) + parts[1].take(1)).uppercase()
    }
}
