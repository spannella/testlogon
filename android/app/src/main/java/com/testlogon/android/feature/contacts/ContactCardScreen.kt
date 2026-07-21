@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.contacts

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Call
import androidx.compose.material.icons.filled.Chat
import androidx.compose.material.icons.filled.OpenInNew
import androidx.compose.material.icons.filled.PersonAdd
import androidx.compose.material.icons.filled.PersonRemove
import androidx.compose.material.icons.filled.Star
import androidx.compose.material.icons.filled.Videocam
import androidx.compose.material.icons.filled.VolunteerActivism
import androidx.compose.material.icons.outlined.StarBorder
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState

/** Feature 1 — stable test tags for the contact card. */
object ContactCardTestTags {
    const val SCREEN = "contact_card_screen"
    const val MESSAGE = "contact_card_message"
    const val CALL_AUDIO = "contact_card_call_audio"
    const val CALL_VIDEO = "contact_card_call_video"
    const val FOLLOW = "contact_card_follow"
    const val TIP = "contact_card_tip"
    const val SAVE = "contact_card_save"
    const val FAVORITE = "contact_card_favorite"
    const val PROFILE = "contact_card_profile"
}

/**
 * Feature 1 — the contact detail card. Reachable from the Contacts hub, from a suggestion, and
 * (via "View contact") from a conversation. Actions: Message, Audio/Video call, Follow/unfollow,
 * Tip, Save/Remove + favorite, View full profile.
 */
@Composable
fun ContactCardRoute(
    onOpenThread: (conversationId: String) -> Unit,
    onPlaceCall: (route: String) -> Unit,
    onOpenFullProfile: (userId: String) -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: ContactCardViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    val snackbarHostState = remember { androidx.compose.material3.SnackbarHostState() }

    LaunchedEffect(Unit) {
        viewModel.events.collect { event ->
            when (event) {
                is ContactCardEvent.ShowSnackbar -> snackbarHostState.showSnackbar(event.message)
                is ContactCardEvent.OpenThread -> onOpenThread(event.conversationId)
                is ContactCardEvent.PlaceCall -> onPlaceCall(event.route)
                is ContactCardEvent.OpenFullProfile -> onOpenFullProfile(event.userId)
            }
        }
    }

    ContactCardScreen(
        state = state,
        snackbarHostState = snackbarHostState,
        onBack = onBack,
        onRetry = viewModel::load,
        onMessage = viewModel::onMessage,
        onAudioCall = { viewModel.onCall(video = false) },
        onVideoCall = { viewModel.onCall(video = true) },
        onToggleFollow = viewModel::onToggleFollow,
        onTip = viewModel::onViewFullProfile,
        onToggleSaved = viewModel::onToggleSaved,
        onToggleFavorite = viewModel::onToggleFavorite,
        onViewProfile = viewModel::onViewFullProfile,
        modifier = modifier,
    )
}

@Composable
private fun ContactCardScreen(
    state: ContactCardUiState,
    snackbarHostState: androidx.compose.material3.SnackbarHostState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onMessage: () -> Unit,
    onAudioCall: () -> Unit,
    onVideoCall: () -> Unit,
    onToggleFollow: () -> Unit,
    onTip: () -> Unit,
    onToggleSaved: () -> Unit,
    onToggleFavorite: () -> Unit,
    onViewProfile: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(ContactCardTestTags.SCREEN),
        topBar = {
            androidx.compose.material3.TopAppBar(
                title = { Text("Contact") },
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
            is ContactCardUiState.Loading ->
                LoadingState(modifier = Modifier.padding(padding).fillMaxSize())

            is ContactCardUiState.Error ->
                ErrorState(message = state.message, onRetry = onRetry, modifier = Modifier.padding(padding).fillMaxSize())

            is ContactCardUiState.Content -> {
                val data = state.data
                val enabled = !state.actionInFlight
                Column(
                    modifier = Modifier
                        .padding(padding)
                        .fillMaxSize()
                        .verticalScroll(rememberScrollState())
                        .padding(16.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    BigAvatar(data.displayName)
                    Text(
                        text = data.displayName,
                        style = MaterialTheme.typography.headlineSmall,
                        textAlign = TextAlign.Center,
                    )
                    val relationship = when {
                        data.isMutual -> "You follow each other"
                        data.isFollowing -> "You follow them"
                        else -> null
                    }
                    if (relationship != null) {
                        Text(
                            text = relationship,
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }

                    // Primary: Message.
                    Button(
                        onClick = onMessage,
                        enabled = enabled,
                        modifier = Modifier.fillMaxWidth().testTag(ContactCardTestTags.MESSAGE),
                    ) {
                        Icon(Icons.Filled.Chat, contentDescription = null, modifier = Modifier.size(18.dp))
                        Text("Message", modifier = Modifier.padding(start = 8.dp))
                    }

                    // Calls (audio + video) side by side.
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        OutlinedButton(
                            onClick = onAudioCall,
                            enabled = enabled,
                            modifier = Modifier.weight(1f).testTag(ContactCardTestTags.CALL_AUDIO),
                        ) {
                            Icon(Icons.Filled.Call, contentDescription = null, modifier = Modifier.size(18.dp))
                            Text("Call", modifier = Modifier.padding(start = 8.dp))
                        }
                        OutlinedButton(
                            onClick = onVideoCall,
                            enabled = enabled,
                            modifier = Modifier.weight(1f).testTag(ContactCardTestTags.CALL_VIDEO),
                        ) {
                            Icon(Icons.Filled.Videocam, contentDescription = null, modifier = Modifier.size(18.dp))
                            Text("Video", modifier = Modifier.padding(start = 8.dp))
                        }
                    }

                    // Follow / unfollow.
                    OutlinedButton(
                        onClick = onToggleFollow,
                        enabled = enabled,
                        modifier = Modifier.fillMaxWidth().testTag(ContactCardTestTags.FOLLOW),
                    ) {
                        Text(if (data.isFollowing) "Unfollow" else "Follow")
                    }

                    // Tip (routes into the full profile's tip surface).
                    OutlinedButton(
                        onClick = onTip,
                        enabled = enabled,
                        modifier = Modifier.fillMaxWidth().testTag(ContactCardTestTags.TIP),
                    ) {
                        Icon(Icons.Filled.VolunteerActivism, contentDescription = null, modifier = Modifier.size(18.dp))
                        Text("Tip", modifier = Modifier.padding(start = 8.dp))
                    }

                    // Save / remove contact + favorite.
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(12.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        OutlinedButton(
                            onClick = onToggleSaved,
                            enabled = enabled,
                            modifier = Modifier.weight(1f).testTag(ContactCardTestTags.SAVE),
                        ) {
                            Icon(
                                if (data.isSaved) Icons.Filled.PersonRemove else Icons.Filled.PersonAdd,
                                contentDescription = null,
                                modifier = Modifier.size(18.dp),
                            )
                            Text(
                                if (data.isSaved) "Remove" else "Save",
                                modifier = Modifier.padding(start = 8.dp),
                            )
                        }
                        if (data.isSaved) {
                            IconButton(
                                onClick = onToggleFavorite,
                                enabled = enabled,
                                modifier = Modifier.testTag(ContactCardTestTags.FAVORITE),
                            ) {
                                if (data.isFavorite) {
                                    Icon(Icons.Filled.Star, contentDescription = "Unfavorite", tint = MaterialTheme.colorScheme.primary)
                                } else {
                                    Icon(Icons.Outlined.StarBorder, contentDescription = "Favorite")
                                }
                            }
                        }
                    }

                    // View full profile (deep-links to the public profile surface).
                    OutlinedButton(
                        onClick = onViewProfile,
                        enabled = enabled,
                        modifier = Modifier.fillMaxWidth().testTag(ContactCardTestTags.PROFILE),
                    ) {
                        Icon(Icons.Filled.OpenInNew, contentDescription = null, modifier = Modifier.size(18.dp))
                        Text("View full profile", modifier = Modifier.padding(start = 8.dp))
                    }
                }
            }
        }
    }
}

@Composable
private fun BigAvatar(displayName: String) {
    val initials = displayName.trim()
        .split(Regex("\\s+"))
        .filter { it.isNotEmpty() }
        .take(2)
        .joinToString("") { it.first().uppercase() }
        .ifBlank { "?" }
    Surface(
        shape = CircleShape,
        color = MaterialTheme.colorScheme.secondaryContainer,
        modifier = Modifier.size(96.dp),
    ) {
        Box(contentAlignment = Alignment.Center) {
            Text(
                text = initials,
                style = MaterialTheme.typography.headlineMedium,
                color = MaterialTheme.colorScheme.onSecondaryContainer,
            )
        }
    }
}
