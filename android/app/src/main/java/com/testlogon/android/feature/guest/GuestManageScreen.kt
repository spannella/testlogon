@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.guest

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.LoadingState

/** AND-312 - stable testTags for the host guest-management surface. */
object GuestManageTestTags {
    const val SCREEN = "guest_manage_screen"
    const val CREATE_INVITE = "guest_create_invite"
    const val INVITE_URL = "guest_invite_url"
    const val COPY = "guest_copy"
    const val SHARE = "guest_share"
    const val REVOKE = "guest_revoke"
    const val PROMOTE = "guest_promote"
    const val MUTE = "guest_mute"
    const val REMOVE = "guest_remove"
    const val REMOVE_CONFIRM = "guest_remove_confirm"
    const val OVERFLOW = "guest_overflow"
    const val EMPTY = "guest_empty"
    const val LIST = "guest_list"

    /** Stable per-row tag: guest_row_<inputId>. */
    fun row(inputId: String): String = "guest_row_$inputId"
}

/**
 * AND-312 - host guest-management entry. Collects [GuestManageViewModel] state, delegates to the stateless
 * [GuestManageScreen], and drives the poll loop only while composed (FR live-refresh).
 */
@Composable
fun GuestManageRoute(
    onBack: () -> Unit,
    viewModel: GuestManageViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    DisposableEffect(viewModel) {
        viewModel.startPolling()
        onDispose { viewModel.stopPolling() }
    }
    GuestManageScreen(
        state = state,
        onCreateInvite = { viewModel.onCreateInvite() },
        onRevokeInvite = viewModel::onRevokeInvite,
        onPromote = viewModel::onPromote,
        onToggleMute = viewModel::onToggleMute,
        onRemove = viewModel::onRemove,
        onBack = onBack,
    )
}

/**
 * AND-312 - stateless host guest-management surface: an invite card (Create -> shows the invite URL with
 * Copy / Share / Revoke) and a LazyColumn of guest rows (name + status chip + overflow menu of
 * Promote / Mute-Unmute / Remove). Remove is confirmed via an [AlertDialog]. In-flight rows show progress and
 * are non-interactive. An empty state renders when there are no guests and no invite.
 */
@Composable
fun GuestManageScreen(
    state: GuestManageUiState,
    onCreateInvite: () -> Unit,
    onRevokeInvite: (String) -> Unit,
    onPromote: (String) -> Unit,
    onToggleMute: (String, Boolean) -> Unit,
    onRemove: (String) -> Unit,
    onBack: () -> Unit,
) {
    // Row pending the remove confirmation dialog (inputId, displayName) or null when dismissed.
    var pendingRemove by remember { mutableStateOf<Guest?>(null) }

    Scaffold(
        modifier = Modifier.testTag(GuestManageTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.guest_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.guest_back_cd),
                        )
                    }
                },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
        ) {
            InviteCard(
                invite = state.invite,
                createInFlight = state.inFlight.contains(GuestManageViewModel.CREATE_KEY),
                revokeInFlight = state.invite?.inviteId?.let { state.inFlight.contains(it) } ?: false,
                onCreateInvite = onCreateInvite,
                onRevokeInvite = onRevokeInvite,
            )

            if (state.isLoading && state.guests.isEmpty() && state.invite == null) {
                LoadingState()
            } else if (state.guests.isEmpty() && state.invite == null) {
                EmptyState(
                    title = stringResource(R.string.guest_empty_title),
                    body = stringResource(R.string.guest_empty_body),
                    modifier = Modifier.testTag(GuestManageTestTags.EMPTY),
                )
            } else {
                LazyColumn(
                    modifier = Modifier
                        .fillMaxSize()
                        .testTag(GuestManageTestTags.LIST)
                        .semantics { liveRegion = LiveRegionMode.Polite },
                    contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    items(state.guests, key = { it.inputId }) { guest ->
                        GuestRow(
                            guest = guest,
                            pending = state.inFlight.contains(guest.inputId),
                            onPromote = onPromote,
                            onToggleMute = onToggleMute,
                            onRemoveRequested = { pendingRemove = guest },
                        )
                    }
                }
            }
        }
    }

    val toRemove = pendingRemove
    if (toRemove != null) {
        AlertDialog(
            modifier = Modifier.testTag(GuestManageTestTags.REMOVE_CONFIRM),
            onDismissRequest = { pendingRemove = null },
            title = { Text(stringResource(R.string.guest_remove_confirm_title)) },
            text = { Text(stringResource(R.string.guest_remove_confirm_body, toRemove.displayName)) },
            confirmButton = {
                TextButton(onClick = {
                    onRemove(toRemove.inputId)
                    pendingRemove = null
                }) {
                    Text(stringResource(R.string.guest_remove_confirm))
                }
            },
            dismissButton = {
                TextButton(onClick = { pendingRemove = null }) {
                    Text(stringResource(R.string.guest_remove_cancel))
                }
            },
        )
    }
}

/**
 * AND-312 - the invite card. With no invite it offers a Create button; once an invite exists it shows the
 * (read-only) URL with Copy / Share / Revoke. The stream_key is a SECRET and is NOT shown here.
 */
@Composable
private fun InviteCard(
    invite: GuestInvite?,
    createInFlight: Boolean,
    revokeInFlight: Boolean,
    onCreateInvite: () -> Unit,
    onRevokeInvite: (String) -> Unit,
) {
    val context = LocalContext.current
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(16.dp),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(
                text = stringResource(R.string.guest_invite_card_title),
                style = MaterialTheme.typography.titleMedium,
            )

            if (invite?.url == null) {
                Text(
                    text = stringResource(R.string.guest_invite_card_body),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                val createCd = stringResource(R.string.guest_create_invite_cd)
                FilledTonalButton(
                    onClick = onCreateInvite,
                    enabled = !createInFlight,
                    modifier = Modifier
                        .heightIn(min = 48.dp)
                        .testTag(GuestManageTestTags.CREATE_INVITE)
                        .semantics { contentDescription = createCd },
                ) {
                    if (createInFlight) {
                        CircularProgressIndicator(strokeWidth = 2.dp, modifier = Modifier.size(20.dp))
                    } else {
                        Text(stringResource(R.string.guest_create_invite))
                    }
                }
            } else {
                val url = invite.url
                val urlCd = stringResource(R.string.guest_invite_url_cd)
                OutlinedTextField(
                    value = url,
                    onValueChange = {},
                    readOnly = true,
                    label = { Text(stringResource(R.string.guest_invite_url_label)) },
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag(GuestManageTestTags.INVITE_URL)
                        .semantics { contentDescription = urlCd },
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    val copyCd = stringResource(R.string.guest_copy_cd)
                    val copyLabel = stringResource(R.string.guest_invite_url_label)
                    TextButton(
                        onClick = { copyToClipboard(context, copyLabel, url) },
                        modifier = Modifier
                            .heightIn(min = 48.dp)
                            .testTag(GuestManageTestTags.COPY)
                            .semantics { contentDescription = copyCd },
                    ) {
                        Text(stringResource(R.string.guest_copy))
                    }
                    val shareCd = stringResource(R.string.guest_share_cd)
                    val shareTitle = stringResource(R.string.guest_share_chooser)
                    TextButton(
                        onClick = { shareLink(context, url, shareTitle) },
                        modifier = Modifier
                            .heightIn(min = 48.dp)
                            .testTag(GuestManageTestTags.SHARE)
                            .semantics { contentDescription = shareCd },
                    ) {
                        Text(stringResource(R.string.guest_share))
                    }
                    val revokeCd = stringResource(R.string.guest_revoke_cd)
                    TextButton(
                        onClick = { onRevokeInvite(invite.inviteId) },
                        enabled = !revokeInFlight,
                        modifier = Modifier
                            .heightIn(min = 48.dp)
                            .testTag(GuestManageTestTags.REVOKE)
                            .semantics { contentDescription = revokeCd },
                    ) {
                        Text(stringResource(R.string.guest_revoke))
                    }
                }
            }
        }
    }
}

/**
 * AND-312 - a single guest row: name + a derived status chip (text + icon, not colour-only) + an overflow
 * menu of Promote / Mute-Unmute / Remove. While [pending] the row shows progress and the overflow is hidden.
 */
@Composable
private fun GuestRow(
    guest: Guest,
    pending: Boolean,
    onPromote: (String) -> Unit,
    onToggleMute: (String, Boolean) -> Unit,
    onRemoveRequested: (Guest) -> Unit,
) {
    var menuOpen by remember { mutableStateOf(false) }
    val name = guest.displayName.takeIf { it.isNotBlank() } ?: stringResource(R.string.guest_unnamed)

    Surface(
        tonalElevation = 1.dp,
        modifier = Modifier
            .fillMaxWidth()
            .testTag(GuestManageTestTags.row(guest.inputId)),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(min = 56.dp)
                .padding(horizontal = 12.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Column(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                Text(text = name, style = MaterialTheme.typography.titleSmall)
                StatusChip(status = guest.status)
            }

            if (pending) {
                val pendingCd = stringResource(R.string.guest_row_pending_cd, name)
                CircularProgressIndicator(
                    strokeWidth = 2.dp,
                    modifier = Modifier
                        .size(24.dp)
                        .semantics { contentDescription = pendingCd },
                )
            } else {
                val overflowCd = stringResource(R.string.guest_overflow_cd, name)
                Box {
                    IconButton(
                        onClick = { menuOpen = true },
                        modifier = Modifier
                            .heightIn(min = 48.dp)
                            .testTag(GuestManageTestTags.OVERFLOW)
                            .semantics { contentDescription = overflowCd },
                    ) {
                        Icon(Icons.Filled.MoreVert, contentDescription = null)
                    }
                    DropdownMenu(expanded = menuOpen, onDismissRequest = { menuOpen = false }) {
                        DropdownMenuItem(
                            text = { Text(stringResource(R.string.guest_promote)) },
                            onClick = {
                                menuOpen = false
                                onPromote(guest.inputId)
                            },
                            modifier = Modifier.testTag(GuestManageTestTags.PROMOTE),
                        )
                        val muteLabel = if (guest.mutedAudio) {
                            stringResource(R.string.guest_unmute)
                        } else {
                            stringResource(R.string.guest_mute)
                        }
                        DropdownMenuItem(
                            text = { Text(muteLabel) },
                            onClick = {
                                menuOpen = false
                                onToggleMute(guest.inputId, !guest.mutedAudio)
                            },
                            modifier = Modifier.testTag(GuestManageTestTags.MUTE),
                        )
                        DropdownMenuItem(
                            text = { Text(stringResource(R.string.guest_remove)) },
                            onClick = {
                                menuOpen = false
                                onRemoveRequested(guest)
                            },
                            modifier = Modifier.testTag(GuestManageTestTags.REMOVE),
                        )
                    }
                }
            }
        }
    }
}

/** AND-312 - status chip conveyed by text (the colour is supplementary). */
@Composable
private fun StatusChip(status: GuestStatus) {
    AssistChip(
        onClick = {},
        enabled = false,
        label = { Text(stringResource(statusLabelRes(status))) },
    )
}

private fun statusLabelRes(status: GuestStatus): Int = when (status) {
    GuestStatus.INVITED -> R.string.guest_status_invited
    GuestStatus.JOINED -> R.string.guest_status_joined
    GuestStatus.ONAIR -> R.string.guest_status_onair
    GuestStatus.MUTED -> R.string.guest_status_muted
    GuestStatus.LEFT -> R.string.guest_status_left
    GuestStatus.REMOVED -> R.string.guest_status_removed
}

/** Copies [text] to the system clipboard under [label]. */
private fun copyToClipboard(context: Context, label: String, text: String) {
    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager ?: return
    clipboard.setPrimaryClip(ClipData.newPlainText(label, text))
}

/** Fires a system ACTION_SEND chooser to share [text]. */
private fun shareLink(context: Context, text: String, chooserTitle: String) {
    val send = Intent(Intent.ACTION_SEND).apply {
        type = "text/plain"
        putExtra(Intent.EXTRA_TEXT, text)
    }
    context.startActivity(Intent.createChooser(send, chooserTitle))
}
