@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.share

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.FilterChip
import androidx.compose.material3.IconButton
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.hilt.navigation.compose.hiltViewModel
import com.testlogon.android.R
import com.testlogon.android.feature.share.model.ShareLink

/** AND-335 - testTags for the owner ShareSheet (used by the androidTest UI test). */
object ShareSheetTestTags {
    const val SHEET = "share_sheet"
    const val CREATE = "share_create"
    const val PASSWORD = "share_password"
    const val MAX = "share_max"
    const val COPY = "share_copy"
    const val REVOKE = "share_revoke"

    /** Per-preset chip tag, e.g. share_expiry_ONE_DAY. */
    fun expiry(preset: ExpiryPreset): String = "share_expiry_${preset.name}"

    /** Per-link row tag, e.g. share_link_<linkId>. */
    fun link(linkId: String): String = "share_link_$linkId"
}

/**
 * AND-335 - the owner ShareSheet route: a ModalBottomSheet over [ShareSheetViewModel]. Copy events go to
 * the platform clipboard; the resulting share url is also copied automatically on create. [onDismiss]
 * closes the sheet (the caller controls visibility).
 */
@Composable
fun ShareSheetRoute(
    onDismiss: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: ShareSheetViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val context = LocalContext.current
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)

    LaunchedEffect(viewModel) {
        viewModel.events.collect { event ->
            when (event) {
                is ShareSheetEvent.CopyToClipboard -> copyToClipboard(context, event.url)
                is ShareSheetEvent.ShowMessage -> { /* copy + create are self-evident; no snackbar host in the sheet. */ }
            }
        }
    }

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState,
        modifier = modifier.testTag(ShareSheetTestTags.SHEET),
    ) {
        ShareSheetContent(
            state = state,
            onExpiry = viewModel::onExpiryChange,
            onPasswordEnabled = viewModel::onPasswordEnabledChange,
            onPassword = viewModel::onPasswordChange,
            onMaxDownloads = viewModel::onMaxDownloadsChange,
            onCreate = viewModel::create,
            onCopy = viewModel::copy,
            onRevoke = viewModel::revoke,
        )
    }
}

/** Stateless ShareSheet content (driven by the androidTest in-test reducer). */
@Composable
fun ShareSheetContent(
    state: ShareSheetUiState,
    onExpiry: (ExpiryPreset) -> Unit,
    onPasswordEnabled: (Boolean) -> Unit,
    onPassword: (String) -> Unit,
    onMaxDownloads: (Int) -> Unit,
    onCreate: () -> Unit,
    onCopy: (ShareLink) -> Unit,
    onRevoke: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier
            .fillMaxWidth()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(text = stringResource(R.string.share_title))

        // ── Expiry presets ──
        Text(text = stringResource(R.string.share_expiry_label))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            ExpiryPreset.entries.forEach { preset ->
                FilterChip(
                    selected = state.expiry == preset,
                    onClick = { onExpiry(preset) },
                    label = { Text(stringResource(expiryLabelRes(preset))) },
                    modifier = Modifier.testTag(ShareSheetTestTags.expiry(preset)),
                )
            }
        }

        // ── Password toggle + field ──
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(text = stringResource(R.string.share_password_label))
            Switch(checked = state.passwordEnabled, onCheckedChange = onPasswordEnabled)
        }
        if (state.passwordEnabled) {
            OutlinedTextField(
                value = state.password,
                onValueChange = onPassword,
                singleLine = true,
                label = { Text(stringResource(R.string.share_password_hint)) },
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag(ShareSheetTestTags.PASSWORD),
            )
        }

        // ── Max downloads stepper ──
        Row(
            modifier = Modifier.fillMaxWidth().testTag(ShareSheetTestTags.MAX),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(text = stringResource(R.string.share_max_label))
            TextButton(onClick = { onMaxDownloads(state.maxDownloads - 1) }) { Text("-") }
            Text(text = state.maxDownloads.toString())
            TextButton(onClick = { onMaxDownloads(state.maxDownloads + 1) }) { Text("+") }
        }

        // ── Create ──
        Button(
            onClick = onCreate,
            enabled = state.canCreate,
            modifier = Modifier.testTag(ShareSheetTestTags.CREATE),
        ) {
            if (state.isCreating) {
                CircularProgressIndicator(modifier = Modifier.heightIn(min = 18.dp))
            } else {
                Text(stringResource(R.string.share_create_button))
            }
        }

        state.error?.let { Text(text = it) }

        HorizontalDivider()

        // ── Existing links ──
        Text(text = stringResource(R.string.share_existing_label))
        // The whole sheet scrolls as one (the outer Column owns the scroll), so the links render in a plain
        // Column - a nested LazyColumn here would create a second scroll container whose rows can land off
        // the visible area with no reachable scroll parent.
        Column(verticalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
            state.visibleLinks.forEach { link ->
                key(link.linkId) {
                    ShareLinkRow(link = link, onCopy = { onCopy(link) }, onRevoke = { onRevoke(link.linkId) })
                }
            }
        }
    }
}

@Composable
private fun ShareLinkRow(
    link: ShareLink,
    onCopy: () -> Unit,
    onRevoke: () -> Unit,
) {
    val copyCd = stringResource(R.string.share_action_copy)
    val revokeCd = stringResource(R.string.share_action_revoke)
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(ShareSheetTestTags.link(link.linkId)),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(text = link.shareUrl, maxLines = 1, overflow = TextOverflow.Ellipsis)
            val count = link.downloadCount ?: 0
            val max = link.maxDownloads
            Text(
                text = if (max != null) {
                    stringResource(R.string.share_downloads_of, count, max)
                } else {
                    stringResource(R.string.share_downloads, count)
                },
            )
        }
        IconButton(
            onClick = onCopy,
            modifier = Modifier
                .semantics { contentDescription =copyCd }
                .testTag(ShareSheetTestTags.COPY),
        ) {
            Text("⧉")
        }
        IconButton(
            onClick = onRevoke,
            modifier = Modifier
                .semantics { contentDescription =revokeCd }
                .testTag(ShareSheetTestTags.REVOKE),
        ) {
            Text("✕")
        }
    }
}

private fun expiryLabelRes(preset: ExpiryPreset): Int = when (preset) {
    ExpiryPreset.ONE_HOUR -> R.string.share_expiry_1h
    ExpiryPreset.ONE_DAY -> R.string.share_expiry_24h
    ExpiryPreset.SEVEN_DAYS -> R.string.share_expiry_7d
    ExpiryPreset.THIRTY_DAYS -> R.string.share_expiry_30d
}

private fun copyToClipboard(context: Context, text: String) {
    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager ?: return
    clipboard.setPrimaryClip(ClipData.newPlainText("share_link", text))
}
