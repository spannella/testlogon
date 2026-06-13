@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.signing.submit

import android.text.format.DateUtils
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Download
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.network.signing.PacketRole
import com.testlogon.android.core.network.signing.PacketStatus
import com.testlogon.android.feature.signing.model.PacketLegalNotice
import com.testlogon.android.feature.signing.submit.data.CompletedPdfOpener
import dagger.hilt.android.EntryPointAccessors
import java.time.Instant

/** Hilt entry point so the route can resolve the singleton completed-PDF opener in a composable. */
@dagger.hilt.EntryPoint
@dagger.hilt.InstallIn(dagger.hilt.components.SingletonComponent::class)
interface CompletedPdfOpenerEntryPoint {
    fun completedPdfOpener(): CompletedPdfOpener
}

/** AND-343 - stable testTags for the TERMINAL e-sign (submit / sign + legal notice) screen. */
object SubmitSignTestTags {
    const val SCREEN = "submit_screen"
    const val LEGAL_TEXT = "submit_legal_text"
    const val LEGAL_VERSION = "submit_legal_version"
    const val ACKNOWLEDGE = "submit_acknowledge"
    const val MARK_DONE = "submit_mark_done"
    const val PROGRESS = "submit_progress"
    const val CONFIRMATION = "submit_confirmation"
    const val COMPLETED_AT = "submit_completed_at"
    const val DOWNLOAD_PDF = "submit_download_pdf"
    const val DISMISS = "submit_dismiss"
    const val RETRY = "submit_retry"
}

/**
 * AND-343 - route-level terminal e-sign surface. Collects the VM's one-shot
 * [SubmitSignEvent.OpenCompletedPdf] and hands the cached completed PDF to the external viewer via the
 * [CompletedPdfOpener] (FileProvider ACTION_VIEW, reusing AND-331/AND-334). [onDismiss] pops back to
 * the packet list. [role] gates the signer-only acknowledge affordance.
 */
@Composable
fun SubmitSignRoute(
    onDismiss: () -> Unit,
    modifier: Modifier = Modifier,
    role: PacketRole = PacketRole.SIGNER,
    viewModel: SubmitSignViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val context = LocalContext.current
    val opener: CompletedPdfOpener = remember(context) {
        EntryPointAccessors.fromApplication(
            context.applicationContext,
            CompletedPdfOpenerEntryPoint::class.java,
        ).completedPdfOpener()
    }
    LaunchedEffect(viewModel) {
        viewModel.events.collect { event ->
            when (event) {
                is SubmitSignEvent.OpenCompletedPdf ->
                    opener.open(context, event.packetId, event.file)
            }
        }
    }
    SubmitSignScreen(
        state = state,
        role = role,
        onAcknowledge = viewModel::acknowledge,
        onMarkDone = viewModel::markDone,
        onDownloadPdf = viewModel::downloadCompletedPdf,
        onRetry = viewModel::retry,
        onDismiss = onDismiss,
        modifier = modifier,
    )
}

@Composable
fun SubmitSignScreen(
    state: SubmitUiState,
    role: PacketRole,
    onAcknowledge: () -> Unit,
    onMarkDone: () -> Unit,
    onDownloadPdf: () -> Unit,
    onRetry: () -> Unit,
    onDismiss: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(SubmitSignTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.submit_title)) },
                navigationIcon = {
                    IconButton(onClick = onDismiss) {
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
            when (state) {
                is SubmitUiState.Loading ->
                    CircularProgressIndicator(Modifier.align(Alignment.Center))

                is SubmitUiState.Ready -> ReadyBody(
                    state = state,
                    role = role,
                    onAcknowledge = onAcknowledge,
                    onMarkDone = onMarkDone,
                )

                is SubmitUiState.Confirmed -> ConfirmedBody(
                    state = state,
                    onDownloadPdf = onDownloadPdf,
                    onDismiss = onDismiss,
                )

                is SubmitUiState.Error -> ErrorBody(
                    message = state.message,
                    retryable = state.retryable,
                    onRetry = onRetry,
                )
            }
        }
    }
}

@Composable
private fun ReadyBody(
    state: SubmitUiState.Ready,
    role: PacketRole,
    onAcknowledge: () -> Unit,
    onMarkDone: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        val notice = state.legalNotice
        if (notice != null) {
            LegalNoticeCard(notice)
            val showAcknowledge =
                role == PacketRole.SIGNER && notice.required && !notice.accepted
            if (showAcknowledge) {
                Button(
                    onClick = onAcknowledge,
                    enabled = !state.submitting,
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 48.dp)
                        .testTag(SubmitSignTestTags.ACKNOWLEDGE),
                ) {
                    Text(stringResource(R.string.submit_acknowledge))
                }
            }
        }

        Button(
            onClick = onMarkDone,
            enabled = state.canMarkDone && !state.submitting,
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(min = 48.dp)
                .testTag(SubmitSignTestTags.MARK_DONE),
        ) {
            if (state.submitting) {
                CircularProgressIndicator(
                    modifier = Modifier.size(20.dp).testTag(SubmitSignTestTags.PROGRESS),
                    strokeWidth = 2.dp,
                    color = MaterialTheme.colorScheme.onPrimary,
                )
                Text(
                    text = stringResource(R.string.submit_mark_done),
                    modifier = Modifier.padding(start = 8.dp),
                )
            } else {
                Text(stringResource(R.string.submit_mark_done))
            }
        }
    }
}

@Composable
private fun LegalNoticeCard(notice: PacketLegalNotice) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(
                text = stringResource(R.string.legal_notice_heading),
                style = MaterialTheme.typography.titleSmall,
            )
            val versionLabel = if (notice.version.isBlank()) {
                stringResource(R.string.legal_notice_version_unknown)
            } else {
                notice.version
            }
            Text(
                text = stringResource(R.string.legal_notice_version, versionLabel),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.testTag(SubmitSignTestTags.LEGAL_VERSION),
            )
            Text(
                text = notice.text,
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(max = 320.dp)
                    .verticalScroll(rememberScrollState())
                    .testTag(SubmitSignTestTags.LEGAL_TEXT),
            )
            if (notice.accepted) {
                Text(
                    text = stringResource(R.string.legal_notice_accepted),
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.primary,
                )
            }
        }
    }
}

@Composable
private fun ConfirmedBody(
    state: SubmitUiState.Confirmed,
    onDownloadPdf: () -> Unit,
    onDismiss: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(24.dp)
            .testTag(SubmitSignTestTags.CONFIRMATION),
        verticalArrangement = Arrangement.spacedBy(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Icon(
            imageVector = Icons.Filled.CheckCircle,
            contentDescription = null,
            modifier = Modifier.size(56.dp),
            tint = MaterialTheme.colorScheme.primary,
        )
        Text(
            text = stringResource(submitStatusLabel(state.status)),
            style = MaterialTheme.typography.titleMedium,
        )
        state.completedAt?.let {
            Text(
                text = stringResource(R.string.submit_completed_at, relativeTime(it)),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.testTag(SubmitSignTestTags.COMPLETED_AT),
            )
        }
        if (state.canDownloadPdf) {
            Button(
                onClick = onDownloadPdf,
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 48.dp)
                    .testTag(SubmitSignTestTags.DOWNLOAD_PDF),
            ) {
                Icon(
                    imageVector = Icons.Filled.Download,
                    contentDescription = null,
                    modifier = Modifier.size(18.dp),
                )
                Text(
                    text = stringResource(R.string.submit_download_pdf),
                    modifier = Modifier.padding(start = 8.dp),
                )
            }
        }
        OutlinedButton(
            onClick = onDismiss,
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(min = 48.dp)
                .testTag(SubmitSignTestTags.DISMISS),
        ) {
            Text(stringResource(R.string.submit_dismiss))
        }
    }
}

@Composable
private fun ErrorBody(message: String, retryable: Boolean, onRetry: () -> Unit) {
    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp, Alignment.CenterVertically),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(text = message, style = MaterialTheme.typography.bodyLarge)
        if (retryable) {
            Button(
                onClick = onRetry,
                modifier = Modifier.heightIn(min = 48.dp).testTag(SubmitSignTestTags.RETRY),
            ) {
                Text(stringResource(R.string.submit_retry))
            }
        }
    }
}

/** Maps the terminal packet status to its localized confirmation label. */
private fun submitStatusLabel(status: PacketStatus): Int = when (status) {
    PacketStatus.COMPLETED -> R.string.submit_status_completed
    PacketStatus.PARTIALLY_SIGNED -> R.string.submit_status_partially_signed
    PacketStatus.SENT -> R.string.submit_status_sent
    PacketStatus.DRAFT -> R.string.submit_status_sent
    PacketStatus.CANCELLED -> R.string.submit_status_other
    PacketStatus.EXPIRED -> R.string.submit_status_other
    PacketStatus.UNKNOWN -> R.string.submit_status_other
}

/** Locale-aware relative time via [DateUtils.getRelativeTimeSpanString]. */
private fun relativeTime(instant: Instant): String =
    DateUtils.getRelativeTimeSpanString(
        instant.toEpochMilli(),
        System.currentTimeMillis(),
        DateUtils.MINUTE_IN_MILLIS,
        DateUtils.FORMAT_ABBREV_RELATIVE,
    ).toString()
