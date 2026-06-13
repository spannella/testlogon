@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.signing

import android.text.format.DateUtils
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
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material.icons.filled.Circle
import androidx.compose.material.icons.filled.Description
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.network.signing.PacketStatus
import com.testlogon.android.core.network.signing.SignatureFieldType
import com.testlogon.android.feature.signing.model.PacketAction
import com.testlogon.android.feature.signing.model.PacketEvent
import com.testlogon.android.feature.signing.model.PacketField
import com.testlogon.android.feature.signing.model.PacketSigner
import com.testlogon.android.feature.signing.model.SignaturePacket
import com.testlogon.android.feature.signing.model.primaryAction
import java.time.Instant

/** AND-340 - stable testTags for the e-signature packet DETAIL screen. */
object PacketDetailTestTags {
    const val SCREEN = "packet_detail_screen"
    const val STATUS = "packet_status"
    const val ACTION = "packet_action"
    const val OPEN_PDF = "packet_open_pdf"
    const val RETRY = "packet_detail_retry"

    /** Per-signer row tag, suffixed by the signer id. */
    fun signer(signerId: String): String = "packet_signer_$signerId"

    /** Per-field manifest row tag, suffixed by the field id (PLACEHOLDER for AND-341/342). */
    fun field(fieldId: String): String = "packet_field_$fieldId"

    /** Per-event row tag, suffixed by the event index (oldest -> newest as returned). */
    fun event(index: Int): String = "packet_event_$index"
}

/**
 * AND-340 - route-level packet DETAIL screen. Forwards [onBack], [onOpenPdf] (the "Open document"
 * affordance -> the PDF viewer, deferred) and [onSign] (the assigned-signer deep flow -> AND-342/343).
 * Collects the VM's one-shot [PacketDetailEvent]s (Sign nav is delegated to [onSign]).
 */
@Composable
fun PacketDetailRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    onOpenPdf: (sourcePath: String) -> Unit = {},
    onSign: (packetId: String) -> Unit = {},
    viewModel: PacketDetailViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    LaunchedEffect(viewModel) {
        viewModel.events.collect { event ->
            when (event) {
                is PacketDetailEvent.NavigateToSign -> onSign(event.packetId)
                PacketDetailEvent.PacketSent -> Unit
                is PacketDetailEvent.ActionFailed -> Unit
            }
        }
    }
    PacketDetailScreen(
        state = state,
        onBack = onBack,
        onOpenPdf = onOpenPdf,
        onPrimaryAction = viewModel::onPrimaryAction,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::retry,
        modifier = modifier,
    )
}

@Composable
fun PacketDetailScreen(
    state: PacketDetailUiState,
    onBack: () -> Unit,
    onOpenPdf: (sourcePath: String) -> Unit,
    onPrimaryAction: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(PacketDetailTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.signing_packet_detail_title)) },
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
            when (state) {
                is PacketDetailUiState.Loading ->
                    CircularProgressIndicator(Modifier.align(Alignment.Center))

                is PacketDetailUiState.Content -> ContentBody(
                    state = state,
                    onOpenPdf = onOpenPdf,
                    onPrimaryAction = onPrimaryAction,
                    onRefresh = onRefresh,
                )

                is PacketDetailUiState.Error -> ErrorBody(
                    message = state.message,
                    retryable = state.retryable,
                    onRetry = onRetry,
                )
            }
        }
    }
}

@Composable
private fun ContentBody(
    state: PacketDetailUiState.Content,
    onOpenPdf: (sourcePath: String) -> Unit,
    onPrimaryAction: () -> Unit,
    onRefresh: () -> Unit,
) {
    val packet = state.packet
    PullToRefreshBox(
        isRefreshing = state.refreshing,
        onRefresh = onRefresh,
        modifier = Modifier.fillMaxSize(),
    ) {
        LazyColumn(
            modifier = Modifier.fillMaxSize().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            if (state.isStale) {
                item {
                    Text(
                        text = stringResource(R.string.signing_stale),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }

            item { StatusCard(packet) }
            item { MetadataCard(packet, onOpenPdf) }

            item {
                SectionHeading(stringResource(R.string.signing_signers_heading))
            }
            if (packet.signers.isEmpty()) {
                item { EmptyLine(stringResource(R.string.signing_no_signers)) }
            } else {
                items(packet.signers, key = { it.signerId }) { signer ->
                    SignerRow(signer)
                }
            }

            item {
                SectionHeading(stringResource(R.string.signing_fields_heading))
            }
            if (packet.fields.isEmpty()) {
                item { EmptyLine(stringResource(R.string.signing_no_fields)) }
            } else {
                items(packet.fields, key = { it.fieldId }) { field ->
                    FieldRow(field)
                }
            }

            item {
                SectionHeading(stringResource(R.string.signing_events_heading))
            }
            if (state.events.isEmpty()) {
                item { EmptyLine(stringResource(R.string.signing_no_events)) }
            } else {
                itemsIndexed(state.events, key = { _, e -> e.eventId }) { index, event ->
                    EventRow(index = index, event = event)
                }
            }

            val action = primaryAction(packet)
            if (action != PacketAction.NONE) {
                item {
                    PrimaryActionButton(
                        action = action,
                        inFlight = state.actionInFlight,
                        onClick = onPrimaryAction,
                    )
                }
            }
        }
    }
}

@Composable
private fun StatusCard(packet: SignaturePacket) {
    Card(modifier = Modifier.fillMaxWidth().testTag(PacketDetailTestTags.STATUS)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(
                text = stringResource(R.string.signing_status_heading),
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            StatusChip(packet.status)
            Text(
                text = packet.packetId,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

/**
 * The status indicator. Label + a leading status dot icon back the colour (text + icon, NOT colour
 * alone) so the status is conveyed accessibly. The dot tint is derived from the status.
 */
@Composable
private fun StatusChip(status: PacketStatus) {
    val label = stringResource(packetStatusLabel(status))
    AssistChip(
        onClick = {},
        enabled = false,
        label = { Text(label) },
        leadingIcon = {
            Icon(
                imageVector = Icons.Filled.Circle,
                contentDescription = null,
                modifier = Modifier.size(12.dp),
                tint = statusTint(status),
            )
        },
        colors = AssistChipDefaults.assistChipColors(
            disabledLabelColor = MaterialTheme.colorScheme.onSurface,
        ),
    )
}

@Composable
private fun MetadataCard(packet: SignaturePacket, onOpenPdf: (sourcePath: String) -> Unit) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            MetaLine(stringResource(R.string.signing_meta_source), packet.sourcePath)
            packet.createdAt?.let {
                MetaLine(stringResource(R.string.signing_meta_created), relativeTime(it))
            }
            packet.sentAt?.let {
                MetaLine(stringResource(R.string.signing_meta_sent), relativeTime(it))
            }
            packet.completedAt?.let {
                MetaLine(stringResource(R.string.signing_meta_completed), relativeTime(it))
            }
            OutlinedButton(
                onClick = { onOpenPdf(packet.sourcePath) },
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 48.dp)
                    .padding(top = 8.dp)
                    .testTag(PacketDetailTestTags.OPEN_PDF),
            ) {
                Icon(
                    imageVector = Icons.Filled.Description,
                    contentDescription = null,
                    modifier = Modifier.size(18.dp),
                )
                Text(
                    text = stringResource(R.string.signing_open_document),
                    modifier = Modifier.padding(start = 8.dp),
                )
            }
        }
    }
}

@Composable
private fun MetaLine(label: String, value: String) {
    Column(verticalArrangement = Arrangement.spacedBy(1.dp)) {
        Text(
            text = label,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(text = value, style = MaterialTheme.typography.bodyMedium)
    }
}

@Composable
private fun SignerRow(signer: PacketSigner) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 48.dp)
            .testTag(PacketDetailTestTags.signer(signer.signerId)),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(12.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(text = signer.signerId, style = MaterialTheme.typography.bodyMedium)
            AssistChip(
                onClick = {},
                enabled = false,
                label = { Text(signer.status) },
                colors = AssistChipDefaults.assistChipColors(
                    disabledLabelColor = MaterialTheme.colorScheme.onSurface,
                ),
            )
        }
    }
}

/**
 * One field-manifest row. A PLACEHOLDER ready for AND-341 (manifest) / AND-342 (capture): it shows the
 * field type + page + an assigned/filled hint, but does NOT yet render or edit the field on the PDF.
 */
@Composable
private fun FieldRow(field: PacketField) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 48.dp)
            .testTag(PacketDetailTestTags.field(field.fieldId)),
    ) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(
                text = stringResource(packetFieldTypeLabel(field.fieldType)),
                style = MaterialTheme.typography.bodyMedium,
            )
            Text(
                text = stringResource(R.string.signing_field_page, field.page + 1),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                text = stringResource(fieldStateLabel(field)),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun EventRow(index: Int, event: PacketEvent) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 48.dp)
            .testTag(PacketDetailTestTags.event(index)),
        verticalAlignment = Alignment.Top,
    ) {
        Icon(
            imageVector = Icons.Filled.Circle,
            contentDescription = null,
            modifier = Modifier.padding(top = 4.dp, end = 12.dp).size(10.dp),
            tint = MaterialTheme.colorScheme.primary,
        )
        Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(text = event.eventType, style = MaterialTheme.typography.bodyMedium)
            event.createdAt?.let {
                Text(
                    text = relativeTime(it),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
private fun PrimaryActionButton(action: PacketAction, inFlight: Boolean, onClick: () -> Unit) {
    val labelRes = when (action) {
        PacketAction.SEND -> R.string.signing_action_send
        PacketAction.SIGN -> R.string.signing_action_sign
        PacketAction.NONE -> R.string.signing_action_send // unreachable; not rendered for NONE.
    }
    Button(
        onClick = onClick,
        enabled = !inFlight,
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 48.dp)
            .testTag(PacketDetailTestTags.ACTION),
    ) {
        if (action == PacketAction.SEND) {
            Icon(
                imageVector = Icons.AutoMirrored.Filled.Send,
                contentDescription = null,
                modifier = Modifier.size(18.dp),
            )
        }
        Text(
            text = stringResource(labelRes),
            modifier = Modifier.padding(start = if (action == PacketAction.SEND) 8.dp else 0.dp),
        )
    }
}

@Composable
private fun SectionHeading(text: String) {
    Column {
        HorizontalDivider(Modifier.padding(bottom = 8.dp))
        Text(text = text, style = MaterialTheme.typography.titleSmall)
    }
}

@Composable
private fun EmptyLine(text: String) {
    Text(
        text = text,
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
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
                modifier = Modifier.heightIn(min = 48.dp).testTag(PacketDetailTestTags.RETRY),
            ) {
                Text(stringResource(R.string.signing_retry))
            }
        }
    }
}

/** Maps a packet status to its localized label resource (UNKNOWN -> a generic fallback). */
private fun packetStatusLabel(status: PacketStatus): Int = when (status) {
    PacketStatus.DRAFT -> R.string.signing_status_draft
    PacketStatus.SENT -> R.string.signing_status_sent
    PacketStatus.PARTIALLY_SIGNED -> R.string.signing_status_partially_signed
    PacketStatus.COMPLETED -> R.string.signing_status_completed
    PacketStatus.CANCELLED -> R.string.signing_status_cancelled
    PacketStatus.EXPIRED -> R.string.signing_status_expired
    PacketStatus.UNKNOWN -> R.string.signing_status_unknown
}

/** Status dot tint (the icon backs the label; colour is NOT the sole status signal). */
@Composable
private fun statusTint(status: PacketStatus) = when (status) {
    PacketStatus.COMPLETED -> MaterialTheme.colorScheme.primary
    PacketStatus.CANCELLED, PacketStatus.EXPIRED -> MaterialTheme.colorScheme.error
    else -> MaterialTheme.colorScheme.tertiary
}

/** Maps a field type to its localized label resource (UNKNOWN -> a generic fallback). */
private fun packetFieldTypeLabel(type: SignatureFieldType): Int = when (type) {
    SignatureFieldType.SIGNATURE -> R.string.signing_field_signature
    SignatureFieldType.INITIALS -> R.string.signing_field_initials
    SignatureFieldType.DATE -> R.string.signing_field_date
    SignatureFieldType.TEXT -> R.string.signing_field_text
    SignatureFieldType.NOTARY_STAMP -> R.string.signing_field_notary_stamp
    SignatureFieldType.UNKNOWN -> R.string.signing_field_unknown
}

/** The assigned/filled hint shown on a field-manifest placeholder row. */
private fun fieldStateLabel(field: PacketField): Int = when {
    field.filledAt != null -> R.string.signing_field_filled
    field.isAssignedToViewer == true -> R.string.signing_field_assigned_to_you
    field.assignedSignerId != null -> R.string.signing_field_assigned
    else -> R.string.signing_field_unassigned
}

/** Locale-aware relative time via [DateUtils.getRelativeTimeSpanString]. */
private fun relativeTime(instant: Instant): String =
    DateUtils.getRelativeTimeSpanString(
        instant.toEpochMilli(),
        System.currentTimeMillis(),
        DateUtils.MINUTE_IN_MILLIS,
        DateUtils.FORMAT_ABBREV_RELATIVE,
    ).toString()
