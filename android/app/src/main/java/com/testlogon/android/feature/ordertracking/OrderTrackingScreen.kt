@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.ordertracking

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.outlined.RadioButtonUnchecked
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Card
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
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.tracking.Shipment
import com.testlogon.android.data.tracking.ShipmentStatus
import com.testlogon.android.data.tracking.TrackingEvent
import com.testlogon.android.feature.tracking.TrackingUiState
import com.testlogon.android.feature.tracking.openCarrierUrl
import com.testlogon.android.feature.tracking.statusLabelRes
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** D4 - stable test tags for the buyer order-tracking screen. */
object OrderTrackingTestTags {
    const val SCREEN = "order_tracking_screen"
    const val CARD = "order_tracking_card"
    const val STATUS_CHIP = "order_tracking_status_chip"
    const val NUMBER = "order_tracking_number"
    const val OPEN_CARRIER = "order_tracking_open_carrier"
    const val TIMELINE = "order_tracking_timeline"
}

private val STEP_LABELS = listOf(
    R.string.order_tracking_step_shipped,
    R.string.order_tracking_step_in_transit,
    R.string.order_tracking_step_out_for_delivery,
    R.string.order_tracking_step_delivered,
)

private fun reachedIndex(status: ShipmentStatus): Int = when (status) {
    ShipmentStatus.PRE_TRANSIT, ShipmentStatus.LABEL_CREATED -> 0
    ShipmentStatus.IN_TRANSIT -> 1
    ShipmentStatus.OUT_FOR_DELIVERY -> 2
    ShipmentStatus.DELIVERED -> 3
    ShipmentStatus.EXCEPTION, ShipmentStatus.RETURNED, ShipmentStatus.UNKNOWN -> 0
}

@Composable
fun OrderTrackingRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: OrderTrackingViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    val context = LocalContext.current
    Scaffold(
        modifier = modifier.testTag(OrderTrackingTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.order_tracking_title)) },
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
            when (val s = state) {
                is TrackingUiState.Loading -> LoadingState()
                is TrackingUiState.NotShipped ->
                    Text(
                        text = stringResource(R.string.order_tracking_not_shipped),
                        style = MaterialTheme.typography.bodyLarge,
                        modifier = Modifier.padding(24.dp),
                    )
                is TrackingUiState.Error ->
                    ErrorState(message = s.message, onRetry = viewModel::retry)
                is TrackingUiState.Ready ->
                    OrderTrackingContent(
                        shipment = s.shipment,
                        onOpenCarrier = { url -> openCarrierUrl(context, url) },
                        onCopy = { number -> copyToClipboard(context, number) },
                    )
            }
        }
    }
}

@Composable
private fun OrderTrackingContent(
    shipment: Shipment,
    onOpenCarrier: (String) -> Unit,
    onCopy: (String) -> Unit,
) {
    val statusLabel = stringResource(statusLabelRes(shipment.status))
    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Card(Modifier.fillMaxWidth().testTag(OrderTrackingTestTags.CARD)) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Text(
                        text = "${stringResource(R.string.tracking_carrier_label)}: ${shipment.carrier.displayName}",
                        style = MaterialTheme.typography.titleMedium,
                    )
                    AssistChip(
                        onClick = {},
                        label = { Text(statusLabel) },
                        modifier = Modifier.testTag(OrderTrackingTestTags.STATUS_CHIP),
                    )
                }
                shipment.trackingNumber?.let { number ->
                    Text(
                        text = "${stringResource(R.string.tracking_number_label)}: $number",
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.testTag(OrderTrackingTestTags.NUMBER).clickable { onCopy(number) },
                    )
                }
                shipment.trackingUrl?.let { url ->
                    TextButton(
                        onClick = { onOpenCarrier(url) },
                        modifier = Modifier.testTag(OrderTrackingTestTags.OPEN_CARRIER),
                    ) {
                        Text(stringResource(R.string.tracking_open_carrier))
                    }
                }
            }
        }

        // Always-visible canonical progress stepper: shipped -> in transit -> out for delivery -> delivered.
        Text(
            text = stringResource(R.string.order_tracking_progress_title),
            style = MaterialTheme.typography.titleSmall,
        )
        val reached = reachedIndex(shipment.status)
        Column(Modifier.testTag(OrderTrackingTestTags.TIMELINE)) {
            STEP_LABELS.forEachIndexed { index, labelRes ->
                val done = index <= reached
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = if (done) Icons.Filled.CheckCircle else Icons.Outlined.RadioButtonUnchecked,
                        contentDescription = null,
                        tint = if (done) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outline,
                        modifier = Modifier.size(22.dp),
                    )
                    Spacer(Modifier.width(12.dp))
                    Text(
                        text = stringResource(labelRes),
                        style = MaterialTheme.typography.bodyMedium,
                        color = if (done) MaterialTheme.colorScheme.onSurface else MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }

        if (shipment.events.isNotEmpty()) {
            Text(
                text = stringResource(R.string.tracking_timeline_title),
                style = MaterialTheme.typography.titleSmall,
            )
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                shipment.events.forEach { event -> EventRow(event) }
            }
        }
    }
}

private val EVENT_FMT = SimpleDateFormat("MMM d, h:mm a", Locale.US)

@Composable
private fun EventRow(event: TrackingEvent) {
    Surface(color = Color.Transparent) {
        Column {
            Text(
                text = event.description.ifBlank { "Update" },
                style = MaterialTheme.typography.bodyMedium,
            )
            val meta = listOfNotNull(
                event.location,
                event.timestampEpochMs.takeIf { it > 0 }?.let { EVENT_FMT.format(Date(it)) },
            ).joinToString(" · ")
            if (meta.isNotBlank()) {
                Text(
                    text = meta,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

private fun copyToClipboard(context: Context, text: String) {
    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager ?: return
    clipboard.setPrimaryClip(ClipData.newPlainText("tracking_number", text))
}
