@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.tracking

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.unit.dp
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.tracking.Shipment
import com.testlogon.android.data.tracking.ShipmentStatus
import com.testlogon.android.data.tracking.TrackingEvent

/** AND-215 — stable test tags for the tracking section. */
object TrackingTestTags {
    const val SECTION = "tracking_section"
    const val NOT_SHIPPED = "tracking_not_shipped"
    const val CARD = "tracking_card"
    const val STATUS_CHIP = "tracking_status_chip"
    const val NUMBER = "tracking_number"
    const val OPEN_CARRIER = "tracking_open_carrier"
    const val TIMELINE_TOGGLE = "tracking_timeline_toggle"
}

/** Maps a [ShipmentStatus] to its localized label string resource. */
fun statusLabelRes(status: ShipmentStatus): Int = when (status) {
    ShipmentStatus.PRE_TRANSIT -> R.string.tracking_status_pre_transit
    ShipmentStatus.LABEL_CREATED -> R.string.tracking_status_label_created
    ShipmentStatus.IN_TRANSIT -> R.string.tracking_status_in_transit
    ShipmentStatus.OUT_FOR_DELIVERY -> R.string.tracking_status_out_for_delivery
    ShipmentStatus.DELIVERED -> R.string.tracking_status_delivered
    ShipmentStatus.EXCEPTION -> R.string.tracking_status_exception
    ShipmentStatus.RETURNED -> R.string.tracking_status_returned
    ShipmentStatus.UNKNOWN -> R.string.tracking_status_unknown
}

/**
 * AND-215 — the tracking section, embeddable into a PurchaseDetailScreen (AND-218) or used standalone.
 * Renders Loading / NotShipped / Error / Ready states. https-only carrier launch is enforced by the
 * caller via [onOpenCarrier].
 */
@Composable
fun TrackingSection(
    state: TrackingUiState,
    onRetry: () -> Unit,
    onOpenCarrier: (url: String) -> Unit,
    onCopy: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(modifier.fillMaxWidth().testTag(TrackingTestTags.SECTION)) {
        Text(
            text = stringResource(R.string.tracking_section_title),
            style = MaterialTheme.typography.titleMedium,
            modifier = Modifier.padding(16.dp),
        )
        when (state) {
            is TrackingUiState.Loading -> LoadingState(fullScreen = false)
            is TrackingUiState.NotShipped ->
                Text(
                    text = stringResource(R.string.tracking_not_shipped),
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.padding(horizontal = 16.dp).testTag(TrackingTestTags.NOT_SHIPPED),
                )
            is TrackingUiState.Error ->
                ErrorState(message = state.message, onRetry = onRetry)
            is TrackingUiState.Ready ->
                ShipmentCard(
                    shipment = state.shipment,
                    onOpenCarrier = onOpenCarrier,
                    onCopy = onCopy,
                )
        }
    }
}

@Composable
private fun ShipmentCard(
    shipment: Shipment,
    onOpenCarrier: (String) -> Unit,
    onCopy: (String) -> Unit,
) {
    var expanded by remember { mutableStateOf(false) }
    val statusLabel = stringResource(statusLabelRes(shipment.status))
    val statusText = shipment.statusDescription ?: statusLabel
    val statusCd = stringResource(R.string.tracking_status_label, statusText)

    Card(
        Modifier.fillMaxWidth().padding(16.dp).testTag(TrackingTestTags.CARD),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Text(
                    text = "${stringResource(R.string.tracking_carrier_label)}: ${shipment.carrier.displayName}",
                    style = MaterialTheme.typography.bodyLarge,
                )
                AssistChip(
                    onClick = {},
                    label = { Text(statusText) },
                    modifier = Modifier
                        .testTag(TrackingTestTags.STATUS_CHIP)
                        .clearAndSetSemantics { contentDescription = statusCd },
                )
            }

            shipment.trackingNumber?.let { number ->
                Text(
                    text = "${stringResource(R.string.tracking_number_label)}: $number",
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier
                        .testTag(TrackingTestTags.NUMBER)
                        .clickable { onCopy(number) },
                )
            }

            // CTA only when a tracking_url is present (FR-4 / AC-4).
            shipment.trackingUrl?.let { url ->
                TextButton(
                    onClick = { onOpenCarrier(url) },
                    modifier = Modifier.testTag(TrackingTestTags.OPEN_CARRIER),
                ) {
                    Text(stringResource(R.string.tracking_open_carrier))
                }
            }

            if (shipment.events.isNotEmpty()) {
                TextButton(
                    onClick = { expanded = !expanded },
                    modifier = Modifier.testTag(TrackingTestTags.TIMELINE_TOGGLE),
                ) {
                    Text(stringResource(R.string.tracking_timeline_title))
                }
                if (expanded) {
                    TrackingTimeline(events = shipment.events)
                }
            }
        }
    }
}

@Composable
private fun TrackingTimeline(events: List<TrackingEvent>) {
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        events.forEach { event ->
            val line = listOfNotNull(
                event.description.ifBlank { null },
                event.location,
            ).joinToString(" · ")
            Text(
                text = line,
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.clearAndSetSemantics { contentDescription = line },
            )
        }
    }
}
