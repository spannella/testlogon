@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class, androidx.compose.ui.ExperimentalComposeUiApi::class)

package com.testlogon.android.feature.messaging.thread

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.testlogon.android.feature.messaging.EcomCardModel

object EcomComposerTestTags {
    const val ATTACH_PRODUCT = "thread_attach_product"
    const val ATTACH_ORDER = "thread_attach_order"
    const val PRODUCT_PICKER = "thread_product_picker"
    const val PRODUCT_PICKER_SEARCH = "thread_product_picker_search"
    const val PRODUCT_PICKER_ROW = "thread_product_picker_row_"
    const val ORDER_PICKER = "thread_order_picker"
    const val ORDER_PICKER_ROW = "thread_order_picker_row_"
    const val ORDER_MODE_CHIP = "thread_order_mode_"
    const val ORDER_SEND = "thread_order_send"
}

/**
 * FE-150 — "Share product": a searchable catalog picker; selecting a row sends a product_card message.
 * The search + rows are driven by the ViewModel [ProductPickerState] (catalog search read).
 */
@Composable
fun ProductPickerSheet(
    state: ProductPickerState,
    onQuery: (String) -> Unit,
    onPick: (ProductPick) -> Unit,
    onDismiss: () -> Unit,
) {
    ModalBottomSheet(
        onDismissRequest = onDismiss,
        modifier = Modifier.testTag(EcomComposerTestTags.PRODUCT_PICKER).semantics { testTagsAsResourceId = true },
    ) {
        Column(Modifier.fillMaxWidth().navigationBarsPadding().padding(16.dp).verticalScroll(rememberScrollState())) {
            Text("Share product", style = MaterialTheme.typography.titleMedium)
            OutlinedTextField(
                value = state.query,
                onValueChange = onQuery,
                modifier = Modifier.fillMaxWidth().padding(top = 8.dp).testTag(EcomComposerTestTags.PRODUCT_PICKER_SEARCH),
                placeholder = { Text("Search products") },
                singleLine = true,
            )
            when {
                state.loading -> CircularProgressIndicator(Modifier.padding(16.dp))
                state.products.isEmpty() -> Text(
                    state.error ?: "No products found.",
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 8.dp),
                )
                else -> state.products.forEach { p ->
                    OutlinedButton(
                        onClick = { onPick(p) },
                        modifier = Modifier.fillMaxWidth().padding(top = 6.dp).testTag(EcomComposerTestTags.PRODUCT_PICKER_ROW + p.itemId),
                    ) {
                        Column(Modifier.fillMaxWidth()) {
                            Text(p.title, style = MaterialTheme.typography.bodyLarge)
                            Text(
                                EcomCardModel.formatPrice(p.priceCents, p.currency) +
                                    (if (p.inStock) "" else "  •  Out of stock"),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                }
            }
            Box(Modifier.fillMaxWidth().heightIn(min = 16.dp))
        }
    }
}

/**
 * FE-151 — "Share purchase": pick one of the caller's orders + a mode (Receipt / Gift / Recommendation),
 * then send an order_share card. RECEIPT mode strips buyer PII in the model choke point (see the note).
 */
@Composable
fun OrderPickerSheet(
    state: OrderPickerState,
    onSend: (OrderPick, EcomCardModel.OrderMode) -> Unit,
    onDismiss: () -> Unit,
) {
    var selectedId by remember { mutableStateOf<String?>(null) }
    var mode by remember { mutableStateOf(EcomCardModel.OrderMode.RECOMMENDATION) }

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        modifier = Modifier.testTag(EcomComposerTestTags.ORDER_PICKER).semantics { testTagsAsResourceId = true },
    ) {
        Column(Modifier.fillMaxWidth().navigationBarsPadding().padding(16.dp).verticalScroll(rememberScrollState())) {
            Text("Share purchase", style = MaterialTheme.typography.titleMedium)
            when {
                state.loading -> CircularProgressIndicator(Modifier.padding(16.dp))
                state.orders.isEmpty() -> Text(
                    state.error ?: "You have no purchases to share.",
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 8.dp),
                )
                else -> {
                    Text("Order", style = MaterialTheme.typography.labelMedium, modifier = Modifier.padding(top = 8.dp))
                    state.orders.forEach { o ->
                        FilterChip(
                            selected = selectedId == o.orderId,
                            onClick = { selectedId = o.orderId },
                            label = { Text("${o.summary}  •  ${o.status}") },
                            modifier = Modifier.padding(top = 4.dp).testTag(EcomComposerTestTags.ORDER_PICKER_ROW + o.orderId),
                        )
                    }
                    Text("Share as", style = MaterialTheme.typography.labelMedium, modifier = Modifier.padding(top = 12.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        ModeChip(EcomCardModel.OrderMode.RECEIPT, "Receipt", mode) { mode = it }
                        ModeChip(EcomCardModel.OrderMode.GIFT, "Gift", mode) { mode = it }
                        ModeChip(EcomCardModel.OrderMode.RECOMMENDATION, "Recommend", mode) { mode = it }
                    }
                    Text(
                        when (mode) {
                            EcomCardModel.OrderMode.RECEIPT -> "Shares the receipt only — your name and address are removed."
                            EcomCardModel.OrderMode.GIFT -> "Shares as a gift, attributed to you."
                            EcomCardModel.OrderMode.RECOMMENDATION -> "Recommends this purchase, attributed to you."
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(top = 6.dp),
                    )
                    val selected = state.orders.firstOrNull { it.orderId == selectedId }
                    Button(
                        onClick = { selected?.let { onSend(it, mode) } },
                        enabled = selected != null,
                        modifier = Modifier.fillMaxWidth().padding(top = 16.dp).testTag(EcomComposerTestTags.ORDER_SEND),
                    ) { Text("Share purchase") }
                }
            }
            Box(Modifier.fillMaxWidth().heightIn(min = 16.dp))
        }
    }
}

@Composable
private fun ModeChip(
    value: EcomCardModel.OrderMode,
    label: String,
    selected: EcomCardModel.OrderMode,
    onSelect: (EcomCardModel.OrderMode) -> Unit,
) {
    FilterChip(
        selected = selected == value,
        onClick = { onSelect(value) },
        label = { Text(label, fontWeight = if (selected == value) FontWeight.SemiBold else FontWeight.Normal) },
        modifier = Modifier.testTag(EcomComposerTestTags.ORDER_MODE_CHIP + value.wire),
    )
}
