@file:OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)

package com.testlogon.android.feature.videos.purchase

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.testlogon.android.R
import com.testlogon.android.data.vod.purchase.PurchaseTier
import com.testlogon.android.data.vod.purchase.PurchaseTypeOption
import java.text.NumberFormat
import java.util.Currency
import java.util.Locale

/** AND-193 — stable test tags for the purchase sheet. */
object PurchaseSheetTestTags {
    const val SHEET = "vod_purchase_sheet"
    const val CONFIRM = "vod_purchase_confirm"
    const val RETRY = "vod_purchase_retry"
}

/**
 * AND-193 — the tier-offer + purchase bottom sheet. Stateless: renders [PurchaseUiState] (skeleton /
 * tier chips / confirm / processing / success / error) and hoists selection + confirm callbacks. Prices
 * are locale-/currency-aware via NumberFormat; tier labels come from strings.xml (no hardcoded `$`).
 */
@Composable
fun PurchaseTierSheet(
    state: PurchaseUiState,
    onTierSelected: (String) -> Unit,
    onConfirm: () -> Unit,
    onRetry: () -> Unit,
    onDismiss: () -> Unit,
    modifier: Modifier = Modifier,
) {
    ModalBottomSheet(onDismissRequest = onDismiss, modifier = modifier.testTag(PurchaseSheetTestTags.SHEET)) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(
                text = stringResource(R.string.vod_purchase_choose),
                style = MaterialTheme.typography.titleMedium,
            )

            when {
                state.isLoadingTiers -> CircularProgressIndicator(modifier = Modifier.size(24.dp))

                state.tiersError != null -> {
                    Text(text = state.tiersError, style = MaterialTheme.typography.bodyMedium)
                    TextButton(onClick = onRetry, modifier = Modifier.testTag(PurchaseSheetTestTags.RETRY)) {
                        Text(stringResource(R.string.vod_purchase_retry))
                    }
                }

                else -> {
                    FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        state.tiers.forEach { tier ->
                            FilterChip(
                                selected = state.selectedType == tier.type.wire,
                                onClick = { onTierSelected(tier.type.wire) },
                                label = { Text(tierLabel(tier)) },
                            )
                        }
                    }
                    if (state.purchaseError != null) {
                        Text(text = state.purchaseError, style = MaterialTheme.typography.bodySmall)
                    }
                    Button(
                        onClick = onConfirm,
                        enabled = state.canConfirm,
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag(PurchaseSheetTestTags.CONFIRM),
                    ) {
                        Text(
                            text = when {
                                state.isPurchased -> stringResource(R.string.vod_purchase_success)
                                state.isSubmitting -> stringResource(R.string.vod_purchase_processing)
                                else -> stringResource(R.string.vod_purchase_confirm)
                            },
                        )
                    }
                }
            }
        }
    }
}

/** A localized, currency-aware label "{tier} — {price}". */
@Composable
private fun tierLabel(tier: PurchaseTier): String {
    val name = when (tier.type) {
        PurchaseTypeOption.VIEW_ONCE -> stringResource(R.string.vod_tier_view_once)
        PurchaseTypeOption.RENTAL -> stringResource(R.string.vod_tier_rental)
        PurchaseTypeOption.PERMANENT -> stringResource(R.string.vod_tier_permanent)
        PurchaseTypeOption.DOWNLOAD -> stringResource(R.string.vod_tier_download)
        PurchaseTypeOption.UNKNOWN -> stringResource(R.string.vod_tier_permanent)
    }
    val price = formatPrice(tier.priceCents)
    return if (price != null) "$name — $price" else name
}

/** Locale-aware cents formatting (no hardcoded `$`); null/zero price => null (label shows name only). */
private fun formatPrice(cents: Long?): String? {
    if (cents == null || cents <= 0L) return null
    val locale = Locale.getDefault()
    val fmt = NumberFormat.getCurrencyInstance(locale)
    runCatching { fmt.currency = Currency.getInstance(locale) }
    return fmt.format(cents / 100.0)
}
