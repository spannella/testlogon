@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.ads.studio.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.testlogon.android.R
import com.testlogon.android.core.model.ads.AdAccountSummary
import com.testlogon.android.core.model.ads.AdCampaign
import com.testlogon.android.feature.ads.studio.data.StudioCampaignSelector

/** PAR-23 - stable testTags for the shared studio campaign picker. */
object StudioCampaignPickerTestTags {
    const val ACCOUNT = "studio_picker_account"
    const val CAMPAIGN = "studio_picker_campaign"
}

/**
 * PAR-23 - a reusable account + campaign picker rendered at the top of each ads STUDIO editor (targeting /
 * scheduling / optimization). Selecting an account/campaign writes the persisted [AdsStudioSelection] (via the
 * [StudioCampaignSelector]) and reloads the host editor against the newly chosen campaign, replacing the old
 * first-of-first auto-resolve with an explicit in-screen choice.
 */
@Composable
fun StudioCampaignPicker(
    accountsState: StudioCampaignSelector.AccountsState,
    campaignsState: StudioCampaignSelector.CampaignsState,
    selectedAccountId: String?,
    selectedCampaignId: String?,
    onAccountSelected: (String) -> Unit,
    onCampaignSelected: (String) -> Unit,
    enabled: Boolean = true,
    modifier: Modifier = Modifier,
) {
    Column(modifier = modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        LabeledDropdown(
            label = stringResource(R.string.studio_picker_account_label),
            selectedLabel = (accountsState as? StudioCampaignSelector.AccountsState.Content)
                ?.accounts?.firstOrNull { it.accountId == selectedAccountId }?.pickerLabel()
                ?: accountsPlaceholder(accountsState),
            options = (accountsState as? StudioCampaignSelector.AccountsState.Content)
                ?.accounts?.mapNotNull { acc -> acc.accountId?.let { it to acc.pickerLabel() } }
                ?: emptyList(),
            onSelect = onAccountSelected,
            enabled = enabled,
            testTag = StudioCampaignPickerTestTags.ACCOUNT,
        )
        LabeledDropdown(
            label = stringResource(R.string.studio_picker_campaign_label),
            selectedLabel = (campaignsState as? StudioCampaignSelector.CampaignsState.Content)
                ?.campaigns?.firstOrNull { it.campaignId == selectedCampaignId }?.pickerLabel()
                ?: campaignsPlaceholder(campaignsState),
            options = (campaignsState as? StudioCampaignSelector.CampaignsState.Content)
                ?.campaigns?.map { it.campaignId to it.pickerLabel() } ?: emptyList(),
            onSelect = onCampaignSelected,
            enabled = enabled,
            testTag = StudioCampaignPickerTestTags.CAMPAIGN,
        )
    }
}

@Composable
private fun LabeledDropdown(
    label: String,
    selectedLabel: String,
    options: List<Pair<String, String>>,
    onSelect: (String) -> Unit,
    enabled: Boolean,
    testTag: String,
) {
    var expanded by remember { mutableStateOf(false) }
    ExposedDropdownMenuBox(
        expanded = expanded,
        onExpandedChange = { if (enabled) expanded = it },
        modifier = Modifier.fillMaxWidth(),
    ) {
        OutlinedTextField(
            value = selectedLabel,
            onValueChange = {},
            readOnly = true,
            label = { Text(label) },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
            enabled = enabled,
            modifier = Modifier
                .menuAnchor()
                .fillMaxWidth()
                .testTag(testTag),
        )
        ExposedDropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
            options.forEach { (value, optLabel) ->
                DropdownMenuItem(
                    text = { Text(optLabel) },
                    onClick = {
                        onSelect(value)
                        expanded = false
                    },
                )
            }
        }
    }
}

@Composable
private fun accountsPlaceholder(state: StudioCampaignSelector.AccountsState): String = when (state) {
    is StudioCampaignSelector.AccountsState.Loading -> stringResource(R.string.studio_picker_loading)
    is StudioCampaignSelector.AccountsState.Empty -> stringResource(R.string.studio_picker_account_none)
    is StudioCampaignSelector.AccountsState.Error -> state.message
    is StudioCampaignSelector.AccountsState.Content -> stringResource(R.string.studio_picker_account_hint)
}

@Composable
private fun campaignsPlaceholder(state: StudioCampaignSelector.CampaignsState): String = when (state) {
    is StudioCampaignSelector.CampaignsState.Idle -> stringResource(R.string.studio_picker_campaign_hint)
    is StudioCampaignSelector.CampaignsState.Loading -> stringResource(R.string.studio_picker_loading)
    is StudioCampaignSelector.CampaignsState.Empty -> stringResource(R.string.studio_picker_campaign_none)
    is StudioCampaignSelector.CampaignsState.Error -> state.message
    is StudioCampaignSelector.CampaignsState.Content -> stringResource(R.string.studio_picker_campaign_hint)
}

private fun AdAccountSummary.pickerLabel(): String {
    val name = companyName ?: accountId ?: "account"
    val status = status?.takeIf { it.isNotBlank() }
    return if (status != null) "$name ($status)" else name
}

private fun AdCampaign.pickerLabel(): String = name ?: campaignId
