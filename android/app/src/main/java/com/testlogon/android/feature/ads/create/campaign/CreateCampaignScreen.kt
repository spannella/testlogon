@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.ads.create.campaign

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.model.ads.AdAccountSummary

/** ADV-108 - stable testTags for the create-campaign screen. */
object CreateCampaignTestTags {
    const val SCREEN = "create_campaign_screen"
    const val ACCOUNT = "create_campaign_account"
    const val NAME = "create_campaign_name"
    const val OBJECTIVE = "create_campaign_objective"
    const val BUDGET_TYPE = "create_campaign_budget_type"
    const val BUDGET = "create_campaign_budget"
    const val BID = "create_campaign_bid"
    const val SUBMIT = "create_campaign_submit"
    const val SUCCESS = "create_campaign_success"
    const val REVIEW = "create_campaign_review"
    const val CONTINUE = "create_campaign_continue"
}

/** ADV-108 - route-level create-campaign entry. [onCreated] carries the new campaign id to continue into creative creation. */
@Composable
fun CreateCampaignRoute(
    onBack: () -> Unit,
    onCreated: (campaignId: String) -> Unit,
    viewModel: CreateCampaignViewModel = hiltViewModel(),
) {
    val accounts by viewModel.accountsState.collectAsStateWithLifecycle()
    val selectedAccount by viewModel.selectedAccountId.collectAsStateWithLifecycle()
    val name by viewModel.name.collectAsStateWithLifecycle()
    val objective by viewModel.objective.collectAsStateWithLifecycle()
    val budgetType by viewModel.budgetType.collectAsStateWithLifecycle()
    val budget by viewModel.budgetUsd.collectAsStateWithLifecycle()
    val bid by viewModel.bidCpmUsd.collectAsStateWithLifecycle()
    val submit by viewModel.submitState.collectAsStateWithLifecycle()
    val review by viewModel.reviewState.collectAsStateWithLifecycle()

    CreateCampaignScreen(
        accounts = accounts,
        selectedAccountId = selectedAccount,
        name = name,
        objective = objective,
        budgetType = budgetType,
        budgetUsd = budget,
        bidCpmUsd = bid,
        submitState = submit,
        reviewState = review,
        canSubmit = viewModel.canSubmit,
        onAccount = viewModel::onAccountSelected,
        onName = viewModel::onName,
        onObjective = viewModel::onObjective,
        onBudgetType = viewModel::onBudgetType,
        onBudget = viewModel::onBudgetUsd,
        onBid = viewModel::onBidCpmUsd,
        onSubmit = viewModel::submit,
        onSubmitForReview = viewModel::submitForReview,
        onContinue = onCreated,
        onBack = onBack,
    )
}

/** ADV-108 - stateless create-campaign form. */
@Composable
fun CreateCampaignScreen(
    accounts: CreateCampaignViewModel.AccountsState,
    selectedAccountId: String?,
    name: String,
    objective: String,
    budgetType: String,
    budgetUsd: String,
    bidCpmUsd: String,
    submitState: CreateCampaignViewModel.SubmitState,
    reviewState: CreateCampaignViewModel.ReviewState,
    canSubmit: Boolean,
    onAccount: (String) -> Unit,
    onName: (String) -> Unit,
    onObjective: (String) -> Unit,
    onBudgetType: (String) -> Unit,
    onBudget: (String) -> Unit,
    onBid: (String) -> Unit,
    onSubmit: () -> Unit,
    onSubmitForReview: () -> Unit,
    onContinue: (campaignId: String) -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val submitting = submitState is CreateCampaignViewModel.SubmitState.Submitting
    Scaffold(
        modifier = modifier.testTag(CreateCampaignTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.create_campaign_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.ads_create_back),
                        )
                    }
                },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            (submitState as? CreateCampaignViewModel.SubmitState.Success)?.let { success ->
                CampaignCreatedCard(
                    reviewState = reviewState,
                    onSubmitForReview = onSubmitForReview,
                    onContinue = { onContinue(success.campaign.campaignId) },
                )
                return@Column
            }

            val accountLabel = when (accounts) {
                is CreateCampaignViewModel.AccountsState.Content ->
                    accounts.accounts.firstOrNull { it.accountId == selectedAccountId }?.pickerLabel()
                        ?: stringResource(R.string.create_campaign_account_hint)
                is CreateCampaignViewModel.AccountsState.Loading ->
                    stringResource(R.string.create_campaign_account_loading)
                is CreateCampaignViewModel.AccountsState.Empty ->
                    stringResource(R.string.create_campaign_account_none)
                is CreateCampaignViewModel.AccountsState.Error -> accounts.message
            }

            LabeledDropdown(
                label = stringResource(R.string.create_campaign_account_label),
                selectedLabel = accountLabel,
                options = (accounts as? CreateCampaignViewModel.AccountsState.Content)
                    ?.accounts?.mapNotNull { acc -> acc.accountId?.let { it to acc.pickerLabel() } }
                    ?: emptyList(),
                onSelect = onAccount,
                enabled = !submitting,
                testTag = CreateCampaignTestTags.ACCOUNT,
            )

            OutlinedTextField(
                value = name,
                onValueChange = onName,
                label = { Text(stringResource(R.string.create_campaign_name_label)) },
                singleLine = true,
                enabled = !submitting,
                modifier = Modifier.fillMaxWidth().testTag(CreateCampaignTestTags.NAME),
            )

            LabeledDropdown(
                label = stringResource(R.string.create_campaign_objective_label),
                selectedLabel = objective,
                options = CreateCampaignViewModel.OBJECTIVES.map { it to it },
                onSelect = onObjective,
                enabled = !submitting,
                testTag = CreateCampaignTestTags.OBJECTIVE,
            )

            LabeledDropdown(
                label = stringResource(R.string.create_campaign_budget_type_label),
                selectedLabel = budgetType,
                options = CreateCampaignViewModel.BUDGET_TYPES.map { it to it },
                onSelect = onBudgetType,
                enabled = !submitting,
                testTag = CreateCampaignTestTags.BUDGET_TYPE,
            )

            OutlinedTextField(
                value = budgetUsd,
                onValueChange = onBudget,
                label = { Text(stringResource(R.string.create_campaign_budget_label)) },
                prefix = { Text("$") },
                singleLine = true,
                enabled = !submitting,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Decimal),
                modifier = Modifier.fillMaxWidth().testTag(CreateCampaignTestTags.BUDGET),
            )

            OutlinedTextField(
                value = bidCpmUsd,
                onValueChange = onBid,
                label = { Text(stringResource(R.string.create_campaign_bid_label)) },
                prefix = { Text("$") },
                supportingText = { Text(stringResource(R.string.create_campaign_bid_hint)) },
                singleLine = true,
                enabled = !submitting,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Decimal),
                modifier = Modifier.fillMaxWidth().testTag(CreateCampaignTestTags.BID),
            )

            (submitState as? CreateCampaignViewModel.SubmitState.Error)?.let {
                Text(it.message, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodyMedium)
            }

            Button(
                onClick = onSubmit,
                enabled = canSubmit && !submitting,
                modifier = Modifier.fillMaxWidth().testTag(CreateCampaignTestTags.SUBMIT),
            ) {
                if (submitting) CircularProgressIndicator(modifier = Modifier.padding(end = 8.dp))
                Text(stringResource(R.string.create_campaign_submit))
            }
        }
    }
}

@Composable
private fun CampaignCreatedCard(
    reviewState: CreateCampaignViewModel.ReviewState,
    onSubmitForReview: () -> Unit,
    onContinue: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth().testTag(CreateCampaignTestTags.SUCCESS)) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(stringResource(R.string.create_campaign_success_title), style = MaterialTheme.typography.titleMedium)

            when (reviewState) {
                is CreateCampaignViewModel.ReviewState.Done -> Text(
                    stringResource(R.string.create_campaign_review_done, reviewState.status),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                is CreateCampaignViewModel.ReviewState.Error -> Text(
                    reviewState.message,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.error,
                )
                else -> Text(
                    stringResource(R.string.create_campaign_success_body),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            val reviewing = reviewState is CreateCampaignViewModel.ReviewState.Submitting
            val reviewed = reviewState is CreateCampaignViewModel.ReviewState.Done
            Button(
                onClick = onSubmitForReview,
                enabled = !reviewing && !reviewed,
                modifier = Modifier.fillMaxWidth().testTag(CreateCampaignTestTags.REVIEW),
            ) {
                if (reviewing) CircularProgressIndicator(modifier = Modifier.padding(end = 8.dp))
                Text(stringResource(R.string.create_campaign_review))
            }
            Button(
                onClick = onContinue,
                modifier = Modifier.fillMaxWidth().testTag(CreateCampaignTestTags.CONTINUE),
            ) {
                Text(stringResource(R.string.create_campaign_continue))
            }
        }
    }
}

/** A labeled exposed-dropdown picker over [options] (value to label). */
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

private fun AdAccountSummary.pickerLabel(): String {
    val name = companyName ?: accountId ?: "account"
    val status = status?.takeIf { it.isNotBlank() }
    return if (status != null) "$name ($status)" else name
}
