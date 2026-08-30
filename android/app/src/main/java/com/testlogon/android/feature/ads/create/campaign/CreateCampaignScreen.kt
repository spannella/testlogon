@file:OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)

package com.testlogon.android.feature.ads.create.campaign

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DatePicker
import androidx.compose.material3.DatePickerDialog
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberDatePickerState
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.model.ads.AdAccountSummary
import com.testlogon.android.feature.ads.create.campaign.PromoteTargetingMath.PromoteEntityKind
import com.testlogon.android.feature.ads.create.campaign.PromoteTargetingMath.SelectedSegments

/** ADV-108 - stable testTags for the create-campaign screen. */
object CreateCampaignTestTags {
    const val SCREEN = "create_campaign_screen"
    const val ACCOUNT = "create_campaign_account"
    const val NAME = "create_campaign_name"
    const val OBJECTIVE = "create_campaign_objective"
    const val BUDGET_TYPE = "create_campaign_budget_type"
    const val BUDGET = "create_campaign_budget"
    const val BID = "create_campaign_bid"
    const val BID_CPC = "create_campaign_bid_cpc"
    const val BID_CPA = "create_campaign_bid_cpa"
    const val SELF_PROMO = "create_campaign_self_promo_toggle"
    const val FILL_MODE = "create_campaign_fill_mode"
    const val START_DATE = "create_campaign_start_date"
    const val END_DATE = "create_campaign_end_date"
    const val ADD_FUNDS = "create_campaign_add_funds"
    const val SUBMIT = "create_campaign_submit"
    const val SUCCESS = "create_campaign_success"
    const val REVIEW = "create_campaign_review"
    const val CONTINUE = "create_campaign_continue"
    // FE-162
    const val PROMOTE_KIND = "create_campaign_promote_kind"
    const val PROMOTE_SEARCH = "create_campaign_promote_search"
    const val PROMOTE_ENTITY = "create_campaign_promote_entity"
    const val TARGETING = "create_campaign_targeting"
    const val ESTIMATE = "create_campaign_estimate"
}

/** ADV-108 - route-level create-campaign entry. [onCreated] carries the new campaign id to continue into creative creation. */
@Composable
fun CreateCampaignRoute(
    onBack: () -> Unit,
    onCreated: (campaignId: String) -> Unit,
    onAddFunds: (accountId: String) -> Unit = {},
    viewModel: CreateCampaignViewModel = hiltViewModel(),
) {
    val accounts by viewModel.accountsState.collectAsStateWithLifecycle()
    val selectedAccount by viewModel.selectedAccountId.collectAsStateWithLifecycle()
    val name by viewModel.name.collectAsStateWithLifecycle()
    val objective by viewModel.objective.collectAsStateWithLifecycle()
    val budgetType by viewModel.budgetType.collectAsStateWithLifecycle()
    val budget by viewModel.budgetUsd.collectAsStateWithLifecycle()
    val bid by viewModel.bidCpmUsd.collectAsStateWithLifecycle()
    val bidCpc by viewModel.bidCpcUsd.collectAsStateWithLifecycle()
    val bidCpa by viewModel.bidCpaUsd.collectAsStateWithLifecycle()
    val isSelfPromo by viewModel.isSelfPromo.collectAsStateWithLifecycle()
    val selfPromoMode by viewModel.selfPromoMode.collectAsStateWithLifecycle()
    val startDate by viewModel.startDateMillis.collectAsStateWithLifecycle()
    val endDate by viewModel.endDateMillis.collectAsStateWithLifecycle()
    val submit by viewModel.submitState.collectAsStateWithLifecycle()
    val review by viewModel.reviewState.collectAsStateWithLifecycle()
    // FE-162
    val promoteKind by viewModel.promoteKind.collectAsStateWithLifecycle()
    val promoteQuery by viewModel.promoteQuery.collectAsStateWithLifecycle()
    val promoteEntities by viewModel.promoteEntities.collectAsStateWithLifecycle()
    val selectedEntity by viewModel.selectedEntity.collectAsStateWithLifecycle()
    val segments by viewModel.segments.collectAsStateWithLifecycle()
    val estimate by viewModel.estimate.collectAsStateWithLifecycle()

    CreateCampaignScreen(
        accounts = accounts,
        selectedAccountId = selectedAccount,
        name = name,
        objective = objective,
        budgetType = budgetType,
        budgetUsd = budget,
        bidCpmUsd = bid,
        bidCpcUsd = bidCpc,
        bidCpaUsd = bidCpa,
        isSelfPromo = isSelfPromo,
        selfPromoMode = selfPromoMode,
        submitState = submit,
        reviewState = review,
        canSubmit = viewModel.canSubmit,
        promoteKind = promoteKind,
        promoteQuery = promoteQuery,
        promoteEntities = promoteEntities,
        selectedEntity = selectedEntity,
        segments = segments,
        estimate = estimate,
        targetingSummary = viewModel.targetingSummary,
        onPromoteKind = viewModel::onPromoteKind,
        onPromoteQuery = viewModel::onPromoteQuery,
        onPromoteEntity = viewModel::onPromoteEntitySelected,
        onToggleAge = viewModel::onToggleAgeRange,
        onToggleGender = viewModel::onToggleGender,
        onToggleCountry = viewModel::onToggleCountry,
        onToggleDevice = viewModel::onToggleDevice,
        onToggleContentCategory = viewModel::onToggleContentCategory,
        onNewUserOnly = viewModel::onNewUserOnly,
        onAccount = viewModel::onAccountSelected,
        onName = viewModel::onName,
        onObjective = viewModel::onObjective,
        onBudgetType = viewModel::onBudgetType,
        onBudget = viewModel::onBudgetUsd,
        onBid = viewModel::onBidCpmUsd,
        onBidCpc = viewModel::onBidCpcUsd,
        onBidCpa = viewModel::onBidCpaUsd,
        onSelfPromo = viewModel::onSelfPromo,
        onSelfPromoMode = viewModel::onSelfPromoMode,
        startDateMillis = startDate,
        endDateMillis = endDate,
        onStartDate = viewModel::onStartDate,
        onEndDate = viewModel::onEndDate,
        onSubmit = viewModel::submit,
        onSubmitForReview = viewModel::submitForReview,
        onContinue = onCreated,
        onAddFunds = { selectedAccount?.let(onAddFunds) },
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
    bidCpcUsd: String,
    bidCpaUsd: String,
    isSelfPromo: Boolean,
    selfPromoMode: String,
    submitState: CreateCampaignViewModel.SubmitState,
    reviewState: CreateCampaignViewModel.ReviewState,
    canSubmit: Boolean,
    promoteKind: PromoteEntityKind?,
    promoteQuery: String,
    promoteEntities: CreateCampaignViewModel.PromoteEntitiesState,
    selectedEntity: CreateCampaignViewModel.PromoteEntity?,
    segments: SelectedSegments,
    estimate: CreateCampaignViewModel.EstimateState,
    targetingSummary: String,
    onPromoteKind: (PromoteEntityKind?) -> Unit,
    onPromoteQuery: (String) -> Unit,
    onPromoteEntity: (CreateCampaignViewModel.PromoteEntity) -> Unit,
    onToggleAge: (String) -> Unit,
    onToggleGender: (String) -> Unit,
    onToggleCountry: (String) -> Unit,
    onToggleDevice: (String) -> Unit,
    onToggleContentCategory: (String) -> Unit,
    onNewUserOnly: (Boolean) -> Unit,
    onAccount: (String) -> Unit,
    onName: (String) -> Unit,
    onObjective: (String) -> Unit,
    onBudgetType: (String) -> Unit,
    onBudget: (String) -> Unit,
    onBid: (String) -> Unit,
    onBidCpc: (String) -> Unit,
    onBidCpa: (String) -> Unit,
    onSelfPromo: (Boolean) -> Unit,
    onSelfPromoMode: (String) -> Unit,
    startDateMillis: Long? = null,
    endDateMillis: Long? = null,
    onStartDate: (Long?) -> Unit = {},
    onEndDate: (Long?) -> Unit = {},
    onSubmit: () -> Unit,
    onSubmitForReview: () -> Unit,
    onContinue: (campaignId: String) -> Unit,
    onAddFunds: () -> Unit = {},
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
                    isSelfPromo = isSelfPromo,
                    onSubmitForReview = onSubmitForReview,
                    onContinue = { onContinue(success.campaign.campaignId) },
                    onAddFunds = onAddFunds,
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

            // FE-162 (EPIC G) — promote-entity picker (choose what to promote) + behavioral targeting panel.
            PromoteEntitySection(
                promoteKind = promoteKind,
                query = promoteQuery,
                entities = promoteEntities,
                selected = selectedEntity,
                enabled = !submitting,
                onPromoteKind = onPromoteKind,
                onQuery = onPromoteQuery,
                onEntity = onPromoteEntity,
            )

            TargetingSegmentsSection(
                segments = segments,
                summary = targetingSummary,
                estimate = estimate,
                enabled = !submitting,
                onToggleAge = onToggleAge,
                onToggleGender = onToggleGender,
                onToggleCountry = onToggleCountry,
                onToggleDevice = onToggleDevice,
                onToggleContentCategory = onToggleContentCategory,
                onNewUserOnly = onNewUserOnly,
            )

            // ADV2-306 (F3) — free "promote my content" self-advertising toggle. When on, the money fields
            // (budget + all bids) are hidden (it is free, needs no funding) and only runs on your own content.
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        stringResource(R.string.create_campaign_self_promo_label),
                        style = MaterialTheme.typography.bodyLarge,
                    )
                    Text(
                        stringResource(R.string.create_campaign_self_promo_hint),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Switch(
                    checked = isSelfPromo,
                    onCheckedChange = onSelfPromo,
                    enabled = !submitting,
                    modifier = Modifier.testTag(CreateCampaignTestTags.SELF_PROMO),
                )
            }

            if (isSelfPromo) {
                LabeledDropdown(
                    label = stringResource(R.string.create_campaign_fill_mode_label),
                    selectedLabel = selfPromoModeLabel(selfPromoMode),
                    options = CreateCampaignViewModel.SELF_PROMO_MODES.map { it to selfPromoModeLabel(it) },
                    onSelect = onSelfPromoMode,
                    enabled = !submitting,
                    testTag = CreateCampaignTestTags.FILL_MODE,
                )
                Text(
                    stringResource(
                        if (selfPromoMode == "always_win") {
                            R.string.create_campaign_fill_mode_always_win_hint
                        } else {
                            R.string.create_campaign_fill_mode_fill_only_hint
                        },
                    ),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

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

            // ADV3-5 (B7): optional flight (start/end) dates. Hidden for a free self-promo.
            if (!isSelfPromo) {
                FlightDateField(
                    label = stringResource(R.string.create_campaign_start_date_label),
                    millis = startDateMillis,
                    enabled = !submitting,
                    onPick = onStartDate,
                    testTag = CreateCampaignTestTags.START_DATE,
                )
                FlightDateField(
                    label = stringResource(R.string.create_campaign_end_date_label),
                    millis = endDateMillis,
                    enabled = !submitting,
                    onPick = onEndDate,
                    testTag = CreateCampaignTestTags.END_DATE,
                )
            }

            // Money fields are hidden for a self-promo (it is free — no budget, no bids, no funding step).
            if (!isSelfPromo) {
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

            OutlinedTextField(
                value = bidCpcUsd,
                onValueChange = onBidCpc,
                label = { Text(stringResource(R.string.create_campaign_bid_cpc_label)) },
                prefix = { Text("$") },
                supportingText = { Text(stringResource(R.string.create_campaign_bid_cpc_hint)) },
                singleLine = true,
                enabled = !submitting,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Decimal),
                modifier = Modifier.fillMaxWidth().testTag(CreateCampaignTestTags.BID_CPC),
            )

            OutlinedTextField(
                value = bidCpaUsd,
                onValueChange = onBidCpa,
                label = { Text(stringResource(R.string.create_campaign_bid_cpa_label)) },
                prefix = { Text("$") },
                supportingText = { Text(stringResource(R.string.create_campaign_bid_cpa_hint)) },
                singleLine = true,
                enabled = !submitting,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Decimal),
                modifier = Modifier.fillMaxWidth().testTag(CreateCampaignTestTags.BID_CPA),
            )
            }

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

/**
 * FE-162 — the promote-entity picker: a KIND chooser (market / creator-token / product; "none" clears it)
 * plus a searchable candidate list from the existing tokens/catalog reads. Degrades to an honest empty
 * state when the entity read 404s (no crash, no scary error). Entirely optional — leaving the kind unset
 * keeps the plain create path.
 */
@Composable
private fun PromoteEntitySection(
    promoteKind: PromoteEntityKind?,
    query: String,
    entities: CreateCampaignViewModel.PromoteEntitiesState,
    selected: CreateCampaignViewModel.PromoteEntity?,
    enabled: Boolean,
    onPromoteKind: (PromoteEntityKind?) -> Unit,
    onQuery: (String) -> Unit,
    onEntity: (CreateCampaignViewModel.PromoteEntity) -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth().testTag(CreateCampaignTestTags.PROMOTE_KIND)) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text("Promote", style = MaterialTheme.typography.titleMedium)
            Text(
                "Optionally pick a market, creator token, or product to promote with this campaign.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                FilterChip(
                    selected = promoteKind == null,
                    onClick = { if (enabled) onPromoteKind(null) },
                    label = { Text("None") },
                    enabled = enabled,
                )
                PromoteEntityKind.entries.forEach { kind ->
                    FilterChip(
                        selected = promoteKind == kind,
                        onClick = { if (enabled) onPromoteKind(kind) },
                        label = { Text(kind.label) },
                        enabled = enabled,
                    )
                }
            }

            if (promoteKind != null) {
                OutlinedTextField(
                    value = query,
                    onValueChange = onQuery,
                    label = { Text("Search ${promoteKind.label.lowercase()}") },
                    singleLine = true,
                    enabled = enabled,
                    modifier = Modifier.fillMaxWidth().testTag(CreateCampaignTestTags.PROMOTE_SEARCH),
                )
                when (entities) {
                    is CreateCampaignViewModel.PromoteEntitiesState.Loading ->
                        CircularProgressIndicator(modifier = Modifier.padding(8.dp))
                    is CreateCampaignViewModel.PromoteEntitiesState.Empty ->
                        Text(
                            "Nothing to promote here yet.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    is CreateCampaignViewModel.PromoteEntitiesState.Error ->
                        Text(
                            entities.message,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.error,
                        )
                    is CreateCampaignViewModel.PromoteEntitiesState.Content ->
                        Column(
                            modifier = Modifier
                                .fillMaxWidth()
                                .heightIn(max = 220.dp)
                                .verticalScroll(rememberScrollState()),
                            verticalArrangement = Arrangement.spacedBy(4.dp),
                        ) {
                            entities.entities.forEach { entity ->
                                FilterChip(
                                    selected = selected?.id == entity.id,
                                    onClick = { if (enabled) onEntity(entity) },
                                    label = {
                                        Text(
                                            entity.subtitle?.let { "${entity.title} · $it" } ?: entity.title,
                                        )
                                    },
                                    enabled = enabled,
                                    modifier = Modifier.testTag(CreateCampaignTestTags.PROMOTE_ENTITY),
                                )
                            }
                        }
                    CreateCampaignViewModel.PromoteEntitiesState.Idle -> Unit
                }
                selected?.let {
                    Text(
                        "Promoting: ${it.title}",
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
            }
        }
    }
}

/**
 * FE-162 — behavioral targeting segments (age / gender / country / device / content-category multi-selects +
 * new-user-only) with an explicit OPT-IN-RESPECTING disclosure and a live audience estimate. Targeting is
 * additive: leaving everything unset reaches everyone. The estimate hides when the endpoint 404s.
 */
@Composable
private fun TargetingSegmentsSection(
    segments: SelectedSegments,
    summary: String,
    estimate: CreateCampaignViewModel.EstimateState,
    enabled: Boolean,
    onToggleAge: (String) -> Unit,
    onToggleGender: (String) -> Unit,
    onToggleCountry: (String) -> Unit,
    onToggleDevice: (String) -> Unit,
    onToggleContentCategory: (String) -> Unit,
    onNewUserOnly: (Boolean) -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth().testTag(CreateCampaignTestTags.TARGETING)) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Text("Audience targeting", style = MaterialTheme.typography.titleMedium)

            // Opt-in disclosure — a product invariant, always shown.
            Text(
                PromoteTargetingMath.RESPECTS_OPT_IN_NOTE,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            ChipMultiSelect("Age", PromoteTargetingMath.SEGMENT_AGE_RANGES, segments.ageRanges, enabled, onToggleAge)
            ChipMultiSelect("Gender", PromoteTargetingMath.SEGMENT_GENDERS, segments.genders, enabled, onToggleGender)
            ChipMultiSelect(
                label = "Country",
                options = PromoteTargetingMath.SEGMENT_COUNTRIES.map { it.code },
                selected = segments.countryCodes,
                enabled = enabled,
                onToggle = onToggleCountry,
            )
            ChipMultiSelect("Device", PromoteTargetingMath.SEGMENT_DEVICE_TYPES, segments.deviceTypes, enabled, onToggleDevice)
            ChipMultiSelect(
                label = "Content category",
                options = PromoteTargetingMath.SEGMENT_CONTENT_CATEGORIES,
                selected = segments.contentCategories,
                enabled = enabled,
                onToggle = onToggleContentCategory,
            )

            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("New users only", modifier = Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium)
                Switch(checked = segments.newUserOnly, onCheckedChange = onNewUserOnly, enabled = enabled)
            }

            HorizontalDivider()
            Text(summary, style = MaterialTheme.typography.bodyMedium)

            when (estimate) {
                is CreateCampaignViewModel.EstimateState.Loading ->
                    Text(
                        "Estimating reach…",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.testTag(CreateCampaignTestTags.ESTIMATE),
                    )
                is CreateCampaignViewModel.EstimateState.Ready ->
                    Text(
                        "Estimated reach: ~${estimate.display}",
                        style = MaterialTheme.typography.titleSmall,
                        modifier = Modifier.testTag(CreateCampaignTestTags.ESTIMATE),
                    )
                // Idle (pre-create) / Unavailable (404) — no numeric estimate shown.
                else -> Unit
            }
        }
    }
}

/** A labeled row of FilterChips backing a multi-select segment. */
@Composable
private fun ChipMultiSelect(
    label: String,
    options: List<String>,
    selected: List<String>,
    enabled: Boolean,
    onToggle: (String) -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(label, style = MaterialTheme.typography.titleSmall)
        FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            options.forEach { opt ->
                FilterChip(
                    selected = opt in selected,
                    onClick = { if (enabled) onToggle(opt) },
                    label = { Text(opt) },
                    enabled = enabled,
                )
            }
        }
    }
}

@Composable
private fun CampaignCreatedCard(
    reviewState: CreateCampaignViewModel.ReviewState,
    isSelfPromo: Boolean,
    onSubmitForReview: () -> Unit,
    onContinue: () -> Unit,
    onAddFunds: () -> Unit = {},
) {
    Card(modifier = Modifier.fillMaxWidth().testTag(CreateCampaignTestTags.SUCCESS)) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(
                stringResource(
                    if (isSelfPromo) R.string.create_campaign_self_promo_success_title
                    else R.string.create_campaign_success_title,
                ),
                style = MaterialTheme.typography.titleMedium,
            )

            when {
                // A self-promo auto-activates (no admin review), so it skips the review-state messaging.
                isSelfPromo -> Text(
                    stringResource(R.string.create_campaign_self_promo_success_body),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                reviewState is CreateCampaignViewModel.ReviewState.Done -> Text(
                    stringResource(R.string.create_campaign_review_done, reviewState.status),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                reviewState is CreateCampaignViewModel.ReviewState.Error -> Text(
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

            // Paid campaigns need admin review; a free self-promo is already live so it skips this button.
            if (!isSelfPromo) {
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
            }
            // ADV3-4 (B3): prompt funding the specific campaign account (paid campaigns only).
            if (!isSelfPromo) {
                androidx.compose.material3.OutlinedButton(
                    onClick = onAddFunds,
                    modifier = Modifier.fillMaxWidth().testTag(CreateCampaignTestTags.ADD_FUNDS),
                ) {
                    Text(stringResource(R.string.create_campaign_add_funds))
                }
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

/** ADV3-5 (B7): a read-only date field that opens a Material date picker; a cleared pick sends null. */
@Composable
private fun FlightDateField(
    label: String,
    millis: Long?,
    enabled: Boolean,
    onPick: (Long?) -> Unit,
    testTag: String,
) {
    var show by remember { mutableStateOf(false) }
    val display = millis?.let {
        java.text.SimpleDateFormat("yyyy-MM-dd", java.util.Locale.US).apply {
            timeZone = java.util.TimeZone.getTimeZone("UTC")
        }.format(java.util.Date(it))
    } ?: ""
    OutlinedTextField(
        value = display,
        onValueChange = {},
        readOnly = true,
        enabled = enabled,
        label = { Text(label) },
        trailingIcon = {
            TextButton(onClick = { if (enabled) show = true }) {
                Text(stringResource(R.string.create_campaign_pick_date))
            }
        },
        modifier = Modifier.fillMaxWidth().testTag(testTag),
    )
    if (show) {
        val pickerState = rememberDatePickerState(initialSelectedDateMillis = millis)
        DatePickerDialog(
            onDismissRequest = { show = false },
            confirmButton = {
                TextButton(onClick = { onPick(pickerState.selectedDateMillis); show = false }) {
                    Text(stringResource(R.string.create_campaign_date_ok))
                }
            },
            dismissButton = {
                TextButton(onClick = { onPick(null); show = false }) {
                    Text(stringResource(R.string.create_campaign_date_clear))
                }
            },
        ) {
            DatePicker(state = pickerState)
        }
    }
}

/** ADV2-306 (F3) — maps a self-promo fill mode wire value to its friendly picker label. */
@Composable
private fun selfPromoModeLabel(mode: String): String = stringResource(
    if (mode == "always_win") R.string.create_campaign_fill_mode_always_win
    else R.string.create_campaign_fill_mode_fill_only
)

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
    // ADV2-R5: a syndicate ad account is clearly hinted ("Syndicate") so the admin picks the right one.
    val tags = buildList {
        if (isSyndicate) add("Syndicate")
        status?.takeIf { it.isNotBlank() }?.let { add(it) }
    }
    return if (tags.isEmpty()) name else "$name (" + tags.joinToString(" · ") + ")"
}
