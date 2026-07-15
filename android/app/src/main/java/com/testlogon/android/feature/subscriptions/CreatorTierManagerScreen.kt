@file:OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)

package com.testlogon.android.feature.subscriptions

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.foundation.text.KeyboardOptions
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.i18n.asString
import com.testlogon.android.core.ui.i18n.resolve
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.subscriptions.BillingInterval
import com.testlogon.android.data.subscriptions.SubscriptionTier

/** SUBX-40 — stable test tags for the creator tier-authoring screen. */
object CreatorTierManagerTestTags {
    const val SCREEN = "tier_manager_screen"
    const val LIST = "tier_manager_list"
    const val NEW = "tier_manager_new"
    const val EDITOR = "tier_manager_editor"
    const val EDITOR_NAME = "tier_manager_editor_name"
    const val EDITOR_PRICE = "tier_manager_editor_price"
    const val EDITOR_SAVE = "tier_manager_editor_save"
    fun card(id: String) = "tier_manager_card_$id"
    fun edit(id: String) = "tier_manager_edit_$id"
    fun archive(id: String) = "tier_manager_archive_$id"
}

/** SUBX-40 — creator "Your subscription tiers" authoring route (arg-less; owner-scoped in the VM). */
@Composable
fun CreatorTierManagerRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: CreatorTierManagerViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    val context = LocalContext.current

    val actionError = (state as? TierManagerUiState.Content)?.actionError
    LaunchedEffect(actionError) {
        val text = actionError?.resolve(context.resources) ?: return@LaunchedEffect
        snackbarHostState.showSnackbar(text)
        viewModel.onActionErrorConsumed()
    }

    Scaffold(
        modifier = modifier.testTag(CreatorTierManagerTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.tier_manager_title)) },
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
        floatingActionButton = {
            if (state is TierManagerUiState.Content) {
                ExtendedFloatingActionButton(
                    onClick = viewModel::onNewTier,
                    icon = { Icon(Icons.Filled.Add, contentDescription = null) },
                    text = { Text(stringResource(R.string.tier_manager_new)) },
                    modifier = Modifier.testTag(CreatorTierManagerTestTags.NEW),
                )
            }
        },
    ) { padding ->
        when (val s = state) {
            is TierManagerUiState.Loading ->
                LoadingState(modifier = Modifier.padding(padding).fillMaxSize())

            is TierManagerUiState.Error ->
                ErrorState(
                    message = s.message.asString(),
                    onRetry = viewModel::onRetry,
                    modifier = Modifier.padding(padding).fillMaxSize(),
                )

            is TierManagerUiState.Content -> TierList(
                state = s,
                padding = padding,
                onEdit = viewModel::onEditTier,
                onArchive = viewModel::onArchiveTier,
                onMove = viewModel::onMove,
            )
        }
    }

    val editor = (state as? TierManagerUiState.Content)?.editor
    if (editor != null) {
        TierEditorDialog(
            draft = editor,
            saving = (state as? TierManagerUiState.Content)?.saving == true,
            onChange = viewModel::onDraftChanged,
            onAddBenefit = viewModel::onAddBenefit,
            onRemoveBenefit = viewModel::onRemoveBenefit,
            onSave = viewModel::onSaveDraft,
            onDismiss = viewModel::onEditorDismissed,
        )
    }
}

@Composable
private fun TierList(
    state: TierManagerUiState.Content,
    padding: PaddingValues,
    onEdit: (SubscriptionTier) -> Unit,
    onArchive: (SubscriptionTier) -> Unit,
    onMove: (SubscriptionTier, Boolean) -> Unit,
) {
    if (state.tiers.isEmpty()) {
        EmptyState(
            title = stringResource(R.string.tier_manager_empty_title),
            body = stringResource(R.string.tier_manager_empty_body),
            modifier = Modifier.padding(padding).fillMaxSize(),
        )
        return
    }
    LazyColumn(
        modifier = Modifier.padding(padding).fillMaxSize().testTag(CreatorTierManagerTestTags.LIST),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        items(items = state.tiers, key = { it.planId }) { tier ->
            TierCard(
                tier = tier,
                isFirst = state.tiers.first().planId == tier.planId,
                isLast = state.tiers.last().planId == tier.planId,
                enabled = !state.saving,
                onEdit = { onEdit(tier) },
                onArchive = { onArchive(tier) },
                onMove = { up -> onMove(tier, up) },
            )
        }
    }
}

@Composable
private fun TierCard(
    tier: SubscriptionTier,
    isFirst: Boolean,
    isLast: Boolean,
    enabled: Boolean,
    onEdit: () -> Unit,
    onArchive: () -> Unit,
    onMove: (Boolean) -> Unit,
) {
    val currency = tier.currency.uppercase()
    val free = stringResource(R.string.creator_subs_zero_money)
    Card(modifier = Modifier.fillMaxWidth().testTag(CreatorTierManagerTestTags.card(tier.planId))) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    tier.name,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f),
                )
                if (!tier.isActive) {
                    Surface(
                        color = MaterialTheme.colorScheme.surfaceVariant,
                        contentColor = MaterialTheme.colorScheme.onSurfaceVariant,
                    ) {
                        Text(
                            stringResource(R.string.tier_manager_archived_badge),
                            style = MaterialTheme.typography.labelSmall,
                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp),
                        )
                    }
                }
            }
            Text(
                formatTierPrice(tier.priceCents, currency, free) + intervalSuffix(
                    tier.interval,
                    stringResource(R.string.subs_tiers_interval_month),
                    stringResource(R.string.subs_tiers_interval_year),
                    stringResource(R.string.subs_tiers_interval_week),
                ),
                style = MaterialTheme.typography.bodyLarge,
            )
            tier.level?.let {
                Text(
                    stringResource(R.string.tier_manager_level_label, it),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            val perks = tier.benefits.map { it.label } + tier.perks
            if (perks.isNotEmpty()) {
                Text(
                    perks.joinToString(" • "),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 3,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                OutlinedButton(
                    onClick = onEdit,
                    enabled = enabled,
                    modifier = Modifier.testTag(CreatorTierManagerTestTags.edit(tier.planId)),
                ) { Text(stringResource(R.string.tier_manager_edit)) }
                if (tier.isActive) {
                    OutlinedButton(
                        onClick = onArchive,
                        enabled = enabled,
                        modifier = Modifier.testTag(CreatorTierManagerTestTags.archive(tier.planId)),
                    ) { Text(stringResource(R.string.tier_manager_archive)) }
                }
                Box(Modifier.weight(1f))
                IconButton(onClick = { onMove(true) }, enabled = enabled && !isFirst) {
                    Icon(Icons.Filled.KeyboardArrowUp, contentDescription = stringResource(R.string.tier_manager_move_up))
                }
                IconButton(onClick = { onMove(false) }, enabled = enabled && !isLast) {
                    Icon(Icons.Filled.KeyboardArrowDown, contentDescription = stringResource(R.string.tier_manager_move_down))
                }
            }
        }
    }
}

@Composable
private fun TierEditorDialog(
    draft: TierDraft,
    saving: Boolean,
    onChange: ((TierDraft) -> TierDraft) -> Unit,
    onAddBenefit: (String) -> Unit,
    onRemoveBenefit: (Int) -> Unit,
    onSave: () -> Unit,
    onDismiss: () -> Unit,
) {
    var benefitInput by rememberSaveable { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        modifier = Modifier.testTag(CreatorTierManagerTestTags.EDITOR),
        title = {
            Text(
                stringResource(
                    if (draft.isNew) R.string.tier_editor_new_title else R.string.tier_editor_edit_title,
                ),
            )
        },
        text = {
            Column(
                modifier = Modifier.heightIn(max = 460.dp).verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                OutlinedTextField(
                    value = draft.name,
                    onValueChange = { v -> onChange { it.copy(name = v) } },
                    label = { Text(stringResource(R.string.tier_editor_name)) },
                    singleLine = true,
                    isError = draft.validationError && draft.name.trim().length < 2,
                    modifier = Modifier.fillMaxWidth().testTag(CreatorTierManagerTestTags.EDITOR_NAME),
                )
                OutlinedTextField(
                    value = draft.priceInput,
                    onValueChange = { v -> onChange { it.copy(priceInput = v) } },
                    label = { Text(stringResource(R.string.tier_editor_price)) },
                    singleLine = true,
                    isError = draft.validationError && CreatorTierManagerViewModel.parseInputToCents(draft.priceInput).let { it == null || it <= 0 },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Decimal),
                    modifier = Modifier.fillMaxWidth().testTag(CreatorTierManagerTestTags.EDITOR_PRICE),
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    FilterChip(
                        selected = draft.interval != BillingInterval.YEAR,
                        onClick = { onChange { it.copy(interval = BillingInterval.MONTH) } },
                        label = { Text(stringResource(R.string.tier_editor_interval_month)) },
                    )
                    FilterChip(
                        selected = draft.interval == BillingInterval.YEAR,
                        onClick = { onChange { it.copy(interval = BillingInterval.YEAR) } },
                        label = { Text(stringResource(R.string.tier_editor_interval_year)) },
                    )
                }
                OutlinedTextField(
                    value = draft.description,
                    onValueChange = { v -> onChange { it.copy(description = v) } },
                    label = { Text(stringResource(R.string.tier_editor_description)) },
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = draft.level,
                    onValueChange = { v -> onChange { it.copy(level = v.filter { c -> c.isDigit() }) } },
                    label = { Text(stringResource(R.string.tier_editor_level)) },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    modifier = Modifier.fillMaxWidth(),
                )
                if (draft.benefits.isNotEmpty()) {
                    FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        draft.benefits.forEachIndexed { i, label ->
                            AssistChip(
                                onClick = { onRemoveBenefit(i) },
                                label = { Text(label, maxLines = 1, overflow = TextOverflow.Ellipsis) },
                                trailingIcon = { Icon(Icons.Filled.Close, contentDescription = null) },
                            )
                        }
                    }
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                    OutlinedTextField(
                        value = benefitInput,
                        onValueChange = { benefitInput = it },
                        label = { Text(stringResource(R.string.tier_editor_benefit_hint)) },
                        singleLine = true,
                        modifier = Modifier.weight(1f),
                    )
                    TextButton(
                        onClick = { onAddBenefit(benefitInput); benefitInput = "" },
                        enabled = benefitInput.isNotBlank(),
                    ) { Text(stringResource(R.string.tier_editor_add_benefit)) }
                }
                if (draft.validationError) {
                    Text(
                        stringResource(R.string.tier_editor_name_required),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                    )
                }
            }
        },
        confirmButton = {
            TextButton(
                onClick = onSave,
                enabled = !saving,
                modifier = Modifier.testTag(CreatorTierManagerTestTags.EDITOR_SAVE),
            ) {
                if (saving) {
                    CircularProgressIndicator(modifier = Modifier.padding(end = 4.dp))
                }
                Text(stringResource(R.string.tier_editor_save))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss, enabled = !saving) {
                Text(stringResource(R.string.tier_editor_cancel))
            }
        },
    )
}
