@file:OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)

package com.testlogon.android.feature.promo

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.promo.DiscountType
import com.testlogon.android.data.promo.PromoCode

/** AND-266 — stable testTags for the promo-codes screen. */
object PromoCodesTestTags {
    const val SCREEN = "promo_screen"
    const val LIST = "promo_list"
    const val LOADING = "promo_loading"
    const val EMPTY = "promo_empty"
    const val ERROR = "promo_error"
    const val OFFLINE = "promo_offline"
    const val FAB = "promo_fab"
    const val SHEET = "promo_create_sheet"
    const val CODE_FIELD = "promo_code_field"
    const val SUBMIT = "promo_submit"
    const val ROW_PREFIX = "promo_row_"
}

/** AND-266 — route-level promo-codes entry (reachable from the More hub). */
@Composable
fun PromoCodesRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: PromoCodesViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    val context = LocalContext.current

    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is PromoCodesEffect.ShowMessage ->
                    snackbarHostState.showSnackbar(context.getString(effect.resId))
                is PromoCodesEffect.ShowError ->
                    snackbarHostState.showSnackbar(effect.message)
            }
        }
    }

    PromoCodesScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::onRefresh,
        onRetry = viewModel::onRetry,
        onOpenSheet = viewModel::onOpenSheet,
        onDismissSheet = viewModel::onDismissSheet,
        onCreate = viewModel::onCreate,
        onDeactivate = viewModel::onDeactivate,
        snackbarHostState = snackbarHostState,
        modifier = modifier,
    )
}

@Composable
fun PromoCodesScreen(
    state: PromoCodesUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onOpenSheet: () -> Unit,
    onDismissSheet: () -> Unit,
    onCreate: (CreatePromoForm) -> PromoFormError?,
    onDeactivate: (String) -> Unit,
    modifier: Modifier = Modifier,
    snackbarHostState: SnackbarHostState = remember { SnackbarHostState() },
) {
    Scaffold(
        modifier = modifier.testTag(PromoCodesTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.promo_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack, modifier = Modifier.testTag("promo_back")) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
            )
        },
        floatingActionButton = {
            FloatingActionButton(onClick = onOpenSheet, modifier = Modifier.testTag(PromoCodesTestTags.FAB)) {
                Icon(Icons.Outlined.Add, contentDescription = stringResource(R.string.promo_create))
            }
        },
    ) { padding ->
        Box(modifier = Modifier.padding(padding).fillMaxSize()) {
            when (state.phase) {
                PromoCodesUiState.Phase.Loading ->
                    LoadingState(modifier = Modifier.testTag(PromoCodesTestTags.LOADING))

                PromoCodesUiState.Phase.Empty ->
                    EmptyState(
                        title = stringResource(R.string.promo_empty_title),
                        body = stringResource(R.string.promo_empty_body),
                        actionLabel = stringResource(R.string.promo_create),
                        onAction = onOpenSheet,
                        modifier = Modifier.testTag(PromoCodesTestTags.EMPTY),
                    )

                PromoCodesUiState.Phase.Error ->
                    ErrorState(
                        message = state.errorMessage ?: stringResource(R.string.promo_error_generic),
                        onRetry = onRetry,
                        modifier = Modifier.testTag(PromoCodesTestTags.ERROR),
                    )

                PromoCodesUiState.Phase.Offline ->
                    ErrorState(
                        message = state.errorMessage ?: stringResource(R.string.promo_error_generic),
                        onRetry = onRetry,
                        modifier = Modifier.testTag(PromoCodesTestTags.OFFLINE),
                    )

                PromoCodesUiState.Phase.Content ->
                    PullToRefreshBox(
                        isRefreshing = state.isRefreshing,
                        onRefresh = onRefresh,
                        modifier = Modifier.fillMaxSize(),
                    ) {
                        LazyColumn(
                            modifier = Modifier
                                .testTag(PromoCodesTestTags.LIST)
                                .fillMaxSize()
                                .padding(16.dp),
                            verticalArrangement = Arrangement.spacedBy(12.dp),
                        ) {
                            items(state.codes, key = { it.codeId }) { code ->
                                PromoRow(code = code, onDeactivate = { onDeactivate(code.codeId) })
                            }
                        }
                    }
            }
        }

        if (state.isSheetOpen) {
            CreatePromoSheet(
                isSubmitting = state.isSubmitting,
                onDismiss = onDismissSheet,
                onSubmit = onCreate,
            )
        }
    }
}

@Composable
private fun PromoRow(code: PromoCode, onDeactivate: () -> Unit) {
    ElevatedCard(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(PromoCodesTestTags.ROW_PREFIX + code.codeId)
            .semantics(mergeDescendants = true) {},
    ) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(code.code, style = MaterialTheme.typography.titleMedium)
                val statusRes = when {
                    !code.active -> R.string.promo_status_inactive
                    else -> R.string.promo_status_active
                }
                AssistChip(onClick = {}, label = { Text(stringResource(statusRes)) })
            }
            Text(code.discountSummary(), style = MaterialTheme.typography.bodyMedium)
            Text(
                stringResource(R.string.promo_usage, code.usageLabel()),
                style = MaterialTheme.typography.bodySmall,
            )
            Text(
                stringResource(R.string.promo_expiry, code.expiryLabel()),
                style = MaterialTheme.typography.bodySmall,
            )
            if (code.active) {
                TextButton(onClick = onDeactivate) {
                    Text(stringResource(R.string.promo_deactivate))
                }
            }
        }
    }
}

@Composable
private fun CreatePromoSheet(
    isSubmitting: Boolean,
    onDismiss: () -> Unit,
    onSubmit: (CreatePromoForm) -> PromoFormError?,
) {
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    var code by remember { mutableStateOf("") }
    var discountType by remember { mutableStateOf(DiscountType.PERCENTAGE) }
    var discountValue by remember { mutableStateOf("") }
    var trialDays by remember { mutableStateOf("") }
    var maxUses by remember { mutableStateOf("0") }

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState,
        modifier = Modifier.testTag(PromoCodesTestTags.SHEET),
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(stringResource(R.string.promo_create), style = MaterialTheme.typography.titleLarge)
            OutlinedTextField(
                value = code,
                onValueChange = { code = it },
                label = { Text(stringResource(R.string.promo_field_code)) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth().testTag(PromoCodesTestTags.CODE_FIELD),
            )
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                DiscountChip(R.string.promo_discount_percentage, discountType == DiscountType.PERCENTAGE) {
                    discountType = DiscountType.PERCENTAGE
                }
                DiscountChip(R.string.promo_discount_fixed, discountType == DiscountType.FIXED_AMOUNT) {
                    discountType = DiscountType.FIXED_AMOUNT
                }
                DiscountChip(R.string.promo_discount_trial, discountType == DiscountType.FREE_TRIAL) {
                    discountType = DiscountType.FREE_TRIAL
                }
            }
            if (discountType == DiscountType.FREE_TRIAL) {
                OutlinedTextField(
                    value = trialDays,
                    onValueChange = { trialDays = it.filter { c -> c.isDigit() } },
                    label = { Text(stringResource(R.string.promo_field_trial_days)) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
            } else {
                OutlinedTextField(
                    value = discountValue,
                    onValueChange = { discountValue = it.filter { c -> c.isDigit() } },
                    label = { Text(stringResource(R.string.promo_field_discount_value)) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
            OutlinedTextField(
                value = maxUses,
                onValueChange = { maxUses = it.filter { c -> c.isDigit() } },
                label = { Text(stringResource(R.string.promo_field_max_uses)) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            Button(
                onClick = {
                    val form = CreatePromoForm(
                        code = code,
                        discountType = discountType,
                        discountValue = discountValue.toIntOrNull() ?: 0,
                        freeTrialDays = trialDays.toIntOrNull() ?: 0,
                        maxUses = maxUses.toIntOrNull() ?: 0,
                    )
                    onSubmit(form)
                },
                enabled = !isSubmitting && code.trim().isNotEmpty(),
                modifier = Modifier.fillMaxWidth().testTag(PromoCodesTestTags.SUBMIT),
            ) {
                if (isSubmitting) {
                    CircularProgressIndicator(modifier = Modifier.padding(end = 8.dp))
                }
                Text(stringResource(R.string.promo_create))
            }
        }
    }
}

@Composable
private fun DiscountChip(labelRes: Int, selected: Boolean, onClick: () -> Unit) {
    FilterChip(
        selected = selected,
        onClick = onClick,
        label = { Text(stringResource(labelRes)) },
    )
}
