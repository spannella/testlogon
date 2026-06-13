@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.boost

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.model.syndicates.formatCents
import com.testlogon.android.core.ui.input.TlButton
import com.testlogon.android.core.ui.input.TlButtonVariant
import com.testlogon.android.core.ui.input.TlTextField
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState

/** AND-364 - stable testTags for the content-boost screen. */
object BoostTestTags {
    const val SCREEN = "boost_screen"
    const val BUDGET = "boost_budget"
    const val DURATION = "boost_duration"
    const val SUBMIT = "boost_submit"
    const val STATUS = "boost_status"
    const val STATUS_VALUE = "boost_status_value"
    const val CANCEL = "boost_cancel"
    const val ERROR = "boost_error"
}

/**
 * AND-364 - route-level content-boost entry (reached from the post detail / composer-success entry points;
 * see BoostNavigation). Hosts the budget/duration form and, once boosted, the status watch view.
 */
@Composable
fun BoostRoute(
    onBack: () -> Unit,
    viewModel: BoostViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    BoostScreen(
        state = state,
        onBack = onBack,
        onBudgetChanged = viewModel::onBudgetChanged,
        onDurationChanged = viewModel::onDurationChanged,
        onSubmit = viewModel::submit,
        onCancel = viewModel::cancel,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::onRetry,
    )
}

/** AND-364 - stateless content-boost screen. */
@Composable
fun BoostScreen(
    state: BoostUiState,
    onBack: () -> Unit,
    onBudgetChanged: (String) -> Unit,
    onDurationChanged: (String) -> Unit,
    onSubmit: () -> Unit,
    onCancel: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(BoostTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.boost_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.boost_back),
                        )
                    }
                },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
        ) {
            when (state) {
                is BoostUiState.Loading -> LoadingState()
                is BoostUiState.Form -> BoostForm(
                    state = state,
                    onBudgetChanged = onBudgetChanged,
                    onDurationChanged = onDurationChanged,
                    onSubmit = onSubmit,
                )
                is BoostUiState.Status -> BoostStatusView(
                    state = state,
                    onCancel = onCancel,
                    onRefresh = onRefresh,
                )
                is BoostUiState.Error -> ErrorState(
                    message = state.message,
                    onRetry = onRetry,
                    modifier = Modifier.testTag(BoostTestTags.ERROR),
                )
            }
        }
    }
}

@Composable
private fun BoostForm(
    state: BoostUiState.Form,
    onBudgetChanged: (String) -> Unit,
    onDurationChanged: (String) -> Unit,
    onSubmit: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text(
            text = stringResource(R.string.boost_form_intro),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        TlTextField(
            value = state.budgetText,
            onValueChange = onBudgetChanged,
            label = stringResource(R.string.boost_budget_label),
            enabled = !state.submitting,
            helperText = stringResource(
                R.string.boost_budget_helper,
                formatCents(state.budgetCents),
            ),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Decimal),
            modifier = Modifier.testTag(BoostTestTags.BUDGET),
        )

        TlTextField(
            value = state.durationMinutesText,
            onValueChange = onDurationChanged,
            label = stringResource(R.string.boost_duration_label),
            enabled = !state.submitting,
            helperText = stringResource(R.string.boost_duration_helper),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            modifier = Modifier.testTag(BoostTestTags.DURATION),
        )

        if (state.error != null) {
            Text(
                text = state.error,
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.testTag(BoostTestTags.ERROR),
            )
        }

        TlButton(
            text = stringResource(R.string.boost_submit),
            onClick = onSubmit,
            enabled = state.canSubmit,
            loading = state.submitting,
            modifier = Modifier
                .fillMaxWidth()
                .testTag(BoostTestTags.SUBMIT),
        )
    }
}

@Composable
private fun BoostStatusView(
    state: BoostUiState.Status,
    onCancel: () -> Unit,
    onRefresh: () -> Unit,
) {
    val boost = state.boost
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp)
            .testTag(BoostTestTags.STATUS),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        val statusCd = stringResource(R.string.boost_status_cd, boost.status)
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Text(stringResource(R.string.boost_status_label), style = MaterialTheme.typography.titleMedium)
            Text(
                text = boost.status,
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.primary,
                modifier = Modifier
                    .testTag(BoostTestTags.STATUS_VALUE)
                    .semantics { contentDescription = statusCd },
            )
        }

        HorizontalDivider()

        DetailRow(stringResource(R.string.boost_id_label), boost.boostId)
        DetailRow(stringResource(R.string.boost_budget_field), formatCents(boost.budgetCents))
        boost.spentCents?.let {
            DetailRow(stringResource(R.string.boost_spent_field), formatCents(it))
        }
        boost.remainingCents?.let {
            DetailRow(stringResource(R.string.boost_remaining_field), formatCents(it))
        }
        boost.durationSeconds?.let {
            DetailRow(
                stringResource(R.string.boost_duration_field),
                stringResource(R.string.boost_minutes_value, it / 60L),
            )
        }
        boost.endsAt?.let {
            DetailRow(stringResource(R.string.boost_ends_field), endsAtLabel(it))
        }

        if (state.error != null) {
            Text(
                text = state.error,
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.testTag(BoostTestTags.ERROR),
            )
        }

        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            TlButton(
                text = stringResource(R.string.boost_refresh),
                onClick = onRefresh,
                variant = TlButtonVariant.Secondary,
                loading = state.refreshing,
            )
            if (state.canCancel) {
                TlButton(
                    text = stringResource(R.string.boost_cancel),
                    onClick = onCancel,
                    variant = TlButtonVariant.Secondary,
                    enabled = !state.refreshing,
                    modifier = Modifier.testTag(BoostTestTags.CANCEL),
                )
            }
        }
    }
}

@Composable
private fun DetailRow(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(label, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, style = MaterialTheme.typography.bodyMedium)
    }
}

/**
 * Renders the epoch-seconds [endsAt] as a coarse relative label ("in N min" / "ended"). Pure + locale-safe
 * via plurals-free string templates; the wall clock is read once for a snapshot label (the poll re-renders).
 */
@Composable
private fun endsAtLabel(endsAt: Long): String {
    val nowSeconds = System.currentTimeMillis() / 1_000L
    val deltaSeconds = endsAt - nowSeconds
    return if (deltaSeconds <= 0L) {
        stringResource(R.string.boost_ends_passed)
    } else {
        stringResource(R.string.boost_ends_in, (deltaSeconds / 60L).coerceAtLeast(1L))
    }
}
