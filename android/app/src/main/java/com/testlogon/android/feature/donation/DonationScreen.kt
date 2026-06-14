@file:OptIn(ExperimentalLayoutApi::class)

package com.testlogon.android.feature.donation

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.compose.foundation.text.KeyboardOptions
import coil.compose.SubcomposeAsyncImage
import com.testlogon.android.R
import com.testlogon.android.feature.donation.model.DonationReceipt
import com.testlogon.android.feature.donation.model.Fundraiser
import java.text.NumberFormat
import java.util.Currency
import java.util.Locale

/** AND-393 - testTags for the donation screen (used by the androidTest UI test). */
object DonationTestTags {
    const val SCREEN = "donation_screen"
    const val AMOUNT = "donation_amount"
    const val EMAIL = "donation_email"
    const val NAME = "donation_name"
    const val SUBMIT = "donation_submit"
    const val CONFIRMATION = "donation_confirmation"
    const val UNAVAILABLE = "donation_unavailable"
    const val ERROR = "donation_error"
    const val PROGRESS = "donation_progress"
}

/** Preset amount chips in cents ($5 / $10 / $25 / $50), mirroring the web client (FR-4). */
private val PRESET_CENTS = listOf(500L, 1000L, 2500L, 5000L)

/**
 * AND-393 - the session-free public donation route. Reachable from the
 * https://testlogon.com/donate/{fundraiserId} App Link and the testlogon://donate/{fundraiserId} scheme
 * while signed OUT (registered in both nav graphs). [onClose] pops or falls back to the graph start.
 */
@Composable
fun DonationRoute(
    onClose: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: DonationViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    DonationScreen(
        state = state,
        onClose = onClose,
        onRetry = viewModel::loadFundraiser,
        onAmountChanged = viewModel::onAmountChanged,
        onPresetSelected = viewModel::onPresetSelected,
        onEmailChanged = viewModel::onEmailChanged,
        onNameChanged = viewModel::onNameChanged,
        onSubmit = viewModel::submit,
        modifier = modifier,
    )
}

/** Stateless donation screen (also driven by the androidTest in-test reducer). No business logic here. */
@Composable
fun DonationScreen(
    state: DonationUiState,
    onClose: () -> Unit,
    onRetry: () -> Unit,
    onAmountChanged: (String) -> Unit,
    onPresetSelected: (Long) -> Unit,
    onEmailChanged: (String) -> Unit,
    onNameChanged: (String) -> Unit,
    onSubmit: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(modifier = modifier.testTag(DonationTestTags.SCREEN)) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            when (state.phase) {
                Phase.LoadingFundraiser ->
                    CircularProgressIndicator()

                Phase.LoadError ->
                    ErrorContent(
                        message = state.transientError
                            ?: stringResource(R.string.donation_load_error),
                        onRetry = onRetry,
                    )

                Phase.Unavailable ->
                    UnavailableContent(onClose = onClose)

                Phase.Confirmed ->
                    ConfirmationContent(receipt = state.receipt, onClose = onClose)

                Phase.Form, Phase.Submitting -> {
                    state.fundraiser?.let { FundraiserHeader(it) }
                    AmountSection(state = state, onAmountChanged = onAmountChanged, onPresetSelected = onPresetSelected)
                    DonorDetailsSection(state = state, onEmailChanged = onEmailChanged, onNameChanged = onNameChanged)
                    state.transientError?.let { Text(text = it, color = MaterialTheme.colorScheme.error) }
                    SubmitBar(state = state, onSubmit = onSubmit)
                }
            }
        }
    }
}

@Composable
private fun FundraiserHeader(fundraiser: Fundraiser) {
    fundraiser.coverImageUrl?.let { url ->
        SubcomposeAsyncImage(
            model = url,
            contentDescription = stringResource(R.string.donation_cover_cd, fundraiser.title),
            loading = { CircularProgressIndicator() },
            modifier = Modifier
                .fillMaxWidth()
                .height(160.dp),
        )
    }
    Text(text = fundraiser.title, style = MaterialTheme.typography.titleLarge)
    Text(text = fundraiser.groupName, style = MaterialTheme.typography.bodyMedium)
    fundraiser.description?.let { Text(text = it, style = MaterialTheme.typography.bodySmall) }

    val progress = fundraiser.progress
    if (progress != null) {
        LinearProgressIndicator(
            progress = { progress },
            modifier = Modifier
                .fillMaxWidth()
                .testTag(DonationTestTags.PROGRESS),
        )
    }
    val raised = formatMoney(fundraiser.raisedCents, fundraiser.currency)
    val goalText = fundraiser.goalCents?.let { formatMoney(it, fundraiser.currency) }
    Text(
        text = if (goalText != null) {
            stringResource(R.string.donation_raised_of_goal, raised, goalText)
        } else {
            stringResource(R.string.donation_raised, raised)
        },
        style = MaterialTheme.typography.bodyMedium,
    )
    Text(
        text = stringResource(R.string.donation_count, fundraiser.donationCount),
        style = MaterialTheme.typography.bodySmall,
    )
}

@Composable
private fun AmountSection(
    state: DonationUiState,
    onAmountChanged: (String) -> Unit,
    onPresetSelected: (Long) -> Unit,
) {
    val currency = state.fundraiser?.currency ?: "usd"
    FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        PRESET_CENTS.forEach { cents ->
            FilterChip(
                selected = state.amountCents == cents,
                onClick = { onPresetSelected(cents) },
                enabled = !state.isSubmitting,
                label = { Text(formatMoney(cents, currency)) },
            )
        }
    }
    val amountError = state.fieldErrors[DonationField.Amount]
    OutlinedTextField(
        value = state.amountInput,
        onValueChange = onAmountChanged,
        singleLine = true,
        enabled = !state.isSubmitting,
        isError = amountError != null,
        label = { Text(stringResource(R.string.donation_amount_label, currency.uppercase(Locale.US))) },
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Decimal),
        modifier = Modifier
            .fillMaxWidth()
            .testTag(DonationTestTags.AMOUNT),
    )
    amountError?.let { Text(text = it, color = MaterialTheme.colorScheme.error) }
}

@Composable
private fun DonorDetailsSection(
    state: DonationUiState,
    onEmailChanged: (String) -> Unit,
    onNameChanged: (String) -> Unit,
) {
    val nameError = state.fieldErrors[DonationField.Name]
    OutlinedTextField(
        value = state.donorName,
        onValueChange = onNameChanged,
        singleLine = true,
        enabled = !state.isSubmitting,
        isError = nameError != null,
        label = { Text(stringResource(R.string.donation_name_label)) },
        modifier = Modifier
            .fillMaxWidth()
            .testTag(DonationTestTags.NAME),
    )
    nameError?.let { Text(text = it, color = MaterialTheme.colorScheme.error) }

    val emailError = state.fieldErrors[DonationField.Email]
    OutlinedTextField(
        value = state.donorEmail,
        onValueChange = onEmailChanged,
        singleLine = true,
        enabled = !state.isSubmitting,
        isError = emailError != null,
        label = { Text(stringResource(R.string.donation_email_label)) },
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Email),
        modifier = Modifier
            .fillMaxWidth()
            .testTag(DonationTestTags.EMAIL),
    )
    emailError?.let { Text(text = it, color = MaterialTheme.colorScheme.error) }
}

@Composable
private fun SubmitBar(state: DonationUiState, onSubmit: () -> Unit) {
    val busyDesc = stringResource(R.string.donation_submitting)
    Button(
        onClick = onSubmit,
        enabled = state.canSubmit,
        modifier = Modifier
            .fillMaxWidth()
            .testTag(DonationTestTags.SUBMIT)
            .semantics { if (state.isSubmitting) stateDescription = busyDesc },
    ) {
        if (state.isSubmitting) {
            CircularProgressIndicator(modifier = Modifier.height(20.dp))
        } else {
            Text(stringResource(R.string.donation_submit))
        }
    }
}

@Composable
private fun ConfirmationContent(receipt: DonationReceipt?, onClose: () -> Unit) {
    Column(
        modifier = Modifier.testTag(DonationTestTags.CONFIRMATION),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Text(
            text = stringResource(R.string.donation_thanks),
            style = MaterialTheme.typography.titleLarge,
        )
        if (receipt != null) {
            Text(
                text = stringResource(
                    R.string.donation_receipt_amount,
                    formatMoney(receipt.amountCents, receipt.currency),
                ),
            )
            Text(text = stringResource(R.string.donation_receipt_id, receipt.donationId))
            receipt.fundraiserTitle?.let { Text(text = it) }
        }
        Button(onClick = onClose) { Text(stringResource(R.string.donation_close)) }
    }
}

@Composable
private fun UnavailableContent(onClose: () -> Unit) {
    Column(
        modifier = Modifier.testTag(DonationTestTags.UNAVAILABLE),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Text(
            text = stringResource(R.string.donation_unavailable),
            style = MaterialTheme.typography.titleMedium,
        )
        Button(onClick = onClose) { Text(stringResource(R.string.donation_close)) }
    }
}

@Composable
private fun ErrorContent(message: String, onRetry: () -> Unit) {
    Column(
        modifier = Modifier.testTag(DonationTestTags.ERROR),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Text(text = message)
        Button(onClick = onRetry) { Text(stringResource(R.string.donation_retry)) }
    }
}

/**
 * Locale-aware currency formatting from integer cents using the fundraiser currency code. An unknown
 * currency code (e.g. a non-ISO test value) falls back to a plain "<code> <major>.<minor>" rendering so
 * formatting never throws.
 */
private fun formatMoney(cents: Long, currencyCode: String): String {
    val major = cents / 100.0
    return try {
        val format = NumberFormat.getCurrencyInstance(Locale.US)
        format.currency = Currency.getInstance(currencyCode.uppercase(Locale.US))
        format.format(major)
    } catch (_: IllegalArgumentException) {
        "%s %.2f".format(currencyCode.uppercase(Locale.US), major)
    }
}
