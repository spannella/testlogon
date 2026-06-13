@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.kyc.prooffunds

import android.content.Context
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.InputChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import coil.compose.AsyncImage
import com.testlogon.android.R
import com.testlogon.android.feature.kyc.prooffunds.model.PoFSource
import com.testlogon.android.feature.kyc.prooffunds.model.PoFStatus
import com.testlogon.android.feature.kyc.prooffunds.model.ProofOfFunds
import java.io.File
import java.text.NumberFormat
import java.util.Currency
import java.util.Locale

/** AND-327 - stable testTags for the proof-of-funds screen. */
object ProofOfFundsTestTags {
    const val SCREEN = "pof_screen"
    const val SOURCE = "pof_source"
    const val AMOUNT = "pof_amount"
    const val CURRENCY = "pof_currency"
    const val NOTE = "pof_note"
    const val ADD_DOC = "pof_add_doc"
    const val REMOVE_DOC = "pof_remove_doc"
    const val SUBMIT = "pof_submit"
    const val STATUS = "pof_status"
    const val RESUBMIT = "pof_resubmit"
}

/**
 * AND-327 - route-level proof-of-funds screen.
 *
 * REAL REST. The optional supporting document acquisition reuses AND-321's dependency-free system intents:
 * live camera via [ActivityResultContracts.TakePicture] writing to a FileProvider Uri, and an image/PDF
 * pick via [ActivityResultContracts.GetContent]. The acquired File is handed to the VM, which downscales it
 * OFF-MAIN via AND-321's CaptureImageProcessor and uploads it through the AND-129 presign->PUT pipeline
 * before the submit POST carries the returned key as document_s3_key.
 */
@Composable
fun ProofOfFundsRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: ProofOfFundsViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val context = LocalContext.current

    // A stable capture target File + its FileProvider content Uri for the live-camera TakePicture intent
    // (reuses the existing `${applicationId}.fileprovider` + the kyc-capture cache-path from AND-321).
    val captureFile = remember {
        File(context.cacheDir, "kyc-capture").apply { mkdirs() }
            .let { File(it, "kyc-pof-${System.currentTimeMillis()}.jpg") }
    }
    val captureUri = remember {
        androidx.core.content.FileProvider.getUriForFile(
            context,
            "${context.packageName}.fileprovider",
            captureFile,
        )
    }

    val takePicture = rememberLauncherForActivityResult(ActivityResultContracts.TakePicture()) { ok ->
        if (ok) viewModel.onDocumentAcquired(captureFile)
    }
    val pickDoc = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        if (uri != null) viewModel.onDocumentAcquired(copyUriToCache(context, uri))
    }

    ProofOfFundsScreen(
        state = state,
        onBack = onBack,
        onSourceChanged = viewModel::onSourceChanged,
        onAmountChanged = viewModel::onAmountChanged,
        onCurrencyChanged = viewModel::onCurrencyChanged,
        onNoteChanged = viewModel::onNoteChanged,
        onCapture = { takePicture.launch(captureUri) },
        onPick = { pickDoc.launch(DOC_PICK_FILTER) },
        onRemoveDocument = viewModel::onRemoveDocument,
        onSubmit = viewModel::submit,
        onResubmit = viewModel::onResubmit,
        onRetry = viewModel::retry,
        modifier = modifier,
    )
}

@Composable
fun ProofOfFundsScreen(
    state: ProofOfFundsUiState,
    onBack: () -> Unit,
    onSourceChanged: (PoFSource) -> Unit,
    onAmountChanged: (String) -> Unit,
    onCurrencyChanged: (String) -> Unit,
    onNoteChanged: (String) -> Unit,
    onCapture: () -> Unit,
    onPick: () -> Unit,
    onRemoveDocument: () -> Unit,
    onSubmit: () -> Unit,
    onResubmit: () -> Unit,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(ProofOfFundsTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.pof_title)) },
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
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            when (state) {
                is ProofOfFundsUiState.Loading ->
                    CircularProgressIndicator(Modifier.align(Alignment.Center))

                is ProofOfFundsUiState.Status -> StatusContent(
                    state = state,
                    onResubmit = onResubmit,
                )

                is ProofOfFundsUiState.Form -> FormContent(
                    state = state,
                    onSourceChanged = onSourceChanged,
                    onAmountChanged = onAmountChanged,
                    onCurrencyChanged = onCurrencyChanged,
                    onNoteChanged = onNoteChanged,
                    onCapture = onCapture,
                    onPick = onPick,
                    onRemoveDocument = onRemoveDocument,
                    onSubmit = onSubmit,
                )

                is ProofOfFundsUiState.Error -> ErrorContent(
                    message = state.message,
                    retryable = state.retryable,
                    onRetry = onRetry,
                )
            }
        }
    }
}

@Composable
private fun SummaryHeader(state: ProofOfFundsUiState) {
    val summary = when (state) {
        is ProofOfFundsUiState.Status -> state.summary
        is ProofOfFundsUiState.Form -> state.summary
        else -> return
    }
    val locale = currentLocale()
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(
                text = stringResource(R.string.pof_summary_heading),
                style = MaterialTheme.typography.titleSmall,
            )
            Text(
                text = stringResource(R.string.pof_summary_counts, summary.count, summary.verifiedCount),
                style = MaterialTheme.typography.bodyMedium,
            )
            summary.verifiedAmountCents?.let { cents ->
                Text(
                    text = stringResource(
                        R.string.pof_summary_verified_amount,
                        formatMoney(cents, summary.verifiedCategories.firstOrNull(), locale),
                    ),
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }
    }
}

@Composable
private fun StatusContent(
    state: ProofOfFundsUiState.Status,
    onResubmit: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        SummaryHeader(state)

        Card(modifier = Modifier.fillMaxWidth().testTag(ProofOfFundsTestTags.STATUS)) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    text = stringResource(R.string.pof_latest_heading),
                    style = MaterialTheme.typography.titleMedium,
                )
                StatusBadge(state.latest.status)
                SubmissionDetails(state.latest)
                if (state.latest.status.invitesResubmit) {
                    state.latest.reviewerNote?.let {
                        Text(
                            text = stringResource(R.string.pof_reviewer_note, it),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.error,
                        )
                    }
                }
                if (state.canResubmit) {
                    Button(
                        onClick = onResubmit,
                        modifier = Modifier
                            .fillMaxWidth()
                            .heightIn(min = 48.dp)
                            .testTag(ProofOfFundsTestTags.RESUBMIT),
                    ) {
                        Text(stringResource(R.string.pof_resubmit))
                    }
                }
            }
        }

        if (state.history.size > 1) {
            HorizontalDivider()
            Text(
                text = stringResource(R.string.pof_history_heading),
                style = MaterialTheme.typography.titleSmall,
            )
            state.history.drop(1).forEach { item ->
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        StatusBadge(item.status)
                        SubmissionDetails(item)
                    }
                }
            }
        }
    }
}

@Composable
private fun SubmissionDetails(item: ProofOfFunds) {
    val locale = currentLocale()
    item.source?.let {
        Text(
            text = stringResource(sourceLabel(it)),
            style = MaterialTheme.typography.bodyMedium,
        )
    }
    item.declaredAmountCents?.let { cents ->
        Text(
            text = formatMoney(cents, item.currency, locale),
            style = MaterialTheme.typography.bodyMedium,
        )
    }
    item.note?.takeIf { it.isNotBlank() }?.let {
        Text(text = it, style = MaterialTheme.typography.bodySmall)
    }
}

@Composable
private fun StatusBadge(status: PoFStatus) {
    AssistChip(
        onClick = {},
        enabled = false,
        label = { Text(stringResource(statusLabel(status))) },
    )
}

@Composable
private fun FormContent(
    state: ProofOfFundsUiState.Form,
    onSourceChanged: (PoFSource) -> Unit,
    onAmountChanged: (String) -> Unit,
    onCurrencyChanged: (String) -> Unit,
    onNoteChanged: (String) -> Unit,
    onCapture: () -> Unit,
    onPick: () -> Unit,
    onRemoveDocument: () -> Unit,
    onSubmit: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        SummaryHeader(state)

        Text(
            text = stringResource(R.string.pof_form_heading),
            style = MaterialTheme.typography.titleMedium,
        )

        SourceDropdown(
            options = state.sourceCategoryList,
            selected = state.source,
            isError = state.fieldErrors.sourceMissing,
            onSelected = onSourceChanged,
        )

        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedTextField(
                value = state.amountRaw,
                onValueChange = onAmountChanged,
                label = { Text(stringResource(R.string.pof_amount_label)) },
                singleLine = true,
                isError = state.fieldErrors.amountMissing || state.fieldErrors.amountInvalid,
                keyboardOptions = KeyboardOptions(
                    keyboardType = KeyboardType.Decimal,
                    imeAction = ImeAction.Next,
                ),
                modifier = Modifier
                    .weight(2f)
                    .testTag(ProofOfFundsTestTags.AMOUNT),
            )
            OutlinedTextField(
                value = state.currency,
                onValueChange = onCurrencyChanged,
                label = { Text(stringResource(R.string.pof_currency_label)) },
                singleLine = true,
                keyboardOptions = KeyboardOptions(imeAction = ImeAction.Next),
                modifier = Modifier
                    .weight(1f)
                    .testTag(ProofOfFundsTestTags.CURRENCY),
            )
        }

        OutlinedTextField(
            value = state.note,
            onValueChange = onNoteChanged,
            label = { Text(stringResource(R.string.pof_note_label)) },
            keyboardOptions = KeyboardOptions(imeAction = ImeAction.Done),
            modifier = Modifier
                .fillMaxWidth()
                .testTag(ProofOfFundsTestTags.NOTE),
        )

        DocumentSection(
            documentKey = state.documentKey,
            documentLabel = state.documentLabel,
            uploading = state.uploading,
            isError = state.fieldErrors.documentMissing,
            onCapture = onCapture,
            onPick = onPick,
            onRemove = onRemoveDocument,
        )

        state.inlineError?.let {
            Text(
                text = it,
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodySmall,
            )
        }

        Button(
            onClick = onSubmit,
            enabled = state.submitEnabled && !state.submitting && !state.uploading,
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(min = 48.dp)
                .testTag(ProofOfFundsTestTags.SUBMIT),
        ) {
            Text(stringResource(R.string.pof_submit))
        }
    }
}

@Composable
private fun SourceDropdown(
    options: List<PoFSource>,
    selected: PoFSource?,
    isError: Boolean,
    onSelected: (PoFSource) -> Unit,
) {
    var expanded by remember { mutableStateOf(false) }
    val label = selected?.let { stringResource(sourceLabel(it)) }
        ?: stringResource(R.string.pof_source_unselected)

    ExposedDropdownMenuBox(
        expanded = expanded,
        onExpandedChange = { expanded = it },
        modifier = Modifier.testTag(ProofOfFundsTestTags.SOURCE),
    ) {
        OutlinedTextField(
            value = label,
            onValueChange = {},
            readOnly = true,
            isError = isError,
            label = { Text(stringResource(R.string.pof_source_label)) },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
            modifier = Modifier
                .fillMaxWidth()
                .menuAnchor(),
        )
        ExposedDropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
            options.forEach { source ->
                DropdownMenuItem(
                    text = { Text(stringResource(sourceLabel(source))) },
                    onClick = {
                        onSelected(source)
                        expanded = false
                    },
                )
            }
        }
    }
}

@Composable
private fun DocumentSection(
    documentKey: String?,
    documentLabel: String?,
    uploading: Boolean,
    isError: Boolean,
    onCapture: () -> Unit,
    onPick: () -> Unit,
    onRemove: () -> Unit,
) {
    Text(
        text = stringResource(R.string.pof_document_heading),
        style = MaterialTheme.typography.titleSmall,
        color = if (isError) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface,
    )

    Row(
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        modifier = Modifier.testTag(ProofOfFundsTestTags.ADD_DOC),
    ) {
        Button(
            onClick = onCapture,
            enabled = !uploading,
            modifier = Modifier.heightIn(min = 48.dp),
        ) {
            Text(stringResource(R.string.pof_document_capture))
        }
        OutlinedButton(
            onClick = onPick,
            enabled = !uploading,
            modifier = Modifier.heightIn(min = 48.dp),
        ) {
            Text(stringResource(R.string.pof_document_choose))
        }
    }

    when {
        uploading -> CircularProgressIndicator(Modifier.size(24.dp))
        documentKey != null -> Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            AsyncImage(
                model = documentLabel,
                contentDescription = stringResource(R.string.pof_document_thumbnail_cd),
                modifier = Modifier.size(48.dp),
            )
            InputChip(
                selected = true,
                onClick = onRemove,
                label = { Text(documentLabel ?: stringResource(R.string.pof_document_attached)) },
                modifier = Modifier.testTag(ProofOfFundsTestTags.REMOVE_DOC),
            )
        }
    }
}

@Composable
private fun ErrorContent(message: String, retryable: Boolean, onRetry: () -> Unit) {
    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp, Alignment.CenterVertically),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(text = message, style = MaterialTheme.typography.bodyLarge)
        if (retryable) {
            Button(onClick = onRetry, modifier = Modifier.heightIn(min = 48.dp)) {
                Text(stringResource(R.string.pof_retry))
            }
        }
    }
}

@Composable
private fun currentLocale(): Locale {
    val config = LocalConfiguration.current
    return if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.N) {
        config.locales[0]
    } else {
        @Suppress("DEPRECATION")
        config.locale
    }
}

private fun sourceLabel(source: PoFSource): Int = when (source) {
    PoFSource.BANK_STATEMENT -> R.string.pof_source_bank_statement
    PoFSource.PAY_STUB -> R.string.pof_source_pay_stub
    PoFSource.SALE_OF_ASSET -> R.string.pof_source_sale_of_asset
    PoFSource.INVESTMENT -> R.string.pof_source_investment
    PoFSource.BUSINESS_INCOME -> R.string.pof_source_business_income
    PoFSource.INHERITANCE -> R.string.pof_source_inheritance
    PoFSource.GIFT -> R.string.pof_source_gift
    PoFSource.SAVINGS -> R.string.pof_source_savings
    PoFSource.UNKNOWN -> R.string.pof_source_unselected
}

private fun statusLabel(status: PoFStatus): Int = when (status) {
    PoFStatus.PENDING -> R.string.pof_status_pending
    PoFStatus.VERIFIED -> R.string.pof_status_verified
    PoFStatus.REJECTED -> R.string.pof_status_rejected
    PoFStatus.NEEDS_MORE_INFO -> R.string.pof_status_needs_more_info
    PoFStatus.EXPIRED -> R.string.pof_status_expired
    PoFStatus.UNKNOWN -> R.string.pof_status_pending
}

/**
 * Locale-aware money rendering for integer [cents]. Uses the optional ISO-4217 [currencyCode] when valid
 * (falls back to the locale's default currency formatting). Kept out of the data layer (no hardcoded glyph).
 */
private fun formatMoney(cents: Long, currencyCode: String?, locale: Locale): String {
    val nf = NumberFormat.getCurrencyInstance(locale)
    currencyCode?.takeIf { it.length == 3 }?.let { code ->
        runCatching { nf.currency = Currency.getInstance(code.uppercase(Locale.ROOT)) }
    }
    return nf.format(cents / 100.0)
}

/**
 * Copies a picked content:// [uri] into the app cache so the VM/processor get a stable [File] (mirrors the
 * AND-321 / AND-326 screens' temp-copy). Best-effort.
 */
private fun copyUriToCache(context: Context, uri: Uri): File {
    val dir = File(context.cacheDir, "kyc-capture").apply { mkdirs() }
    val out = File(dir, "kyc-pof-pick-${System.currentTimeMillis()}")
    context.contentResolver.openInputStream(uri)?.use { input ->
        out.outputStream().use { input.copyTo(it) }
    }
    return out
}

// A document is an image OR a PDF; the picker filters on this MIME (kept out of comments per style).
private val DOC_PICK_FILTER = "*/*"
