@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.kyc.residency

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
import androidx.compose.foundation.rememberScrollState
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.compose.runtime.LaunchedEffect
import com.testlogon.android.R
import com.testlogon.android.feature.kyc.residency.model.AddressForm
import com.testlogon.android.feature.kyc.residency.model.AddressVerification
import com.testlogon.android.feature.kyc.residency.model.ResidencyDocType
import com.testlogon.android.feature.kyc.residency.model.ResidencyDocument
import java.io.File

/** AND-326 - stable testTags for the residency / address-verification screen. */
object ResidencyTestTags {
    const val SCREEN = "residency_screen"
    const val TYPE = "residency_type"
    const val ISSUER = "residency_issuer"
    const val DATE = "residency_date"
    const val CAPTURE = "residency_capture"
    const val PICK = "residency_pick"
    const val SUBMIT = "residency_submit"
    const val STATUS = "residency_status"
    const val ADDRESS_LINE1 = "address_line1"
    const val ADDRESS_CITY = "address_city"
    const val ADDRESS_STATE = "address_state"
    const val ADDRESS_POSTAL = "address_postal"
    const val ADDRESS_COUNTRY = "address_country"
    const val ADDRESS_VERIFY = "address_verify"
    const val ADDRESS_RESULT = "address_result"
}

/**
 * AND-326 - route-level residency / address-verification screen.
 *
 * BOTH surfaces are REAL REST. The proof-of-residency acquisition reuses AND-321's dependency-free system
 * intents: live camera via [ActivityResultContracts.TakePicture] writing to a FileProvider Uri, and a
 * PDF/image pick via [ActivityResultContracts.GetContent] (the ACTION_OPEN_DOCUMENT idiom; the document
 * picker needs NO runtime permission). The acquired file is handed to the VM, which base64-encodes the
 * bytes OFF-MAIN via AND-321's CaptureImageProcessor before the inline-base64 upload POST. The case_id is
 * an OPTIONAL nav arg read by the VM from SavedStateHandle (required only for address verification).
 */
@Composable
fun ResidencyRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: ResidencyViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val context = LocalContext.current

    LaunchedEffect(Unit) { viewModel.onScreenEntered() }

    // A stable capture target File + its FileProvider content Uri for the live-camera TakePicture intent
    // (reuses the existing `${applicationId}.fileprovider` + the kyc-capture cache-path from AND-321).
    val captureFile = remember {
        File(context.cacheDir, "kyc-capture").apply { mkdirs() }
            .let { File(it, "kyc-residency-${System.currentTimeMillis()}.jpg") }
    }
    val captureUri = remember {
        androidx.core.content.FileProvider.getUriForFile(
            context,
            "${context.packageName}.fileprovider",
            captureFile,
        )
    }

    val takePicture = rememberLauncherForActivityResult(ActivityResultContracts.TakePicture()) { ok ->
        if (ok) viewModel.onProofCaptured(captureFile)
    }
    // ACTION_OPEN_DOCUMENT idiom (GetContent) for a proof PDF or image; needs no runtime permission.
    val pickProof = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        if (uri != null) viewModel.onProofPicked(copyUriToCache(context, uri))
    }

    ResidencyScreen(
        state = state,
        canVerifyAddress = viewModel.canVerifyAddress,
        onBack = onBack,
        onProofTypeSelected = viewModel::onProofTypeSelected,
        onIssuerChanged = viewModel::onIssuingEntityChanged,
        onDateChanged = viewModel::onDocumentDateChanged,
        onCapture = { takePicture.launch(captureUri) },
        onPick = { pickProof.launch(PROOF_PICK_FILTER) },
        onRemoveProof = viewModel::onRemoveProof,
        onAddressFieldChanged = viewModel::onAddressFieldChanged,
        onSubmitResidency = viewModel::submitResidency,
        onVerifyAddress = viewModel::submitAddress,
        onRetry = viewModel::retrySubmit,
        modifier = modifier,
    )
}

@Composable
fun ResidencyScreen(
    state: ResidencyUiState,
    canVerifyAddress: Boolean,
    onBack: () -> Unit,
    onProofTypeSelected: (ResidencyDocType) -> Unit,
    onIssuerChanged: (String) -> Unit,
    onDateChanged: (String) -> Unit,
    onCapture: () -> Unit,
    onPick: () -> Unit,
    onRemoveProof: () -> Unit,
    onAddressFieldChanged: ((AddressForm) -> AddressForm) -> Unit,
    onSubmitResidency: () -> Unit,
    onVerifyAddress: () -> Unit,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(ResidencyTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.residency_title)) },
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
                is ResidencyUiState.Loading, is ResidencyUiState.Submitting ->
                    CircularProgressIndicator(Modifier.align(Alignment.Center))

                is ResidencyUiState.Editing -> EditingContent(
                    state = state,
                    canVerifyAddress = canVerifyAddress,
                    onProofTypeSelected = onProofTypeSelected,
                    onIssuerChanged = onIssuerChanged,
                    onDateChanged = onDateChanged,
                    onCapture = onCapture,
                    onPick = onPick,
                    onRemoveProof = onRemoveProof,
                    onAddressFieldChanged = onAddressFieldChanged,
                    onSubmitResidency = onSubmitResidency,
                    onVerifyAddress = onVerifyAddress,
                )

                is ResidencyUiState.Pending -> StatusPanel(
                    document = state.document,
                    titleRes = R.string.residency_status_pending,
                    reason = null,
                    onRetry = onRetry,
                )

                is ResidencyUiState.Verified -> StatusPanel(
                    document = state.document,
                    titleRes = R.string.residency_status_verified,
                    reason = null,
                    onRetry = onRetry,
                )

                is ResidencyUiState.Rejected -> StatusPanel(
                    document = state.document,
                    titleRes = R.string.residency_status_rejected,
                    reason = state.reason,
                    onRetry = onRetry,
                )

                is ResidencyUiState.AddressResult -> AddressResultContent(
                    verification = state.verification,
                    onRetry = onRetry,
                )

                is ResidencyUiState.Error -> ErrorContent(
                    message = state.message,
                    retryable = state.retryable,
                    onRetry = onRetry,
                )
            }
        }
    }
}

@Composable
private fun EditingContent(
    state: ResidencyUiState.Editing,
    canVerifyAddress: Boolean,
    onProofTypeSelected: (ResidencyDocType) -> Unit,
    onIssuerChanged: (String) -> Unit,
    onDateChanged: (String) -> Unit,
    onCapture: () -> Unit,
    onPick: () -> Unit,
    onRemoveProof: () -> Unit,
    onAddressFieldChanged: ((AddressForm) -> AddressForm) -> Unit,
    onSubmitResidency: () -> Unit,
    onVerifyAddress: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        ProofSection(
            state = state,
            onProofTypeSelected = onProofTypeSelected,
            onIssuerChanged = onIssuerChanged,
            onDateChanged = onDateChanged,
            onCapture = onCapture,
            onPick = onPick,
            onRemoveProof = onRemoveProof,
            onSubmitResidency = onSubmitResidency,
        )

        state.latestDocument?.let { LatestDocumentSummary(it) }

        HorizontalDivider()

        AddressSection(
            form = state.addressForm,
            canVerify = canVerifyAddress,
            inlineError = state.inlineError,
            onAddressFieldChanged = onAddressFieldChanged,
            onVerifyAddress = onVerifyAddress,
        )

        state.addressResult?.let { AddressResultCard(it) }
    }
}

@Composable
private fun ProofSection(
    state: ResidencyUiState.Editing,
    onProofTypeSelected: (ResidencyDocType) -> Unit,
    onIssuerChanged: (String) -> Unit,
    onDateChanged: (String) -> Unit,
    onCapture: () -> Unit,
    onPick: () -> Unit,
    onRemoveProof: () -> Unit,
    onSubmitResidency: () -> Unit,
) {
    Text(
        text = stringResource(R.string.residency_proof_heading),
        style = MaterialTheme.typography.titleMedium,
    )

    ProofTypeDropdown(
        accepted = state.acceptedProofTypes,
        selected = state.selectedProofType,
        onSelected = onProofTypeSelected,
    )

    OutlinedTextField(
        value = state.issuingEntity,
        onValueChange = onIssuerChanged,
        label = { Text(stringResource(R.string.residency_issuer_label)) },
        singleLine = true,
        isError = state.validation.issuerMissing,
        keyboardOptions = KeyboardOptions(imeAction = ImeAction.Next),
        modifier = Modifier.fillMaxWidth().testTag(ResidencyTestTags.ISSUER),
    )

    OutlinedTextField(
        value = state.documentDate,
        onValueChange = onDateChanged,
        label = { Text(stringResource(R.string.residency_date_label)) },
        placeholder = { Text(stringResource(R.string.residency_date_hint)) },
        singleLine = true,
        isError = state.validation.dateMissing,
        keyboardOptions = KeyboardOptions(imeAction = ImeAction.Next),
        modifier = Modifier.fillMaxWidth().testTag(ResidencyTestTags.DATE),
    )

    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Button(
            onClick = onCapture,
            modifier = Modifier.heightIn(min = 48.dp).testTag(ResidencyTestTags.CAPTURE),
        ) {
            Text(stringResource(R.string.residency_capture))
        }
        OutlinedButton(
            onClick = onPick,
            modifier = Modifier.heightIn(min = 48.dp).testTag(ResidencyTestTags.PICK),
        ) {
            Text(stringResource(R.string.residency_pick))
        }
    }

    state.proof?.let { proof ->
        InputChip(
            selected = true,
            onClick = onRemoveProof,
            label = { Text(proof.displayName) },
            modifier = Modifier.testTag("${ResidencyTestTags.PICK}_chip"),
        )
    }

    if (state.validation.proofTooLarge) {
        Text(
            text = stringResource(R.string.residency_proof_too_large),
            color = MaterialTheme.colorScheme.error,
            style = MaterialTheme.typography.bodySmall,
        )
    }

    Button(
        onClick = onSubmitResidency,
        enabled = state.submitEnabled,
        modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag(ResidencyTestTags.SUBMIT),
    ) {
        Text(stringResource(R.string.residency_submit))
    }
}

@Composable
private fun ProofTypeDropdown(
    accepted: List<ResidencyDocType>,
    selected: ResidencyDocType?,
    onSelected: (ResidencyDocType) -> Unit,
) {
    var expanded by remember { mutableStateOf(false) }
    val label = selected?.let { stringResource(proofTypeLabel(it)) }
        ?: stringResource(R.string.residency_type_unselected)

    ExposedDropdownMenuBox(
        expanded = expanded,
        onExpandedChange = { expanded = it },
        modifier = Modifier.testTag(ResidencyTestTags.TYPE),
    ) {
        OutlinedTextField(
            value = label,
            onValueChange = {},
            readOnly = true,
            label = { Text(stringResource(R.string.residency_type_label)) },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
            modifier = Modifier
                .fillMaxWidth()
                .menuAnchor(),
        )
        ExposedDropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
            accepted.forEach { docType ->
                DropdownMenuItem(
                    text = { Text(stringResource(proofTypeLabel(docType))) },
                    onClick = {
                        onSelected(docType)
                        expanded = false
                    },
                )
            }
        }
    }
}

@Composable
private fun AddressSection(
    form: AddressForm,
    canVerify: Boolean,
    inlineError: String?,
    onAddressFieldChanged: ((AddressForm) -> AddressForm) -> Unit,
    onVerifyAddress: () -> Unit,
) {
    Text(
        text = stringResource(R.string.address_heading),
        style = MaterialTheme.typography.titleMedium,
    )

    AddressField(
        value = form.line1,
        labelRes = R.string.address_line1_label,
        tag = ResidencyTestTags.ADDRESS_LINE1,
        onChange = { v -> onAddressFieldChanged { it.copy(line1 = v) } },
    )
    AddressField(
        value = form.line2,
        labelRes = R.string.address_line2_label,
        tag = "${ResidencyTestTags.ADDRESS_LINE1}_2",
        onChange = { v -> onAddressFieldChanged { it.copy(line2 = v) } },
    )
    AddressField(
        value = form.city,
        labelRes = R.string.address_city_label,
        tag = ResidencyTestTags.ADDRESS_CITY,
        onChange = { v -> onAddressFieldChanged { it.copy(city = v) } },
    )
    AddressField(
        value = form.state,
        labelRes = R.string.address_state_label,
        tag = ResidencyTestTags.ADDRESS_STATE,
        onChange = { v -> onAddressFieldChanged { it.copy(state = v) } },
    )
    AddressField(
        value = form.postalCode,
        labelRes = R.string.address_postal_label,
        tag = ResidencyTestTags.ADDRESS_POSTAL,
        keyboardType = KeyboardType.Ascii,
        onChange = { v -> onAddressFieldChanged { it.copy(postalCode = v) } },
    )
    AddressField(
        value = form.country,
        labelRes = R.string.address_country_label,
        tag = ResidencyTestTags.ADDRESS_COUNTRY,
        onChange = { v -> onAddressFieldChanged { it.copy(country = v) } },
    )

    if (inlineError != null) {
        Text(
            text = inlineError,
            color = MaterialTheme.colorScheme.error,
            style = MaterialTheme.typography.bodySmall,
        )
    }

    Button(
        onClick = onVerifyAddress,
        enabled = canVerify,
        modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag(ResidencyTestTags.ADDRESS_VERIFY),
    ) {
        Text(stringResource(R.string.address_verify))
    }
    if (!canVerify) {
        Text(
            text = stringResource(R.string.address_needs_case),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun AddressField(
    value: String,
    labelRes: Int,
    tag: String,
    onChange: (String) -> Unit,
    keyboardType: KeyboardType = KeyboardType.Text,
) {
    OutlinedTextField(
        value = value,
        onValueChange = onChange,
        label = { Text(stringResource(labelRes)) },
        singleLine = true,
        keyboardOptions = KeyboardOptions(keyboardType = keyboardType, imeAction = ImeAction.Next),
        modifier = Modifier.fillMaxWidth().testTag(tag),
    )
}

@Composable
private fun LatestDocumentSummary(document: ResidencyDocument) {
    Card(modifier = Modifier.fillMaxWidth().testTag(ResidencyTestTags.STATUS)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(
                text = stringResource(R.string.residency_latest_heading),
                style = MaterialTheme.typography.titleSmall,
            )
            Text(text = document.fileName, style = MaterialTheme.typography.bodyMedium)
            Text(
                text = stringResource(residencyStatusLabel(document.status)),
                style = MaterialTheme.typography.bodyMedium,
            )
            document.reviewNote?.let {
                Text(text = it, style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

@Composable
private fun StatusPanel(
    document: ResidencyDocument,
    titleRes: Int,
    reason: String?,
    onRetry: () -> Unit,
) {
    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp).testTag(ResidencyTestTags.STATUS),
        verticalArrangement = Arrangement.spacedBy(12.dp, Alignment.CenterVertically),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(text = stringResource(titleRes), style = MaterialTheme.typography.titleMedium)
        Text(text = document.fileName, style = MaterialTheme.typography.bodyMedium)
        reason?.let { Text(text = it, style = MaterialTheme.typography.bodySmall) }
        Button(onClick = onRetry, modifier = Modifier.heightIn(min = 48.dp)) {
            Text(stringResource(R.string.residency_back_to_form))
        }
    }
}

@Composable
private fun AddressResultContent(
    verification: AddressVerification,
    onRetry: () -> Unit,
) {
    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp).testTag(ResidencyTestTags.ADDRESS_RESULT),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        AddressResultBody(verification)
        Button(onClick = onRetry, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) {
            Text(stringResource(R.string.residency_back_to_form))
        }
    }
}

@Composable
private fun AddressResultCard(verification: AddressVerification) {
    Card(modifier = Modifier.fillMaxWidth().testTag(ResidencyTestTags.ADDRESS_RESULT)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            AddressResultBody(verification)
        }
    }
}

@Composable
private fun AddressResultBody(verification: AddressVerification) {
    Text(
        text = stringResource(R.string.address_result_heading),
        style = MaterialTheme.typography.titleMedium,
    )
    Text(
        text = stringResource(addrStatusLabel(verification.status)),
        style = MaterialTheme.typography.bodyLarge,
    )
    Text(
        text = stringResource(addrDecisionLabel(verification.decision)),
        style = MaterialTheme.typography.bodyMedium,
    )
    verification.confidenceScore?.let {
        Text(
            text = stringResource(R.string.address_confidence, it),
            style = MaterialTheme.typography.bodySmall,
        )
    }
    if (verification.discrepancies.isNotEmpty()) {
        Text(
            text = stringResource(R.string.address_discrepancies_heading),
            style = MaterialTheme.typography.titleSmall,
        )
        verification.discrepancies.forEach { field ->
            Text(text = field, style = MaterialTheme.typography.bodySmall)
        }
    }
    verification.standardizedAddress?.takeIf { it.isNotEmpty() }?.let { standardized ->
        Text(
            text = stringResource(R.string.address_standardized_heading),
            style = MaterialTheme.typography.titleSmall,
        )
        Text(
            text = standardized.values.joinToString(", "),
            style = MaterialTheme.typography.bodySmall,
        )
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
                Text(stringResource(R.string.residency_retry))
            }
        }
    }
}

private fun proofTypeLabel(docType: ResidencyDocType): Int = when (docType) {
    ResidencyDocType.UTILITY_BILL -> R.string.residency_type_utility_bill
    ResidencyDocType.BANK_STATEMENT -> R.string.residency_type_bank_statement
    ResidencyDocType.GOVERNMENT_LETTER -> R.string.residency_type_government_letter
    ResidencyDocType.TAX_DOCUMENT -> R.string.residency_type_tax_document
    ResidencyDocType.LEASE_AGREEMENT -> R.string.residency_type_lease_agreement
    ResidencyDocType.UNKNOWN -> R.string.residency_type_unselected
}

private fun residencyStatusLabel(status: com.testlogon.android.feature.kyc.residency.model.ResidencyStatus): Int =
    when (status) {
        com.testlogon.android.feature.kyc.residency.model.ResidencyStatus.PENDING -> R.string.residency_status_pending
        com.testlogon.android.feature.kyc.residency.model.ResidencyStatus.VERIFIED -> R.string.residency_status_verified
        com.testlogon.android.feature.kyc.residency.model.ResidencyStatus.REJECTED -> R.string.residency_status_rejected
        com.testlogon.android.feature.kyc.residency.model.ResidencyStatus.EXPIRED -> R.string.residency_status_expired
        com.testlogon.android.feature.kyc.residency.model.ResidencyStatus.UNKNOWN -> R.string.residency_status_pending
    }

private fun addrStatusLabel(status: com.testlogon.android.feature.kyc.residency.model.AddrStatus): Int = when (status) {
    com.testlogon.android.feature.kyc.residency.model.AddrStatus.PENDING -> R.string.address_status_pending
    com.testlogon.android.feature.kyc.residency.model.AddrStatus.PARTIAL_MATCH -> R.string.address_status_partial
    com.testlogon.android.feature.kyc.residency.model.AddrStatus.UNVERIFIABLE -> R.string.address_status_unverifiable
    com.testlogon.android.feature.kyc.residency.model.AddrStatus.VERIFIED -> R.string.address_status_verified
    com.testlogon.android.feature.kyc.residency.model.AddrStatus.ERROR -> R.string.address_status_error
    com.testlogon.android.feature.kyc.residency.model.AddrStatus.UNKNOWN -> R.string.address_status_pending
}

private fun addrDecisionLabel(decision: com.testlogon.android.feature.kyc.residency.model.AddrDecision): Int =
    when (decision) {
        com.testlogon.android.feature.kyc.residency.model.AddrDecision.VERIFIED -> R.string.address_decision_verified
        com.testlogon.android.feature.kyc.residency.model.AddrDecision.NEEDS_REVIEW -> R.string.address_decision_needs_review
        com.testlogon.android.feature.kyc.residency.model.AddrDecision.FAILED -> R.string.address_decision_failed
        com.testlogon.android.feature.kyc.residency.model.AddrDecision.UNKNOWN -> R.string.address_decision_needs_review
    }

/**
 * Copies a picked content:// [uri] into the app cache so the VM/processor get a stable [File] (mirrors the
 * AND-321 screen's own temp-copy). Best-effort; the proof keeps its picked display name when resolvable.
 */
private fun copyUriToCache(context: Context, uri: Uri): File {
    val dir = File(context.cacheDir, "kyc-capture").apply { mkdirs() }
    val out = File(dir, "kyc-residency-pick-${System.currentTimeMillis()}")
    context.contentResolver.openInputStream(uri)?.use { input ->
        out.outputStream().use { input.copyTo(it) }
    }
    return out
}

// A proof is an image OR a PDF; the document picker filters on this MIME (kept out of comments per style).
private val PROOF_PICK_FILTER = "*/*"
