@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.dmca

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
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
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.error
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.data.dmca.DmcaContentType

/** AND-384 - test tags for the DMCA submit screen (Compose UI tests). */
object DmcaTestTags {
    const val SCREEN = "dmca_screen"
    const val DESCRIPTION = "dmca_description"
    const val CONTENT_URL = "dmca_content_url"
    const val CONTENT_TYPE = "dmca_content_type"
    const val CONTENT_ID = "dmca_content_id"
    const val NAME = "dmca_name"
    const val EMAIL = "dmca_email"
    const val ADDRESS = "dmca_address"
    const val PHONE = "dmca_phone"
    const val SWORN = "dmca_sworn"
    const val GOOD_FAITH = "dmca_good_faith"
    const val SIGNATURE = "dmca_signature"
    const val SUBMIT = "dmca_submit"
    const val RETRY = "dmca_retry"
    const val PROGRESS = "dmca_progress"
    const val ERROR = "dmca_error"
    const val CONFIRMATION = "dmca_confirmation"
    const val CLAIM_ID = "dmca_claim_id"
    const val DONE = "dmca_done"
}

/**
 * AND-384 - the navigation entry point. Reads its pre-target args via the injected ViewModel
 * (SavedStateHandle) and renders the stateless [DmcaSubmitScreen]. On success, the Done button pops back to
 * the origin.
 */
@Composable
fun DmcaRoute(
    onBack: () -> Unit,
    viewModel: DmcaViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    DmcaSubmitScreen(
        state = state,
        onFieldChanged = viewModel::onFieldChanged,
        onToggle = viewModel::onToggle,
        onSubmit = viewModel::submit,
        onRetry = viewModel::retry,
        onBack = onBack,
        onDone = onBack,
    )
}

/** AND-384 - stateless DMCA submit screen: a scrollable form, or the post-submit confirmation. */
@Composable
fun DmcaSubmitScreen(
    state: DmcaUiState,
    onFieldChanged: (DmcaField, String) -> Unit,
    onToggle: (DmcaField, Boolean) -> Unit,
    onSubmit: () -> Unit,
    onRetry: () -> Unit,
    onBack: () -> Unit,
    onDone: () -> Unit,
) {
    Scaffold(
        modifier = Modifier.testTag(DmcaTestTags.SCREEN),
        topBar = {
            TopAppBar(title = { Text(stringResource(R.string.dmca_title)) })
        },
    ) { padding ->
        when (state) {
            is DmcaUiState.Submitted -> DmcaConfirmation(
                state = state,
                onDone = onDone,
                modifier = Modifier.padding(padding).fillMaxSize(),
            )
            is DmcaUiState.Editing -> DmcaForm(
                form = state.form,
                submitting = state.submitting,
                errorMessage = null,
                retryable = false,
                onFieldChanged = onFieldChanged,
                onToggle = onToggle,
                onSubmit = onSubmit,
                onRetry = onRetry,
                modifier = Modifier.padding(padding).fillMaxSize(),
            )
            is DmcaUiState.Error -> DmcaForm(
                form = state.form,
                submitting = false,
                errorMessage = state.message,
                retryable = true,
                onFieldChanged = onFieldChanged,
                onToggle = onToggle,
                onSubmit = onSubmit,
                onRetry = onRetry,
                modifier = Modifier.padding(padding).fillMaxSize(),
            )
        }
    }
}

@Composable
private fun DmcaForm(
    form: DmcaFormState,
    submitting: Boolean,
    errorMessage: String?,
    retryable: Boolean,
    onFieldChanged: (DmcaField, String) -> Unit,
    onToggle: (DmcaField, Boolean) -> Unit,
    onSubmit: () -> Unit,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        // --- Copyrighted work ---
        Text(stringResource(R.string.dmca_section_work))
        DmcaTextField(
            value = form.originalWorkDescription,
            onValueChange = { onFieldChanged(DmcaField.OriginalWorkDescription, it) },
            label = stringResource(R.string.dmca_field_description),
            error = form.fieldErrors[DmcaField.OriginalWorkDescription],
            enabled = !submitting,
            testTag = DmcaTestTags.DESCRIPTION,
        )

        // --- Infringing material ---
        Text(stringResource(R.string.dmca_section_infringing))
        DmcaTextField(
            value = form.contentUrl,
            onValueChange = { onFieldChanged(DmcaField.ContentUrl, it) },
            label = stringResource(R.string.dmca_field_content_url),
            error = form.fieldErrors[DmcaField.ContentUrl],
            enabled = !submitting && !form.contentLocked,
            testTag = DmcaTestTags.CONTENT_URL,
        )
        DmcaContentTypeField(
            selected = form.contentType,
            enabled = !submitting && !form.contentLocked,
            onSelect = { onFieldChanged(DmcaField.ContentType, it) },
        )

        // --- Your contact info ---
        Text(stringResource(R.string.dmca_section_contact))
        DmcaTextField(
            value = form.claimantName,
            onValueChange = { onFieldChanged(DmcaField.ClaimantName, it) },
            label = stringResource(R.string.dmca_field_name),
            error = form.fieldErrors[DmcaField.ClaimantName],
            enabled = !submitting,
            testTag = DmcaTestTags.NAME,
        )
        DmcaTextField(
            value = form.claimantEmail,
            onValueChange = { onFieldChanged(DmcaField.ClaimantEmail, it) },
            label = stringResource(R.string.dmca_field_email),
            error = form.fieldErrors[DmcaField.ClaimantEmail],
            enabled = !submitting,
            testTag = DmcaTestTags.EMAIL,
        )
        DmcaTextField(
            value = form.claimantAddress,
            onValueChange = { onFieldChanged(DmcaField.ClaimantAddress, it) },
            label = stringResource(R.string.dmca_field_address),
            error = form.fieldErrors[DmcaField.ClaimantAddress],
            enabled = !submitting,
            testTag = DmcaTestTags.ADDRESS,
        )
        DmcaTextField(
            value = form.claimantPhone,
            onValueChange = { onFieldChanged(DmcaField.ClaimantPhone, it) },
            label = stringResource(R.string.dmca_field_phone),
            error = form.fieldErrors[DmcaField.ClaimantPhone],
            enabled = !submitting,
            testTag = DmcaTestTags.PHONE,
        )

        // --- Legal statements ---
        Text(stringResource(R.string.dmca_section_legal))
        DmcaCheckboxRow(
            checked = form.swornStatement,
            statement = stringResource(R.string.dmca_sworn_statement),
            enabled = !submitting,
            testTag = DmcaTestTags.SWORN,
            onCheckedChange = { onToggle(DmcaField.SwornStatement, it) },
        )
        DmcaCheckboxRow(
            checked = form.goodFaithBelief,
            statement = stringResource(R.string.dmca_good_faith_statement),
            enabled = !submitting,
            testTag = DmcaTestTags.GOOD_FAITH,
            onCheckedChange = { onToggle(DmcaField.GoodFaithBelief, it) },
        )
        val signatureWarning = if (form.signatureNameMismatch) {
            stringResource(R.string.dmca_signature_mismatch)
        } else {
            form.fieldErrors[DmcaField.Signature]
        }
        DmcaTextField(
            value = form.signature,
            onValueChange = { onFieldChanged(DmcaField.Signature, it) },
            label = stringResource(R.string.dmca_field_signature),
            error = signatureWarning,
            enabled = !submitting,
            testTag = DmcaTestTags.SIGNATURE,
            // The signature is never persisted (§8); capitalize words for a typed legal name.
            keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.Words),
        )

        if (errorMessage != null) {
            Text(
                text = errorMessage,
                modifier = Modifier
                    .testTag(DmcaTestTags.ERROR)
                    .semantics { liveRegion = LiveRegionMode.Assertive },
            )
        }

        if (submitting) {
            CircularProgressIndicator(
                Modifier
                    .padding(8.dp)
                    .testTag(DmcaTestTags.PROGRESS)
                    .semantics { liveRegion = LiveRegionMode.Polite },
            )
        } else if (retryable) {
            Button(
                onClick = onRetry,
                enabled = form.isSubmittable,
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 48.dp)
                    .testTag(DmcaTestTags.RETRY),
            ) { Text(stringResource(R.string.dmca_try_again)) }
        } else {
            Button(
                onClick = onSubmit,
                enabled = form.isSubmittable,
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 48.dp)
                    .testTag(DmcaTestTags.SUBMIT),
            ) { Text(stringResource(R.string.dmca_submit)) }
        }
    }
}

@Composable
private fun DmcaTextField(
    value: String,
    onValueChange: (String) -> Unit,
    label: String,
    error: String?,
    enabled: Boolean,
    testTag: String,
    keyboardOptions: KeyboardOptions = KeyboardOptions.Default,
) {
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        enabled = enabled,
        readOnly = !enabled,
        isError = error != null,
        label = { Text(label) },
        supportingText = error?.let { { Text(it) } },
        keyboardOptions = keyboardOptions,
        modifier = Modifier
            .fillMaxWidth()
            .testTag(testTag)
            .semantics { if (error != null) error(error) },
    )
}

@Composable
private fun DmcaContentTypeField(
    selected: String,
    enabled: Boolean,
    onSelect: (String) -> Unit,
) {
    var expanded by remember { mutableStateOf(false) }
    ExposedDropdownMenuBox(
        expanded = expanded && enabled,
        onExpandedChange = { if (enabled) expanded = it },
        modifier = Modifier.fillMaxWidth(),
    ) {
        OutlinedTextField(
            value = contentTypeLabel(selected),
            onValueChange = {},
            readOnly = true,
            enabled = enabled,
            label = { Text(stringResource(R.string.dmca_field_content_type)) },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
            modifier = Modifier
                .fillMaxWidth()
                .menuAnchor()
                .testTag(DmcaTestTags.CONTENT_TYPE),
        )
        ExposedDropdownMenu(
            expanded = expanded && enabled,
            onDismissRequest = { expanded = false },
        ) {
            DmcaContentType.ALL.forEach { type ->
                DropdownMenuItem(
                    text = { Text(contentTypeLabel(type)) },
                    onClick = {
                        expanded = false
                        if (type != selected) onSelect(type)
                    },
                )
            }
        }
    }
}

@Composable
private fun contentTypeLabel(type: String): String = when (type) {
    DmcaContentType.FEED_POST -> stringResource(R.string.dmca_content_type_feed_post)
    DmcaContentType.FEED_MEDIA -> stringResource(R.string.dmca_content_type_feed_media)
    DmcaContentType.MESSAGE_MEDIA -> stringResource(R.string.dmca_content_type_message_media)
    DmcaContentType.VIDEO -> stringResource(R.string.dmca_content_type_video)
    else -> stringResource(R.string.dmca_content_type_other)
}

@Composable
private fun DmcaCheckboxRow(
    checked: Boolean,
    statement: String,
    enabled: Boolean,
    testTag: String,
    onCheckedChange: (Boolean) -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 48.dp)
            .toggleable(
                value = checked,
                enabled = enabled,
                role = Role.Checkbox,
                onValueChange = onCheckedChange,
            )
            .semantics { contentDescription = statement }
            .testTag(testTag),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Checkbox(checked = checked, onCheckedChange = null)
        Text(text = statement, modifier = Modifier.padding(start = 8.dp))
    }
}

@Composable
private fun DmcaConfirmation(
    state: DmcaUiState.Submitted,
    onDone: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier
            .padding(16.dp)
            .testTag(DmcaTestTags.CONFIRMATION)
            .semantics { liveRegion = LiveRegionMode.Assertive },
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(stringResource(R.string.dmca_confirm_title))
        Text(
            text = stringResource(R.string.dmca_confirm_claim_id, state.claimId),
            modifier = Modifier.testTag(DmcaTestTags.CLAIM_ID),
        )
        if (state.contentRemoved) {
            Text(stringResource(R.string.dmca_confirm_content_removed))
        }
        Button(
            onClick = onDone,
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(min = 48.dp)
                .testTag(DmcaTestTags.DONE),
        ) { Text(stringResource(R.string.dmca_done)) }
    }
}
