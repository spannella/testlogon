@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.kycadmin

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.ViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.kycadmin.AddressVerificationOutDto
import com.testlogon.android.data.kycadmin.KycAddressVerifAdminRepository
import com.testlogon.android.data.kycadmin.PostalCodeValidationDto
import com.testlogon.android.feature.adminops.AdminOpsErrorType
import com.testlogon.android.feature.adminops.CardSection
import com.testlogon.android.feature.adminops.StatRow
import com.testlogon.android.feature.adminops.adminOpsErrorFor
import com.testlogon.android.feature.adminops.adminOpsErrorMessage
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.util.Locale
import javax.inject.Inject

data class KycAddressVerifUiState(
    val caseId: String = "",
    val loading: Boolean = false,
    val actionInFlight: Boolean = false,
    val verification: AddressVerificationOutDto? = null,
    val attempts: List<AddressVerificationOutDto> = emptyList(),
    val postalResult: PostalCodeValidationDto? = null,
    val message: String? = null,
)

@HiltViewModel
class KycAddressVerifAdminViewModel @Inject constructor(
    private val repo: KycAddressVerifAdminRepository,
) : ViewModel() {

    private val _state = MutableStateFlow(KycAddressVerifUiState())
    val state: StateFlow<KycAddressVerifUiState> = _state.asStateFlow()

    fun setCaseId(v: String) { _state.value = _state.value.copy(caseId = v) }
    fun clearMessage() { _state.value = _state.value.copy(message = null) }

    fun load() {
        val caseId = _state.value.caseId.trim()
        if (caseId.isEmpty() || _state.value.loading) return
        _state.value = _state.value.copy(loading = true, message = null)
        viewModelScope.launch {
            val v = repo.get(caseId)
            val a = repo.attempts(caseId)
            _state.value = when (v) {
                is ApiResult.Success -> _state.value.copy(
                    loading = false,
                    verification = v.data,
                    attempts = (a as? ApiResult.Success)?.data ?: emptyList(),
                )
                is ApiResult.Failure -> _state.value.copy(loading = false, verification = null, message = failMsg(v.error.status))
                is ApiResult.NetworkError -> _state.value.copy(loading = false, message = adminOpsErrorMessage(AdminOpsErrorType.NETWORK))
            }
        }
    }

    fun validatePostal(postal: String, country: String) {
        if (postal.isBlank() || country.isBlank()) return
        viewModelScope.launch {
            when (val r = repo.validatePostal(postal, country)) {
                is ApiResult.Success -> _state.value = _state.value.copy(postalResult = r.data)
                is ApiResult.Failure -> _state.value = _state.value.copy(message = failMsg(r.error.status))
                is ApiResult.NetworkError -> _state.value = _state.value.copy(message = adminOpsErrorMessage(AdminOpsErrorType.NETWORK))
            }
        }
    }

    fun override(decision: String, note: String) {
        val caseId = _state.value.caseId.trim()
        if (caseId.isEmpty() || _state.value.actionInFlight) return
        _state.value = _state.value.copy(actionInFlight = true)
        viewModelScope.launch {
            val msg = when (val r = repo.override(caseId, decision, note)) {
                is ApiResult.Success -> { _state.value = _state.value.copy(verification = r.data); "Decision overridden" }
                is ApiResult.Failure -> failMsg(r.error.status)
                is ApiResult.NetworkError -> adminOpsErrorMessage(AdminOpsErrorType.NETWORK)
            }
            _state.value = _state.value.copy(actionInFlight = false, message = msg)
        }
    }

    private fun failMsg(status: Int): String =
        if (status == 403) "Not authorised (admin required)." else adminOpsErrorMessage(adminOpsErrorFor(status))
}

object KycAddressVerifTestTags {
    const val SCREEN = "kyc_addr_verif_screen"
    const val CASE_FIELD = "kyc_addr_verif_case_field"
    const val LOAD_BTN = "kyc_addr_verif_load"
    const val OVERRIDE_BTN = "kyc_addr_verif_override"
    const val OVERRIDE_CONFIRM = "kyc_addr_verif_override_confirm"
    const val POSTAL_BTN = "kyc_addr_verif_postal"
}

@Composable
fun KycAddressVerifAdminRoute(
    onBack: () -> Unit,
    viewModel: KycAddressVerifAdminViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    val snackbar = remember { SnackbarHostState() }
    var overrideDialog by remember { mutableStateOf(false) }
    var postalDialog by remember { mutableStateOf(false) }

    LaunchedEffect(state.message) { state.message?.let { snackbar.showSnackbar(it); viewModel.clearMessage() } }

    Scaffold(
        modifier = Modifier.testTag(KycAddressVerifTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            TopAppBar(
                title = { Text("Address verification") },
                navigationIcon = { IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back") } },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier.fillMaxSize().padding(padding).verticalScroll(rememberScrollState()).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            OutlinedTextField(
                value = state.caseId,
                onValueChange = viewModel::setCaseId,
                label = { Text("KYC case id") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth().testTag(KycAddressVerifTestTags.CASE_FIELD),
            )
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(
                    onClick = viewModel::load,
                    enabled = state.caseId.isNotBlank() && !state.loading,
                    modifier = Modifier.testTag(KycAddressVerifTestTags.LOAD_BTN),
                ) { Text("Load") }
                OutlinedButton(onClick = { postalDialog = true }, modifier = Modifier.testTag(KycAddressVerifTestTags.POSTAL_BTN)) {
                    Text("Validate postal")
                }
            }

            if (state.loading) {
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Center) { CircularProgressIndicator() }
            }

            state.postalResult?.let { p ->
                CardSection("Postal validation") {
                    StatRow("Valid", if (p.valid) "Yes" else "No")
                    if (p.formatHint.isNotBlank()) StatRow("Format", p.formatHint)
                    if (p.normalized.isNotBlank()) StatRow("Normalized", p.normalized)
                }
            }

            state.verification?.let { v ->
                CardSection("Verification") {
                    StatRow("Status", v.status.replace('_', ' '))
                    StatRow("Decision", v.decision.replace('_', ' '))
                    StatRow("Confidence", String.format(Locale.US, "%.2f", v.confidenceScore))
                    v.country?.let { StatRow("Country", it) }
                    StatRow("Postal format valid", if (v.countryFormatValid) "Yes" else "No")
                    if (v.discrepancies.isNotEmpty()) StatRow("Discrepancies", v.discrepancies.joinToString("; "))
                    v.provider?.let { StatRow("Provider", it) }
                }
                v.standardizedAddress?.let { addr ->
                    CardSection("Standardized address") {
                        StatRow("Line 1", addr.line1)
                        addr.line2?.let { if (it.isNotBlank()) StatRow("Line 2", it) }
                        StatRow("City", addr.city)
                        addr.state?.let { if (it.isNotBlank()) StatRow("State", it) }
                        StatRow("Postal", addr.postalCode)
                        StatRow("Country", addr.country)
                    }
                }
                Button(
                    onClick = { overrideDialog = true },
                    enabled = !state.actionInFlight,
                    modifier = Modifier.fillMaxWidth().testTag(KycAddressVerifTestTags.OVERRIDE_BTN),
                ) { Text("Override decision") }
            }

            if (state.attempts.isNotEmpty()) {
                Text("Attempts (${state.attempts.size})", style = MaterialTheme.typography.titleMedium)
                state.attempts.forEach { a ->
                    CardSection(a.verificationId ?: "attempt") {
                        StatRow("Status", a.status.replace('_', ' '))
                        StatRow("Decision", a.decision.replace('_', ' '))
                        StatRow("Confidence", String.format(Locale.US, "%.2f", a.confidenceScore))
                    }
                }
            }
        }
    }

    if (overrideDialog) {
        OverrideDialog(
            onDismiss = { overrideDialog = false },
            onConfirm = { decision, note -> viewModel.override(decision, note); overrideDialog = false },
        )
    }
    if (postalDialog) {
        PostalDialog(
            onDismiss = { postalDialog = false },
            onConfirm = { postal, country -> viewModel.validatePostal(postal, country); postalDialog = false },
        )
    }
}

@Composable
private fun OverrideDialog(onDismiss: () -> Unit, onConfirm: (String, String) -> Unit) {
    val decisions = listOf("verified", "needs_review", "failed")
    var selected by remember { mutableStateOf(decisions.first()) }
    var note by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Override decision") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                decisions.forEach { d ->
                    Row(
                        Modifier
                            .fillMaxWidth()
                            .selectable(selected = selected == d, onClick = { selected = d })
                            .padding(vertical = 2.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        androidx.compose.material3.RadioButton(selected = selected == d, onClick = { selected = d })
                        Text(d.replace('_', ' ').replaceFirstChar { it.uppercase() })
                    }
                }
                OutlinedTextField(value = note, onValueChange = { note = it }, label = { Text("Note (optional)") }, modifier = Modifier.fillMaxWidth())
            }
        },
        confirmButton = {
            TextButton(onClick = { onConfirm(selected, note) }, modifier = Modifier.testTag(KycAddressVerifTestTags.OVERRIDE_CONFIRM)) { Text("Override") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

@Composable
private fun PostalDialog(onDismiss: () -> Unit, onConfirm: (String, String) -> Unit) {
    var postal by remember { mutableStateOf("") }
    var country by remember { mutableStateOf("US") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Validate postal code") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(value = postal, onValueChange = { postal = it }, label = { Text("Postal code") }, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(value = country, onValueChange = { country = it }, label = { Text("Country (ISO)") }, modifier = Modifier.fillMaxWidth())
            }
        },
        confirmButton = {
            TextButton(onClick = { onConfirm(postal, country) }, enabled = postal.isNotBlank() && country.isNotBlank()) { Text("Validate") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}
