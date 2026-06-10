@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.checkout.address

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.selection.selectable
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.address.Address
import com.testlogon.android.data.address.AddressDraft

/** AND-214 — stable test tags for the address step. */
object AddressShippingTestTags {
    const val SCREEN = "address_screen"
    const val LIST = "address_list"
    const val ADD = "address_add"
    const val APPLY = "address_apply"
    const val FORM_SHEET = "address_form_sheet"
    const val FORM_LINE1 = "address_form_line1"
    const val FORM_SUBMIT = "address_form_submit"

    fun row(addressId: String) = "address_row_$addressId"
}

/**
 * AND-214 — address-step route. Lists saved addresses, supports adding one, and applies the selection
 * by marking it primary. `Applied` navigates onward to the payment step.
 */
@Composable
fun AddressShippingRoute(
    onContinueToPayment: (addressId: String) -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: AddressShippingViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    var sheetOpen by remember { mutableStateOf(false) }
    var fieldErrors by remember { mutableStateOf<Map<String, String>>(emptyMap()) }

    LaunchedEffect(Unit) {
        viewModel.events.collect { event ->
            when (event) {
                is AddressShippingEvent.Applied -> {
                    sheetOpen = false
                    onContinueToPayment(event.addressId)
                }
                is AddressShippingEvent.ActionFailed -> snackbarHostState.showSnackbar(event.message)
                is AddressShippingEvent.ValidationFailed -> fieldErrors = event.fieldErrors
            }
        }
    }

    AddressShippingScreen(
        state = state,
        snackbarHostState = snackbarHostState,
        sheetOpen = sheetOpen,
        fieldErrors = fieldErrors,
        onSelect = viewModel::onSelectAddress,
        onApply = viewModel::onApply,
        onAddClick = { fieldErrors = emptyMap(); sheetOpen = true },
        onDismissSheet = { sheetOpen = false },
        onSubmitDraft = viewModel::onAddAddress,
        onRetry = viewModel::retry,
        onBack = onBack,
        modifier = modifier,
    )
}

@Composable
fun AddressShippingScreen(
    state: AddressShippingUiState,
    snackbarHostState: SnackbarHostState,
    sheetOpen: Boolean,
    fieldErrors: Map<String, String>,
    onSelect: (String) -> Unit,
    onApply: () -> Unit,
    onAddClick: () -> Unit,
    onDismissSheet: () -> Unit,
    onSubmitDraft: (AddressDraft) -> Unit,
    onRetry: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(AddressShippingTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.address_title)) },
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
        snackbarHost = { SnackbarHost(snackbarHostState) },
        bottomBar = {
            if (state is AddressShippingUiState.Ready) {
                ApplyBar(
                    enabled = state.selectedAddressId != null && !state.applying,
                    onApply = onApply,
                )
            }
        },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            when (state) {
                is AddressShippingUiState.Loading -> LoadingState()
                is AddressShippingUiState.Error -> ErrorState(message = state.message, onRetry = onRetry)
                is AddressShippingUiState.Ready -> AddressList(
                    addresses = state.addresses,
                    selectedId = state.selectedAddressId,
                    onSelect = onSelect,
                    onAddClick = onAddClick,
                )
            }
        }
    }

    if (sheetOpen) {
        AddressFormSheet(
            fieldErrors = fieldErrors,
            onSubmit = onSubmitDraft,
            onDismiss = onDismissSheet,
        )
    }
}

@Composable
private fun AddressList(
    addresses: List<Address>,
    selectedId: String?,
    onSelect: (String) -> Unit,
    onAddClick: () -> Unit,
) {
    LazyColumn(
        modifier = Modifier.fillMaxSize().testTag(AddressShippingTestTags.LIST),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        items(addresses, key = { it.addressId }) { address ->
            AddressRow(
                address = address,
                selected = address.addressId == selectedId,
                onSelect = { onSelect(address.addressId) },
            )
        }
        item {
            OutlinedButton(
                onClick = onAddClick,
                modifier = Modifier.fillMaxWidth().testTag(AddressShippingTestTags.ADD),
            ) {
                Text(stringResource(R.string.address_add))
            }
        }
    }
}

@Composable
private fun AddressRow(address: Address, selected: Boolean, onSelect: () -> Unit) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(AddressShippingTestTags.row(address.addressId))
            .selectable(selected = selected, role = Role.RadioButton, onClick = onSelect),
    ) {
        Row(
            Modifier.fillMaxWidth().padding(12.dp),
            verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
        ) {
            RadioButton(selected = selected, onClick = onSelect)
            Column(Modifier.padding(start = 8.dp)) {
                Text(
                    text = address.name ?: address.line1.orEmpty(),
                    style = MaterialTheme.typography.bodyLarge,
                )
                val sub = listOfNotNull(address.line1.takeIf { address.name != null }, address.city)
                    .joinToString(", ")
                if (sub.isNotBlank()) {
                    Text(text = sub, style = MaterialTheme.typography.bodyMedium)
                }
                if (address.isPrimaryMailing) {
                    Text(
                        text = stringResource(R.string.address_primary_label),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.primary,
                    )
                }
            }
        }
    }
}

@Composable
private fun ApplyBar(enabled: Boolean, onApply: () -> Unit) {
    Surface(tonalElevation = 3.dp) {
        Column(Modifier.fillMaxWidth().padding(16.dp)) {
            Button(
                onClick = onApply,
                enabled = enabled,
                modifier = Modifier.fillMaxWidth().testTag(AddressShippingTestTags.APPLY),
            ) {
                Text(stringResource(R.string.address_continue))
            }
        }
    }
}

@Composable
private fun AddressFormSheet(
    fieldErrors: Map<String, String>,
    onSubmit: (AddressDraft) -> Unit,
    onDismiss: () -> Unit,
) {
    val sheetState = rememberModalBottomSheetState()
    var draft by remember { mutableStateOf(AddressDraft()) }

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState,
        modifier = Modifier.testTag(AddressShippingTestTags.FORM_SHEET),
    ) {
        Column(
            Modifier.fillMaxWidth().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(stringResource(R.string.address_add), style = MaterialTheme.typography.titleLarge)
            OutlinedTextField(
                value = draft.name,
                onValueChange = { draft = draft.copy(name = it) },
                label = { Text(stringResource(R.string.address_field_name)) },
                modifier = Modifier.fillMaxWidth(),
            )
            val line1Error = fieldErrors[AddressShippingViewModel.FIELD_LINE1]
            OutlinedTextField(
                value = draft.line1,
                onValueChange = { draft = draft.copy(line1 = it) },
                label = { Text(stringResource(R.string.address_field_line1)) },
                isError = line1Error != null,
                supportingText = if (line1Error != null) {
                    { Text(line1Error) }
                } else {
                    null
                },
                modifier = Modifier.fillMaxWidth().testTag(AddressShippingTestTags.FORM_LINE1),
            )
            OutlinedTextField(
                value = draft.city,
                onValueChange = { draft = draft.copy(city = it) },
                label = { Text(stringResource(R.string.address_field_city)) },
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = draft.state,
                onValueChange = { draft = draft.copy(state = it) },
                label = { Text(stringResource(R.string.address_field_state)) },
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = draft.postalCode,
                onValueChange = { draft = draft.copy(postalCode = it) },
                label = { Text(stringResource(R.string.address_field_postal)) },
                modifier = Modifier.fillMaxWidth(),
            )
            Button(
                onClick = { onSubmit(draft) },
                enabled = draft.isValid,
                modifier = Modifier.fillMaxWidth().testTag(AddressShippingTestTags.FORM_SUBMIT),
            ) {
                Text(stringResource(R.string.address_save))
            }
        }
    }
}
