package com.testlogon.android.feature.billing

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.CreditCard
import androidx.compose.material.icons.outlined.Delete
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.input.TlButton
import com.testlogon.android.core.ui.i18n.asString
import com.testlogon.android.core.ui.i18n.resolve
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.billing.CardBrand
import com.testlogon.android.data.billing.PaymentMethod
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.emptyFlow

/** Stable testTags for the Payment Methods screen (AND-224). */
object PaymentMethodsTestTags {
    const val SCREEN = "payment_methods_screen"
    const val LIST = "payment_methods_list"
    const val ROW = "payment_methods_row"
    const val ADD = "payment_methods_add"
    const val SET_DEFAULT = "payment_methods_set_default"
    const val REMOVE = "payment_methods_remove"
    const val EMPTY = "payment_methods_empty"
    const val ERROR = "payment_methods_error"
    const val ROW_SPINNER = "payment_methods_row_spinner"
}

/** AND-224 — route-level Payment Methods entry, reached from the More hub. */
@Composable
fun PaymentMethodsRoute(
    onBack: () -> Unit,
    onAddCard: () -> Unit,
    modifier: Modifier = Modifier,
    // PW14 — a one-shot signal (true) emitted by the add-card flow on return so the list refreshes
    // IMMEDIATELY (not only on the next ON_RESUME). Defaulted off so other callers are unaffected.
    refreshSignal: Flow<Boolean> = emptyFlow(),
    onRefreshSignalConsumed: () -> Unit = {},
    viewModel: PaymentMethodsViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }

    // PW14 — when the add-card flow signals a freshly-added method, force a refresh right away and
    // clear the signal so a later return doesn't re-trigger it. This is the reliable path; the
    // ON_RESUME re-fetch below is kept only as a backstop.
    val added by refreshSignal.collectAsStateWithLifecycle(initialValue = false)
    LaunchedEffect(added) {
        if (added) {
            viewModel.refresh()
            onRefreshSignalConsumed()
        }
    }

    // Re-fetch when returning to this screen (e.g. after adding a method) so the list stays fresh.
    // Skip the very first resume — the ViewModel's init already performs the initial load.
    val firstResume = remember { mutableStateOf(true) }
    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) {
        if (firstResume.value) firstResume.value = false else viewModel.refresh()
    }

    val removedMsg = stringResource(R.string.payment_methods_removed)
    val defaultMsg = stringResource(R.string.payment_methods_default_set)
    val resources = LocalContext.current.resources
    LaunchedEffect(Unit) {
        viewModel.events.collect { event ->
            val message = when (event) {
                is PaymentMethodsEvent.Removed -> removedMsg
                is PaymentMethodsEvent.DefaultSet -> defaultMsg
                is PaymentMethodsEvent.Failure -> event.message.resolve(resources)
            }
            snackbarHostState.showSnackbar(message)
        }
    }

    PaymentMethodsScreen(
        state = state,
        snackbarHostState = snackbarHostState,
        onAdd = onAddCard,
        onSetDefault = viewModel::setDefault,
        onRemove = viewModel::remove,
        onRetry = viewModel::retry,
        onBack = onBack,
        modifier = modifier,
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PaymentMethodsScreen(
    state: PaymentMethodsUiState,
    snackbarHostState: SnackbarHostState,
    onAdd: () -> Unit,
    onSetDefault: (String) -> Unit,
    onRemove: (String) -> Unit,
    onRetry: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    var pendingRemoval by remember { mutableStateOf<PaymentMethod?>(null) }

    Scaffold(
        modifier = modifier.testTag(PaymentMethodsTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.payment_methods_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack, modifier = Modifier.testTag("payment_methods_back")) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            when (val load = state.load) {
                is PaymentMethodsLoadState.Loading -> LoadingState()

                is PaymentMethodsLoadState.Error -> ErrorState(
                    message = load.message.asString(),
                    onRetry = onRetry,
                    modifier = Modifier.testTag(PaymentMethodsTestTags.ERROR),
                )

                is PaymentMethodsLoadState.Loaded ->
                    if (load.methods.isEmpty()) {
                        EmptyState(
                            title = stringResource(R.string.payment_methods_empty_title),
                            body = stringResource(R.string.payment_methods_empty_body),
                            imageVector = Icons.Outlined.CreditCard,
                            actionLabel = stringResource(R.string.payment_methods_add),
                            onAction = onAdd,
                            modifier = Modifier.testTag(PaymentMethodsTestTags.EMPTY),
                        )
                    } else {
                        PaymentMethodsList(
                            methods = load.methods,
                            rowInFlight = state.rowInFlight,
                            onAdd = onAdd,
                            onSetDefault = onSetDefault,
                            onRemove = { pendingRemoval = it },
                        )
                    }
            }
        }
    }

    pendingRemoval?.let { method ->
        AlertDialog(
            onDismissRequest = { pendingRemoval = null },
            title = { Text(stringResource(R.string.payment_methods_remove_confirm_title)) },
            text = { Text(stringResource(R.string.payment_methods_remove_confirm_body, method.displayLabel())) },
            confirmButton = {
                TextButton(onClick = {
                    onRemove(method.id)
                    pendingRemoval = null
                }) { Text(stringResource(R.string.payment_methods_remove)) }
            },
            dismissButton = {
                TextButton(onClick = { pendingRemoval = null }) {
                    Text(stringResource(R.string.action_cancel))
                }
            },
        )
    }
}

@Composable
private fun PaymentMethodsList(
    methods: List<PaymentMethod>,
    rowInFlight: Set<String>,
    onAdd: () -> Unit,
    onSetDefault: (String) -> Unit,
    onRemove: (PaymentMethod) -> Unit,
) {
    LazyColumn(
        modifier = Modifier.fillMaxSize().testTag(PaymentMethodsTestTags.LIST),
    ) {
        items(items = methods, key = { it.id }) { method ->
            PaymentMethodRow(
                method = method,
                inFlight = method.id in rowInFlight,
                onSetDefault = { onSetDefault(method.id) },
                onRemove = { onRemove(method) },
            )
            HorizontalDivider()
        }
        item {
            Box(Modifier.fillMaxWidth().padding(16.dp), contentAlignment = Alignment.Center) {
                TlButton(
                    text = stringResource(R.string.payment_methods_add),
                    onClick = onAdd,
                    modifier = Modifier.testTag(PaymentMethodsTestTags.ADD),
                )
            }
        }
    }
}

@Composable
private fun PaymentMethodRow(
    method: PaymentMethod,
    inFlight: Boolean,
    onSetDefault: () -> Unit,
    onRemove: () -> Unit,
) {
    val label = method.displayLabel()
    val expiry = method.expiryLabel()
    val rowCd = stringResource(
        R.string.payment_methods_row_cd,
        label,
        if (method.isDefault) ", " + stringResource(R.string.payment_methods_default_badge) else "",
    )
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 56.dp)
            .padding(horizontal = 16.dp, vertical = 12.dp)
            .testTag(PaymentMethodsTestTags.ROW),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(Icons.Outlined.CreditCard, contentDescription = null, modifier = Modifier.size(32.dp))
        Column(
            modifier = Modifier
                .weight(1f)
                .padding(start = 12.dp)
                .clearAndSetSemantics { contentDescription = rowCd },
            verticalArrangement = Arrangement.spacedBy(2.dp),
        ) {
            Text(label, style = MaterialTheme.typography.titleSmall)
            if (expiry != null) {
                Text(
                    expiry,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        if (inFlight) {
            CircularProgressIndicator(
                modifier = Modifier.size(24.dp).testTag(PaymentMethodsTestTags.ROW_SPINNER),
            )
        } else if (method.isDefault) {
            AssistChip(
                onClick = {},
                enabled = false,
                label = { Text(stringResource(R.string.payment_methods_default_badge)) },
            )
        } else {
            TextButton(onClick = onSetDefault, modifier = Modifier.testTag(PaymentMethodsTestTags.SET_DEFAULT)) {
                Text(stringResource(R.string.payment_methods_set_default))
            }
        }
        Spacer(Modifier.width(4.dp))
        IconButton(
            onClick = onRemove,
            enabled = !inFlight,
            modifier = Modifier.testTag(PaymentMethodsTestTags.REMOVE),
        ) {
            Icon(
                Icons.Outlined.Delete,
                contentDescription = stringResource(R.string.payment_methods_remove) + " " + label,
            )
        }
    }
}

@Composable
private fun PaymentMethod.displayLabel(): String {
    val brandText = label ?: rawBrand?.replaceFirstChar { it.uppercase() }
        ?: this.brand.takeIf { it != CardBrand.UNKNOWN }?.name?.lowercase()?.replaceFirstChar { it.uppercase() }
        ?: methodType.replace('_', ' ').replaceFirstChar { it.uppercase() }
    return if (last4 != null) {
        stringResource(R.string.payment_methods_card_label, brandText, last4)
    } else {
        stringResource(R.string.payment_methods_card_no_last4, brandText)
    }
}

@Composable
private fun PaymentMethod.expiryLabel(): String? {
    val month = expMonth ?: return null
    val year = expYear ?: return null
    return stringResource(R.string.payment_methods_expiry, month, year)
}
