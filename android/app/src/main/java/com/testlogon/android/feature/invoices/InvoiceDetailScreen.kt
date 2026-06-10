@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.invoices

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Email
import androidx.compose.material.icons.outlined.PictureAsPdf
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.i18n.asString
import com.testlogon.android.core.ui.i18n.resolve
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.invoices.InvoiceDetail
import com.testlogon.android.data.invoices.InvoiceLineItem
import com.testlogon.android.data.invoices.InvoiceStatus

/** AND-243 — stable testTags for the invoice detail screen. */
object InvoiceDetailTestTags {
    const val SCREEN = "invoice_detail_screen"
    const val CONTENT = "invoice_detail_content"
    const val ERROR = "invoice_detail_error"
    const val LINE_ITEM = "invoice_line_item"
    const val TOTAL = "invoice_total"
    const val EMAIL_BUTTON = "invoice_email_button"
    const val PDF_BUTTON = "invoice_pdf_button"
}

/** AND-243 — route-level invoice detail entry. Opens the PDF via the Custom Tabs [InvoicePdfLauncher]. */
@Composable
fun InvoiceDetailRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: InvoiceDetailViewModel = hiltViewModel(),
    pdfLauncher: InvoicePdfLauncher = remember { CustomTabsInvoicePdfLauncher() },
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val emailState by viewModel.emailState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    val context = LocalContext.current

    LaunchedEffect(Unit) {
        viewModel.events.collect { event ->
            when (event) {
                is InvoiceDetailEvent.ViewPdf -> pdfLauncher.launch(context, event.url)
            }
        }
    }

    // Resolve email feedback to a snackbar, then reset the email state so a later tap starts fresh.
    val sentNoRecipient = stringResource(R.string.invoices_email_sent_generic)
    val sentTemplate = stringResource(R.string.invoices_email_sent_to)
    val resources = androidx.compose.ui.platform.LocalContext.current.resources
    LaunchedEffect(emailState) {
        when (val es = emailState) {
            is EmailUiState.Sent -> {
                val msg = if (es.emailedTo.isBlank()) sentNoRecipient else sentTemplate.format(es.emailedTo)
                snackbarHostState.showSnackbar(msg)
                viewModel.onEmailFeedbackShown()
            }
            is EmailUiState.Error -> {
                snackbarHostState.showSnackbar(es.message.resolve(resources))
                viewModel.onEmailFeedbackShown()
            }
            else -> Unit
        }
    }

    InvoiceDetailScreen(
        state = state,
        emailState = emailState,
        snackbarHostState = snackbarHostState,
        onEmail = viewModel::onEmailClicked,
        onViewPdf = viewModel::onViewPdfClicked,
        onRetry = viewModel::retry,
        onBack = onBack,
        modifier = modifier,
    )
}

@Composable
fun InvoiceDetailScreen(
    state: InvoiceDetailUiState,
    emailState: EmailUiState,
    snackbarHostState: SnackbarHostState,
    onEmail: () -> Unit,
    onViewPdf: () -> Unit,
    onRetry: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(InvoiceDetailTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.invoice_detail_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack, modifier = Modifier.testTag("invoice_detail_back")) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            when (state) {
                is InvoiceDetailUiState.Loading ->
                    LoadingState(message = stringResource(R.string.invoice_detail_loading))

                is InvoiceDetailUiState.Error ->
                    ErrorState(
                        message = state.message.asString(),
                        onRetry = if (state.retryable) onRetry else ({}),
                        modifier = Modifier.testTag(InvoiceDetailTestTags.ERROR),
                    )

                is InvoiceDetailUiState.Content ->
                    InvoiceDetailContent(
                        invoice = state.invoice,
                        emailState = emailState,
                        onEmail = onEmail,
                        onViewPdf = onViewPdf,
                    )
            }
        }
    }
}

@Composable
private fun InvoiceDetailContent(
    invoice: InvoiceDetail,
    emailState: EmailUiState,
    onEmail: () -> Unit,
    onViewPdf: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp)
            .testTag(InvoiceDetailTestTags.CONTENT),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(invoice.invoiceNumber, style = MaterialTheme.typography.titleLarge)
        val dateText = formatInvoiceDate(invoice.createdAtEpochSeconds)
            ?: stringResource(R.string.invoices_date_unknown)
        Text(
            text = "$dateText · ${invoice.invoiceType}",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        if (invoice.status == InvoiceStatus.EMAILED) {
            Text(
                text = stringResource(R.string.invoices_status_emailed),
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.primary,
            )
        }
        if (invoice.sellerName.isNotBlank()) {
            LabelValue(stringResource(R.string.invoice_detail_seller), invoice.sellerName)
        }
        if (invoice.buyerName.isNotBlank() || invoice.buyerEmail.isNotBlank()) {
            val buyer = listOf(invoice.buyerName, invoice.buyerEmail).filter { it.isNotBlank() }.joinToString(" · ")
            LabelValue(stringResource(R.string.invoice_detail_buyer), buyer)
        }
        if (invoice.paymentMethodSummary.isNotBlank()) {
            LabelValue(stringResource(R.string.invoice_detail_payment_method), invoice.paymentMethodSummary)
        }

        HorizontalDivider()

        invoice.lineItems.forEach { item -> LineItemRow(item) }

        HorizontalDivider()

        AmountRow(stringResource(R.string.invoice_detail_subtotal), formatInvoiceMoney(invoice.amount))
        AmountRow(stringResource(R.string.invoice_detail_tax), formatInvoiceMoney(invoice.tax))
        AmountRow(
            label = stringResource(R.string.invoice_detail_total),
            value = formatInvoiceMoney(invoice.total),
            emphasize = true,
            modifier = Modifier.testTag(InvoiceDetailTestTags.TOTAL),
        )

        val sending = emailState is EmailUiState.Sending
        Button(
            onClick = onEmail,
            enabled = !sending,
            modifier = Modifier.fillMaxWidth().testTag(InvoiceDetailTestTags.EMAIL_BUTTON),
        ) {
            if (sending) {
                CircularProgressIndicator(
                    modifier = Modifier.width(18.dp),
                    strokeWidth = 2.dp,
                    color = MaterialTheme.colorScheme.onPrimary,
                )
                Spacer(Modifier.width(8.dp))
                Text(stringResource(R.string.invoices_email_sending))
            } else {
                Icon(Icons.Outlined.Email, contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text(stringResource(R.string.invoices_email_action))
            }
        }
        OutlinedButton(
            onClick = onViewPdf,
            modifier = Modifier.fillMaxWidth().testTag(InvoiceDetailTestTags.PDF_BUTTON),
        ) {
            Icon(Icons.Outlined.PictureAsPdf, contentDescription = null)
            Spacer(Modifier.width(8.dp))
            Text(stringResource(R.string.invoices_pdf_action))
        }
    }
}

@Composable
private fun LineItemRow(item: InvoiceLineItem) {
    Row(
        modifier = Modifier.fillMaxWidth().testTag(InvoiceDetailTestTags.LINE_ITEM),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(item.description, style = MaterialTheme.typography.bodyMedium)
            if (item.quantity != 1) {
                Text(
                    text = stringResource(R.string.invoice_detail_quantity, item.quantity),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        Text(formatInvoiceMoney(item.amount), style = MaterialTheme.typography.bodyMedium)
    }
}

@Composable
private fun AmountRow(
    label: String,
    value: String,
    modifier: Modifier = Modifier,
    emphasize: Boolean = false,
) {
    val style = if (emphasize) MaterialTheme.typography.titleMedium else MaterialTheme.typography.bodyMedium
    Row(
        modifier = modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(label, style = style, fontWeight = if (emphasize) FontWeight.Bold else null)
        Text(value, style = style, fontWeight = if (emphasize) FontWeight.Bold else null)
    }
}

@Composable
private fun LabelValue(label: String, value: String) {
    Column {
        Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, style = MaterialTheme.typography.bodyMedium)
    }
}
