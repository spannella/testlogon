@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.crm

import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.testlogon.android.data.crm.CrmSalesMath

/**
 * CRM-AND-1 — create-lead dialog. Minimal MVP form (first / last / email required; company + source
 * optional). Uses an AlertDialog so it works without any new dependency.
 */
@Composable
fun CreateLeadSheet(
    submitting: Boolean,
    error: String?,
    onDismiss: () -> Unit,
    onSubmit: (first: String, last: String, email: String, company: String?, source: String?) -> Unit,
) {
    var first by remember { mutableStateOf("") }
    var last by remember { mutableStateOf("") }
    var email by remember { mutableStateOf("") }
    var company by remember { mutableStateOf("") }
    var source by remember { mutableStateOf("web_site") }

    AlertDialog(
        onDismissRequest = { if (!submitting) onDismiss() },
        title = { Text("New lead") },
        text = {
            Column(
                modifier = Modifier.verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                OutlinedTextField(first, { first = it }, label = { Text("First name") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(last, { last = it }, label = { Text("Last name") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(email, { email = it }, label = { Text("Email") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(company, { company = it }, label = { Text("Company (optional)") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                Text("Source", style = MaterialTheme.typography.labelMedium)
                SourceChips(selected = source, onSelected = { source = it })
                if (error != null) {
                    Text(error, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                }
            }
        },
        confirmButton = {
            TextButton(
                enabled = !submitting,
                onClick = { onSubmit(first, last, email, company, source) },
            ) {
                if (submitting) CircularProgressIndicator(modifier = Modifier.size(18.dp)) else Text("Create")
            }
        },
        dismissButton = { TextButton(enabled = !submitting, onClick = onDismiss) { Text("Cancel") } },
    )
}

private val LEAD_SOURCES = listOf("web_site", "cold_call", "email", "campaign", "trade_show", "word_of_mouth", "other")

@Composable
private fun SourceChips(selected: String, onSelected: (String) -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        LEAD_SOURCES.forEach { s ->
            FilterChip(
                selected = s == selected,
                onClick = { onSelected(s) },
                label = { Text(s.replace('_', ' ')) },
            )
        }
    }
}

/**
 * CRM-AND-1 — create-opportunity dialog. Name + amount required; stage chosen from the pipeline stages.
 * Close date defaults to +30 days (passed in by the caller as epoch seconds).
 */
@Composable
fun CreateOpportunitySheet(
    submitting: Boolean,
    error: String?,
    stageKeys: List<String>,
    defaultStage: String,
    onDismiss: () -> Unit,
    onSubmit: (name: String, stage: String, amountDollars: String) -> Unit,
) {
    var name by remember { mutableStateOf("") }
    var amount by remember { mutableStateOf("") }
    var stage by remember { mutableStateOf(defaultStage) }

    AlertDialog(
        onDismissRequest = { if (!submitting) onDismiss() },
        title = { Text("New opportunity") },
        text = {
            Column(
                modifier = Modifier.verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                OutlinedTextField(name, { name = it }, label = { Text("Name") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(amount, { amount = it }, label = { Text("Amount (USD)") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                Text("Stage", style = MaterialTheme.typography.labelMedium)
                Row(
                    modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    stageKeys.forEach { s ->
                        FilterChip(
                            selected = s == stage,
                            onClick = { stage = s },
                            label = { Text(CrmSalesMath.stageLabel(s)) },
                        )
                    }
                }
                if (error != null) {
                    Text(error, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                }
            }
        },
        confirmButton = {
            TextButton(enabled = !submitting, onClick = { onSubmit(name, stage, amount) }) {
                if (submitting) CircularProgressIndicator(modifier = Modifier.size(18.dp)) else Text("Create")
            }
        },
        dismissButton = { TextButton(enabled = !submitting, onClick = onDismiss) { Text("Cancel") } },
    )
}
