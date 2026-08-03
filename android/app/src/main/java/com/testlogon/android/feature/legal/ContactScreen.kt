@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.legal

import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.compose.material.icons.outlined.Email
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.testlogon.android.R

/**
 * PAR-29 — the Contact screen. Static support copy + a button that opens the device email client via
 * ACTION_SENDTO (mailto:) pre-addressed to the support email. Mirrors the iOS Contact page.
 */
@Composable
fun ContactScreen(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current
    val subject = stringResource(R.string.legal_contact_email_subject)
    Scaffold(
        modifier = modifier.testTag("contact_screen"),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.legal_contact_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack, modifier = Modifier.testTag("contact_back")) {
                        Icon(
                            Icons.AutoMirrored.Outlined.ArrowBack,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier.fillMaxSize().padding(padding).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Text(
                text = stringResource(R.string.legal_contact_body),
                style = MaterialTheme.typography.bodyMedium,
            )
            Text(
                text = LegalConstants.SUPPORT_EMAIL,
                style = MaterialTheme.typography.titleMedium,
                modifier = Modifier.testTag("contact_email"),
            )
            Button(
                onClick = {
                    val intent = Intent(Intent.ACTION_SENDTO).apply {
                        data = Uri.parse("mailto:${LegalConstants.SUPPORT_EMAIL}")
                        putExtra(Intent.EXTRA_SUBJECT, subject)
                    }
                    runCatching { context.startActivity(intent) }
                },
                modifier = Modifier.fillMaxWidth().testTag("contact_email_button"),
            ) {
                Icon(Icons.Outlined.Email, contentDescription = null)
                Text(
                    text = stringResource(R.string.legal_contact_email_cta),
                    modifier = Modifier.padding(start = 8.dp),
                )
            }
        }
    }
}
