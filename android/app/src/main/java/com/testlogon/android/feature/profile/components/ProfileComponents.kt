package com.testlogon.android.feature.profile.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.testlogon.android.R
import com.testlogon.android.core.model.profile.ProfileLanguage
import com.testlogon.android.feature.profile.ProfileTestTags

/**
 * AND-071 / AND-073 — reusable identity header (display name, title, location, description). Empty
 * optional fields are simply omitted, never rendered as blank rows. Shared by the own- and
 * public-profile screens.
 */
@Composable
fun ProfileHeader(
    displayName: String?,
    title: String?,
    location: String?,
    description: String?,
    modifier: Modifier = Modifier,
    fallbackName: String? = null,
) {
    Column(
        modifier = modifier.fillMaxWidth(),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        val name = displayName ?: fallbackName
        if (!name.isNullOrBlank()) {
            Text(
                text = name,
                style = MaterialTheme.typography.headlineSmall,
                textAlign = TextAlign.Center,
                modifier = Modifier.testTag(ProfileTestTags.OWN_DISPLAY_NAME),
            )
        }
        if (!title.isNullOrBlank()) {
            Text(
                text = title,
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
            )
        }
        if (!location.isNullOrBlank()) {
            Text(
                text = location,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
            )
        }
        if (!description.isNullOrBlank()) {
            Text(
                text = description,
                style = MaterialTheme.typography.bodyMedium,
                textAlign = TextAlign.Center,
                modifier = Modifier.testTag(ProfileTestTags.OWN_DESCRIPTION),
            )
        }
    }
}

/** Contact / language rows; each section hidden when empty. */
@Composable
fun ProfileDetailRows(
    email: String?,
    phone: String?,
    languages: List<ProfileLanguage>,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        if (!email.isNullOrBlank()) {
            LabeledRow(label = stringResource(R.string.profile_email_label), value = email)
        }
        if (!phone.isNullOrBlank()) {
            LabeledRow(label = stringResource(R.string.profile_phone_label), value = phone)
        }
        if (languages.isNotEmpty()) {
            LabeledRow(
                label = stringResource(R.string.profile_languages_label),
                value = languages.joinToString(", ") { lang ->
                    if (lang.level.isBlank()) lang.name else "${lang.name} (${lang.level})"
                },
            )
        }
    }
}

@Composable
private fun LabeledRow(label: String, value: String) {
    Column(modifier = Modifier.fillMaxWidth()) {
        Text(
            text = label,
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(text = value, style = MaterialTheme.typography.bodyMedium)
    }
}
