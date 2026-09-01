@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.hr

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.model.hr.Employment
import com.testlogon.android.core.model.hr.HrMath
import com.testlogon.android.core.model.hr.Position
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState

/** HRM-009 — employment detail route. Arg is the STRING employment_id. */
@Composable
fun HrEmploymentDetailRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: HrEmploymentDetailViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    Scaffold(
        modifier = modifier.testTag("hr_employment_detail_screen"),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.hr_employment_detail_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.action_back))
                    }
                },
            )
        },
    ) { padding ->
        when (val s = state) {
            is HrEmploymentDetailUiState.Loading -> LoadingState(modifier = Modifier.padding(padding))
            is HrEmploymentDetailUiState.Unavailable -> EmptyState(
                title = stringResource(R.string.hr_unavailable_title),
                body = stringResource(R.string.hr_unavailable_body),
                modifier = Modifier.padding(padding),
            )
            is HrEmploymentDetailUiState.Error -> ErrorState(
                message = s.message,
                onRetry = viewModel::retry,
                modifier = Modifier.padding(padding),
            )
            is HrEmploymentDetailUiState.Content -> EmploymentDetailBody(
                employment = s.employment,
                position = s.position,
                modifier = Modifier.padding(padding),
            )
        }
    }
}

@Composable
private fun EmploymentDetailBody(employment: Employment, position: Position?, modifier: Modifier = Modifier) {
    val now = System.currentTimeMillis() / 1000L
    Column(modifier = modifier.fillMaxSize().verticalScroll(rememberScrollState())) {
        Field(stringResource(R.string.hr_field_status), employmentStatusLabel(employment.status))
        position?.let { Field(stringResource(R.string.hr_field_position), it.title.ifBlank { it.positionId }) }
        Field(stringResource(R.string.hr_field_party), employment.partyId.ifBlank { "—" })
        Field(stringResource(R.string.hr_field_org), employment.orgPartyId.ifBlank { "—" })
        Field(stringResource(R.string.hr_field_pay_rate), HrMath.payRateLabel(employment))
        Field(stringResource(R.string.hr_field_pay_period), payPeriodLabel(employment.payPeriod))
        HrMath.annualizedComp(employment)?.let {
            Field(stringResource(R.string.hr_field_annualized), HrMath.formatMoney(it))
        }
        Field(stringResource(R.string.hr_field_start), formatHrDate(employment.startDateEpochSeconds) ?: "—")
        Field(stringResource(R.string.hr_field_end), formatHrDate(employment.endDateEpochSeconds) ?: "—")
        HrMath.employmentTenureLabel(employment, now)?.let {
            Field(stringResource(R.string.hr_field_tenure), it)
        }
    }
}

@Composable
private fun Field(label: String, value: String) {
    ListItem(headlineContent = { Text(value) }, overlineContent = { Text(label) })
    HorizontalDivider()
}
