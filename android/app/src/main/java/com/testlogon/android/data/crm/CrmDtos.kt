package com.testlogon.android.data.crm

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/**
 * CRM-AND-1 — wire DTOs for the SuiteCRM Leads (/ui/leads) + Opportunities (/ui/sales) surfaces.
 *
 * Field names mirror the LIVE contract in frontend/src/api/endpoints/leads.ts +
 * frontend/src/api/endpoints/opportunities.ts (which themselves mirror the Pydantic models in
 * app/models.py). Every field is nullable / defaulted so a partial or drifted server body decodes
 * rather than throwing; unknown fields are ignored by Moshi.
 */

// ─────────────────────────────  LEADS  ─────────────────────────────

@JsonClass(generateAdapter = true)
data class LeadDto(
    @Json(name = "lead_id") val leadId: String = "",
    @Json(name = "first_name") val firstName: String = "",
    @Json(name = "last_name") val lastName: String = "",
    @Json(name = "email") val email: String = "",
    @Json(name = "phone") val phone: String? = null,
    @Json(name = "company") val company: String? = null,
    @Json(name = "title") val title: String? = null,
    @Json(name = "lead_source") val leadSource: String? = null,
    @Json(name = "description") val description: String? = null,
    @Json(name = "status") val status: String = "new",
    @Json(name = "assigned_to") val assignedTo: String? = null,
    @Json(name = "score") val score: Int = 0,
    @Json(name = "website") val website: String? = null,
    @Json(name = "created_by") val createdBy: String? = null,
    @Json(name = "created_at") val createdAt: Long = 0,
    @Json(name = "updated_at") val updatedAt: Long = 0,
    @Json(name = "converted_at") val convertedAt: Long? = null,
    @Json(name = "converted_party_id") val convertedPartyId: String? = null,
    @Json(name = "converted_org_id") val convertedOrgId: String? = null,
)

@JsonClass(generateAdapter = true)
data class LeadListRespDto(
    @Json(name = "leads") val leads: List<LeadDto> = emptyList(),
    @Json(name = "cursor") val cursor: String? = null,
)

@JsonClass(generateAdapter = true)
data class LeadCreateInDto(
    @Json(name = "first_name") val firstName: String,
    @Json(name = "last_name") val lastName: String,
    @Json(name = "email") val email: String,
    @Json(name = "phone") val phone: String? = null,
    @Json(name = "company") val company: String? = null,
    @Json(name = "title") val title: String? = null,
    @Json(name = "lead_source") val leadSource: String? = null,
    @Json(name = "description") val description: String? = null,
)

@JsonClass(generateAdapter = true)
data class LeadUpdateInDto(
    @Json(name = "status") val status: String? = null,
    @Json(name = "assigned_to") val assignedTo: String? = null,
    @Json(name = "score") val score: Int? = null,
    @Json(name = "description") val description: String? = null,
)

@JsonClass(generateAdapter = true)
data class LeadConversionInDto(
    @Json(name = "create_account") val createAccount: Boolean? = null,
    @Json(name = "account_name") val accountName: String? = null,
    @Json(name = "create_opportunity") val createOpportunity: Boolean? = null,
    @Json(name = "opportunity_name") val opportunityName: String? = null,
    @Json(name = "opportunity_amount_cents") val opportunityAmountCents: Long? = null,
)

@JsonClass(generateAdapter = true)
data class OpportunityStubDto(
    @Json(name = "opportunity_id") val opportunityId: String = "",
    @Json(name = "name") val name: String = "",
    @Json(name = "amount_cents") val amountCents: Long = 0,
    @Json(name = "currency") val currency: String = "USD",
    @Json(name = "stage") val stage: String = "prospecting",
    @Json(name = "created_at") val createdAt: Long = 0,
)

@JsonClass(generateAdapter = true)
data class LeadConversionResultDto(
    @Json(name = "lead_id") val leadId: String = "",
    @Json(name = "status") val status: String = "converted",
    @Json(name = "converted_party_id") val convertedPartyId: String? = null,
    @Json(name = "converted_org_id") val convertedOrgId: String? = null,
    @Json(name = "opportunity") val opportunity: OpportunityStubDto? = null,
    @Json(name = "converted_at") val convertedAt: Long = 0,
)

@JsonClass(generateAdapter = true)
data class LeadScoreResultDto(
    @Json(name = "lead_id") val leadId: String = "",
    @Json(name = "score") val score: Int = 0,
    @Json(name = "computed_at") val computedAt: Long = 0,
    @Json(name = "trigger") val trigger: String? = null,
)

@JsonClass(generateAdapter = true)
data class LeadActivityDto(
    @Json(name = "activity_id") val activityId: String = "",
    @Json(name = "lead_id") val leadId: String = "",
    @Json(name = "activity_type") val activityType: String = "note",
    @Json(name = "subject") val subject: String? = null,
    @Json(name = "description") val description: String? = null,
    @Json(name = "actor_sub") val actorSub: String? = null,
    @Json(name = "created_at") val createdAt: Long = 0,
)

@JsonClass(generateAdapter = true)
data class LeadActivityListRespDto(
    @Json(name = "activities") val activities: List<LeadActivityDto> = emptyList(),
    @Json(name = "cursor") val cursor: String? = null,
)

@JsonClass(generateAdapter = true)
data class LeadLogActivityInDto(
    @Json(name = "activity_type") val activityType: String,
    @Json(name = "subject") val subject: String? = null,
    @Json(name = "description") val description: String? = null,
)

// ─────────────────────────  OPPORTUNITIES  ─────────────────────────

@JsonClass(generateAdapter = true)
data class OpportunityOutDto(
    @Json(name = "opp_id") val oppId: String = "",
    @Json(name = "owner_sub") val ownerSub: String? = null,
    @Json(name = "name") val name: String = "",
    @Json(name = "stage") val stage: String = "prospecting",
    @Json(name = "amount_cents") val amountCents: Long = 0,
    @Json(name = "weighted_amount_cents") val weightedAmountCents: Long = 0,
    @Json(name = "close_date") val closeDate: Long = 0,
    @Json(name = "probability") val probability: Int = 0,
    @Json(name = "lead_source") val leadSource: String? = null,
    @Json(name = "description") val description: String? = null,
    @Json(name = "account_party_id") val accountPartyId: String? = null,
    @Json(name = "contact_party_id") val contactPartyId: String? = null,
    @Json(name = "created_at") val createdAt: Long = 0,
    @Json(name = "updated_at") val updatedAt: Long = 0,
)

@JsonClass(generateAdapter = true)
data class OpportunityListRespDto(
    @Json(name = "items") val items: List<OpportunityOutDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
)

@JsonClass(generateAdapter = true)
data class OpportunityCreateInDto(
    @Json(name = "name") val name: String,
    @Json(name = "stage") val stage: String,
    @Json(name = "amount_cents") val amountCents: Long,
    @Json(name = "close_date") val closeDate: Long,
    @Json(name = "probability") val probability: Int? = null,
    @Json(name = "lead_source") val leadSource: String? = null,
    @Json(name = "description") val description: String? = null,
)

@JsonClass(generateAdapter = true)
data class OpportunityUpdateInDto(
    @Json(name = "stage") val stage: String? = null,
    @Json(name = "amount_cents") val amountCents: Long? = null,
    @Json(name = "probability") val probability: Int? = null,
    @Json(name = "close_date") val closeDate: Long? = null,
    @Json(name = "name") val name: String? = null,
    @Json(name = "description") val description: String? = null,
)

@JsonClass(generateAdapter = true)
data class StageConfigItemOutDto(
    @Json(name = "stage_key") val stageKey: String = "",
    @Json(name = "label") val label: String = "",
    @Json(name = "probability_default") val probabilityDefault: Int = 0,
    @Json(name = "order") val order: Int = 0,
    @Json(name = "is_won") val isWon: Boolean = false,
    @Json(name = "is_lost") val isLost: Boolean = false,
    @Json(name = "color") val color: String? = null,
)

@JsonClass(generateAdapter = true)
data class StageConfigOutDto(
    @Json(name = "stages") val stages: List<StageConfigItemOutDto> = emptyList(),
    @Json(name = "updated_at") val updatedAt: Long? = null,
)

@JsonClass(generateAdapter = true)
data class FeatureStatusDto(
    @Json(name = "enabled") val enabled: Boolean = false,
)
