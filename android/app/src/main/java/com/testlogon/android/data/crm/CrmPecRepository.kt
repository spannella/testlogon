package com.testlogon.android.data.crm

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

// ── Aggregate results (each carries a module-disabled flag for degrade-on-404) ──

data class CrmProjectsPage(
    val projects: List<CrmProject>,
    val cursor: String?,
    val moduleDisabled: Boolean = false,
)

data class CrmProjectDetail(
    val project: CrmProject,
    val tasks: List<CrmProjectTask>,
    val members: List<CrmProjectMember> = emptyList(),
    val milestones: CrmMilestoneSummary? = null,
    val workload: CrmProjectWorkload? = null,
)

data class CrmEventsPage(
    val events: List<CrmEvent>,
    val cursor: String?,
    val moduleDisabled: Boolean = false,
)

data class CrmInviteesPage(
    val invitees: List<CrmInvitee>,
    val cursor: String?,
    val moduleDisabled: Boolean = false,
)

data class CrmRegistrationsPage(
    val registrations: List<CrmRegistration>,
    val cursor: String?,
    val moduleDisabled: Boolean = false,
)

data class CrmCampaignsPage(
    val campaigns: List<CrmCampaign>,
    val cursor: String?,
    val moduleDisabled: Boolean = false,
)

data class CrmCampaignDetail(
    val campaign: CrmCampaign,
    val attribution: CrmCampaignAttribution?,
)

data class CrmTemplatesResult(
    val templates: List<CrmProjectTemplate>,
    val cursor: String?,
    val moduleDisabled: Boolean = false,
)

// ───────────────────────────  PROJECTS  ──────────────────────────────

interface CrmProjectsRepository {
    suspend fun list(status: String? = null): ApiResult<CrmProjectsPage>
    suspend fun detail(projectId: String): ApiResult<CrmProjectDetail>
    suspend fun create(body: CrmProjectCreateInDto): ApiResult<CrmProject>

    // PRJ-002: project update / delete
    suspend fun update(projectId: String, body: CrmProjectUpdateInDto): ApiResult<CrmProject>
    suspend fun delete(projectId: String): ApiResult<Unit>

    // PRJ-003: tasks
    suspend fun createTask(projectId: String, body: CrmProjectTaskCreateInDto): ApiResult<CrmProjectTask>
    suspend fun getTask(projectId: String, taskId: String): ApiResult<CrmProjectTask>
    suspend fun updateTask(projectId: String, taskId: String, body: CrmProjectTaskUpdateInDto): ApiResult<CrmProjectTask>
    suspend fun deleteTask(projectId: String, taskId: String): ApiResult<Unit>
    suspend fun reorderTasks(projectId: String, taskIds: List<String>): ApiResult<List<CrmProjectTask>>

    // PRJ-004/005/009: workload / milestones / status history
    suspend fun workload(projectId: String): ApiResult<CrmProjectWorkload?>
    suspend fun milestoneSummary(projectId: String): ApiResult<CrmMilestoneSummary?>
    suspend fun statusHistory(projectId: String): ApiResult<List<CrmProjectStatusHistoryEntry>>

    // PRJ-007: members
    suspend fun listMembers(projectId: String): ApiResult<List<CrmProjectMember>>
    suspend fun addMember(projectId: String, userSub: String, role: String?): ApiResult<CrmProjectMember>
    suspend fun updateMemberRole(projectId: String, userSub: String, role: String): ApiResult<CrmProjectMember>
    suspend fun removeMember(projectId: String, userSub: String): ApiResult<Unit>

    // PRJ-010: contact links
    suspend fun listContactLinks(projectId: String): ApiResult<List<CrmProjectContactLink>>
    suspend fun addContactLink(projectId: String, entityId: String, entityType: String?, note: String?): ApiResult<CrmProjectContactLink>
    suspend fun removeContactLink(projectId: String, entityId: String): ApiResult<Unit>

    // PRJ-006: templates
    suspend fun listTemplates(): ApiResult<CrmTemplatesResult>
    suspend fun getTemplate(templateId: String): ApiResult<CrmProjectTemplate>
    suspend fun createTemplate(name: String, description: String?): ApiResult<CrmProjectTemplate>
    suspend fun createTemplateFromProject(projectId: String, name: String, description: String?): ApiResult<CrmProjectTemplate>
    suspend fun deleteTemplate(templateId: String): ApiResult<Unit>
    suspend fun instantiateTemplate(templateId: String, projectName: String, startDate: Long?): ApiResult<CrmProject>
}

@Singleton
class CrmProjectsRepositoryImpl @Inject constructor(
    private val api: CrmProjectsApi,
    private val errorParser: ApiErrorParser,
) : CrmProjectsRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun list(status: String?): ApiResult<CrmProjectsPage> = withContext(io) {
        when (val r = call { api.listProjects(status = status) }) {
            is ApiResult.Success -> ApiResult.Success(
                CrmProjectsPage(r.data.items.map { it.toDomain() }, r.data.cursor),
            )
            is ApiResult.Failure ->
                if (r.error.status == 404) ApiResult.Success(CrmProjectsPage(emptyList(), null, moduleDisabled = true))
                else r
            is ApiResult.NetworkError -> r
        }
    }

    override suspend fun detail(projectId: String): ApiResult<CrmProjectDetail> = withContext(io) {
        when (val proj = call { api.getProject(projectId).toDomain() }) {
            is ApiResult.Success -> {
                // Tasks / members / milestones / workload are best-effort; a failure or a
                // degraded (404) sub-resource renders an empty slice rather than failing the page.
                val tasks = (call { api.listTasks(projectId) } as? ApiResult.Success)
                    ?.data?.items?.map { it.toDomain() }?.sortedBy { it.taskOrder } ?: emptyList()
                val members = (call { api.listMembers(projectId) } as? ApiResult.Success)
                    ?.data?.items?.map { it.toDomain() } ?: emptyList()
                val milestones = (call { api.getMilestoneSummary(projectId) } as? ApiResult.Success)
                    ?.data?.toDomain()
                val workload = (call { api.getWorkload(projectId) } as? ApiResult.Success)
                    ?.data?.toDomain()
                ApiResult.Success(CrmProjectDetail(proj.data, tasks, members, milestones, workload))
            }
            is ApiResult.Failure -> proj
            is ApiResult.NetworkError -> proj
        }
    }

    override suspend fun create(body: CrmProjectCreateInDto): ApiResult<CrmProject> = withContext(io) {
        call { api.createProject(body).toDomain() }
    }

    override suspend fun update(projectId: String, body: CrmProjectUpdateInDto): ApiResult<CrmProject> =
        withContext(io) { call { api.updateProject(projectId, body).toDomain() } }

    override suspend fun delete(projectId: String): ApiResult<Unit> = withContext(io) {
        call { api.deleteProject(projectId) }
    }

    override suspend fun createTask(
        projectId: String,
        body: CrmProjectTaskCreateInDto,
    ): ApiResult<CrmProjectTask> = withContext(io) {
        call { api.createTask(projectId, body).toDomain() }
    }

    override suspend fun getTask(projectId: String, taskId: String): ApiResult<CrmProjectTask> =
        withContext(io) { call { api.getTask(projectId, taskId).toDomain() } }

    override suspend fun updateTask(
        projectId: String,
        taskId: String,
        body: CrmProjectTaskUpdateInDto,
    ): ApiResult<CrmProjectTask> = withContext(io) {
        call { api.updateTask(projectId, taskId, body).toDomain() }
    }

    override suspend fun deleteTask(projectId: String, taskId: String): ApiResult<Unit> =
        withContext(io) { call { api.deleteTask(projectId, taskId) } }

    override suspend fun reorderTasks(
        projectId: String,
        taskIds: List<String>,
    ): ApiResult<List<CrmProjectTask>> = withContext(io) {
        when (val res = call { api.reorderTasks(projectId, CrmProjectTaskReorderInDto(taskIds)) }) {
            is ApiResult.Success -> ApiResult.Success(res.data.items.map { it.toDomain() })
            is ApiResult.Failure -> res
            is ApiResult.NetworkError -> res
        }
    }

    override suspend fun workload(projectId: String): ApiResult<CrmProjectWorkload?> = withContext(io) {
        when (val res = call { api.getWorkload(projectId).toDomain() }) {
            is ApiResult.Success -> res
            is ApiResult.Failure -> if (res.error.status == 404) ApiResult.Success(null) else res
            is ApiResult.NetworkError -> res
        }
    }

    override suspend fun milestoneSummary(projectId: String): ApiResult<CrmMilestoneSummary?> = withContext(io) {
        when (val res = call { api.getMilestoneSummary(projectId).toDomain() }) {
            is ApiResult.Success -> res
            is ApiResult.Failure -> if (res.error.status == 404) ApiResult.Success(null) else res
            is ApiResult.NetworkError -> res
        }
    }

    override suspend fun statusHistory(projectId: String): ApiResult<List<CrmProjectStatusHistoryEntry>> =
        withContext(io) {
            when (val res = call { api.getStatusHistory(projectId) }) {
                is ApiResult.Success -> ApiResult.Success(res.data.items.map { it.toDomain() })
                is ApiResult.Failure -> if (res.error.status == 404) ApiResult.Success(emptyList()) else res
                is ApiResult.NetworkError -> res
            }
        }

    override suspend fun listMembers(projectId: String): ApiResult<List<CrmProjectMember>> = withContext(io) {
        when (val res = call { api.listMembers(projectId) }) {
            is ApiResult.Success -> ApiResult.Success(res.data.items.map { it.toDomain() })
            is ApiResult.Failure -> if (res.error.status == 404) ApiResult.Success(emptyList()) else res
            is ApiResult.NetworkError -> res
        }
    }

    override suspend fun addMember(
        projectId: String,
        userSub: String,
        role: String?,
    ): ApiResult<CrmProjectMember> = withContext(io) {
        call { api.addMember(projectId, CrmProjectAddMemberInDto(userSub = userSub, role = role?.ifBlank { null })).toDomain() }
    }

    override suspend fun updateMemberRole(
        projectId: String,
        userSub: String,
        role: String,
    ): ApiResult<CrmProjectMember> = withContext(io) {
        call { api.updateMemberRole(projectId, userSub, CrmProjectUpdateMemberInDto(role = role)).toDomain() }
    }

    override suspend fun removeMember(projectId: String, userSub: String): ApiResult<Unit> =
        withContext(io) { call { api.removeMember(projectId, userSub) } }

    override suspend fun listContactLinks(projectId: String): ApiResult<List<CrmProjectContactLink>> =
        withContext(io) {
            when (val res = call { api.listContactLinks(projectId) }) {
                is ApiResult.Success -> ApiResult.Success(res.data.items.map { it.toDomain() })
                is ApiResult.Failure -> if (res.error.status == 404) ApiResult.Success(emptyList()) else res
                is ApiResult.NetworkError -> res
            }
        }

    override suspend fun addContactLink(
        projectId: String,
        entityId: String,
        entityType: String?,
        note: String?,
    ): ApiResult<CrmProjectContactLink> = withContext(io) {
        call {
            api.addContactLink(
                projectId,
                CrmProjectAddContactLinkInDto(
                    linkedEntityId = entityId,
                    linkedEntityType = entityType?.ifBlank { null },
                    note = note?.ifBlank { null },
                ),
            ).toDomain()
        }
    }

    override suspend fun removeContactLink(projectId: String, entityId: String): ApiResult<Unit> =
        withContext(io) { call { api.removeContactLink(projectId, entityId) } }

    override suspend fun listTemplates(): ApiResult<CrmTemplatesResult> = withContext(io) {
        when (val res = call { api.listTemplates() }) {
            is ApiResult.Success -> ApiResult.Success(
                CrmTemplatesResult(res.data.items.map { it.toDomain() }, res.data.cursor),
            )
            is ApiResult.Failure ->
                if (res.error.status == 404) ApiResult.Success(CrmTemplatesResult(emptyList(), null, moduleDisabled = true))
                else res
            is ApiResult.NetworkError -> res
        }
    }

    override suspend fun getTemplate(templateId: String): ApiResult<CrmProjectTemplate> =
        withContext(io) { call { api.getTemplate(templateId).toDomain() } }

    override suspend fun createTemplate(name: String, description: String?): ApiResult<CrmProjectTemplate> =
        withContext(io) {
            call { api.createTemplate(CrmTemplateCreateInDto(name = name, description = description?.ifBlank { null })).toDomain() }
        }

    override suspend fun createTemplateFromProject(
        projectId: String,
        name: String,
        description: String?,
    ): ApiResult<CrmProjectTemplate> = withContext(io) {
        call {
            api.createTemplateFromProject(
                projectId,
                CrmTemplateFromProjectInDto(name = name, description = description?.ifBlank { null }),
            ).toDomain()
        }
    }

    override suspend fun deleteTemplate(templateId: String): ApiResult<Unit> =
        withContext(io) { call { api.deleteTemplate(templateId) } }

    override suspend fun instantiateTemplate(
        templateId: String,
        projectName: String,
        startDate: Long?,
    ): ApiResult<CrmProject> = withContext(io) {
        call {
            api.instantiateTemplate(
                templateId,
                CrmTemplateInstantiateInDto(projectName = projectName, startDate = startDate),
            ).toDomain()
        }
    }

    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = runCatchingApi(errorParser, block)
}

// ───────────────────────────  EVENTS  ────────────────────────────────

interface CrmEventsRepository {
    suspend fun list(): ApiResult<CrmEventsPage>
    suspend fun get(eventId: String): ApiResult<CrmEvent>
    suspend fun capacity(eventId: String): ApiResult<CrmEventCapacity?>
    suspend fun create(body: CrmEventCreateInDto): ApiResult<CrmEvent>

    // EVT-002 — event update + invitee management.
    suspend fun update(eventId: String, body: CrmEventUpdateInDto): ApiResult<CrmEvent>
    suspend fun addInvitee(eventId: String, inviteeSub: String): ApiResult<CrmInvitee>
    suspend fun removeInvitee(eventId: String, inviteeSub: String): ApiResult<Unit>
    suspend fun bulkImportInvitees(eventId: String, userSubs: List<String>): ApiResult<CrmBulkImportResult>
    suspend fun sendInvitations(eventId: String): ApiResult<CrmSendInvitationsResult>
    suspend fun listInvitees(eventId: String): ApiResult<CrmInviteesPage>

    // EVT-003 — registration / RSVP / check-in.
    suspend fun register(eventId: String): ApiResult<CrmRegistration>
    suspend fun respond(eventId: String, registrantSub: String, newStatus: String): ApiResult<CrmRegistration>
    suspend fun checkIn(eventId: String, registrantSub: String): ApiResult<CrmRegistration>
    suspend fun cancelRegistration(eventId: String, registrantSub: String): ApiResult<Unit>
    suspend fun listRegistrations(eventId: String): ApiResult<CrmRegistrationsPage>
}

@Singleton
class CrmEventsRepositoryImpl @Inject constructor(
    private val api: CrmEventsApi,
    private val errorParser: ApiErrorParser,
) : CrmEventsRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun list(): ApiResult<CrmEventsPage> = withContext(io) {
        when (val r = call { api.listEvents() }) {
            is ApiResult.Success -> ApiResult.Success(
                CrmEventsPage(r.data.events.map { it.toDomain() }, r.data.cursor),
            )
            is ApiResult.Failure ->
                if (r.error.status == 404) ApiResult.Success(CrmEventsPage(emptyList(), null, moduleDisabled = true))
                else r
            is ApiResult.NetworkError -> r
        }
    }

    override suspend fun get(eventId: String): ApiResult<CrmEvent> = withContext(io) {
        call { api.getEvent(eventId).toDomain() }
    }

    override suspend fun capacity(eventId: String): ApiResult<CrmEventCapacity?> = withContext(io) {
        when (val r = call { api.getCapacity(eventId).toDomain() }) {
            is ApiResult.Success -> r
            is ApiResult.Failure -> if (r.error.status == 404) ApiResult.Success(null) else r
            is ApiResult.NetworkError -> r
        }
    }

    override suspend fun create(body: CrmEventCreateInDto): ApiResult<CrmEvent> = withContext(io) {
        call { api.createEvent(body).toDomain() }
    }

    override suspend fun update(eventId: String, body: CrmEventUpdateInDto): ApiResult<CrmEvent> = withContext(io) {
        call { api.updateEvent(eventId, body).toDomain() }
    }

    override suspend fun addInvitee(eventId: String, inviteeSub: String): ApiResult<CrmInvitee> = withContext(io) {
        call { api.addInvitee(eventId, CrmInviteeAddInDto(inviteeSub = inviteeSub)).toDomain() }
    }

    override suspend fun removeInvitee(eventId: String, inviteeSub: String): ApiResult<Unit> = withContext(io) {
        call { api.removeInvitee(eventId, inviteeSub) }
    }

    override suspend fun bulkImportInvitees(
        eventId: String,
        userSubs: List<String>,
    ): ApiResult<CrmBulkImportResult> = withContext(io) {
        call { api.bulkImportInvitees(eventId, CrmInviteeBulkImportInDto(userSubs = userSubs)).toDomain() }
    }

    override suspend fun sendInvitations(eventId: String): ApiResult<CrmSendInvitationsResult> = withContext(io) {
        call { api.sendInvitations(eventId).toDomain() }
    }

    override suspend fun listInvitees(eventId: String): ApiResult<CrmInviteesPage> = withContext(io) {
        when (val r = call { api.listInvitees(eventId) }) {
            is ApiResult.Success -> ApiResult.Success(
                CrmInviteesPage(r.data.invitees.map { it.toDomain() }, r.data.cursor),
            )
            is ApiResult.Failure ->
                if (r.error.status == 404) ApiResult.Success(CrmInviteesPage(emptyList(), null, moduleDisabled = true))
                else r
            is ApiResult.NetworkError -> r
        }
    }

    override suspend fun register(eventId: String): ApiResult<CrmRegistration> = withContext(io) {
        call { api.registerForEvent(eventId).toDomain() }
    }

    override suspend fun respond(
        eventId: String,
        registrantSub: String,
        newStatus: String,
    ): ApiResult<CrmRegistration> = withContext(io) {
        call { api.respondToInvitation(eventId, registrantSub, CrmRespondInDto(newStatus = newStatus)).toDomain() }
    }

    override suspend fun checkIn(eventId: String, registrantSub: String): ApiResult<CrmRegistration> = withContext(io) {
        call { api.checkInAttendee(eventId, registrantSub).toDomain() }
    }

    override suspend fun cancelRegistration(eventId: String, registrantSub: String): ApiResult<Unit> = withContext(io) {
        call { api.cancelRegistration(eventId, registrantSub) }
    }

    override suspend fun listRegistrations(eventId: String): ApiResult<CrmRegistrationsPage> = withContext(io) {
        when (val r = call { api.listRegistrations(eventId) }) {
            is ApiResult.Success -> ApiResult.Success(
                CrmRegistrationsPage(r.data.registrations.map { it.toDomain() }, r.data.cursor),
            )
            is ApiResult.Failure ->
                if (r.error.status == 404) ApiResult.Success(CrmRegistrationsPage(emptyList(), null, moduleDisabled = true))
                else r
            is ApiResult.NetworkError -> r
        }
    }

    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = runCatchingApi(errorParser, block)
}

// ──────────────────────────  CAMPAIGNS  ──────────────────────────────

interface CrmCampaignsRepository {
    suspend fun list(status: String? = null): ApiResult<CrmCampaignsPage>
    suspend fun detail(campaignId: String): ApiResult<CrmCampaignDetail>
}

@Singleton
class CrmCampaignsRepositoryImpl @Inject constructor(
    private val api: CrmCampaignsApi,
    private val errorParser: ApiErrorParser,
) : CrmCampaignsRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun list(status: String?): ApiResult<CrmCampaignsPage> = withContext(io) {
        when (val r = call { api.listCampaigns(status = status) }) {
            is ApiResult.Success -> ApiResult.Success(
                CrmCampaignsPage(r.data.campaigns.map { it.toDomain() }, r.data.cursor),
            )
            is ApiResult.Failure ->
                if (r.error.status == 404) ApiResult.Success(CrmCampaignsPage(emptyList(), null, moduleDisabled = true))
                else r
            is ApiResult.NetworkError -> r
        }
    }

    override suspend fun detail(campaignId: String): ApiResult<CrmCampaignDetail> = withContext(io) {
        when (val camp = call { api.getCampaign(campaignId).toDomain() }) {
            is ApiResult.Success -> {
                // Attribution is best-effort (analytics can be off even when the campaign exists).
                val attribution = (call { api.getAttribution(campaignId).toDomain() } as? ApiResult.Success)?.data
                ApiResult.Success(CrmCampaignDetail(camp.data, attribution))
            }
            is ApiResult.Failure -> camp
            is ApiResult.NetworkError -> camp
        }
    }

    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = runCatchingApi(errorParser, block)
}

// ── Shared error-mapping helper (mirrors the LeadsRepository `call` body). ──
private suspend fun <T> runCatchingApi(
    errorParser: ApiErrorParser,
    block: suspend () -> T,
): ApiResult<T> = try {
    ApiResult.Success(block())
} catch (e: CancellationException) {
    throw e
} catch (e: HttpException) {
    ApiResult.Failure(errorParser.from(e))
} catch (e: IOException) {
    ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
}
