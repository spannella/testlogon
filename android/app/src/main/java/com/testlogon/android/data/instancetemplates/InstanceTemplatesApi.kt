package com.testlogon.android.data.instancetemplates

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import com.squareup.moshi.JsonDataException
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import retrofit2.Retrofit
import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * B7 Remote-Access: Instance Templates (browse + apply/launch + clone/delete). Mirrors the web
 * /remote/templates page (TemplateBrowserPage.tsx + api/endpoints/instanceTemplates.ts). Backend:
 * instance_templates.py, prefix /ui/remote/templates, require_ui_session (owner-scoped). Whole surface
 * is behind INSTANCE_TEMPLATES_ENABLED (default true; 400 -> disabled state), launch behind
 * TEMPLATE_LAUNCH_ENABLED (default true). Timestamps epoch SECONDS. Self-contained (Api + DTOs +
 * Repository + DI).
 */
interface InstanceTemplatesApi {

    @GET("ui/remote/templates")
    suspend fun list(): TemplateListDto

    @GET("ui/remote/templates/{id}")
    suspend fun get(@Path("id") templateId: String): TemplateDto

    @POST("ui/remote/templates/{id}/clone")
    suspend fun clone(@Path("id") templateId: String, @Body body: CloneTemplateReq): TemplateDto

    @POST("ui/remote/templates/{id}/launch")
    suspend fun launch(@Path("id") templateId: String, @Body body: LaunchFromTemplateReq): LaunchFromTemplateDto

    @DELETE("ui/remote/templates/{id}")
    suspend fun delete(@Path("id") templateId: String): OkDto
}

@JsonClass(generateAdapter = true)
data class TemplateDto(
    @Json(name = "template_id") val templateId: String = "",
    @Json(name = "name") val name: String = "",
    @Json(name = "description") val description: String = "",
    @Json(name = "category") val category: String = "custom",
    @Json(name = "target") val target: String = "ec2",
    @Json(name = "instance_type") val instanceType: String = "",
    @Json(name = "ami_id") val amiId: String = "",
    @Json(name = "k8s_image") val k8sImage: String = "",
    @Json(name = "k8s_preset") val k8sPreset: String = "",
    @Json(name = "startup_script") val startupScript: String = "",
    @Json(name = "ports") val ports: List<Int> = emptyList(),
    @Json(name = "tags") val tags: List<String> = emptyList(),
    @Json(name = "auto_terminate_after") val autoTerminateAfter: Int = 7200,
    @Json(name = "icon") val icon: String = "",
    @Json(name = "is_system") val isSystem: Boolean = false,
    @Json(name = "owner_sub") val ownerSub: String = "",
    @Json(name = "created_at") val createdAt: Long = 0L,
    @Json(name = "updated_at") val updatedAt: Long = 0L,
    @Json(name = "use_count") val useCount: Int = 0,
)

@JsonClass(generateAdapter = true)
data class TemplateListDto(
    @Json(name = "templates") val templates: List<TemplateDto> = emptyList(),
    @Json(name = "count") val count: Int = 0,
)

@JsonClass(generateAdapter = true)
data class CloneTemplateReq(
    @Json(name = "new_name") val newName: String,
)

@JsonClass(generateAdapter = true)
data class LaunchFromTemplateReq(
    @Json(name = "label") val label: String = "",
    @Json(name = "ssh_key_id") val sshKeyId: String? = null,
)

@JsonClass(generateAdapter = true)
data class TemplateLaunchInstanceDto(
    @Json(name = "instance_id") val instanceId: String = "",
    @Json(name = "label") val label: String = "",
    @Json(name = "instance_type") val instanceType: String = "",
    @Json(name = "ami_id") val amiId: String = "",
    @Json(name = "status") val status: String = "",
    @Json(name = "public_ip") val publicIp: String = "",
    @Json(name = "auto_terminate_after") val autoTerminateAfter: Int = 0,
)

@JsonClass(generateAdapter = true)
data class TemplateLaunchPodDto(
    @Json(name = "pod_id") val podId: String = "",
    @Json(name = "label") val label: String = "",
    @Json(name = "image") val image: String = "",
)

@JsonClass(generateAdapter = true)
data class LaunchFromTemplateDto(
    @Json(name = "target") val target: String = "",
    @Json(name = "template_id") val templateId: String = "",
    @Json(name = "resource_id") val resourceId: String = "",
    @Json(name = "instance") val instance: TemplateLaunchInstanceDto? = null,
    @Json(name = "pod") val pod: TemplateLaunchPodDto? = null,
)

@JsonClass(generateAdapter = true)
data class OkDto(
    @Json(name = "ok") val ok: Boolean = true,
)

interface InstanceTemplatesRepository {
    suspend fun list(): ApiResult<TemplateListDto>
    suspend fun clone(templateId: String, newName: String): ApiResult<TemplateDto>
    suspend fun launch(templateId: String, req: LaunchFromTemplateReq): ApiResult<LaunchFromTemplateDto>
    suspend fun delete(templateId: String): ApiResult<OkDto>
}

@Singleton
class DefaultInstanceTemplatesRepository @Inject constructor(
    private val api: InstanceTemplatesApi,
    private val errorParser: ApiErrorParser,
) : InstanceTemplatesRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun list(): ApiResult<TemplateListDto> = withContext(io) { call { api.list() } }

    override suspend fun clone(templateId: String, newName: String): ApiResult<TemplateDto> =
        withContext(io) { call { api.clone(templateId, CloneTemplateReq(newName)) } }

    override suspend fun launch(templateId: String, req: LaunchFromTemplateReq): ApiResult<LaunchFromTemplateDto> =
        withContext(io) { call { api.launch(templateId, req) } }

    override suspend fun delete(templateId: String): ApiResult<OkDto> =
        withContext(io) { call { api.delete(templateId) } }

    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: JsonDataException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }
}

@Module
@InstallIn(SingletonComponent::class)
object InstanceTemplatesApiModule {
    @Provides
    @Singleton
    fun provideInstanceTemplatesApi(retrofit: Retrofit): InstanceTemplatesApi =
        retrofit.create(InstanceTemplatesApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class InstanceTemplatesDataModule {
    @dagger.Binds
    @Singleton
    abstract fun bindInstanceTemplatesRepository(impl: DefaultInstanceTemplatesRepository): InstanceTemplatesRepository
}
