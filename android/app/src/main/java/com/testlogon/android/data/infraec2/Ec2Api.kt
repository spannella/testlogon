package com.testlogon.android.data.infraec2

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
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * B7 Cloud-Infra: EC2 Instance Launcher (management screen). Mirrors the web /remote/ec2 page
 * (Ec2LauncherPage.tsx + api/endpoints/ec2.ts). Backend: ec2_launcher.py, prefix /ui/remote/ec2,
 * gated by require_ui_session (owner-scoped, NOT admin — but this app surfaces it in the operator/Infra
 * hub). Timestamps are epoch SECONDS. Self-contained (Api + DTOs + Repository + DI) per the B5 fraud
 * data-layer pattern. NO new endpoint module / migration / dependency.
 */
interface Ec2Api {

    @GET("ui/remote/ec2/instance-types")
    suspend fun instanceTypes(): Ec2InstanceTypeListDto

    @GET("ui/remote/ec2/amis")
    suspend fun amis(): Ec2AmiListDto

    @POST("ui/remote/ec2/launch")
    suspend fun launch(@Body body: Ec2LaunchReq): Ec2InstanceDto

    @GET("ui/remote/ec2/instances")
    suspend fun instances(@Query("status") status: String? = null): Ec2InstanceListDto

    @GET("ui/remote/ec2/instances/{id}")
    suspend fun instance(@Path("id") instanceId: String): Ec2InstanceDto

    @POST("ui/remote/ec2/instances/{id}/start")
    suspend fun start(@Path("id") instanceId: String): Ec2InstanceDto

    @POST("ui/remote/ec2/instances/{id}/stop")
    suspend fun stop(@Path("id") instanceId: String): Ec2InstanceDto

    @POST("ui/remote/ec2/instances/{id}/reboot")
    suspend fun reboot(@Path("id") instanceId: String): Ec2InstanceDto

    @POST("ui/remote/ec2/instances/{id}/terminate")
    suspend fun terminate(@Path("id") instanceId: String): Ec2InstanceDto
}

@JsonClass(generateAdapter = true)
data class Ec2InstanceDto(
    @Json(name = "instance_id") val instanceId: String = "",
    @Json(name = "ec2_instance_id") val ec2InstanceId: String = "",
    @Json(name = "label") val label: String = "",
    @Json(name = "instance_type") val instanceType: String = "",
    @Json(name = "ami_id") val amiId: String = "",
    @Json(name = "ami_name") val amiName: String = "",
    @Json(name = "status") val status: String = "",
    @Json(name = "public_ip") val publicIp: String = "",
    @Json(name = "private_ip") val privateIp: String = "",
    @Json(name = "ssh_key_id") val sshKeyId: String = "",
    @Json(name = "host_id") val hostId: String = "",
    @Json(name = "created_at") val createdAt: Long = 0L,
    @Json(name = "auto_terminate_after") val autoTerminateAfter: Long = 7200L,
)

@JsonClass(generateAdapter = true)
data class Ec2InstanceListDto(
    @Json(name = "instances") val instances: List<Ec2InstanceDto> = emptyList(),
    @Json(name = "count") val count: Int = 0,
)

@JsonClass(generateAdapter = true)
data class Ec2InstanceTypeDto(
    @Json(name = "instance_type") val instanceType: String = "",
    @Json(name = "vcpu") val vcpu: Int = 0,
    @Json(name = "memory_gb") val memoryGb: Double = 0.0,
    @Json(name = "cost_cents_per_min") val costCentsPerMin: Double = 0.0,
    @Json(name = "description") val description: String = "",
)

@JsonClass(generateAdapter = true)
data class Ec2InstanceTypeListDto(
    @Json(name = "types") val types: List<Ec2InstanceTypeDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class Ec2AmiDto(
    @Json(name = "ami_id") val amiId: String = "",
    @Json(name = "name") val name: String = "",
    @Json(name = "os_type") val osType: String = "",
    @Json(name = "username") val username: String = "",
)

@JsonClass(generateAdapter = true)
data class Ec2AmiListDto(
    @Json(name = "amis") val amis: List<Ec2AmiDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class Ec2LaunchReq(
    @Json(name = "label") val label: String,
    @Json(name = "instance_type") val instanceType: String,
    @Json(name = "ami_id") val amiId: String,
    @Json(name = "auto_terminate_after") val autoTerminateAfter: Int = 7200,
    @Json(name = "ssh_key_id") val sshKeyId: String? = null,
    @Json(name = "security_group_id") val securityGroupId: String? = null,
)

interface Ec2Repository {
    suspend fun reference(): ApiResult<Ec2Reference>
    suspend fun list(status: String?): ApiResult<Ec2InstanceListDto>
    suspend fun launch(req: Ec2LaunchReq): ApiResult<Ec2InstanceDto>
    suspend fun action(instanceId: String, action: Ec2Action): ApiResult<Ec2InstanceDto>
}

/** The launch-form reference data (instance types + AMIs) fetched together. */
data class Ec2Reference(
    val types: List<Ec2InstanceTypeDto>,
    val amis: List<Ec2AmiDto>,
)

enum class Ec2Action { START, STOP, REBOOT, TERMINATE }

@Singleton
class DefaultEc2Repository @Inject constructor(
    private val api: Ec2Api,
    private val errorParser: ApiErrorParser,
) : Ec2Repository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun reference(): ApiResult<Ec2Reference> = withContext(io) {
        call { Ec2Reference(types = api.instanceTypes().types, amis = api.amis().amis) }
    }

    override suspend fun list(status: String?): ApiResult<Ec2InstanceListDto> =
        withContext(io) { call { api.instances(status?.takeIf { it.isNotBlank() }) } }

    override suspend fun launch(req: Ec2LaunchReq): ApiResult<Ec2InstanceDto> =
        withContext(io) { call { api.launch(req) } }

    override suspend fun action(instanceId: String, action: Ec2Action): ApiResult<Ec2InstanceDto> =
        withContext(io) {
            call {
                when (action) {
                    Ec2Action.START -> api.start(instanceId)
                    Ec2Action.STOP -> api.stop(instanceId)
                    Ec2Action.REBOOT -> api.reboot(instanceId)
                    Ec2Action.TERMINATE -> api.terminate(instanceId)
                }
            }
        }

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
object Ec2ApiModule {
    @Provides
    @Singleton
    fun provideEc2Api(retrofit: Retrofit): Ec2Api = retrofit.create(Ec2Api::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class Ec2DataModule {
    @dagger.Binds
    @Singleton
    abstract fun bindEc2Repository(impl: DefaultEc2Repository): Ec2Repository
}
