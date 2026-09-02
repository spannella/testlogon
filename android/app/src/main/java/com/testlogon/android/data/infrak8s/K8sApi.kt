package com.testlogon.android.data.infrak8s

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
import retrofit2.http.Query
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * B7 Cloud-Infra: K8s pod launcher ("Containers") management screen. Mirrors K8sLauncherPage.tsx +
 * api/endpoints/k8s.ts. Backend: k8s_launcher.py, prefix /ui/remote/k8s, require_ui_session. Deploy a
 * pod from an image + preset, list pods, view pod logs, terminate. Self-contained per the B5 pattern.
 */
interface K8sApi {

    @GET("ui/remote/k8s/images")
    suspend fun images(): K8sImageListDto

    @GET("ui/remote/k8s/presets")
    suspend fun presets(): K8sPresetListDto

    @POST("ui/remote/k8s/launch")
    suspend fun launch(@Body body: K8sLaunchReq): K8sPodDto

    @GET("ui/remote/k8s/pods")
    suspend fun pods(@Query("status") status: String? = null): K8sPodListDto

    @GET("ui/remote/k8s/pods/{id}")
    suspend fun getPod(@Path("id") podId: String): K8sPodDto

    @GET("ui/remote/k8s/pods/{id}/logs")
    suspend fun logs(@Path("id") podId: String, @Query("tail") tail: Int? = null): K8sPodLogsDto

    @DELETE("ui/remote/k8s/pods/{id}")
    suspend fun terminate(@Path("id") podId: String): K8sPodDto
}

@JsonClass(generateAdapter = true)
data class K8sPodDto(
    @Json(name = "pod_id") val podId: String = "",
    @Json(name = "k8s_pod_name") val k8sPodName: String = "",
    @Json(name = "namespace") val namespace: String = "",
    @Json(name = "label") val label: String = "",
    @Json(name = "image") val image: String = "",
    @Json(name = "image_display_name") val imageDisplayName: String = "",
    @Json(name = "preset") val preset: String = "",
    @Json(name = "cpu_millicores") val cpuMillicores: Int = 0,
    @Json(name = "memory_mb") val memoryMb: Int = 0,
    @Json(name = "status") val status: String = "",
    @Json(name = "pod_ip") val podIp: String = "",
    @Json(name = "service_hostname") val serviceHostname: String = "",
    @Json(name = "ssh_port") val sshPort: Int = 22,
    @Json(name = "created_at") val createdAt: Long = 0L,
    @Json(name = "ttl_seconds") val ttlSeconds: Long = 14400L,
    @Json(name = "expires_at") val expiresAt: Long = 0L,
)

@JsonClass(generateAdapter = true)
data class K8sPodListDto(
    @Json(name = "pods") val pods: List<K8sPodDto> = emptyList(),
    @Json(name = "count") val count: Int = 0,
)

@JsonClass(generateAdapter = true)
data class K8sPodLogsDto(
    @Json(name = "pod_id") val podId: String = "",
    @Json(name = "lines") val lines: List<String> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class K8sImageDto(
    @Json(name = "image") val image: String = "",
    @Json(name = "display_name") val displayName: String = "",
    @Json(name = "os_type") val osType: String = "",
    @Json(name = "username") val username: String = "",
)

@JsonClass(generateAdapter = true)
data class K8sImageListDto(
    @Json(name = "images") val images: List<K8sImageDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class K8sPresetDto(
    @Json(name = "preset") val preset: String = "",
    @Json(name = "cpu_millicores") val cpuMillicores: Int = 0,
    @Json(name = "memory_mb") val memoryMb: Int = 0,
    @Json(name = "cost_cents_per_min") val costCentsPerMin: Double = 0.0,
)

@JsonClass(generateAdapter = true)
data class K8sPresetListDto(
    @Json(name = "presets") val presets: List<K8sPresetDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class K8sLaunchReq(
    @Json(name = "label") val label: String,
    @Json(name = "image") val image: String,
    @Json(name = "preset") val preset: String = "small",
    @Json(name = "ttl_seconds") val ttlSeconds: Int = 14400,
)

interface K8sRepository {
    suspend fun reference(): ApiResult<K8sReference>
    suspend fun list(status: String?): ApiResult<K8sPodListDto>
    suspend fun get(podId: String): ApiResult<K8sPodDto>
    suspend fun launch(req: K8sLaunchReq): ApiResult<K8sPodDto>
    suspend fun logs(podId: String): ApiResult<K8sPodLogsDto>
    suspend fun terminate(podId: String): ApiResult<K8sPodDto>
}

data class K8sReference(
    val images: List<K8sImageDto>,
    val presets: List<K8sPresetDto>,
)

@Singleton
class DefaultK8sRepository @Inject constructor(
    private val api: K8sApi,
    private val errorParser: ApiErrorParser,
) : K8sRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun reference(): ApiResult<K8sReference> = withContext(io) {
        call { K8sReference(images = api.images().images, presets = api.presets().presets) }
    }

    override suspend fun list(status: String?): ApiResult<K8sPodListDto> =
        withContext(io) { call { api.pods(status?.takeIf { it.isNotBlank() }) } }

    override suspend fun get(podId: String): ApiResult<K8sPodDto> =
        withContext(io) { call { api.getPod(podId) } }

    override suspend fun launch(req: K8sLaunchReq): ApiResult<K8sPodDto> =
        withContext(io) { call { api.launch(req) } }

    override suspend fun logs(podId: String): ApiResult<K8sPodLogsDto> =
        withContext(io) { call { api.logs(podId, tail = 200) } }

    override suspend fun terminate(podId: String): ApiResult<K8sPodDto> =
        withContext(io) { call { api.terminate(podId) } }

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
object K8sApiModule {
    @Provides
    @Singleton
    fun provideK8sApi(retrofit: Retrofit): K8sApi = retrofit.create(K8sApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class K8sDataModule {
    @dagger.Binds
    @Singleton
    abstract fun bindK8sRepository(impl: DefaultK8sRepository): K8sRepository
}
