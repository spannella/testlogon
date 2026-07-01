package com.testlogon.android.data.infrahosts

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
import retrofit2.http.GET
import retrofit2.http.Query
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * B7 Cloud-Infra: Host inventory (list). Mirrors HostInventoryPage.tsx + api/endpoints/hostInventory.ts.
 * Backend: host_inventory.py, prefix /ui/hosts, require_ui_session (owner-scoped). This screen surfaces the
 * READ list (filter by protocol, sort); create/import/quick-connect are managed on the web console.
 * Self-contained per the B5 pattern.
 */
interface HostInventoryApi {

    @GET("ui/hosts")
    suspend fun list(
        @Query("protocol") protocol: String? = null,
        @Query("group") group: String? = null,
        @Query("sort_by") sortBy: String? = null,
        @Query("limit") limit: Int? = null,
    ): HostListDto

    @GET("ui/hosts/groups")
    suspend fun groups(): HostGroupListDto
}

@JsonClass(generateAdapter = true)
data class HostDto(
    @Json(name = "host_id") val hostId: String = "",
    @Json(name = "label") val label: String = "",
    @Json(name = "hostname") val hostname: String = "",
    @Json(name = "port") val port: Int = 0,
    @Json(name = "protocol") val protocol: String = "",
    @Json(name = "username") val username: String = "",
    @Json(name = "description") val description: String = "",
    @Json(name = "tags") val tags: List<String> = emptyList(),
    @Json(name = "group") val group: String = "",
    @Json(name = "os_type") val osType: String = "unknown",
    @Json(name = "last_connected_at") val lastConnectedAt: Long = 0L,
    @Json(name = "connection_count") val connectionCount: Int = 0,
    @Json(name = "status") val status: String = "unknown",
    @Json(name = "is_pinned") val isPinned: Boolean = false,
    @Json(name = "source") val source: String = "manual",
)

@JsonClass(generateAdapter = true)
data class HostListDto(
    @Json(name = "hosts") val hosts: List<HostDto> = emptyList(),
    @Json(name = "count") val count: Int = 0,
    @Json(name = "cursor") val cursor: String? = null,
)

@JsonClass(generateAdapter = true)
data class HostGroupListDto(
    @Json(name = "groups") val groups: List<String> = emptyList(),
)

interface HostInventoryRepository {
    suspend fun list(protocol: String?, group: String?): ApiResult<HostListDto>
    suspend fun groups(): ApiResult<List<String>>
}

@Singleton
class DefaultHostInventoryRepository @Inject constructor(
    private val api: HostInventoryApi,
    private val errorParser: ApiErrorParser,
) : HostInventoryRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun list(protocol: String?, group: String?): ApiResult<HostListDto> =
        withContext(io) {
            call {
                api.list(
                    protocol = protocol?.takeIf { it.isNotBlank() },
                    group = group?.takeIf { it.isNotBlank() },
                    sortBy = "label",
                    limit = 200,
                )
            }
        }

    override suspend fun groups(): ApiResult<List<String>> =
        withContext(io) { call { api.groups().groups } }

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
object HostInventoryApiModule {
    @Provides
    @Singleton
    fun provideHostInventoryApi(retrofit: Retrofit): HostInventoryApi =
        retrofit.create(HostInventoryApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class HostInventoryDataModule {
    @dagger.Binds
    @Singleton
    abstract fun bindHostInventoryRepository(impl: DefaultHostInventoryRepository): HostInventoryRepository
}
