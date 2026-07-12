package com.testlogon.android.data.sshkeys

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
 * B7 Remote-Access: SSH Key Manager (management screen). Mirrors the web /remote/ssh-keys page
 * (SshKeyManagerPage.tsx + api/endpoints/sshKeys.ts). Backend: ssh_key_manager.py, prefix
 * /ui/remote/ssh-keys, gated by require_ui_session (owner-scoped). Timestamps are epoch SECONDS.
 *
 * NOTE on the "create-once secret" playbook hint: generate_key stores the private key server-side
 * (encrypted) and NEVER returns it — the create response is a plain SshKeyOut (public metadata only).
 * So this is a public-key manager (show/copy the OpenSSH public key + fingerprint), NOT a once-shown
 * private secret like developer API keys. Self-contained (Api + DTOs + Repository + DI).
 */
interface SshKeysApi {

    @GET("ui/remote/ssh-keys")
    suspend fun list(): SshKeyListDto

    @GET("ui/remote/ssh-keys/{id}")
    suspend fun get(@Path("id") keyId: String): SshKeyDto

    @POST("ui/remote/ssh-keys/generate")
    suspend fun generate(@Body body: GenerateSshKeyReq): SshKeyDto

    @POST("ui/remote/ssh-keys")
    suspend fun upload(@Body body: UploadSshKeyReq): SshKeyDto

    @DELETE("ui/remote/ssh-keys/{id}")
    suspend fun delete(@Path("id") keyId: String): OkDto

    @GET("ui/remote/ssh-keys/{id}/public")
    suspend fun publicKey(@Path("id") keyId: String): PublicKeyDto
}

@JsonClass(generateAdapter = true)
data class SshKeyDto(
    @Json(name = "key_id") val keyId: String = "",
    @Json(name = "label") val label: String = "",
    @Json(name = "key_type") val keyType: String = "",
    @Json(name = "key_bits") val keyBits: Int = 0,
    @Json(name = "public_key_openssh") val publicKeyOpenssh: String = "",
    @Json(name = "public_key_fingerprint") val publicKeyFingerprint: String = "",
    @Json(name = "passphrase_protected") val passphraseProtected: Boolean = false,
    @Json(name = "created_at") val createdAt: Long = 0L,
    @Json(name = "last_used_at") val lastUsedAt: Long = 0L,
    @Json(name = "associated_hosts") val associatedHosts: List<String> = emptyList(),
    @Json(name = "use_count") val useCount: Int = 0,
)

@JsonClass(generateAdapter = true)
data class SshKeyListDto(
    @Json(name = "keys") val keys: List<SshKeyDto> = emptyList(),
    @Json(name = "count") val count: Int = 0,
)

@JsonClass(generateAdapter = true)
data class PublicKeyDto(
    @Json(name = "key_id") val keyId: String = "",
    @Json(name = "public_key_openssh") val publicKeyOpenssh: String = "",
    @Json(name = "public_key_fingerprint") val publicKeyFingerprint: String = "",
)

@JsonClass(generateAdapter = true)
data class GenerateSshKeyReq(
    @Json(name = "label") val label: String,
    @Json(name = "key_type") val keyType: String = "ed25519",
    @Json(name = "key_bits") val keyBits: Int = 4096,
)

@JsonClass(generateAdapter = true)
data class UploadSshKeyReq(
    @Json(name = "label") val label: String,
    @Json(name = "private_key_pem") val privateKeyPem: String,
    @Json(name = "passphrase") val passphrase: String? = null,
)

@JsonClass(generateAdapter = true)
data class OkDto(
    @Json(name = "ok") val ok: Boolean = true,
)

interface SshKeysRepository {
    suspend fun list(): ApiResult<SshKeyListDto>
    suspend fun generate(req: GenerateSshKeyReq): ApiResult<SshKeyDto>
    suspend fun upload(req: UploadSshKeyReq): ApiResult<SshKeyDto>
    suspend fun delete(keyId: String): ApiResult<OkDto>
    suspend fun publicKey(keyId: String): ApiResult<PublicKeyDto>
}

@Singleton
class DefaultSshKeysRepository @Inject constructor(
    private val api: SshKeysApi,
    private val errorParser: ApiErrorParser,
) : SshKeysRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun list(): ApiResult<SshKeyListDto> = withContext(io) { call { api.list() } }

    override suspend fun generate(req: GenerateSshKeyReq): ApiResult<SshKeyDto> =
        withContext(io) { call { api.generate(req) } }

    override suspend fun upload(req: UploadSshKeyReq): ApiResult<SshKeyDto> =
        withContext(io) { call { api.upload(req) } }

    override suspend fun delete(keyId: String): ApiResult<OkDto> =
        withContext(io) { call { api.delete(keyId) } }

    override suspend fun publicKey(keyId: String): ApiResult<PublicKeyDto> =
        withContext(io) { call { api.publicKey(keyId) } }

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
object SshKeysApiModule {
    @Provides
    @Singleton
    fun provideSshKeysApi(retrofit: Retrofit): SshKeysApi = retrofit.create(SshKeysApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class SshKeysDataModule {
    @dagger.Binds
    @Singleton
    abstract fun bindSshKeysRepository(impl: DefaultSshKeysRepository): SshKeysRepository
}
