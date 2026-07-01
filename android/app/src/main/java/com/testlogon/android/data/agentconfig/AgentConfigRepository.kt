package com.testlogon.android.data.agentconfig

import com.squareup.moshi.JsonDataException
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.agentconfig.AgentConfigApi
import com.testlogon.android.core.network.agentconfig.ConfigValidationDto
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

/**
 * B4 web-parity - data layer over [AgentConfigApi] for the five agent-TYPE config forms. Routes each
 * [AgentConfigType] to the correct GET/PUT/validate method, unwraps the DevOps envelope on load and re-wraps
 * on save, and projects the loaded config map into a render-ready [ConfigForm]. Every call is wrapped in
 * [ApiResult]; a 403 surfaces as ApiResult.Failure with status 403 (the VM maps that to a Forbidden state -
 * expected for the non-operator test user).
 */
interface AgentConfigRepository {

    suspend fun load(type: AgentConfigType, typeId: String): ApiResult<ConfigForm>

    suspend fun save(type: AgentConfigType, typeId: String, form: ConfigForm): ApiResult<ConfigValidation>

    suspend fun validate(type: AgentConfigType, typeId: String, form: ConfigForm): ApiResult<ConfigValidation>
}

@Singleton
class AgentConfigRepositoryImpl @Inject constructor(
    private val api: AgentConfigApi,
    private val errorParser: ApiErrorParser,
) : AgentConfigRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun load(type: AgentConfigType, typeId: String): ApiResult<ConfigForm> =
        withContext(io) {
            call {
                val raw = when (type) {
                    AgentConfigType.CODER -> api.getCoderConfig(typeId)
                    AgentConfigType.QA -> api.getQaConfig(typeId)
                    AgentConfigType.DEVOPS -> api.getDevOpsConfig(typeId)
                    AgentConfigType.ARCHITECT -> api.getArchitectConfig(typeId)
                    AgentConfigType.PM -> api.getPmConfig(typeId)
                }
                projectForm(type, unwrap(type, raw))
            }
        }

    override suspend fun save(
        type: AgentConfigType,
        typeId: String,
        form: ConfigForm,
    ): ApiResult<ConfigValidation> = withContext(io) {
        val body = wrap(type, form.toRequestBody())
        call {
            when (type) {
                AgentConfigType.CODER -> api.putCoderConfig(typeId, body)
                AgentConfigType.QA -> api.putQaConfig(typeId, body)
                AgentConfigType.DEVOPS -> api.putDevOpsConfig(typeId, body)
                AgentConfigType.ARCHITECT -> api.putArchitectConfig(typeId, body)
                AgentConfigType.PM -> api.putPmConfig(typeId, body)
            }
            // A 2xx PUT means the server accepted (and validated) the config.
            ConfigValidation(valid = true, errors = emptyList())
        }
    }

    override suspend fun validate(
        type: AgentConfigType,
        typeId: String,
        form: ConfigForm,
    ): ApiResult<ConfigValidation> = withContext(io) {
        val body = wrap(type, form.toRequestBody())
        call {
            val dto: ConfigValidationDto = when (type) {
                AgentConfigType.CODER -> api.validateCoderConfig(typeId, body)
                AgentConfigType.QA -> api.validateQaConfig(typeId, body)
                AgentConfigType.DEVOPS -> api.validateDevOpsConfig(typeId, body)
                AgentConfigType.ARCHITECT -> api.validateArchitectConfig(typeId, body)
                AgentConfigType.PM -> api.validatePmConfig(typeId, body)
            }
            ConfigValidation(valid = dto.valid, errors = dto.errors)
        }
    }

    // ---- Envelope handling (DevOps wraps under `devops_config`) ----

    @Suppress("UNCHECKED_CAST")
    private fun unwrap(type: AgentConfigType, raw: Map<String, Any?>): Map<String, Any?> {
        val key = type.wrappedUnder ?: return raw
        return (raw[key] as? Map<String, Any?>) ?: raw
    }

    private fun wrap(type: AgentConfigType, body: Map<String, Any?>): Map<String, Any?> {
        val key = type.wrappedUnder ?: return body
        return mapOf(key to body)
    }

    // ---- Map -> ConfigForm projection ----

    private fun projectForm(type: AgentConfigType, config: Map<String, Any?>): ConfigForm {
        val values = mutableMapOf<String, String>()
        val bools = mutableMapOf<String, Boolean>()
        for (spec in type.fields) {
            val v = config[spec.key]
            when (spec.type) {
                AgentField.BOOL -> bools[spec.key] = (v as? Boolean) ?: false
                AgentField.STRING_LIST -> values[spec.key] =
                    (v as? List<*>)?.joinToString("\n") { it?.toString().orEmpty() } ?: ""
                AgentField.NUMBER_INT, AgentField.NUMBER_DOUBLE ->
                    values[spec.key] = numberToString(v)
                AgentField.TEXT, AgentField.MULTILINE, AgentField.ENUM ->
                    values[spec.key] = v?.toString().orEmpty()
            }
        }
        return ConfigForm(type = type, values = values, bools = bools, raw = config)
    }

    /** Render a JSON number cleanly (Moshi decodes JSON numbers as Double, so 600.0 -> "600"). */
    private fun numberToString(v: Any?): String = when (v) {
        null -> ""
        is Double -> if (v % 1.0 == 0.0) v.toLong().toString() else v.toString()
        else -> v.toString()
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
