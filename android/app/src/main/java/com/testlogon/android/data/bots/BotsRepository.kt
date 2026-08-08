package com.testlogon.android.data.bots

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

/**
 * Bots data layer over [BotsApi].
 *
 * loadBots() / loadAutoReplyRules() / loadTemplates() issue idempotent GETs and map to domain;
 * the create/update/delete calls POST/PUT/PATCH/DELETE the mutations (not auto-retried). Every call is
 * wrapped in [ApiResult] (CancellationException re-thrown, HTTP -> Failure, transport -> NetworkError).
 * A last-known-good bots list is held in memory so a failed refresh can fall back to a stale snapshot;
 * [clear] empties it (logout cleanup). The per-bot auto-reply / template lists are not cached (they are
 * scoped to a transient detail screen).
 */
interface BotsRepository {

    suspend fun loadBots(): ApiResult<List<Bot>>

    suspend fun createBot(name: String, description: String?, personality: String?): ApiResult<Unit>

    suspend fun updateBotStatus(botId: String, status: BotStatus): ApiResult<Unit>

    suspend fun deleteBot(botId: String): ApiResult<Unit>

    /**
     * PAR-32 - sends a test message as [botId] into [conversationId]. Default impl returns a
     * not-implemented NetworkError so pre-existing fakes need no change (only the impl overrides it).
     */
    suspend fun sendTest(
        botId: String,
        conversationId: String,
        text: String,
    ): ApiResult<Unit> = ApiResult.NetworkError(
        UnsupportedOperationException("sendTest not implemented"),
        isTimeout = false,
    )

    suspend fun loadAutoReplyRules(botId: String): ApiResult<List<AutoReplyRule>>

    suspend fun createAutoReplyRule(
        botId: String,
        triggerPattern: String,
        responseTemplate: String,
        matchType: AutoReplyMatchType,
        priority: Int,
        enabled: Boolean,
    ): ApiResult<Unit>

    suspend fun updateAutoReplyRule(
        botId: String,
        ruleId: String,
        triggerPattern: String,
        responseTemplate: String,
        matchType: AutoReplyMatchType,
        priority: Int,
        enabled: Boolean,
    ): ApiResult<Unit>

    suspend fun deleteAutoReplyRule(botId: String, ruleId: String): ApiResult<Unit>

    suspend fun loadTemplates(botId: String): ApiResult<List<BotTemplate>>

    suspend fun createTemplate(
        botId: String,
        name: String,
        text: String,
        category: TemplateCategory,
        bodyFormat: String,
    ): ApiResult<Unit>

    suspend fun deleteTemplate(botId: String, templateId: String): ApiResult<Unit>

    fun cachedBots(): List<Bot>?

    fun clear()
}

@Singleton
class BotsRepositoryImpl @Inject constructor(
    private val api: BotsApi,
    private val errorParser: ApiErrorParser,
) : BotsRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    @Volatile
    private var snapshot: List<Bot>? = null

    override suspend fun loadBots(): ApiResult<List<Bot>> = withContext(io) {
        call { api.listBots().toDomain() }
            .also { if (it is ApiResult.Success) snapshot = it.data }
    }

    override suspend fun createBot(
        name: String,
        description: String?,
        personality: String?,
    ): ApiResult<Unit> = withContext(io) {
        call {
            api.createBot(
                BotCreateReqDto(
                    name = name.trim(),
                    description = description?.trim()?.takeIf { it.isNotBlank() },
                    personality = personality?.trim()?.takeIf { it.isNotBlank() },
                ),
            )
            Unit
        }
    }

    override suspend fun updateBotStatus(botId: String, status: BotStatus): ApiResult<Unit> =
        withContext(io) {
            call { api.updateBotStatus(botId, BotStatusReqDto(status.wire)); Unit }
        }

    override suspend fun deleteBot(botId: String): ApiResult<Unit> = withContext(io) {
        call { api.deleteBot(botId); Unit }
    }

    override suspend fun sendTest(
        botId: String,
        conversationId: String,
        text: String,
    ): ApiResult<Unit> = withContext(io) {
        call {
            api.sendTest(
                botId,
                BotSendTestReqDto(conversationId = conversationId.trim(), text = text.trim()),
            )
            Unit
        }
    }

    override suspend fun loadAutoReplyRules(botId: String): ApiResult<List<AutoReplyRule>> =
        withContext(io) {
            call { api.listAutoReplyRules(botId).toDomain() }
        }

    override suspend fun createAutoReplyRule(
        botId: String,
        triggerPattern: String,
        responseTemplate: String,
        matchType: AutoReplyMatchType,
        priority: Int,
        enabled: Boolean,
    ): ApiResult<Unit> = withContext(io) {
        call {
            api.createAutoReplyRule(
                botId,
                AutoReplyReqDto(
                    triggerPattern = triggerPattern.trim(),
                    responseTemplate = responseTemplate.trim(),
                    matchType = matchType.wire,
                    priority = priority,
                    enabled = enabled,
                ),
            )
            Unit
        }
    }

    override suspend fun updateAutoReplyRule(
        botId: String,
        ruleId: String,
        triggerPattern: String,
        responseTemplate: String,
        matchType: AutoReplyMatchType,
        priority: Int,
        enabled: Boolean,
    ): ApiResult<Unit> = withContext(io) {
        call {
            api.updateAutoReplyRule(
                botId,
                ruleId,
                AutoReplyReqDto(
                    triggerPattern = triggerPattern.trim(),
                    responseTemplate = responseTemplate.trim(),
                    matchType = matchType.wire,
                    priority = priority,
                    enabled = enabled,
                ),
            )
            Unit
        }
    }

    override suspend fun deleteAutoReplyRule(botId: String, ruleId: String): ApiResult<Unit> =
        withContext(io) {
            call { api.deleteAutoReplyRule(botId, ruleId); Unit }
        }

    override suspend fun loadTemplates(botId: String): ApiResult<List<BotTemplate>> =
        withContext(io) {
            call { api.listTemplates(botId).map { it.toDomain() } }
        }

    override suspend fun createTemplate(
        botId: String,
        name: String,
        text: String,
        category: TemplateCategory,
        bodyFormat: String,
    ): ApiResult<Unit> = withContext(io) {
        call {
            api.createTemplate(
                botId,
                TemplateReqDto(
                    name = name.trim(),
                    text = text.trim(),
                    category = category.wire,
                    bodyFormat = bodyFormat,
                ),
            )
            Unit
        }
    }

    override suspend fun deleteTemplate(botId: String, templateId: String): ApiResult<Unit> =
        withContext(io) {
            call { api.deleteTemplate(botId, templateId); Unit }
        }

    override fun cachedBots(): List<Bot>? = snapshot

    override fun clear() {
        snapshot = null
    }

    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: com.squareup.moshi.JsonDataException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }
}
