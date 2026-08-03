package com.testlogon.android.feature.webhooks.testing

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.webhooks.Webhook
import com.testlogon.android.core.model.webhooks.WebhookEventType
import com.testlogon.android.core.model.webhooks.WebhookTestResult
import com.testlogon.android.core.network.webhooks.CreateWebhookRequest
import com.testlogon.android.core.network.webhooks.EventTypesDto
import com.testlogon.android.core.network.webhooks.WebhookEndpointDto
import com.testlogon.android.core.network.webhooks.WebhookEventTypeDto
import com.testlogon.android.core.network.webhooks.WebhookRotateSecretDto
import com.testlogon.android.core.network.webhooks.WebhookTestResultDto
import com.testlogon.android.core.network.webhooks.WebhooksApi
import com.testlogon.android.feature.webhooks.data.WebhooksRepository
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.ResponseBody.Companion.toResponseBody
import retrofit2.HttpException
import retrofit2.Response

/**
 * AND-398 - in-memory fakes for the webhooks unit tests.
 *
 * The :app unit-test classpath has NO moshi-kotlin KotlinJsonAdapterFactory, so :app tests use a FAKE
 * [WebhooksApi] (no Moshi). Each call RECORDS its args / call-count BEFORE honouring a configured throw, so a
 * test can assert the @Path / @Body was passed even when the call fails. Helper / recording names are distinct
 * (the -Webhook- infix) and never shadow an interface method.
 */
class FakeWebhooksApi(
    var list: () -> List<WebhookEndpointDto> = { emptyList() },
    var get: () -> WebhookEndpointDto = { endpointDto("wh_1") },
    var create: () -> WebhookEndpointDto = { endpointDto("wh_new") },
    var eventTypes: () -> EventTypesDto = { EventTypesDto(eventTypes = emptyList()) },
    var test: () -> WebhookTestResultDto = { WebhookTestResultDto(status = "success", responseCode = 200) },
    var rotateSecret: () -> WebhookRotateSecretDto = { WebhookRotateSecretDto(secret = "whsec_rotated") },
) : WebhooksApi {

    var listCallCount = 0
    val getIds = mutableListOf<String>()
    val createBodies = mutableListOf<CreateWebhookRequest>()
    var eventTypesCallCount = 0

    override suspend fun list(): List<WebhookEndpointDto> {
        listCallCount++
        return list.invoke()
    }

    override suspend fun get(endpointId: String): WebhookEndpointDto {
        getIds += endpointId
        return get.invoke()
    }

    override suspend fun create(body: CreateWebhookRequest): WebhookEndpointDto {
        createBodies += body
        return create.invoke()
    }

    override suspend fun eventTypes(): EventTypesDto {
        eventTypesCallCount++
        return eventTypes.invoke()
    }

    val testIds = mutableListOf<String>()
    val rotateIds = mutableListOf<String>()

    override suspend fun test(endpointId: String): WebhookTestResultDto {
        testIds += endpointId
        return test.invoke()
    }

    override suspend fun rotateSecret(endpointId: String): WebhookRotateSecretDto {
        rotateIds += endpointId
        return rotateSecret.invoke()
    }

    companion object {
        /** Builds a wire [WebhookEndpointDto] with the AND-398 corrected field names. */
        fun endpointDto(
            id: String,
            url: String = "https://example.com/hooks/$id",
            eventTypes: List<String> = listOf("session.finalized"),
            enabled: Boolean = true,
            secret: String? = null,
            createdAt: Long? = 1_747_072_651L,
        ): WebhookEndpointDto = WebhookEndpointDto(
            endpointId = id,
            url = url,
            description = "",
            eventTypes = eventTypes,
            enabled = enabled,
            secret = secret,
            createdAt = createdAt,
            updatedAt = createdAt,
        )

        fun eventTypeDto(type: String, description: String = "desc") =
            WebhookEventTypeDto(type = type, description = description)

        /** Builds an HttpException with [status] (simulate a 401 / 422 / 500). */
        fun httpWebhookError(status: Int): HttpException = HttpException(
            Response.error<Any>(
                status,
                """{"detail":"boom"}""".toResponseBody("application/json".toMediaType()),
            ),
        )

        /** Builds a 422 HTTPValidationError whose loc tail is [field] (for the field-error mapping test). */
        fun http422FieldError(field: String, msg: String): HttpException = HttpException(
            Response.error<Any>(
                422,
                """{"detail":[{"loc":["body","$field"],"msg":"$msg","type":"value_error"}]}"""
                    .toResponseBody("application/json".toMediaType()),
            ),
        )
    }
}

/**
 * A fake [WebhooksRepository] for the ViewModel tests. Each result is independently swappable so a test can vary
 * a second (refresh) read. Records create args so a test can assert the POSTed url / events.
 */
class FakeWebhooksRepo(
    var listResult: ApiResult<List<Webhook>> = ApiResult.Success(emptyList()),
    var getResult: ApiResult<Webhook> = ApiResult.Success(webhook("wh_1")),
    var createResult: ApiResult<Webhook> = ApiResult.Success(webhook("wh_new")),
    var eventTypesResult: ApiResult<List<WebhookEventType>> = ApiResult.Success(emptyList()),
    var testResult: ApiResult<WebhookTestResult> = ApiResult.Success(WebhookTestResult(status = "success", responseCode = 200)),
    var rotateResult: ApiResult<String> = ApiResult.Success("whsec_rotated"),
) : WebhooksRepository {

    var listCallCount = 0
    var getCallCount = 0
    var eventTypesCallCount = 0

    /** Records each create as (url, events) so a test can assert the submitted form. */
    val createArgs = mutableListOf<Pair<String, List<String>>>()

    override suspend fun list(forceRefresh: Boolean): ApiResult<List<Webhook>> {
        listCallCount++
        return listResult
    }

    override suspend fun get(id: String): ApiResult<Webhook> {
        getCallCount++
        return getResult
    }

    override suspend fun create(targetUrl: String, events: List<String>): ApiResult<Webhook> {
        createArgs += targetUrl to events
        return createResult
    }

    override suspend fun eventTypes(): ApiResult<List<WebhookEventType>> {
        eventTypesCallCount++
        return eventTypesResult
    }

    val testIds = mutableListOf<String>()
    val rotateIds = mutableListOf<String>()

    override suspend fun test(id: String): ApiResult<WebhookTestResult> {
        testIds += id
        return testResult
    }

    override suspend fun rotateSecret(id: String): ApiResult<String> {
        rotateIds += id
        return rotateResult
    }

    companion object {
        fun webhooksFailure(status: Int = 500, message: String = "boom"): ApiResult.Failure =
            ApiResult.Failure(ApiError(status = status, message = message))

        /** A small domain webhook builder for the ViewModel tests. */
        fun webhook(
            id: String,
            url: String = "https://example.com/hooks/$id",
            events: List<String> = listOf("session.finalized"),
            enabled: Boolean = true,
            secret: String? = null,
            createdAt: Long? = 1_747_072_651L,
        ): Webhook = Webhook(
            id = id,
            url = url,
            description = "",
            events = events,
            enabled = enabled,
            secretSet = secret != null,
            secret = secret,
            createdAt = createdAt,
        )

        fun eventType(type: String, description: String = "desc") =
            WebhookEventType(type = type, description = description)
    }
}
