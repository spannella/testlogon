package com.testlogon.android.core.network.agents

import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path

/**
 * AGENTS-BASICS (web-parity) - Retrofit interface for the LLM provider KEYS surface (web /agents/llm-keys).
 * Transport only; the :app repository folds these into ApiResult. Mirrors frontend/src/api/endpoints/llmKeys.ts.
 *
 * Paths have NO leading slash. The shared authenticated client attaches auth via the global interceptors. All
 * user paths are backend require_ui_session (the admin variant ui/admin/agent/llm-keys is require_admin_or_root
 * and is intentionally NOT surfaced here).
 *
 * The plaintext api_key is sent ONCE on [create]; the server NEVER returns it (only key_suffix). [list], [get]
 * and [providers] are idempotent GETs; [create], [delete], [test] are NON-idempotent (no auto-retry).
 */
interface LlmKeysApi {

    @GET("ui/agent/llm-providers")
    suspend fun providers(): LlmProviderListDto

    @GET("ui/agent/llm-keys")
    suspend fun list(): LlmKeyListDto

    @GET("ui/agent/llm-keys/{keyId}")
    suspend fun get(@Path("keyId") keyId: String): LlmKeyDto

    @POST("ui/agent/llm-keys")
    suspend fun create(@Body body: CreateLlmKeyRequest): LlmKeyDto

    @DELETE("ui/agent/llm-keys/{keyId}")
    suspend fun delete(@Path("keyId") keyId: String)

    @POST("ui/agent/llm-keys/{keyId}/test")
    suspend fun test(@Path("keyId") keyId: String): LlmKeyTestDto
}
