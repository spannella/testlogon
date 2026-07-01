package com.testlogon.android.core.network.agentconfig

import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.PUT
import retrofit2.http.POST
import retrofit2.http.Path

/**
 * B4 web-parity - Retrofit interface for the agent-TYPE config surfaces (web /agents/types/:typeId/{coder,
 * qa,devops,architect,pm}). Transport only; the :app AgentConfigRepository wraps these into ApiResult.
 *
 * These endpoints are OPERATOR-gated on the backend: every GET/PUT/POST here is served under
 * require_admin_or_root (PUTs additionally require_admin_or_root_csrf). The signed-in member (test acct) is
 * NOT an operator, so calls return 403 - the app renders a Forbidden(operatorOnly) state (expected, not a
 * failure). The shared authenticated OkHttp client attaches the session cookie + X-CSRF-Token via the global
 * interceptors, so no per-call header is needed.
 *
 * The five agent types share the get-config -> edit -> validate -> save lifecycle but each has a
 * type-specific config SHAPE (coder/qa/architect/pm are flat scalars + string lists; devops nests an
 * `environments` array and its GET is wrapped { type_id, devops_config, updated_at }). To keep ONE transport
 * + ONE screen, the config body/response is modeled as a free-form Map<String, Any?> (decoded via the shared
 * reflective Moshi, same as ProjectDtos `settings` / AdOptimization `optimization_config`); the :app layer
 * projects the map into a type-specific editable field list and rebuilds the PUT body map.
 *
 * Contract (relative paths, NO leading slash; {typeId} is the agent-type id, e.g. "coder"):
 *   GET  ui/agents/types/{type}/config-schema                         -> Map (JSON schema, read-only hint)
 *   GET  ui/agents/types/{typeId}/{coder|qa|architect|pm}-config      -> Map (the config object, bare)
 *   PUT  ui/agents/types/{typeId}/{...}-config          {config map}  -> Map (the saved config)
 *   POST ui/agents/types/{typeId}/{...}-config/validate {config map}  -> ConfigValidationDto { valid, errors }
 *   GET  ui/agents/types/{typeId}/devops-config                       -> Map { type_id, devops_config, updated_at }
 *   PUT  ui/agents/types/{typeId}/devops-config         {config map}  -> Map { type_id, devops_config, updated_at }
 */
interface AgentConfigApi {

    // ---- Coder (AGENT-008) ----
    @GET("ui/agents/types/coder/config-schema")
    suspend fun getCoderSchema(): Map<String, Any?>

    @GET("ui/agents/types/{typeId}/coder-config")
    suspend fun getCoderConfig(@Path("typeId") typeId: String): Map<String, Any?>

    @Headers("Content-Type: application/json")
    @PUT("ui/agents/types/{typeId}/coder-config")
    suspend fun putCoderConfig(
        @Path("typeId") typeId: String,
        @Body body: Map<String, Any?>,
    ): Map<String, Any?>

    @Headers("Content-Type: application/json")
    @POST("ui/agents/types/{typeId}/coder-config/validate")
    suspend fun validateCoderConfig(
        @Path("typeId") typeId: String,
        @Body body: Map<String, Any?>,
    ): ConfigValidationDto

    // ---- QA (AGENT-009) ----
    @GET("ui/agents/types/qa/config-schema")
    suspend fun getQaSchema(): Map<String, Any?>

    @GET("ui/agents/types/{typeId}/qa-config")
    suspend fun getQaConfig(@Path("typeId") typeId: String): Map<String, Any?>

    @Headers("Content-Type: application/json")
    @PUT("ui/agents/types/{typeId}/qa-config")
    suspend fun putQaConfig(
        @Path("typeId") typeId: String,
        @Body body: Map<String, Any?>,
    ): Map<String, Any?>

    @Headers("Content-Type: application/json")
    @POST("ui/agents/types/{typeId}/qa-config/validate")
    suspend fun validateQaConfig(
        @Path("typeId") typeId: String,
        @Body body: Map<String, Any?>,
    ): ConfigValidationDto

    // ---- DevOps/SRE (AGENT-010) - GET/PUT return a WRAPPED envelope ----
    @GET("ui/agents/types/devops/config-schema")
    suspend fun getDevOpsSchema(): Map<String, Any?>

    @GET("ui/agents/types/{typeId}/devops-config")
    suspend fun getDevOpsConfig(@Path("typeId") typeId: String): Map<String, Any?>

    @Headers("Content-Type: application/json")
    @PUT("ui/agents/types/{typeId}/devops-config")
    suspend fun putDevOpsConfig(
        @Path("typeId") typeId: String,
        @Body body: Map<String, Any?>,
    ): Map<String, Any?>

    @Headers("Content-Type: application/json")
    @POST("ui/agents/types/{typeId}/devops-config/validate")
    suspend fun validateDevOpsConfig(
        @Path("typeId") typeId: String,
        @Body body: Map<String, Any?>,
    ): ConfigValidationDto

    // ---- Solution Architect (AGENT-011) ----
    @GET("ui/agents/types/architect/config-schema")
    suspend fun getArchitectSchema(): Map<String, Any?>

    @GET("ui/agents/types/{typeId}/architect-config")
    suspend fun getArchitectConfig(@Path("typeId") typeId: String): Map<String, Any?>

    @Headers("Content-Type: application/json")
    @PUT("ui/agents/types/{typeId}/architect-config")
    suspend fun putArchitectConfig(
        @Path("typeId") typeId: String,
        @Body body: Map<String, Any?>,
    ): Map<String, Any?>

    @Headers("Content-Type: application/json")
    @POST("ui/agents/types/{typeId}/architect-config/validate")
    suspend fun validateArchitectConfig(
        @Path("typeId") typeId: String,
        @Body body: Map<String, Any?>,
    ): ConfigValidationDto

    // ---- Project Manager (AGENT-012) ----
    @GET("ui/agents/types/{typeId}/pm-config")
    suspend fun getPmConfig(@Path("typeId") typeId: String): Map<String, Any?>

    @Headers("Content-Type: application/json")
    @PUT("ui/agents/types/{typeId}/pm-config")
    suspend fun putPmConfig(
        @Path("typeId") typeId: String,
        @Body body: Map<String, Any?>,
    ): Map<String, Any?>

    @Headers("Content-Type: application/json")
    @POST("ui/agents/types/{typeId}/pm-config/validate")
    suspend fun validatePmConfig(
        @Path("typeId") typeId: String,
        @Body body: Map<String, Any?>,
    ): ConfigValidationDto
}
