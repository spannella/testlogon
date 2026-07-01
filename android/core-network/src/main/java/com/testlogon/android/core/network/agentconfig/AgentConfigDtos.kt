package com.testlogon.android.core.network.agentconfig

import com.squareup.moshi.Json

/**
 * B4 web-parity - transport DTO for the shared agent-type config VALIDATE response
 * ({ valid, errors[] }, identical shape across coder/qa/devops/architect/pm - see the *ConfigValidation
 * interfaces in frontend/src/api/types.ts). Decodes via the reflective KotlinJsonAdapterFactory on the
 * shared Moshi (core-network applies no codegen). The config objects themselves are transported as free-form
 * Map<String, Any?> (see AgentConfigApi), so no per-type config DTO is declared here.
 */
data class ConfigValidationDto(
    @Json(name = "valid") val valid: Boolean = false,
    @Json(name = "errors") val errors: List<String> = emptyList(),
)
