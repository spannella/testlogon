package com.testlogon.android.core.network.agentrun

import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/**
 * AGENT-RUN (web-parity) - Hilt wiring for the agent-run console transport. Provides [AgentRunApi] from the
 * shared singleton [Retrofit] (reusing the global OkHttp cookie-jar / CSRF / 401-refresh + shared Moshi; no
 * new Retrofit/OkHttp/Moshi/dependency). Mirrors AgentConfigNetworkModule.
 */
@Module
@InstallIn(SingletonComponent::class)
object AgentRunNetworkModule {

    @Provides
    @Singleton
    fun provideAgentRunApi(retrofit: Retrofit): AgentRunApi =
        retrofit.create(AgentRunApi::class.java)
}
