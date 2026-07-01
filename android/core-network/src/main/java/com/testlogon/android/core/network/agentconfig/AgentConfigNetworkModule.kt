package com.testlogon.android.core.network.agentconfig

import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/**
 * B4 web-parity - Hilt wiring for the agent-type config transport layer. Provides [AgentConfigApi] from the
 * shared singleton [Retrofit] (reusing the global OkHttp cookie-jar / CSRF / 401-refresh + shared Moshi; no
 * new Retrofit/OkHttp/Moshi/dependency). Mirrors ProjectsNetworkModule.
 */
@Module
@InstallIn(SingletonComponent::class)
object AgentConfigNetworkModule {

    @Provides
    @Singleton
    fun provideAgentConfigApi(retrofit: Retrofit): AgentConfigApi =
        retrofit.create(AgentConfigApi::class.java)
}
