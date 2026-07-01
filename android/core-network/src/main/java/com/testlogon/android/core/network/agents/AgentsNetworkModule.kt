package com.testlogon.android.core.network.agents

import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/**
 * AGENTS-BASICS (web-parity) - Hilt wiring for the agents-BASICS transport layer.
 *
 * Provides the Retrofit interfaces from the shared singleton [Retrofit] (reusing the production OkHttp
 * cookie-jar / CSRF / 401-refresh + the shared Moshi with its reflective KotlinJsonAdapterFactory; no new
 * Retrofit / OkHttp / Moshi / dependency). Wave 1: workers / LLM keys / fleet. Wave 2: feedback / PR / memory /
 * doc-coverage. Mirrors AgentConfigNetworkModule / ApiKeysNetworkModule.
 */
@Module
@InstallIn(SingletonComponent::class)
object AgentsNetworkModule {

    @Provides
    @Singleton
    fun provideWorkersApi(retrofit: Retrofit): WorkersApi =
        retrofit.create(WorkersApi::class.java)

    @Provides
    @Singleton
    fun provideLlmKeysApi(retrofit: Retrofit): LlmKeysApi =
        retrofit.create(LlmKeysApi::class.java)

    @Provides
    @Singleton
    fun provideFleetApi(retrofit: Retrofit): FleetApi =
        retrofit.create(FleetApi::class.java)

    @Provides
    @Singleton
    fun provideFeedbackApi(retrofit: Retrofit): FeedbackApi =
        retrofit.create(FeedbackApi::class.java)

    @Provides
    @Singleton
    fun provideAgentPrApi(retrofit: Retrofit): AgentPrApi =
        retrofit.create(AgentPrApi::class.java)

    @Provides
    @Singleton
    fun provideMemoryApi(retrofit: Retrofit): MemoryApi =
        retrofit.create(MemoryApi::class.java)

    @Provides
    @Singleton
    fun provideDocsApi(retrofit: Retrofit): DocsApi =
        retrofit.create(DocsApi::class.java)
}
