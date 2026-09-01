package com.testlogon.android.core.network.workflow

import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/**
 * Hilt wiring for the SuiteCRM Workflow (WFL) transport layer. Provides [WorkflowRulesApi] from the
 * shared singleton [Retrofit] (reusing the production OkHttp / Moshi / converter config; no new Retrofit,
 * OkHttp, Moshi or dependency is introduced). The WFL read DTOs use String / Long / Boolean / loosely-
 * typed Map fields, which the shared reflective Moshi decodes without any new adapter.
 */
@Module
@InstallIn(SingletonComponent::class)
object WorkflowNetworkModule {

    @Provides
    @Singleton
    fun provideWorkflowRulesApi(retrofit: Retrofit): WorkflowRulesApi =
        retrofit.create(WorkflowRulesApi::class.java)
}
