package com.testlogon.android.core.network.jira

import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/**
 * JIRA-AND-1 - Hilt wiring for the Jira integration transport layer.
 *
 * Provides [JiraApi] from the shared singleton [Retrofit] (reusing the production OkHttp / Moshi / converter
 * config; NO new Retrofit, OkHttp, Moshi, or dependency is introduced). The Jira DTOs decode with the reflective
 * KotlinJsonAdapterFactory already on the shared Moshi. Mirrors the AND-371 TicketsNetworkModule pattern.
 */
@Module
@InstallIn(SingletonComponent::class)
object JiraNetworkModule {

    @Provides
    @Singleton
    fun provideJiraApi(retrofit: Retrofit): JiraApi =
        retrofit.create(JiraApi::class.java)
}
