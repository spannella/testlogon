package com.testlogon.android.core.network.groups

import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/**
 * AND-355 - Hilt wiring for the social-groups transport layer.
 *
 * Provides [GroupsApi] from the shared singleton [Retrofit] (reusing the production OkHttp / Moshi /
 * converter config; no new Retrofit, OkHttp or Moshi is built, and no new dependency is introduced).
 * The group DTOs decode with the reflective KotlinJsonAdapterFactory already on the shared Moshi (my_role
 * / role are plain Strings on the wire - the typed GroupRole enum + UNKNOWN fallback lives in core-model).
 * Mirrors the AND-353 OrgsNetworkModule pattern.
 */
@Module
@InstallIn(SingletonComponent::class)
object GroupsNetworkModule {

    @Provides
    @Singleton
    fun provideGroupsApi(retrofit: Retrofit): GroupsApi =
        retrofit.create(GroupsApi::class.java)
}
