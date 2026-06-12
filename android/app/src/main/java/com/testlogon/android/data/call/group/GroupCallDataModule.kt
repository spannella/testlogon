package com.testlogon.android.data.call.group

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/**
 * AND-299 — Hilt wiring for the GROUP-call CONTROL PLANE.
 *
 * Provides [GroupCallApi] on the shared (authenticated) Retrofit and binds [GroupCallRepository]. The
 * FLAGGED media seam ([com.testlogon.android.data.webrtc.MeshConnectionManager]) is bound in
 * [com.testlogon.android.data.webrtc.WebRtcDataModule] alongside the other engine stubs, so the FLAGGED
 * media seams stay the single source of truth and the group-call media is "unavailable" until the native
 * WebRTC SDK is wired.
 */
@Module
@InstallIn(SingletonComponent::class)
object GroupCallProvidesModule {

    @Provides
    @Singleton
    fun provideGroupCallApi(retrofit: Retrofit): GroupCallApi =
        retrofit.create(GroupCallApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class GroupCallBindsModule {

    @Binds
    @Singleton
    abstract fun bindGroupCallRepository(impl: GroupCallRepositoryImpl): GroupCallRepository
}
