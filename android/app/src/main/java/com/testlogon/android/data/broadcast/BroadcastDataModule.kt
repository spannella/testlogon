package com.testlogon.android.data.broadcast

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/**
 * AND-278 — provides the dedicated [BroadcastApi] on the shared Retrofit (no new OkHttp/Retrofit) and
 * binds [BroadcastRepository]. Kept separate from other feature wiring.
 */
@Module
@InstallIn(SingletonComponent::class)
object BroadcastApiModule {

    @Provides
    @Singleton
    fun provideBroadcastApi(retrofit: Retrofit): BroadcastApi =
        retrofit.create(BroadcastApi::class.java)

    /** AND-309 — host LIVE lifecycle control plane on the SAME shared Retrofit (no new OkHttp/Retrofit). */
    @Provides
    @Singleton
    fun provideHostControlApi(retrofit: Retrofit): HostControlApi =
        retrofit.create(HostControlApi::class.java)

    /** AND-310 — inputs-management (list / activate / deactivate / layout) on the SAME shared Retrofit. */
    @Provides
    @Singleton
    fun provideInputsApi(retrofit: Retrofit): InputsApi =
        retrofit.create(InputsApi::class.java)

    /** AND-312 — guest invite / management surface on the SAME shared Retrofit (no new OkHttp/Retrofit). */
    @Provides
    @Singleton
    fun provideGuestApi(
        retrofit: Retrofit,
    ): com.testlogon.android.feature.guest.GuestApi =
        retrofit.create(com.testlogon.android.feature.guest.GuestApi::class.java)

    /** AND-313 — chat moderation (mute / ban / delete / pin / log) on the SAME shared Retrofit. */
    @Provides
    @Singleton
    fun provideModerationApi(
        retrofit: Retrofit,
    ): com.testlogon.android.feature.broadcast.moderation.ModerationApi =
        retrofit.create(com.testlogon.android.feature.broadcast.moderation.ModerationApi::class.java)

    /** AND-315 — host monetization (tip-config PATCH + private-show lifecycle) on the SAME shared Retrofit. */
    @Provides
    @Singleton
    fun provideBroadcastMonetizationApi(retrofit: Retrofit): BroadcastMonetizationApi =
        retrofit.create(BroadcastMonetizationApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class BroadcastDataModule {

    @Binds
    @Singleton
    abstract fun bindBroadcastRepository(impl: BroadcastRepositoryImpl): BroadcastRepository

    /** AND-309 — separate host control repository (keeps the shared BroadcastRepository fakes untouched). */
    @Binds
    @Singleton
    abstract fun bindHostControlRepository(impl: HostControlRepositoryImpl): HostControlRepository

    /** AND-310 — separate inputs-management repository (keeps the shared BroadcastRepository fakes untouched). */
    @Binds
    @Singleton
    abstract fun bindInputsRepository(impl: InputsRepositoryImpl): InputsRepository

    /**
     * AND-311 — separate layout-management repository. THIN: reuses the AND-310 [InputsApi] (getLayout /
     * switchLayout) + [com.testlogon.android.core.data.broadcast.InputsDao] layout cache; kept distinct from
     * InputsRepository so its fakes are untouched. No new API/DAO/migration.
     */
    @Binds
    @Singleton
    abstract fun bindLayoutRepository(
        impl: com.testlogon.android.feature.broadcast.layout.LayoutRepositoryImpl,
    ): com.testlogon.android.feature.broadcast.layout.LayoutRepository

    /**
     * AND-312 — separate guest invite/management repository. Consumes the AND-310 [InputsApi] for the
     * "guests = inputs filtered to input_type==guest" half; keeps its own in-memory cache (NO Room /
     * migration). Kept distinct so the shared broadcast/inputs fakes are untouched.
     */
    @Binds
    @Singleton
    abstract fun bindGuestRepository(
        impl: com.testlogon.android.feature.guest.GuestRepositoryImpl,
    ): com.testlogon.android.feature.guest.GuestRepository

    /**
     * AND-313 — separate chat-moderation repository. Kept distinct from BroadcastRepository / HostControl /
     * Guest so the shared broadcast fakes are NOT touched. No new API/DAO/migration/dependency.
     */
    @Binds
    @Singleton
    abstract fun bindModerationRepository(
        impl: com.testlogon.android.feature.broadcast.moderation.ModerationRepositoryImpl,
    ): com.testlogon.android.feature.broadcast.moderation.ModerationRepository

    /**
     * AND-315 — separate monetization repository (tip-config + private-show). Kept distinct from the shared
     * BroadcastRepository / HostControl / Inputs so their fakes are NOT touched. No new API/DAO/migration.
     */
    @Binds
    @Singleton
    abstract fun bindBroadcastMonetizationRepository(
        impl: BroadcastMonetizationRepositoryImpl,
    ): BroadcastMonetizationRepository
}
