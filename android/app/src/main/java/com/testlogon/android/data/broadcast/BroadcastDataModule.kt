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
}
