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
}

@Module
@InstallIn(SingletonComponent::class)
abstract class BroadcastDataModule {

    @Binds
    @Singleton
    abstract fun bindBroadcastRepository(impl: BroadcastRepositoryImpl): BroadcastRepository
}
