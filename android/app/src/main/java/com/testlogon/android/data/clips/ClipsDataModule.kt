package com.testlogon.android.data.clips

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/**
 * AND-196 — provides the dedicated [ClipsApi] on the shared Retrofit and binds [ClipsRepository].
 * Kept separate from the videos / VOD modules so this feature never touches their wiring.
 */
@Module
@InstallIn(SingletonComponent::class)
object ClipsApiModule {

    @Provides
    @Singleton
    fun provideClipsApi(retrofit: Retrofit): ClipsApi =
        retrofit.create(ClipsApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class ClipsDataModule {

    @Binds
    @Singleton
    abstract fun bindClipsRepository(impl: ClipsRepositoryImpl): ClipsRepository
}
