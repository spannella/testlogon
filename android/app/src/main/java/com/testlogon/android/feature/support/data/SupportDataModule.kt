package com.testlogon.android.feature.support.data

import com.testlogon.android.core.network.support.SupportApi
import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/** B-SUP (batch 7) — provides the SupportApi + binds the SupportRepository on the shared authed Retrofit. */
@Module
@InstallIn(SingletonComponent::class)
object SupportApiModule {
    @Provides
    @Singleton
    fun provideSupportApi(retrofit: Retrofit): SupportApi = retrofit.create(SupportApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class SupportDataModule {
    @Binds
    @Singleton
    abstract fun bindSupportRepository(impl: SupportRepositoryImpl): SupportRepository
}
