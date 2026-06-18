package com.testlogon.android.data.licenses

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/** Provides [LicensesApi] on the shared (authenticated) Retrofit. */
@Module
@InstallIn(SingletonComponent::class)
object LicensesApiModule {

    @Provides
    @Singleton
    fun provideLicensesApi(retrofit: Retrofit): LicensesApi =
        retrofit.create(LicensesApi::class.java)
}

/** Binds the licensing-hub data-layer implementation. */
@Module
@InstallIn(SingletonComponent::class)
abstract class LicensesDataModule {

    @Binds
    @Singleton
    abstract fun bindLicensesRepository(impl: LicensesRepositoryImpl): LicensesRepository
}
