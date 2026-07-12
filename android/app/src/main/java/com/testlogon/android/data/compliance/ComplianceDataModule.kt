package com.testlogon.android.data.compliance

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/** Provides [ComplianceApi] on the shared (authenticated) Retrofit. */
@Module
@InstallIn(SingletonComponent::class)
object ComplianceApiModule {

    @Provides
    @Singleton
    fun provideComplianceApi(retrofit: Retrofit): ComplianceApi =
        retrofit.create(ComplianceApi::class.java)
}

/** Binds the compliance/security data-layer implementation. */
@Module
@InstallIn(SingletonComponent::class)
abstract class ComplianceDataModule {

    @Binds
    @Singleton
    abstract fun bindComplianceRepository(impl: ComplianceRepositoryImpl): ComplianceRepository
}
