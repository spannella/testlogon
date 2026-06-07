package com.testlogon.android.auth

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * Binds the auth-state seam.
 *
 * WAVE 4 / AND-029: change this binding to point at the real session-backed provider. The router
 * depends only on the [AuthStateProvider] interface, so no navigation code changes are needed.
 */
@Module
@InstallIn(SingletonComponent::class)
abstract class AuthModule {
    @Binds
    @Singleton
    abstract fun bindAuthStateProvider(impl: DefaultAuthStateProvider): AuthStateProvider
}
