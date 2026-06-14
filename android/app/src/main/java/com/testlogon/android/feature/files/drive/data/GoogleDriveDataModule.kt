package com.testlogon.android.feature.files.drive.data

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * AND-336 - binds the BACKEND-MEDIATED Google Drive repository.
 *
 * [com.testlogon.android.core.network.drive.GoogleDriveApi] is provided by the core-network
 * GoogleDriveModule (AUTHED Retrofit), so this module only binds the :app-side seam. No new dependency,
 * no Room, no Google SDK.
 */
@Module
@InstallIn(SingletonComponent::class)
abstract class GoogleDriveDataModule {

    @Binds
    @Singleton
    abstract fun bindGoogleDriveRepository(impl: GoogleDriveRepositoryImpl): GoogleDriveRepository
}
