package com.securevault.mobile.di

import com.securevault.mobile.data.api.SecureVaultApi
import com.securevault.mobile.data.local.IosEntryEncryptor
import com.securevault.mobile.data.repository.*
import com.securevault.mobile.domain.repository.AuthRepository
import com.securevault.mobile.domain.repository.DeviceRepository
import com.securevault.mobile.domain.repository.TwoFactorRepository
import com.securevault.mobile.domain.repository.VaultRepository
import org.koin.dsl.module

val appModule = module {
    single<SecureVaultApi> { SecureVaultApi.create("http://password-manager-compose-tsyrns-8069af-173-249-209-81.sslip.io") }

    single<EntryEncryptor> { IosEntryEncryptor() }

    single<AuthRepository> { AuthRepositoryImpl(get()) }
    single<VaultRepository> { VaultRepositoryImpl(get(), get()) }
    single<DeviceRepository> { DeviceRepositoryImpl(get()) }
    single<TwoFactorRepository> { TwoFactorRepositoryImpl(get()) }
}
