package com.securevault.mobile.di

import com.securevault.mobile.data.api.SecureVaultApi
import com.securevault.mobile.data.local.IosEntryEncryptor
import com.securevault.mobile.data.local.createSecureVaultDatabase
import com.securevault.mobile.data.repository.*
import com.securevault.mobile.domain.crypto.CryptoEngine
import com.securevault.mobile.domain.repository.AuthRepository
import com.securevault.mobile.domain.repository.DeviceRepository
import com.securevault.mobile.domain.repository.TwoFactorRepository
import com.securevault.mobile.domain.repository.VaultRepository
import com.securevault.mobile.domain.usecase.auth.*
import com.securevault.mobile.domain.usecase.auth.impl.*
import com.securevault.mobile.domain.usecase.device.*
import com.securevault.mobile.domain.usecase.device.impl.*
import com.securevault.mobile.domain.usecase.twofactor.*
import com.securevault.mobile.domain.usecase.twofactor.impl.*
import com.securevault.mobile.domain.usecase.vault.*
import com.securevault.mobile.domain.usecase.vault.impl.*
import com.securevault.mobile.ui.screens.auth.LoginViewModel
import com.securevault.mobile.ui.screens.auth.RegisterViewModel
import com.securevault.mobile.ui.screens.auth.UnlockViewModel
import com.securevault.mobile.ui.screens.settings.SettingsViewModel
import com.securevault.mobile.ui.screens.vault.AddEditEntryViewModel
import com.securevault.mobile.ui.screens.vault.VaultViewModel
import org.koin.dsl.module

val appModule = module {
    single<SecureVaultApi> { SecureVaultApi.create("https://vault.tanay.pro") }

    single<IosEntryEncryptor> { IosEntryEncryptor() }
    single<EntryEncryptor> { get<IosEntryEncryptor>() }
    single<VaultKeyManager> { get<IosEntryEncryptor>() }

    single<CryptoEngine> { CryptoEngine() }

    single<AuthRepository> { AuthRepositoryImpl(get(), get(), get(), get()) }
    single<VaultRepository> {
        CachedVaultRepository(
            dbProvider = { createSecureVaultDatabase() },
            apiRepository = VaultRepositoryImpl(get(), get()),
            encryptor = get()
        )
    }
    single<DeviceRepository> { DeviceRepositoryImpl(get()) }
    single<TwoFactorRepository> { TwoFactorRepositoryImpl(get()) }

    // Auth Use Cases
    factory<GetAuthStateUseCase> { GetAuthStateUseCaseImpl(get()) }
    factory<LoginUseCase> { LoginUseCaseImpl(get()) }
    factory<VerifyTwoFactorUseCase> { VerifyTwoFactorUseCaseImpl(get()) }
    factory<RegisterUseCase> { RegisterUseCaseImpl(get()) }
    factory<LogoutUseCase> { LogoutUseCaseImpl(get()) }
    factory<RefreshTokenUseCase> { RefreshTokenUseCaseImpl(get()) }
    factory<UnlockVaultUseCase> { UnlockVaultUseCaseImpl(get()) }

    // Vault Use Cases
    factory<GetVaultEntriesUseCase> { GetVaultEntriesUseCaseImpl(get()) }
    factory<GetVaultEntryUseCase> { GetVaultEntryUseCaseImpl(get()) }
    factory<CreateVaultEntryUseCase> { CreateVaultEntryUseCaseImpl(get()) }
    factory<UpdateVaultEntryUseCase> { UpdateVaultEntryUseCaseImpl(get()) }
    factory<DeleteVaultEntryUseCase> { DeleteVaultEntryUseCaseImpl(get()) }
    factory<DeleteAllVaultEntriesUseCase> { DeleteAllVaultEntriesUseCaseImpl(get()) }

    // Device Use Cases
    factory<GetDevicesUseCase> { GetDevicesUseCaseImpl(get()) }
    factory<RegisterDeviceUseCase> { RegisterDeviceUseCaseImpl(get()) }
    factory<RemoveDeviceUseCase> { RemoveDeviceUseCaseImpl(get()) }

    // Two-Factor Use Cases
    factory<SetupTwoFactorUseCase> { SetupTwoFactorUseCaseImpl(get()) }
    factory<EnableTwoFactorUseCase> { EnableTwoFactorUseCaseImpl(get()) }
    factory<DisableTwoFactorUseCase> { DisableTwoFactorUseCaseImpl(get()) }
    factory<GetTwoFactorStatusUseCase> { GetTwoFactorStatusUseCaseImpl(get()) }

    // ViewModels
    factory { LoginViewModel(get(), get(), get()) }
    factory { RegisterViewModel(get(), get()) }
    factory { VaultViewModel(get(), get(), get()) }
    factory { AddEditEntryViewModel(get(), get(), get()) }
    factory { SettingsViewModel(get(), get(), get(), get()) }
    factory { UnlockViewModel(get(), get()) }
}
