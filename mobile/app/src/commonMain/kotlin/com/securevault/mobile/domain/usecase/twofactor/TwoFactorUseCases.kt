package com.securevault.mobile.domain.usecase.twofactor

import com.securevault.mobile.domain.entity.TwoFactorSetup

interface SetupTwoFactorUseCase {
    suspend operator fun invoke(): SetupTwoFactorResult
}

sealed class SetupTwoFactorResult {
    data class Success(val setup: TwoFactorSetup) : SetupTwoFactorResult()
    data class Error(val message: String) : SetupTwoFactorResult()
}

interface EnableTwoFactorUseCase {
    suspend operator fun invoke(code: String): EnableTwoFactorResult
}

sealed class EnableTwoFactorResult {
    data object Success : EnableTwoFactorResult()
    data class Error(val message: String) : EnableTwoFactorResult()
}

interface DisableTwoFactorUseCase {
    suspend operator fun invoke(code: String): DisableTwoFactorResult
}

sealed class DisableTwoFactorResult {
    data object Success : DisableTwoFactorResult()
    data class Error(val message: String) : DisableTwoFactorResult()
}

interface GetTwoFactorStatusUseCase {
    suspend operator fun invoke(): TwoFactorStatusResult
}

sealed class TwoFactorStatusResult {
    data class Success(val enabled: Boolean) : TwoFactorStatusResult()
    data class Error(val message: String) : TwoFactorStatusResult()
}