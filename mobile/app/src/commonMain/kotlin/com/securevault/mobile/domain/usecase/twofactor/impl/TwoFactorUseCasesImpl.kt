package com.securevault.mobile.domain.usecase.twofactor.impl

import com.securevault.mobile.domain.entity.TwoFactorSetup
import com.securevault.mobile.domain.model.Result
import com.securevault.mobile.domain.repository.TwoFactorRepository
import com.securevault.mobile.domain.usecase.twofactor.*

class SetupTwoFactorUseCaseImpl(
    private val twoFactorRepository: TwoFactorRepository
) : SetupTwoFactorUseCase {
    override suspend operator fun invoke(): SetupTwoFactorResult {
        return when (val result = twoFactorRepository.setupTwoFactor()) {
            is Result.Success -> SetupTwoFactorResult.Success(
                TwoFactorSetup(secret = result.data.first, qrCodeUrl = result.data.second)
            )
            is Result.Error -> SetupTwoFactorResult.Error(result.message)
            is Result.Loading -> SetupTwoFactorResult.Error("Loading...")
        }
    }
}

class EnableTwoFactorUseCaseImpl(
    private val twoFactorRepository: TwoFactorRepository
) : EnableTwoFactorUseCase {
    override suspend operator fun invoke(code: String): EnableTwoFactorResult {
        return when (val result = twoFactorRepository.enableTwoFactor(code)) {
            is Result.Success -> EnableTwoFactorResult.Success
            is Result.Error -> EnableTwoFactorResult.Error(result.message)
            is Result.Loading -> EnableTwoFactorResult.Error("Loading...")
        }
    }
}

class DisableTwoFactorUseCaseImpl(
    private val twoFactorRepository: TwoFactorRepository
) : DisableTwoFactorUseCase {
    override suspend operator fun invoke(code: String): DisableTwoFactorResult {
        return when (val result = twoFactorRepository.disableTwoFactor(code)) {
            is Result.Success -> DisableTwoFactorResult.Success
            is Result.Error -> DisableTwoFactorResult.Error(result.message)
            is Result.Loading -> DisableTwoFactorResult.Error("Loading...")
        }
    }
}

class GetTwoFactorStatusUseCaseImpl(
    private val twoFactorRepository: TwoFactorRepository
) : GetTwoFactorStatusUseCase {
    override suspend operator fun invoke(): TwoFactorStatusResult {
        return when (val result = twoFactorRepository.getStatus()) {
            is Result.Success -> TwoFactorStatusResult.Success(result.data)
            is Result.Error -> TwoFactorStatusResult.Error(result.message)
            is Result.Loading -> TwoFactorStatusResult.Error("Loading...")
        }
    }
}