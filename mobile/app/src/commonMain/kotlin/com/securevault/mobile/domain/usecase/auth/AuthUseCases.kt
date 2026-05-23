package com.securevault.mobile.domain.usecase.auth

import com.securevault.mobile.domain.entity.AuthTokens
import com.securevault.mobile.domain.entity.User
import com.securevault.mobile.domain.model.TwoFactorInfo

interface LoginUseCase {
    suspend operator fun invoke(email: String, password: String): LoginResult
}

sealed class LoginResult {
    data class Success(val tokens: AuthTokens, val user: User) : LoginResult()
    data class TwoFactorRequired(val info: TwoFactorInfo) : LoginResult()
    data class Error(val message: String) : LoginResult()
}

interface VerifyTwoFactorUseCase {
    suspend operator fun invoke(email: String, code: String, password: String): VerifyTwoFactorResult
}

sealed class VerifyTwoFactorResult {
    data class Success(val tokens: AuthTokens, val user: User) : VerifyTwoFactorResult()
    data class Error(val message: String) : VerifyTwoFactorResult()
}

interface RegisterUseCase {
    suspend operator fun invoke(email: String, password: String): RegisterResult
}

sealed class RegisterResult {
    data class Success(val tokens: AuthTokens, val user: User) : RegisterResult()
    data class Error(val message: String) : RegisterResult()
}

interface LogoutUseCase {
    suspend operator fun invoke(): LogoutResult
}

sealed class LogoutResult {
    data object Success : LogoutResult()
    data class Error(val message: String) : LogoutResult()
}

interface RefreshTokenUseCase {
    suspend operator fun invoke(): RefreshTokenResult
}

sealed class RefreshTokenResult {
    data class Success(val tokens: AuthTokens) : RefreshTokenResult()
    data class Error(val message: String) : RefreshTokenResult()
}

interface UnlockVaultUseCase {
    suspend operator fun invoke(password: String): UnlockVaultResult
}

sealed class UnlockVaultResult {
    data object Success : UnlockVaultResult()
    data class Error(val message: String) : UnlockVaultResult()
}

interface GetAuthStateUseCase {
    operator fun invoke(): AuthStateResult
}

sealed class AuthStateResult {
    data class Authenticated(val user: User, val encryptionSalt: String?) : AuthStateResult()
    data object Unauthenticated : AuthStateResult()
}