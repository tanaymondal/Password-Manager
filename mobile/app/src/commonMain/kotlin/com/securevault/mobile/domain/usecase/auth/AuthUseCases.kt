package com.securevault.mobile.domain.usecase.auth

import com.securevault.mobile.domain.entity.AuthTokens
import com.securevault.mobile.domain.entity.User

interface LoginUseCase {
    suspend operator fun invoke(email: String, password: String): LoginResult
}

sealed class LoginResult {
    data class Success(val tokens: AuthTokens, val user: User) : LoginResult()
    data class Error(val message: String) : LoginResult()
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

interface ChangePasswordUseCase {
    suspend operator fun invoke(currentPassword: String, newPassword: String): ChangePasswordResult
}

sealed class ChangePasswordResult {
    data object Success : ChangePasswordResult()
    data class Error(val message: String) : ChangePasswordResult()
}

interface GetAuthStateUseCase {
    operator fun invoke(): AuthStateResult
}

sealed class AuthStateResult {
    data class Authenticated(val user: User, val encryptionSalt: String?) : AuthStateResult()
    data object Unauthenticated : AuthStateResult()
}