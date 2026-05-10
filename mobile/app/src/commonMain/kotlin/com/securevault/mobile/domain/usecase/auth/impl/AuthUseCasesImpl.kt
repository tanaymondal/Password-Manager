package com.securevault.mobile.domain.usecase.auth.impl

import com.securevault.mobile.data.model.LoginRequest
import com.securevault.mobile.data.model.RegisterRequest
import com.securevault.mobile.data.repository.SessionManager
import com.securevault.mobile.domain.entity.AuthTokens
import com.securevault.mobile.domain.entity.User
import com.securevault.mobile.domain.model.Result
import com.securevault.mobile.domain.repository.AuthRepository
import com.securevault.mobile.domain.usecase.auth.*

class LoginUseCaseImpl(
    private val authRepository: AuthRepository
) : LoginUseCase {
    override suspend operator fun invoke(email: String, password: String): LoginResult {
        return when (val result = authRepository.login(email, password)) {
            is Result.Success -> {
                val authState = result.data
                LoginResult.Success(
                    tokens = AuthTokens(
                        accessToken = authState.accessToken!!,
                        refreshToken = authState.refreshToken!!,
                        encryptionSalt = authState.encryptionSalt!!,
                        userId = authState.user!!.id,
                        email = authState.user.email
                    ),
                    user = User(authState.user.id, authState.user.email)
                )
            }
            is Result.Error -> LoginResult.Error(result.message)
            is Result.Loading -> LoginResult.Error("Loading...")
        }
    }
}

class RegisterUseCaseImpl(
    private val authRepository: AuthRepository
) : RegisterUseCase {
    override suspend operator fun invoke(email: String, password: String): RegisterResult {
        return when (val result = authRepository.register(email, password)) {
            is Result.Success -> {
                val authState = result.data
                RegisterResult.Success(
                    tokens = AuthTokens(
                        accessToken = authState.accessToken!!,
                        refreshToken = authState.refreshToken!!,
                        encryptionSalt = authState.encryptionSalt!!,
                        userId = authState.user!!.id,
                        email = authState.user.email
                    ),
                    user = User(authState.user.id, authState.user.email)
                )
            }
            is Result.Error -> RegisterResult.Error(result.message)
            is Result.Loading -> RegisterResult.Error("Loading...")
        }
    }
}

class LogoutUseCaseImpl(
    private val authRepository: AuthRepository
) : LogoutUseCase {
    override suspend operator fun invoke(): LogoutResult {
        return when (val result = authRepository.logout()) {
            is Result.Success -> LogoutResult.Success
            is Result.Error -> LogoutResult.Error(result.message)
            is Result.Loading -> LogoutResult.Error("Loading...")
        }
    }
}

class RefreshTokenUseCaseImpl(
    private val authRepository: AuthRepository
) : RefreshTokenUseCase {
    override suspend operator fun invoke(): RefreshTokenResult {
        return when (val result = authRepository.refreshToken()) {
            is Result.Success -> {
                val authState = result.data
                RefreshTokenResult.Success(
                    AuthTokens(
                        accessToken = authState.accessToken!!,
                        refreshToken = authState.refreshToken!!,
                        encryptionSalt = authState.encryptionSalt!!,
                        userId = authState.user!!.id,
                        email = authState.user.email
                    )
                )
            }
            is Result.Error -> RefreshTokenResult.Error(result.message)
            is Result.Loading -> RefreshTokenResult.Error("Loading...")
        }
    }
}

class ChangePasswordUseCaseImpl(
    private val authRepository: AuthRepository
) : ChangePasswordUseCase {
    override suspend operator fun invoke(currentPassword: String, newPassword: String): ChangePasswordResult {
        return when (val result = authRepository.changePassword(currentPassword, newPassword)) {
            is Result.Success -> ChangePasswordResult.Success
            is Result.Error -> ChangePasswordResult.Error(result.message)
            is Result.Loading -> ChangePasswordResult.Error("Loading...")
        }
    }
}

class GetAuthStateUseCaseImpl(
    private val authRepository: AuthRepository
) : GetAuthStateUseCase {
    override operator fun invoke(): AuthStateResult {
        val authState = authRepository.getAuthState()
        return if (authState.isAuthenticated && authState.user != null) {
            AuthStateResult.Authenticated(
                user = User(authState.user.id, authState.user.email),
                encryptionSalt = authState.encryptionSalt
            )
        } else {
            AuthStateResult.Unauthenticated
        }
    }
}