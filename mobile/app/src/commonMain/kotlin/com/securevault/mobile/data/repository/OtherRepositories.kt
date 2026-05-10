package com.securevault.mobile.data.repository

import com.securevault.mobile.data.api.SecureVaultApi
import com.securevault.mobile.domain.model.Device
import com.securevault.mobile.domain.model.Result
import com.securevault.mobile.domain.repository.DeviceRepository
import com.securevault.mobile.domain.repository.TwoFactorRepository

class DeviceRepositoryImpl(
    private val api: SecureVaultApi
) : DeviceRepository {

    override suspend fun getDevices(): Result<List<Device>> {
        return try {
            val token = getValidToken()
            val response = api.getDevices(token)
            response.fold(
                onSuccess = { devices ->
                    val result = devices.map { device ->
                        Device(
                            id = device.id,
                            deviceName = device.deviceName,
                            deviceId = device.deviceId,
                            registeredAt = device.registeredAt,
                            lastAccessed = device.lastAccessed
                        )
                    }
                    Result.Success(result)
                },
                onFailure = { Result.Error(it.message ?: "Failed to fetch devices", it) }
            )
        } catch (e: Exception) {
            Result.Error(e.message ?: "Failed to fetch devices", e)
        }
    }

    override suspend fun registerDevice(deviceName: String, deviceId: String): Result<Device> {
        return try {
            val token = getValidToken()
            val response = api.registerDevice(token, com.securevault.mobile.data.model.DeviceRequest(deviceName, deviceId))
            response.fold(
                onSuccess = { device ->
                    Result.Success(
                        Device(
                            id = device.id,
                            deviceName = device.deviceName,
                            deviceId = device.deviceId,
                            registeredAt = device.registeredAt,
                            lastAccessed = device.lastAccessed
                        )
                    )
                },
                onFailure = { Result.Error(it.message ?: "Failed to register device", it) }
            )
        } catch (e: Exception) {
            Result.Error(e.message ?: "Failed to register device", e)
        }
    }

    override suspend fun removeDevice(id: Long): Result<Unit> {
        return try {
            val token = getValidToken()
            val response = api.removeDevice(token, id)
            response.fold(
                onSuccess = { Result.Success(Unit) },
                onFailure = { Result.Error(it.message ?: "Failed to remove device", it) }
            )
        } catch (e: Exception) {
            Result.Error(e.message ?: "Failed to remove device", e)
        }
    }

    private fun getValidToken(): String {
        val token = SessionManager.getAccessToken()
        if (token.isEmpty()) throw IllegalStateException("Not authenticated")
        return token
    }
}

class TwoFactorRepositoryImpl(
    private val api: SecureVaultApi
) : TwoFactorRepository {

    override suspend fun setupTwoFactor(): Result<Pair<String, String>> {
        return try {
            val token = getValidToken()
            val response = api.setupTwoFactor(token)
            response.fold(
                onSuccess = { setup ->
                    Result.Success(Pair(setup.secret, setup.qrCodeUrl))
                },
                onFailure = { Result.Error(it.message ?: "Failed to setup 2FA", it) }
            )
        } catch (e: Exception) {
            Result.Error(e.message ?: "Failed to setup 2FA", e)
        }
    }

    override suspend fun enableTwoFactor(code: String): Result<Unit> {
        return try {
            val token = getValidToken()
            val response = api.enableTwoFactor(token, com.securevault.mobile.data.model.EnableTwoFactorRequest(code))
            response.fold(
                onSuccess = { Result.Success(Unit) },
                onFailure = { Result.Error(it.message ?: "Failed to enable 2FA", it) }
            )
        } catch (e: Exception) {
            Result.Error(e.message ?: "Failed to enable 2FA", e)
        }
    }

    override suspend fun disableTwoFactor(code: String): Result<Unit> {
        return try {
            val token = getValidToken()
            val response = api.disableTwoFactor(token, code)
            response.fold(
                onSuccess = { Result.Success(Unit) },
                onFailure = { Result.Error(it.message ?: "Failed to disable 2FA", it) }
            )
        } catch (e: Exception) {
            Result.Error(e.message ?: "Failed to disable 2FA", e)
        }
    }

    override suspend fun getStatus(): Result<Boolean> {
        return try {
            val token = getValidToken()
            val response = api.getTwoFactorStatus(token)
            response.fold(
                onSuccess = { Result.Success(it.enabled) },
                onFailure = { Result.Error(it.message ?: "Failed to get 2FA status", it) }
            )
        } catch (e: Exception) {
            Result.Error(e.message ?: "Failed to get 2FA status", e)
        }
    }

    private fun getValidToken(): String {
        val token = SessionManager.getAccessToken()
        if (token.isEmpty()) throw IllegalStateException("Not authenticated")
        return token
    }
}