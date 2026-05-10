package com.securevault.mobile.domain.usecase.device

import com.securevault.mobile.domain.entity.DeviceEntity

interface GetDevicesUseCase {
    suspend operator fun invoke(): DevicesResult
}

sealed class DevicesResult {
    data class Success(val devices: List<DeviceEntity>) : DevicesResult()
    data class Error(val message: String) : DevicesResult()
}

interface RegisterDeviceUseCase {
    suspend operator fun invoke(deviceName: String, deviceId: String): RegisterDeviceResult
}

sealed class RegisterDeviceResult {
    data class Success(val device: DeviceEntity) : RegisterDeviceResult()
    data class Error(val message: String) : RegisterDeviceResult()
}

interface RemoveDeviceUseCase {
    suspend operator fun invoke(id: Long): RemoveDeviceResult
}

sealed class RemoveDeviceResult {
    data object Success : RemoveDeviceResult()
    data class Error(val message: String) : RemoveDeviceResult()
}