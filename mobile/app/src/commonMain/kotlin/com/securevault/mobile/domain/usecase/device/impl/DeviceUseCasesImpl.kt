package com.securevault.mobile.domain.usecase.device.impl

import com.securevault.mobile.domain.entity.DeviceEntity
import com.securevault.mobile.domain.model.Result
import com.securevault.mobile.domain.repository.DeviceRepository
import com.securevault.mobile.domain.usecase.device.*

class GetDevicesUseCaseImpl(
    private val deviceRepository: DeviceRepository
) : GetDevicesUseCase {
    override suspend operator fun invoke(): DevicesResult {
        return when (val result = deviceRepository.getDevices()) {
            is Result.Success -> DevicesResult.Success(result.data.map { it.toEntity() })
            is Result.Error -> DevicesResult.Error(result.message)
            is Result.Loading -> DevicesResult.Error("Loading...")
        }
    }

    private fun com.securevault.mobile.domain.model.Device.toEntity() = DeviceEntity(
        id = id,
        deviceName = deviceName,
        deviceId = deviceId,
        registeredAt = registeredAt,
        lastAccessed = lastAccessed
    )
}

class RegisterDeviceUseCaseImpl(
    private val deviceRepository: DeviceRepository
) : RegisterDeviceUseCase {
    override suspend operator fun invoke(deviceName: String, deviceId: String): RegisterDeviceResult {
        return when (val result = deviceRepository.registerDevice(deviceName, deviceId)) {
            is Result.Success -> RegisterDeviceResult.Success(result.data.toEntity())
            is Result.Error -> RegisterDeviceResult.Error(result.message)
            is Result.Loading -> RegisterDeviceResult.Error("Loading...")
        }
    }

    private fun com.securevault.mobile.domain.model.Device.toEntity() = DeviceEntity(
        id = id,
        deviceName = deviceName,
        deviceId = deviceId,
        registeredAt = registeredAt,
        lastAccessed = lastAccessed
    )
}

class RemoveDeviceUseCaseImpl(
    private val deviceRepository: DeviceRepository
) : RemoveDeviceUseCase {
    override suspend operator fun invoke(id: Long): RemoveDeviceResult {
        return when (val result = deviceRepository.removeDevice(id)) {
            is Result.Success -> RemoveDeviceResult.Success
            is Result.Error -> RemoveDeviceResult.Error(result.message)
            is Result.Loading -> RemoveDeviceResult.Error("Loading...")
        }
    }
}