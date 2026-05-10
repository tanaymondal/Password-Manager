package com.securevault.mobile.domain.repository

import com.securevault.mobile.domain.model.Device
import com.securevault.mobile.domain.model.Result
import com.securevault.mobile.domain.model.VaultEntry

interface VaultRepository {
    suspend fun getEntries(): Result<List<VaultEntry>>
    suspend fun getEntry(id: Long): Result<VaultEntry>
    suspend fun createEntry(entry: VaultEntry): Result<VaultEntry>
    suspend fun updateEntry(id: Long, entry: VaultEntry): Result<VaultEntry>
    suspend fun deleteEntry(id: Long): Result<Unit>
    suspend fun deleteAllEntries(): Result<Unit>
}

interface DeviceRepository {
    suspend fun getDevices(): Result<List<Device>>
    suspend fun registerDevice(deviceName: String, deviceId: String): Result<Device>
    suspend fun removeDevice(id: Long): Result<Unit>
}

interface TwoFactorRepository {
    suspend fun setupTwoFactor(): Result<Pair<String, String>>
    suspend fun enableTwoFactor(code: String): Result<Unit>
    suspend fun disableTwoFactor(code: String): Result<Unit>
    suspend fun getStatus(): Result<Boolean>
}