package com.securevault.mobile.data.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class DeviceRequest(
    @SerialName("device_name") val deviceName: String,
    @SerialName("device_id") val deviceId: String
)

@Serializable
data class DeviceResponse(
    val id: Long,
    @SerialName("device_name") val deviceName: String,
    @SerialName("device_id") val deviceId: String,
    @SerialName("registered_at") val registeredAt: String,
    @SerialName("last_accessed") val lastAccessed: String? = null
)

@Serializable
data class DevicesApiResponse(
    val success: Boolean,
    val message: String? = null,
    val data: DevicesData? = null,
    val timestamp: String? = null
)

@Serializable
data class DevicesData(
    val devices: List<DeviceResponse>
)

@Serializable
data class DeviceApiResponse(
    val success: Boolean,
    val message: String? = null,
    val data: DeviceResponse? = null,
    val timestamp: String? = null
)

@Serializable
data class TwoFactorSetupResponse(
    val secret: String,
    val qrCodeUrl: String
)

@Serializable
data class EnableTwoFactorRequest(
    val code: String
)

@Serializable
data class TwoFactorStatusResponse(
    @SerialName("enabled") val enabled: Boolean
)

@Serializable
data class HealthResponse(
    val status: String,
    val database: String? = null,
    val timestamp: String
)