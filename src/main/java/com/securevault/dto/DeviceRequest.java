package com.securevault.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class DeviceRequest {

    @NotBlank(message = "Device name is required")
    private String deviceName;

    @NotBlank(message = "Device ID is required")
    private String deviceId;
}