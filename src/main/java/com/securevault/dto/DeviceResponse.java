package com.securevault.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class DeviceResponse {
    private String id;
    private String deviceName;
    private String deviceId;
    private LocalDateTime lastAccessedAt;
    private LocalDateTime createdAt;
}