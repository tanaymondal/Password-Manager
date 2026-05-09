package com.securevault.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import java.util.List;

@Data
@AllArgsConstructor
public class DevicesResponse {
    private List<DeviceResponse> devices;
    private int count;
}