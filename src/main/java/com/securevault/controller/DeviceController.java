package com.securevault.controller;

import com.securevault.dto.ApiResponse;
import com.securevault.dto.DeviceRequest;
import com.securevault.dto.DeviceResponse;
import com.securevault.dto.DevicesResponse;
import com.securevault.service.DeviceService;
import com.securevault.util.UserUtils;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@Slf4j
@RestController
@RequestMapping("/api/v1/devices")
@RequiredArgsConstructor
public class DeviceController {

    private final DeviceService deviceService;

    @PostMapping
    public ResponseEntity<ApiResponse<DeviceResponse>> registerDevice(
            @AuthenticationPrincipal UserDetails userDetails,
            @Valid @RequestBody DeviceRequest request) {
        UUID userId = getUserId(userDetails);
        log.info("Registering device: {} for user: {}", request.getDeviceId(), userId);
        DeviceResponse response = deviceService.registerDevice(userId, request);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponse.success("Device registered successfully", response));
    }

    @GetMapping
    public ResponseEntity<ApiResponse<DevicesResponse>> getAllDevices(
            @AuthenticationPrincipal UserDetails userDetails) {
        UUID userId = getUserId(userDetails);
        DevicesResponse response = deviceService.getAllDevices(userId);
        return ResponseEntity.ok(ApiResponse.success(response));
    }

    @DeleteMapping("/{deviceId}")
    public ResponseEntity<ApiResponse<String>> deleteDevice(
            @AuthenticationPrincipal UserDetails userDetails,
            @PathVariable String deviceId) {
        UUID userId = getUserId(userDetails);
        log.info("Deleting device: {} for user: {}", deviceId, userId);
        deviceService.deleteDevice(userId, deviceId);
        return ResponseEntity.ok(ApiResponse.success("Device removed successfully", ""));
    }

    private UUID getUserId(UserDetails userDetails) {
        return UserUtils.getUserId(userDetails);
    }
}