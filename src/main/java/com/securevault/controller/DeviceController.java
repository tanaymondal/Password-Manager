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

/**
 * REST controller for device management endpoints.
 *
 * Allows users to manage devices authorized to access their vault.
 * Users can register new devices, view registered devices, and remove devices.
 *
 * SECURITY:
 * - All endpoints require JWT authentication
 * - Users can only manage their own devices
 * - Device ownership is verified on deletion
 *
 * @see DeviceService for business logic
 */
@Slf4j
@RestController
@RequestMapping("/api/v1/devices")
@RequiredArgsConstructor
public class DeviceController {

    private final DeviceService deviceService;

    /**
     * Registers a new device or updates an existing one.
     *
     * If the device ID already exists for this user, updates device info.
     * If the device ID is new, creates a new device registration.
     *
     * @param userDetails Injected from JWT authentication
     * @param request Contains deviceId, deviceName, and optionally publicKey
     * @return DeviceResponse with registered device details
     */
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

    /**
     * Retrieves all devices registered for the authenticated user.
     *
     * Returns a list of devices including names, IDs, and last access times.
     *
     * @param userDetails Injected from JWT authentication
     * @return DevicesResponse containing list of registered devices
     */
    @GetMapping
    public ResponseEntity<ApiResponse<DevicesResponse>> getAllDevices(
            @AuthenticationPrincipal UserDetails userDetails) {
        UUID userId = getUserId(userDetails);
        DevicesResponse response = deviceService.getAllDevices(userId);
        return ResponseEntity.ok(ApiResponse.success(response));
    }

    /**
     * Removes a device from the user's registered devices.
     *
     * Permanently removes the device registration. The device will
     * no longer be able to access the vault until re-registered.
     *
     * @param userDetails Injected from JWT authentication
     * @param deviceId String ID of the device to remove
     * @return Success response
     */
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